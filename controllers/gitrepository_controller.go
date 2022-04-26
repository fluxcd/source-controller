/*
Copyright 2020 The Flux authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/fluxcd/pkg/runtime/logger"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kuberecorder "k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/ratelimiter"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/conditions"
	helper "github.com/fluxcd/pkg/runtime/controller"
	"github.com/fluxcd/pkg/runtime/events"
	"github.com/fluxcd/pkg/runtime/patch"
	"github.com/fluxcd/pkg/runtime/predicates"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
	serror "github.com/fluxcd/source-controller/internal/error"
	sreconcile "github.com/fluxcd/source-controller/internal/reconcile"
	"github.com/fluxcd/source-controller/internal/reconcile/summarize"
	"github.com/fluxcd/source-controller/internal/util"
	"github.com/fluxcd/source-controller/pkg/git"
	"github.com/fluxcd/source-controller/pkg/git/libgit2/managed"
	"github.com/fluxcd/source-controller/pkg/git/strategy"
	"github.com/fluxcd/source-controller/pkg/sourceignore"
)

// gitRepositoryReadyCondition contains the information required to summarize a
// v1beta2.GitRepository Ready Condition.
var gitRepositoryReadyCondition = summarize.Conditions{
	Target: meta.ReadyCondition,
	Owned: []string{
		sourcev1.StorageOperationFailedCondition,
		sourcev1.FetchFailedCondition,
		sourcev1.IncludeUnavailableCondition,
		sourcev1.ArtifactOutdatedCondition,
		sourcev1.ArtifactInStorageCondition,
		sourcev1.SourceVerifiedCondition,
		meta.ReadyCondition,
		meta.ReconcilingCondition,
		meta.StalledCondition,
	},
	Summarize: []string{
		sourcev1.StorageOperationFailedCondition,
		sourcev1.FetchFailedCondition,
		sourcev1.IncludeUnavailableCondition,
		sourcev1.ArtifactOutdatedCondition,
		sourcev1.ArtifactInStorageCondition,
		sourcev1.SourceVerifiedCondition,
		meta.StalledCondition,
		meta.ReconcilingCondition,
	},
	NegativePolarity: []string{
		sourcev1.StorageOperationFailedCondition,
		sourcev1.FetchFailedCondition,
		sourcev1.IncludeUnavailableCondition,
		sourcev1.ArtifactOutdatedCondition,
		meta.StalledCondition,
		meta.ReconcilingCondition,
	},
}

// gitRepositoryFailConditions contains the conditions that represent a failure.
var gitRepositoryFailConditions = []string{
	sourcev1.FetchFailedCondition,
	sourcev1.IncludeUnavailableCondition,
	sourcev1.StorageOperationFailedCondition,
}

// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=gitrepositories,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=gitrepositories/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=gitrepositories/finalizers,verbs=get;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// GitRepositoryReconciler reconciles a v1beta2.GitRepository object.
type GitRepositoryReconciler struct {
	client.Client
	kuberecorder.EventRecorder
	helper.Metrics

	Storage        *Storage
	ControllerName string

	requeueDependency time.Duration
}

type GitRepositoryReconcilerOptions struct {
	MaxConcurrentReconciles   int
	DependencyRequeueInterval time.Duration
	RateLimiter               ratelimiter.RateLimiter
}

// gitRepositoryReconcileFunc is the function type for all the
// v1beta2.GitRepository (sub)reconcile functions.
type gitRepositoryReconcileFunc func(ctx context.Context, obj *sourcev1.GitRepository, commit *git.Commit, includes *artifactSet, dir string) (sreconcile.Result, error)

func (r *GitRepositoryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return r.SetupWithManagerAndOptions(mgr, GitRepositoryReconcilerOptions{})
}

func (r *GitRepositoryReconciler) SetupWithManagerAndOptions(mgr ctrl.Manager, opts GitRepositoryReconcilerOptions) error {
	r.requeueDependency = opts.DependencyRequeueInterval

	return ctrl.NewControllerManagedBy(mgr).
		For(&sourcev1.GitRepository{}, builder.WithPredicates(
			predicate.Or(predicate.GenerationChangedPredicate{}, predicates.ReconcileRequestedPredicate{}),
		)).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: opts.MaxConcurrentReconciles,
			RateLimiter:             opts.RateLimiter,
		}).
		Complete(r)
}

func (r *GitRepositoryReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, retErr error) {
	start := time.Now()
	log := ctrl.LoggerFrom(ctx)

	// Fetch the GitRepository
	obj := &sourcev1.GitRepository{}
	if err := r.Get(ctx, req.NamespacedName, obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Record suspended status metric
	r.RecordSuspend(ctx, obj, obj.Spec.Suspend)

	// Return early if the object is suspended
	if obj.Spec.Suspend {
		log.Info("reconciliation is suspended for this object")
		return ctrl.Result{}, nil
	}

	// Initialize the patch helper with the current version of the object.
	patchHelper, err := patch.NewHelper(obj, r.Client)
	if err != nil {
		return ctrl.Result{}, err
	}

	// recResult stores the abstracted reconcile result.
	var recResult sreconcile.Result

	// Always attempt to patch the object and status after each reconciliation
	// NOTE: The final runtime result and error are set in this block.
	defer func() {
		summarizeHelper := summarize.NewHelper(r.EventRecorder, patchHelper)
		summarizeOpts := []summarize.Option{
			summarize.WithConditions(gitRepositoryReadyCondition),
			summarize.WithReconcileResult(recResult),
			summarize.WithReconcileError(retErr),
			summarize.WithIgnoreNotFound(),
			summarize.WithProcessors(
				summarize.RecordContextualError,
				summarize.RecordReconcileReq,
			),
			summarize.WithResultBuilder(sreconcile.AlwaysRequeueResultBuilder{RequeueAfter: obj.GetRequeueAfter()}),
			summarize.WithPatchFieldOwner(r.ControllerName),
		}
		result, retErr = summarizeHelper.SummarizeAndPatch(ctx, obj, summarizeOpts...)

		// Always record readiness and duration metrics
		r.Metrics.RecordReadiness(ctx, obj)
		r.Metrics.RecordDuration(ctx, obj, start)
	}()

	// Add finalizer first if not exist to avoid the race condition
	// between init and delete
	if !controllerutil.ContainsFinalizer(obj, sourcev1.SourceFinalizer) {
		controllerutil.AddFinalizer(obj, sourcev1.SourceFinalizer)
		recResult = sreconcile.ResultRequeue
		return
	}

	// Examine if the object is under deletion
	if !obj.ObjectMeta.DeletionTimestamp.IsZero() {
		recResult, retErr = r.reconcileDelete(ctx, obj)
		return
	}

	// Reconcile actual object
	reconcilers := []gitRepositoryReconcileFunc{
		r.reconcileStorage,
		r.reconcileSource,
		r.reconcileInclude,
		r.reconcileArtifact,
	}
	recResult, retErr = r.reconcile(ctx, obj, reconcilers)
	return
}

// reconcile iterates through the gitRepositoryReconcileFunc tasks for the
// object. It returns early on the first call that returns
// reconcile.ResultRequeue, or produces an error.
func (r *GitRepositoryReconciler) reconcile(ctx context.Context, obj *sourcev1.GitRepository, reconcilers []gitRepositoryReconcileFunc) (sreconcile.Result, error) {
	oldObj := obj.DeepCopy()

	// Mark as reconciling if generation differs
	if obj.Generation != obj.Status.ObservedGeneration {
		conditions.MarkReconciling(obj, "NewGeneration", "reconciling new object generation (%d)", obj.Generation)
	}

	// Create temp dir for Git clone
	tmpDir, err := util.TempDirForObj("", obj)
	if err != nil {
		e := &serror.Event{
			Err:    fmt.Errorf("failed to create temporary working directory: %w", err),
			Reason: sourcev1.DirCreationFailedReason,
		}
		conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, e.Reason, e.Err.Error())
		return sreconcile.ResultEmpty, e
	}
	defer func() {
		if err = os.RemoveAll(tmpDir); err != nil {
			ctrl.LoggerFrom(ctx).Error(err, "failed to remove temporary working directory")
		}
	}()
	conditions.Delete(obj, sourcev1.StorageOperationFailedCondition)

	// Run the sub-reconcilers and build the result of reconciliation.
	var (
		commit   git.Commit
		includes artifactSet

		res    sreconcile.Result
		resErr error
	)
	for _, rec := range reconcilers {
		recResult, err := rec(ctx, obj, &commit, &includes, tmpDir)
		// Exit immediately on ResultRequeue.
		if recResult == sreconcile.ResultRequeue {
			return sreconcile.ResultRequeue, nil
		}
		// If an error is received, prioritize the returned results because an
		// error also means immediate requeue.
		if err != nil {
			resErr = err
			res = recResult
			break
		}
		// Prioritize requeue request in the result.
		res = sreconcile.LowestRequeuingResult(res, recResult)
	}

	r.notify(oldObj, obj, commit, res, resErr)

	return res, resErr
}

// notify emits notification related to the reconciliation.
func (r *GitRepositoryReconciler) notify(oldObj, newObj *sourcev1.GitRepository, commit git.Commit, res sreconcile.Result, resErr error) {
	// Notify successful reconciliation for new artifact and recovery from any
	// failure.
	if resErr == nil && res == sreconcile.ResultSuccess && newObj.Status.Artifact != nil {
		annotations := map[string]string{
			sourcev1.GroupVersion.Group + "/revision": newObj.Status.Artifact.Revision,
			sourcev1.GroupVersion.Group + "/checksum": newObj.Status.Artifact.Checksum,
		}

		var oldChecksum string
		if oldObj.GetArtifact() != nil {
			oldChecksum = oldObj.GetArtifact().Checksum
		}

		message := fmt.Sprintf("stored artifact for commit '%s'", commit.ShortMessage())

		// Notify on new artifact and failure recovery.
		if oldChecksum != newObj.GetArtifact().Checksum {
			r.AnnotatedEventf(newObj, annotations, corev1.EventTypeNormal,
				"NewArtifact", message)
		} else {
			if sreconcile.FailureRecovery(oldObj, newObj, gitRepositoryFailConditions) {
				r.AnnotatedEventf(newObj, annotations, corev1.EventTypeNormal,
					meta.SucceededReason, message)
			}
		}
	}
}

// reconcileStorage ensures the current state of the storage matches the
// desired and previously observed state.
//
// The garbage collection is executed based on the flag based settings and
// may remove files that are beyond their TTL or the maximum number of files
// to survive a collection cycle.
// If the Artifact in the Status of the object disappeared from the Storage,
// it is removed from the object.
// If the object does not have an Artifact in its Status, a Reconciling
// condition is added.
// The hostname of any URL in the Status of the object are updated, to ensure
// they match the Storage server hostname of current runtime.
func (r *GitRepositoryReconciler) reconcileStorage(ctx context.Context,
	obj *sourcev1.GitRepository, _ *git.Commit, _ *artifactSet, _ string) (sreconcile.Result, error) {
	// Garbage collect previous advertised artifact(s) from storage
	_ = r.garbageCollect(ctx, obj)

	// Determine if the advertised artifact is still in storage
	if artifact := obj.GetArtifact(); artifact != nil && !r.Storage.ArtifactExist(*artifact) {
		obj.Status.Artifact = nil
		obj.Status.URL = ""
		// Remove the condition as the artifact doesn't exist.
		conditions.Delete(obj, sourcev1.ArtifactInStorageCondition)
	}

	// Record that we do not have an artifact
	if obj.GetArtifact() == nil {
		conditions.MarkReconciling(obj, "NoArtifact", "no artifact for resource in storage")
		conditions.Delete(obj, sourcev1.ArtifactInStorageCondition)
		return sreconcile.ResultSuccess, nil
	}

	// Always update URLs to ensure hostname is up-to-date
	// TODO(hidde): we may want to send out an event only if we notice the URL has changed
	r.Storage.SetArtifactURL(obj.GetArtifact())
	obj.Status.URL = r.Storage.SetHostname(obj.Status.URL)

	return sreconcile.ResultSuccess, nil
}

// reconcileSource ensures the upstream Git repository and reference can be
// cloned and checked out using the specified configuration, and observes its
// state.
//
// The repository is cloned to the given dir, using the specified configuration
// to check out the reference. In case of an error during this process
// (including transient errors), it records v1beta2.FetchFailedCondition=True
// and returns early.
// On a successful checkout, it removes v1beta2.FetchFailedCondition and
// compares the current revision of HEAD to the revision of the Artifact in the
// Status of the object. It records v1beta2.ArtifactOutdatedCondition=True when
// they differ.
// If specified, the signature of the Git commit is verified. If the signature
// can not be verified or the verification fails, it records
// v1beta2.SourceVerifiedCondition=False and returns early. When successful,
// it records v1beta2.SourceVerifiedCondition=True.
// When all the above is successful, the given Commit pointer is set to the
// commit of the checked out Git repository.
func (r *GitRepositoryReconciler) reconcileSource(ctx context.Context,
	obj *sourcev1.GitRepository, commit *git.Commit, _ *artifactSet, dir string) (sreconcile.Result, error) {
	// Configure authentication strategy to access the source
	var authOpts *git.AuthOptions
	var err error
	if obj.Spec.SecretRef != nil {
		// Attempt to retrieve secret
		name := types.NamespacedName{
			Namespace: obj.GetNamespace(),
			Name:      obj.Spec.SecretRef.Name,
		}
		var secret corev1.Secret
		if err := r.Client.Get(ctx, name, &secret); err != nil {
			e := &serror.Event{
				Err:    fmt.Errorf("failed to get secret '%s': %w", name.String(), err),
				Reason: sourcev1.AuthenticationFailedReason,
			}
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, e.Err.Error())
			// Return error as the world as observed may change
			return sreconcile.ResultEmpty, e
		}

		// Configure strategy with secret
		authOpts, err = git.AuthOptionsFromSecret(obj.Spec.URL, &secret)
	} else {
		// Set the minimal auth options for valid transport.
		authOpts, err = git.AuthOptionsWithoutSecret(obj.Spec.URL)
	}
	if err != nil {
		e := &serror.Event{
			Err:    fmt.Errorf("failed to configure auth strategy for Git implementation '%s': %w", obj.Spec.GitImplementation, err),
			Reason: sourcev1.AuthenticationFailedReason,
		}
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, e.Err.Error())
		// Return error as the contents of the secret may change
		return sreconcile.ResultEmpty, e
	}

	// Configure checkout strategy
	checkoutOpts := git.CheckoutOptions{RecurseSubmodules: obj.Spec.RecurseSubmodules}
	if ref := obj.Spec.Reference; ref != nil {
		checkoutOpts.Branch = ref.Branch
		checkoutOpts.Commit = ref.Commit
		checkoutOpts.Tag = ref.Tag
		checkoutOpts.SemVer = ref.SemVer
	}

	if artifact := obj.GetArtifact(); artifact != nil {
		checkoutOpts.LastRevision = artifact.Revision
	}

	checkoutStrategy, err := strategy.CheckoutStrategyForImplementation(ctx,
		git.Implementation(obj.Spec.GitImplementation), checkoutOpts)
	if err != nil {
		e := &serror.Stalling{
			Err:    fmt.Errorf("failed to configure checkout strategy for Git implementation '%s': %w", obj.Spec.GitImplementation, err),
			Reason: sourcev1.GitOperationFailedReason,
		}
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, e.Err.Error())
		// Do not return err as recovery without changes is impossible
		return sreconcile.ResultEmpty, e
	}

	repositoryURL := obj.Spec.URL
	// managed GIT transport only affects the libgit2 implementation
	if managed.Enabled() && obj.Spec.GitImplementation == sourcev1.LibGit2Implementation {
		// At present only HTTP connections have the ability to define remote options.
		// Although this can be easily extended by ensuring that the fake URL below uses the
		// target ssh scheme, and the libgit2/managed/ssh.go pulls that information accordingly.
		//
		// This is due to the fact the key libgit2 remote callbacks do not take place for HTTP
		// whilst most still work for SSH.
		if strings.HasPrefix(repositoryURL, "http") {
			// Due to the lack of the callback feature, a fake target URL is created to allow
			// for the smart sub transport be able to pick the options specific for this
			// GitRepository object.
			// The URL should use unique information that do not collide in a multi tenant
			// deployment.
			repositoryURL = fmt.Sprintf("http://%s/%s/%d", obj.Name, obj.UID, obj.Generation)
			managed.AddTransportOptions(repositoryURL,
				managed.TransportOptions{
					TargetURL: obj.Spec.URL,
					CABundle:  authOpts.CAFile,
				})

			// We remove the options from memory, to avoid accumulating unused options over time.
			defer managed.RemoveTransportOptions(repositoryURL)
		}
	}

	// Checkout HEAD of reference in object
	gitCtx, cancel := context.WithTimeout(ctx, obj.Spec.Timeout.Duration)
	defer cancel()
	c, err := checkoutStrategy.Checkout(gitCtx, dir, repositoryURL, authOpts)
	if err != nil {
		var v git.NoChangesError
		if errors.As(err, &v) {
			return sreconcile.ResultSuccess, nil
		}

		e := &serror.Event{
			Err:    fmt.Errorf("failed to checkout and determine revision: %w", err),
			Reason: sourcev1.GitOperationFailedReason,
		}
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, e.Err.Error())
		// Coin flip on transient or persistent error, return error and hope for the best
		return sreconcile.ResultEmpty, e
	}
	// Assign the commit to the shared commit reference.
	*commit = *c
	ctrl.LoggerFrom(ctx).V(logger.DebugLevel).Info("git repository checked out", "url", obj.Spec.URL, "revision", commit.String())
	conditions.Delete(obj, sourcev1.FetchFailedCondition)

	// Verify commit signature
	if result, err := r.verifyCommitSignature(ctx, obj, *commit); err != nil || result == sreconcile.ResultEmpty {
		return result, err
	}

	// Mark observations about the revision on the object
	if !obj.GetArtifact().HasRevision(commit.String()) {
		message := fmt.Sprintf("new upstream revision '%s'", commit.String())
		conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "NewRevision", message)
		conditions.MarkReconciling(obj, "NewRevision", message)
	}
	return sreconcile.ResultSuccess, nil
}

// reconcileArtifact archives a new Artifact to the Storage, if the current
// (Status) data on the object does not match the given.
//
// The inspection of the given data to the object is differed, ensuring any
// stale observations like v1beta2.ArtifactOutdatedCondition are removed.
// If the given Artifact and/or artifactSet (includes) do not differ from the
// object's current, it returns early.
// Source ignore patterns are loaded, and the given directory is archived while
// taking these patterns into account.
// On a successful archive, the Artifact and Includes in the Status of the
// object are set, and the symlink in the Storage is updated to its path.
func (r *GitRepositoryReconciler) reconcileArtifact(ctx context.Context,
	obj *sourcev1.GitRepository, commit *git.Commit, includes *artifactSet, dir string) (sreconcile.Result, error) {
	// If reconciliation resulted in git.NoChangesError,
	// avoid reconciling artifact, as this was already done
	// on a previous reconciliation.
	if commit == nil || commit.Hash.String() == "" {
		return sreconcile.ResultSuccess, nil
	}

	// Create potential new artifact with current available metadata
	artifact := r.Storage.NewArtifactFor(obj.Kind, obj.GetObjectMeta(), commit.String(), fmt.Sprintf("%s.tar.gz", commit.Hash.String()))

	// Set the ArtifactInStorageCondition if there's no drift.
	defer func() {
		if obj.GetArtifact().HasRevision(artifact.Revision) && !includes.Diff(obj.Status.IncludedArtifacts) {
			conditions.Delete(obj, sourcev1.ArtifactOutdatedCondition)
			conditions.MarkTrue(obj, sourcev1.ArtifactInStorageCondition, meta.SucceededReason,
				"stored artifact for revision '%s'", artifact.Revision)
		}
	}()

	// The artifact is up-to-date
	if obj.GetArtifact().HasRevision(artifact.Revision) && !includes.Diff(obj.Status.IncludedArtifacts) {
		r.eventLogf(ctx, obj, events.EventTypeTrace, sourcev1.ArtifactUpToDateReason, "artifact up-to-date with remote revision: '%s'", artifact.Revision)
		return sreconcile.ResultSuccess, nil
	}

	// Ensure target path exists and is a directory
	if f, err := os.Stat(dir); err != nil {
		e := &serror.Event{
			Err:    fmt.Errorf("failed to stat target artifact path: %w", err),
			Reason: sourcev1.StatOperationFailedReason,
		}
		conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, e.Reason, e.Err.Error())
		return sreconcile.ResultEmpty, e
	} else if !f.IsDir() {
		e := &serror.Event{
			Err:    fmt.Errorf("invalid target path: '%s' is not a directory", dir),
			Reason: sourcev1.InvalidPathReason,
		}
		conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, e.Reason, e.Err.Error())
		return sreconcile.ResultEmpty, e
	}

	// Ensure artifact directory exists and acquire lock
	if err := r.Storage.MkdirAll(artifact); err != nil {
		e := &serror.Event{
			Err:    fmt.Errorf("failed to create artifact directory: %w", err),
			Reason: sourcev1.DirCreationFailedReason,
		}
		conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, e.Reason, e.Err.Error())
		return sreconcile.ResultEmpty, e
	}
	unlock, err := r.Storage.Lock(artifact)
	if err != nil {
		return sreconcile.ResultEmpty, &serror.Event{
			Err:    fmt.Errorf("failed to acquire lock for artifact: %w", err),
			Reason: meta.FailedReason,
		}
	}
	defer unlock()

	// Load ignore rules for archiving
	ignoreDomain := strings.Split(dir, string(filepath.Separator))
	ps, err := sourceignore.LoadIgnorePatterns(dir, ignoreDomain)
	if err != nil {
		return sreconcile.ResultEmpty, &serror.Event{
			Err:    fmt.Errorf("failed to load source ignore patterns from repository: %w", err),
			Reason: "SourceIgnoreError",
		}
	}
	if obj.Spec.Ignore != nil {
		ps = append(ps, sourceignore.ReadPatterns(strings.NewReader(*obj.Spec.Ignore), ignoreDomain)...)
	}

	// Archive directory to storage
	if err := r.Storage.Archive(&artifact, dir, SourceIgnoreFilter(ps, ignoreDomain)); err != nil {
		e := &serror.Event{
			Err:    fmt.Errorf("unable to archive artifact to storage: %w", err),
			Reason: sourcev1.ArchiveOperationFailedReason,
		}
		conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, e.Reason, e.Err.Error())
		return sreconcile.ResultEmpty, e
	}

	// Record it on the object
	obj.Status.Artifact = artifact.DeepCopy()
	obj.Status.IncludedArtifacts = *includes

	// Update symlink on a "best effort" basis
	url, err := r.Storage.Symlink(artifact, "latest.tar.gz")
	if err != nil {
		r.eventLogf(ctx, obj, events.EventTypeTrace, sourcev1.SymlinkUpdateFailedReason,
			"failed to update status URL symlink: %s", err)
	}
	if url != "" {
		obj.Status.URL = url
	}
	conditions.Delete(obj, sourcev1.StorageOperationFailedCondition)
	return sreconcile.ResultSuccess, nil
}

// reconcileInclude reconciles the on the object specified
// v1beta2.GitRepositoryInclude list by copying their Artifact (sub)contents to
// the specified paths in the given directory.
//
// When one of the includes is unavailable, it marks the object with
// v1beta2.IncludeUnavailableCondition=True and returns early.
// When the copy operations are successful, it removes the
// v1beta2.IncludeUnavailableCondition from the object.
// When the composed artifactSet differs from the current set in the Status of
// the object, it marks the object with v1beta2.ArtifactOutdatedCondition=True.
func (r *GitRepositoryReconciler) reconcileInclude(ctx context.Context,
	obj *sourcev1.GitRepository, _ *git.Commit, includes *artifactSet, dir string) (sreconcile.Result, error) {

	artifacts := make(artifactSet, len(obj.Spec.Include))
	for i, incl := range obj.Spec.Include {
		// Do this first as it is much cheaper than copy operations
		toPath, err := securejoin.SecureJoin(dir, incl.GetToPath())
		if err != nil {
			e := &serror.Event{
				Err:    fmt.Errorf("path calculation for include '%s' failed: %w", incl.GitRepositoryRef.Name, err),
				Reason: "IllegalPath",
			}
			conditions.MarkTrue(obj, sourcev1.IncludeUnavailableCondition, e.Reason, e.Err.Error())
			return sreconcile.ResultEmpty, e
		}

		// Retrieve the included GitRepository
		dep := &sourcev1.GitRepository{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: obj.Namespace, Name: incl.GitRepositoryRef.Name}, dep); err != nil {
			e := &serror.Event{
				Err:    fmt.Errorf("could not get resource for include '%s': %w", incl.GitRepositoryRef.Name, err),
				Reason: "NotFound",
			}
			conditions.MarkTrue(obj, sourcev1.IncludeUnavailableCondition, e.Reason, e.Err.Error())
			return sreconcile.ResultEmpty, e
		}

		// Confirm include has an artifact
		if dep.GetArtifact() == nil {
			e := &serror.Event{
				Err:    fmt.Errorf("no artifact available for include '%s'", incl.GitRepositoryRef.Name),
				Reason: "NoArtifact",
			}
			conditions.MarkTrue(obj, sourcev1.IncludeUnavailableCondition, e.Reason, e.Err.Error())
			return sreconcile.ResultEmpty, e
		}

		// Copy artifact (sub)contents to configured directory
		if err := r.Storage.CopyToPath(dep.GetArtifact(), incl.GetFromPath(), toPath); err != nil {
			e := &serror.Event{
				Err:    fmt.Errorf("failed to copy '%s' include from %s to %s: %w", incl.GitRepositoryRef.Name, incl.GetFromPath(), incl.GetToPath(), err),
				Reason: "CopyFailure",
			}
			conditions.MarkTrue(obj, sourcev1.IncludeUnavailableCondition, e.Reason, e.Err.Error())
			return sreconcile.ResultEmpty, e
		}
		artifacts[i] = dep.GetArtifact().DeepCopy()
	}

	// We now know all includes are available
	conditions.Delete(obj, sourcev1.IncludeUnavailableCondition)

	// Observe if the artifacts still match the previous included ones
	if artifacts.Diff(obj.Status.IncludedArtifacts) {
		message := fmt.Sprintf("included artifacts differ from last observed includes")
		conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "IncludeChange", message)
		conditions.MarkReconciling(obj, "IncludeChange", message)
	}

	// Persist the artifactSet.
	*includes = artifacts
	return sreconcile.ResultSuccess, nil
}

// verifyCommitSignature verifies the signature of the given Git commit, if a
// verification mode is specified on the object.
// If the signature can not be verified or the verification fails, it records
// v1beta2.SourceVerifiedCondition=False and returns.
// When successful, it records v1beta2.SourceVerifiedCondition=True.
// If no verification mode is specified on the object, the
// v1beta2.SourceVerifiedCondition Condition is removed.
func (r *GitRepositoryReconciler) verifyCommitSignature(ctx context.Context, obj *sourcev1.GitRepository, commit git.Commit) (sreconcile.Result, error) {
	// Check if there is a commit verification is configured and remove any old
	// observations if there is none
	if obj.Spec.Verification == nil || obj.Spec.Verification.Mode == "" {
		conditions.Delete(obj, sourcev1.SourceVerifiedCondition)
		return sreconcile.ResultSuccess, nil
	}

	// Get secret with GPG data
	publicKeySecret := types.NamespacedName{
		Namespace: obj.Namespace,
		Name:      obj.Spec.Verification.SecretRef.Name,
	}
	secret := &corev1.Secret{}
	if err := r.Client.Get(ctx, publicKeySecret, secret); err != nil {
		e := &serror.Event{
			Err:    fmt.Errorf("PGP public keys secret error: %w", err),
			Reason: "VerificationError",
		}
		conditions.MarkFalse(obj, sourcev1.SourceVerifiedCondition, e.Reason, e.Err.Error())
		return sreconcile.ResultEmpty, e
	}

	var keyRings []string
	for _, v := range secret.Data {
		keyRings = append(keyRings, string(v))
	}
	// Verify commit with GPG data from secret
	if _, err := commit.Verify(keyRings...); err != nil {
		e := &serror.Event{
			Err:    fmt.Errorf("signature verification of commit '%s' failed: %w", commit.Hash.String(), err),
			Reason: "InvalidCommitSignature",
		}
		conditions.MarkFalse(obj, sourcev1.SourceVerifiedCondition, e.Reason, e.Err.Error())
		// Return error in the hope the secret changes
		return sreconcile.ResultEmpty, e
	}

	conditions.MarkTrue(obj, sourcev1.SourceVerifiedCondition, meta.SucceededReason,
		"verified signature of commit '%s'", commit.Hash.String())
	r.eventLogf(ctx, obj, events.EventTypeTrace, "VerifiedCommit",
		"verified signature of commit '%s'", commit.Hash.String())
	return sreconcile.ResultSuccess, nil
}

// reconcileDelete handles the deletion of the object.
// It first garbage collects all Artifacts for the object from the Storage.
// Removing the finalizer from the object if successful.
func (r *GitRepositoryReconciler) reconcileDelete(ctx context.Context, obj *sourcev1.GitRepository) (sreconcile.Result, error) {
	// Garbage collect the resource's artifacts
	if err := r.garbageCollect(ctx, obj); err != nil {
		// Return the error so we retry the failed garbage collection
		return sreconcile.ResultEmpty, err
	}

	// Remove our finalizer from the list
	controllerutil.RemoveFinalizer(obj, sourcev1.SourceFinalizer)

	// Stop reconciliation as the object is being deleted
	return sreconcile.ResultEmpty, nil
}

// garbageCollect performs a garbage collection for the given object.
//
// It removes all but the current Artifact from the Storage, unless the
// deletion timestamp on the object is set. Which will result in the
// removal of all Artifacts for the objects.
func (r *GitRepositoryReconciler) garbageCollect(ctx context.Context, obj *sourcev1.GitRepository) error {
	if !obj.DeletionTimestamp.IsZero() {
		if deleted, err := r.Storage.RemoveAll(r.Storage.NewArtifactFor(obj.Kind, obj.GetObjectMeta(), "", "*")); err != nil {
			return &serror.Event{
				Err:    fmt.Errorf("garbage collection for deleted resource failed: %w", err),
				Reason: "GarbageCollectionFailed",
			}
		} else if deleted != "" {
			r.eventLogf(ctx, obj, events.EventTypeTrace, "GarbageCollectionSucceeded",
				"garbage collected artifacts for deleted resource")
		}
		obj.Status.Artifact = nil
		return nil
	}
	if obj.GetArtifact() != nil {
		delFiles, err := r.Storage.GarbageCollect(ctx, *obj.GetArtifact(), time.Second*5)
		if err != nil {
			return &serror.Event{
				Err:    fmt.Errorf("garbage collection of artifacts failed: %w", err),
				Reason: "GarbageCollectionFailed",
			}
		}
		if len(delFiles) > 0 {
			r.eventLogf(ctx, obj, events.EventTypeTrace, "GarbageCollectionSucceeded",
				fmt.Sprintf("garbage collected %d artifacts", len(delFiles)))
			return nil
		}
	}
	return nil
}

// eventLogf records events, and logs at the same time.
//
// This log is different from the debug log in the EventRecorder, in the sense
// that this is a simple log. While the debug log contains complete details
// about the event.
func (r *GitRepositoryReconciler) eventLogf(ctx context.Context, obj runtime.Object, eventType string, reason string, messageFmt string, args ...interface{}) {
	msg := fmt.Sprintf(messageFmt, args...)
	// Log and emit event.
	if eventType == corev1.EventTypeWarning {
		ctrl.LoggerFrom(ctx).Error(errors.New(reason), msg)
	} else {
		ctrl.LoggerFrom(ctx).Info(msg)
	}
	r.Eventf(obj, eventType, reason, msg)
}
