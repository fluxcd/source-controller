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
	"strings"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
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
	"github.com/fluxcd/source-controller/pkg/git/strategy"
	"github.com/fluxcd/source-controller/pkg/sourceignore"
)

// gitRepoReadyConditions contains all the conditions information needed
// for GitRepository Ready status conditions summary calculation.
var gitRepoReadyConditions = summarize.Conditions{
	Target: meta.ReadyCondition,
	Owned: []string{
		sourcev1.SourceVerifiedCondition,
		sourcev1.FetchFailedCondition,
		sourcev1.IncludeUnavailableCondition,
		sourcev1.ArtifactOutdatedCondition,
		meta.ReadyCondition,
		meta.ReconcilingCondition,
		meta.StalledCondition,
	},
	Summarize: []string{
		sourcev1.IncludeUnavailableCondition,
		sourcev1.SourceVerifiedCondition,
		sourcev1.FetchFailedCondition,
		sourcev1.ArtifactOutdatedCondition,
		meta.StalledCondition,
		meta.ReconcilingCondition,
	},
	NegativePolarity: []string{
		sourcev1.FetchFailedCondition,
		sourcev1.IncludeUnavailableCondition,
		sourcev1.ArtifactOutdatedCondition,
		meta.StalledCondition,
		meta.ReconcilingCondition,
	},
}

// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=gitrepositories,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=gitrepositories/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=gitrepositories/finalizers,verbs=get;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// GitRepositoryReconciler reconciles a GitRepository object
type GitRepositoryReconciler struct {
	client.Client
	kuberecorder.EventRecorder
	helper.Metrics

	Storage *Storage

	requeueDependency time.Duration
}

type GitRepositoryReconcilerOptions struct {
	MaxConcurrentReconciles   int
	DependencyRequeueInterval time.Duration
}

// gitRepoReconcilerFunc is the function type for all the Git repository
// reconciler functions.
type gitRepoReconcilerFunc func(ctx context.Context, obj *sourcev1.GitRepository, artifact *sourcev1.Artifact, includes *artifactSet, dir string) (sreconcile.Result, error)

func (r *GitRepositoryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return r.SetupWithManagerAndOptions(mgr, GitRepositoryReconcilerOptions{})
}

func (r *GitRepositoryReconciler) SetupWithManagerAndOptions(mgr ctrl.Manager, opts GitRepositoryReconcilerOptions) error {
	r.requeueDependency = opts.DependencyRequeueInterval

	return ctrl.NewControllerManagedBy(mgr).
		For(&sourcev1.GitRepository{}, builder.WithPredicates(
			predicate.Or(predicate.GenerationChangedPredicate{}, predicates.ReconcileRequestedPredicate{}),
		)).
		WithOptions(controller.Options{MaxConcurrentReconciles: opts.MaxConcurrentReconciles}).
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
			summarize.WithConditions(gitRepoReadyConditions),
			summarize.WithReconcileResult(recResult),
			summarize.WithReconcileError(retErr),
			summarize.WithIgnoreNotFound(),
			summarize.WithProcessors(
				summarize.RecordContextualError,
				summarize.RecordReconcileReq,
			),
			summarize.WithResultBuilder(sreconcile.AlwaysRequeueResultBuilder{RequeueAfter: obj.GetInterval().Duration}),
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
	reconcilers := []gitRepoReconcilerFunc{
		r.reconcileStorage,
		r.reconcileSource,
		r.reconcileInclude,
		r.reconcileArtifact,
	}
	recResult, retErr = r.reconcile(ctx, obj, reconcilers)
	return
}

// reconcile steps iterates through the actual reconciliation tasks for objec,
// it returns early on the first step that returns ResultRequeue or produces an
// error.
func (r *GitRepositoryReconciler) reconcile(ctx context.Context, obj *sourcev1.GitRepository, reconcilers []gitRepoReconcilerFunc) (sreconcile.Result, error) {
	if obj.Generation != obj.Status.ObservedGeneration {
		conditions.MarkReconciling(obj, "NewGeneration", "reconciling new generation %d", obj.Generation)
	}

	var artifact sourcev1.Artifact
	var includes artifactSet

	// Create temp dir for Git clone
	tmpDir, err := util.TempDirForObj("", obj)
	if err != nil {
		return sreconcile.ResultEmpty, &serror.Event{
			Err:    fmt.Errorf("failed to create temporary directory: %w", err),
			Reason: sourcev1.StorageOperationFailedReason,
		}
	}
	defer os.RemoveAll(tmpDir)

	// Run the sub-reconcilers and build the result of reconciliation.
	var res sreconcile.Result
	var resErr error
	for _, rec := range reconcilers {
		recResult, err := rec(ctx, obj, &artifact, &includes, tmpDir)
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
	return res, resErr
}

// reconcileStorage ensures the current state of the storage matches the desired and previously observed state.
//
// All artifacts for the resource except for the current one are garbage collected from the storage.
// If the artifact in the Status object of the resource disappeared from storage, it is removed from the object.
// If the object does not have an artifact in its Status object, a v1beta1.ArtifactUnavailableCondition is set.
// If the hostname of any of the URLs on the object do not match the current storage server hostname, they are updated.
func (r *GitRepositoryReconciler) reconcileStorage(ctx context.Context, obj *sourcev1.GitRepository, artifact *sourcev1.Artifact, includes *artifactSet, dir string) (sreconcile.Result, error) {
	// Garbage collect previous advertised artifact(s) from storage
	_ = r.garbageCollect(ctx, obj)

	// Determine if the advertised artifact is still in storage
	if artifact := obj.GetArtifact(); artifact != nil && !r.Storage.ArtifactExist(*artifact) {
		obj.Status.Artifact = nil
		obj.Status.URL = ""
	}

	// Record that we do not have an artifact
	if obj.GetArtifact() == nil {
		conditions.MarkReconciling(obj, "NoArtifact", "no artifact for resource in storage")
		return sreconcile.ResultSuccess, nil
	}

	// Always update URLs to ensure hostname is up-to-date
	// TODO(hidde): we may want to send out an event only if we notice the URL has changed
	r.Storage.SetArtifactURL(obj.GetArtifact())
	obj.Status.URL = r.Storage.SetHostname(obj.Status.URL)

	return sreconcile.ResultSuccess, nil
}

// reconcileSource ensures the upstream Git repository can be reached and checked out using the declared configuration,
// and observes its state.
//
// The repository is checked out to the given dir using the defined configuration, and in case of an error during the
// checkout process (including transient errors), it records v1beta1.FetchFailedCondition=True and returns early.
// On a successful checkout it removes v1beta1.FetchFailedCondition, and compares the current revision of HEAD to the
// artifact on the object, and records v1beta1.ArtifactOutdatedCondition if they differ.
// If instructed, the signature of the commit is verified if and recorded as v1beta1.SourceVerifiedCondition. If the
// signature can not be verified or the verification fails, the Condition=False and it returns early.
// If both the checkout and signature verification are successful, the given artifact pointer is set to a new artifact
// with the available metadata.
func (r *GitRepositoryReconciler) reconcileSource(ctx context.Context,
	obj *sourcev1.GitRepository, artifact *sourcev1.Artifact, _ *artifactSet, dir string) (sreconcile.Result, error) {
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
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, e.Err.Error())
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
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, e.Err.Error())
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
	checkoutStrategy, err := strategy.CheckoutStrategyForImplementation(ctx,
		git.Implementation(obj.Spec.GitImplementation), checkoutOpts)
	if err != nil {
		e := &serror.Stalling{
			Err:    fmt.Errorf("failed to configure checkout strategy for Git implementation '%s': %w", obj.Spec.GitImplementation, err),
			Reason: sourcev1.GitOperationFailedReason,
		}
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.GitOperationFailedReason, e.Err.Error())
		// Do not return err as recovery without changes is impossible
		return sreconcile.ResultEmpty, e
	}

	// Checkout HEAD of reference in object
	gitCtx, cancel := context.WithTimeout(ctx, obj.Spec.Timeout.Duration)
	defer cancel()
	commit, err := checkoutStrategy.Checkout(gitCtx, dir, obj.Spec.URL, authOpts)
	if err != nil {
		e := &serror.Event{
			Err:    fmt.Errorf("failed to checkout and determine revision: %w", err),
			Reason: sourcev1.GitOperationFailedReason,
		}
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.GitOperationFailedReason, e.Err.Error())
		// Coin flip on transient or persistent error, return error and hope for the best
		return sreconcile.ResultEmpty, e
	}
	r.eventLogf(ctx, obj, events.EventTypeTrace, sourcev1.GitOperationSucceedReason,
		"cloned '%s' and checked out revision '%s'", obj.Spec.URL, commit.String())
	conditions.Delete(obj, sourcev1.FetchFailedCondition)

	// Verify commit signature
	if result, err := r.verifyCommitSignature(ctx, obj, *commit); err != nil || result == sreconcile.ResultEmpty {
		return result, err
	}

	// Create potential new artifact with current available metadata
	*artifact = r.Storage.NewArtifactFor(obj.Kind, obj.GetObjectMeta(), commit.String(), fmt.Sprintf("%s.tar.gz", commit.Hash.String()))

	// Mark observations about the revision on the object
	if !obj.GetArtifact().HasRevision(commit.String()) {
		message := fmt.Sprintf("new upstream revision '%s'", commit.String())
		conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "NewRevision", message)
		conditions.MarkReconciling(obj, "NewRevision", message)
	}
	return sreconcile.ResultSuccess, nil
}

// reconcileArtifact archives a new artifact to the storage, if the current observation on the object does not match the
// given data.
//
// The inspection of the given data to the object is differed, ensuring any stale observations as
// v1beta1.ArtifactUnavailableCondition and v1beta1.ArtifactOutdatedCondition are always deleted.
// If the given artifact and/or includes do not differ from the object's current, it returns early.
// Source ignore patterns are loaded, and the given directory is archived.
// On a successful archive, the artifact and includes in the status of the given object are set, and the symlink in the
// storage is updated to its path.
func (r *GitRepositoryReconciler) reconcileArtifact(ctx context.Context, obj *sourcev1.GitRepository, artifact *sourcev1.Artifact, includes *artifactSet, dir string) (sreconcile.Result, error) {
	// Always restore the Ready condition in case it got removed due to a transient error
	defer func() {
		if obj.GetArtifact().HasRevision(artifact.Revision) && !includes.Diff(obj.Status.IncludedArtifacts) {
			conditions.Delete(obj, sourcev1.ArtifactOutdatedCondition)
			conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason,
				"stored artifact for revision '%s'", artifact.Revision)
		}
	}()

	// The artifact is up-to-date
	if obj.GetArtifact().HasRevision(artifact.Revision) && !includes.Diff(obj.Status.IncludedArtifacts) {
		ctrl.LoggerFrom(ctx).Info("artifact up-to-date", "revision", artifact.Revision)
		return sreconcile.ResultSuccess, nil
	}

	// Mark reconciling because the artifact and remote source are different.
	// and they have to be reconciled.
	conditions.MarkReconciling(obj, "NewRevision", "new upstream revision '%s'", artifact.Revision)

	// Ensure target path exists and is a directory
	if f, err := os.Stat(dir); err != nil {
		e := &serror.Event{
			Err:    fmt.Errorf("failed to stat target path: %w", err),
			Reason: sourcev1.StorageOperationFailedReason,
		}
		return sreconcile.ResultEmpty, e
	} else if !f.IsDir() {
		e := &serror.Event{
			Err:    fmt.Errorf("invalid target path: '%s' is not a directory", dir),
			Reason: sourcev1.StorageOperationFailedReason,
		}
		return sreconcile.ResultEmpty, e
	}

	// Ensure artifact directory exists and acquire lock
	if err := r.Storage.MkdirAll(*artifact); err != nil {
		e := &serror.Event{
			Err:    fmt.Errorf("failed to create artifact directory: %w", err),
			Reason: sourcev1.StorageOperationFailedReason,
		}
		return sreconcile.ResultEmpty, e
	}
	unlock, err := r.Storage.Lock(*artifact)
	if err != nil {
		return sreconcile.ResultEmpty, &serror.Event{
			Err:    fmt.Errorf("failed to acquire lock for artifact: %w", err),
			Reason: meta.FailedReason,
		}
	}
	defer unlock()

	// Load ignore rules for archiving
	ps, err := sourceignore.LoadIgnorePatterns(dir, nil)
	if err != nil {
		return sreconcile.ResultEmpty, &serror.Event{
			Err:    fmt.Errorf("failed to load source ignore patterns from repository: %w", err),
			Reason: "SourceIgnoreError",
		}
	}
	if obj.Spec.Ignore != nil {
		ps = append(ps, sourceignore.ReadPatterns(strings.NewReader(*obj.Spec.Ignore), nil)...)
	}

	// Archive directory to storage
	if err := r.Storage.Archive(artifact, dir, SourceIgnoreFilter(ps, nil)); err != nil {
		return sreconcile.ResultEmpty, &serror.Event{
			Err:    fmt.Errorf("unable to archive artifact to storage: %w", err),
			Reason: sourcev1.StorageOperationFailedReason,
		}
	}
	r.AnnotatedEventf(obj, map[string]string{
		"revision": artifact.Revision,
		"checksum": artifact.Checksum,
	}, corev1.EventTypeNormal, "NewArtifact", "stored artifact for revision '%s'", artifact.Revision)

	// Record it on the object
	obj.Status.Artifact = artifact.DeepCopy()
	obj.Status.IncludedArtifacts = *includes

	// Update symlink on a "best effort" basis
	url, err := r.Storage.Symlink(*artifact, "latest.tar.gz")
	if err != nil {
		r.eventLogf(ctx, obj, corev1.EventTypeWarning, sourcev1.StorageOperationFailedReason,
			"failed to update status URL symlink: %s", err)
	}
	if url != "" {
		obj.Status.URL = url
	}
	return sreconcile.ResultSuccess, nil
}

// reconcileInclude reconciles the declared includes from the object by copying their artifact (sub)contents to the
// declared paths in the given directory.
//
// If an include is unavailable, it marks the object with v1beta1.IncludeUnavailableCondition and returns early.
// If the copy operations are successful, it deletes the v1beta1.IncludeUnavailableCondition from the object.
// If the artifactSet differs from the current set, it marks the object with v1beta1.ArtifactOutdatedCondition.
func (r *GitRepositoryReconciler) reconcileInclude(ctx context.Context, obj *sourcev1.GitRepository, _ *sourcev1.Artifact, includes *artifactSet, dir string) (sreconcile.Result, error) {
	artifacts := make(artifactSet, len(obj.Spec.Include))
	for i, incl := range obj.Spec.Include {
		// Do this first as it is much cheaper than copy operations
		toPath, err := securejoin.SecureJoin(dir, incl.GetToPath())
		if err != nil {
			e := &serror.Event{
				Err:    fmt.Errorf("path calculation for include '%s' failed: %w", incl.GitRepositoryRef.Name, err),
				Reason: "IllegalPath",
			}
			conditions.MarkTrue(obj, sourcev1.IncludeUnavailableCondition, "IllegalPath", e.Err.Error())
			return sreconcile.ResultEmpty, e
		}

		// Retrieve the included GitRepository
		dep := &sourcev1.GitRepository{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: obj.Namespace, Name: incl.GitRepositoryRef.Name}, dep); err != nil {
			e := &serror.Event{
				Err:    fmt.Errorf("could not get resource for include '%s': %w", incl.GitRepositoryRef.Name, err),
				Reason: "NotFound",
			}
			conditions.MarkTrue(obj, sourcev1.IncludeUnavailableCondition, "NotFound", e.Err.Error())
			return sreconcile.ResultEmpty, err
		}

		// Confirm include has an artifact
		if dep.GetArtifact() == nil {
			e := &serror.Stalling{
				Err:    fmt.Errorf("no artifact available for include '%s'", incl.GitRepositoryRef.Name),
				Reason: "NoArtifact",
			}
			conditions.MarkTrue(obj, sourcev1.IncludeUnavailableCondition, "NoArtifact", e.Err.Error())
			return sreconcile.ResultEmpty, e
		}

		// Copy artifact (sub)contents to configured directory
		if err := r.Storage.CopyToPath(dep.GetArtifact(), incl.GetFromPath(), toPath); err != nil {
			e := &serror.Event{
				Err:    fmt.Errorf("failed to copy '%s' include from %s to %s: %w", incl.GitRepositoryRef.Name, incl.GetFromPath(), incl.GetToPath(), err),
				Reason: "CopyFailure",
			}
			conditions.MarkTrue(obj, sourcev1.IncludeUnavailableCondition, "CopyFailure", e.Err.Error())
			return sreconcile.ResultEmpty, e
		}
		artifacts[i] = dep.GetArtifact().DeepCopy()
	}

	// We now know all includes are available
	conditions.Delete(obj, sourcev1.IncludeUnavailableCondition)

	// Observe if the artifacts still match the previous included ones
	if artifacts.Diff(obj.Status.IncludedArtifacts) {
		conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "IncludeChange",
			"included artifacts differ from last observed includes")
	}

	// Persist the artifactSet.
	*includes = artifacts
	return sreconcile.ResultSuccess, nil
}

// reconcileDelete handles the delete of an object. It first garbage collects all artifacts for the object from the
// artifact storage, if successful, the finalizer is removed from the object.
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

// verifyCommitSignature verifies the signature of the given commit if a verification mode is configured on the object.
func (r *GitRepositoryReconciler) verifyCommitSignature(ctx context.Context, obj *sourcev1.GitRepository, commit git.Commit) (sreconcile.Result, error) {
	// Check if there is a commit verification is configured and remove any old observations if there is none
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
		conditions.MarkFalse(obj, sourcev1.SourceVerifiedCondition, meta.FailedReason, e.Err.Error())
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
		conditions.MarkFalse(obj, sourcev1.SourceVerifiedCondition, meta.FailedReason, e.Err.Error())
		// Return error in the hope the secret changes
		return sreconcile.ResultEmpty, e
	}

	conditions.MarkTrue(obj, sourcev1.SourceVerifiedCondition, meta.SucceededReason,
		"verified signature of commit '%s'", commit.Hash.String())
	r.eventLogf(ctx, obj, events.EventTypeTrace, "VerifiedCommit",
		"verified signature of commit '%s'", commit.Hash.String())
	return sreconcile.ResultSuccess, nil
}

// garbageCollect performs a garbage collection for the given v1beta1.GitRepository. It removes all but the current
// artifact except for when the deletion timestamp is set, which will result in the removal of all artifacts for the
// resource.
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
		if deleted, err := r.Storage.RemoveAllButCurrent(*obj.GetArtifact()); err != nil {
			return &serror.Event{
				Err: fmt.Errorf("garbage collection of old artifacts failed: %w", err),
			}
		} else if len(deleted) > 0 {
			r.eventLogf(ctx, obj, events.EventTypeTrace, "GarbageCollectionSucceeded",
				"garbage collected old artifacts")
		}
	}
	return nil
}

// eventLog records event and logs at the same time. This log is different from
// the debug log in the event recorder in the sense that this is a simple log,
// the event recorder debug log contains complete details about the event.
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
