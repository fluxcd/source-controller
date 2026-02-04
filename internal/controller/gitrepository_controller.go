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

package controller

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/fluxcd/pkg/auth"
	authutils "github.com/fluxcd/pkg/auth/utils"
	"github.com/fluxcd/pkg/git/github"
	"github.com/fluxcd/pkg/runtime/logger"
	"github.com/fluxcd/pkg/runtime/secrets"
	"github.com/go-git/go-git/v5/plumbing/transport"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kuberecorder "k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	eventv1 "github.com/fluxcd/pkg/apis/event/v1beta1"
	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/artifact/storage"
	"github.com/fluxcd/pkg/cache"
	"github.com/fluxcd/pkg/git"
	"github.com/fluxcd/pkg/git/gogit"
	"github.com/fluxcd/pkg/git/repository"
	"github.com/fluxcd/pkg/runtime/conditions"
	helper "github.com/fluxcd/pkg/runtime/controller"
	"github.com/fluxcd/pkg/runtime/jitter"
	"github.com/fluxcd/pkg/runtime/patch"
	"github.com/fluxcd/pkg/runtime/predicates"
	rreconcile "github.com/fluxcd/pkg/runtime/reconcile"
	"github.com/fluxcd/pkg/sourceignore"

	sourcev1 "github.com/werf/nelm-source-controller/api/v1"
	serror "github.com/werf/nelm-source-controller/internal/error"
	"github.com/werf/nelm-source-controller/internal/features"
	sreconcile "github.com/werf/nelm-source-controller/internal/reconcile"
	"github.com/werf/nelm-source-controller/internal/reconcile/summarize"
	"github.com/werf/nelm-source-controller/internal/util"
)

// gitRepositoryReadyCondition contains the information required to summarize a
// v1.GitRepository Ready Condition.
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

// getPatchOptions composes patch options based on the given parameters.
// It is used as the options used when patching an object.
func getPatchOptions(ownedConditions []string, controllerName string) []patch.Option {
	return []patch.Option{
		patch.WithOwnedConditions{Conditions: ownedConditions},
		patch.WithFieldOwner(controllerName),
	}
}

// +kubebuilder:rbac:groups=source.werf.io,resources=gitrepositories,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=source.werf.io,resources=gitrepositories/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=source.werf.io,resources=gitrepositories/finalizers,verbs=get;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// GitRepositoryReconciler reconciles a v1.GitRepository object.
type GitRepositoryReconciler struct {
	client.Client
	kuberecorder.EventRecorder
	helper.Metrics

	Storage        *storage.Storage
	ControllerName string
	TokenCache     *cache.TokenCache

	requeueDependency time.Duration
	features          map[string]bool

	patchOptions []patch.Option
}

type GitRepositoryReconcilerOptions struct {
	DependencyRequeueInterval time.Duration
	RateLimiter               workqueue.TypedRateLimiter[reconcile.Request]
}

// gitRepositoryReconcileFunc is the function type for all the
// v1.GitRepository (sub)reconcile functions.
type gitRepositoryReconcileFunc func(ctx context.Context, sp *patch.SerialPatcher, obj *sourcev1.GitRepository, commit *git.Commit, includes *artifactSet, dir string) (sreconcile.Result, error)

func (r *GitRepositoryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return r.SetupWithManagerAndOptions(mgr, GitRepositoryReconcilerOptions{})
}

func (r *GitRepositoryReconciler) SetupWithManagerAndOptions(mgr ctrl.Manager, opts GitRepositoryReconcilerOptions) error {
	r.patchOptions = getPatchOptions(gitRepositoryReadyCondition.Owned, r.ControllerName)

	r.requeueDependency = opts.DependencyRequeueInterval

	if r.features == nil {
		r.features = features.FeatureGates()
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&sourcev1.GitRepository{}, builder.WithPredicates(
			predicate.Or(predicate.GenerationChangedPredicate{}, predicates.ReconcileRequestedPredicate{}),
		)).
		WithOptions(controller.Options{
			RateLimiter: opts.RateLimiter,
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

	// Initialize the patch helper with the current version of the object.
	serialPatcher := patch.NewSerialPatcher(obj, r.Client)

	// recResult stores the abstracted reconcile result.
	var recResult sreconcile.Result

	// Always attempt to patch the object and status after each reconciliation
	// NOTE: The final runtime result and error are set in this block.
	defer func() {
		summarizeHelper := summarize.NewHelper(r.EventRecorder, serialPatcher)
		summarizeOpts := []summarize.Option{
			summarize.WithConditions(gitRepositoryReadyCondition),
			summarize.WithBiPolarityConditionTypes(sourcev1.SourceVerifiedCondition),
			summarize.WithReconcileResult(recResult),
			summarize.WithReconcileError(retErr),
			summarize.WithIgnoreNotFound(),
			summarize.WithProcessors(
				summarize.ErrorActionHandler,
				summarize.RecordReconcileReq,
			),
			summarize.WithResultBuilder(sreconcile.AlwaysRequeueResultBuilder{
				RequeueAfter: jitter.JitteredIntervalDuration(obj.GetRequeueAfter()),
			}),
			summarize.WithPatchFieldOwner(r.ControllerName),
		}
		result, retErr = summarizeHelper.SummarizeAndPatch(ctx, obj, summarizeOpts...)

		// Always record duration metrics.
		r.Metrics.RecordDuration(ctx, obj, start)
	}()

	// Examine if the object is under deletion.
	if !obj.ObjectMeta.DeletionTimestamp.IsZero() {
		recResult, retErr = r.reconcileDelete(ctx, obj)
		return
	}

	// Add finalizer first if not exist to avoid the race condition
	// between init and delete.
	// Note: Finalizers in general can only be added when the deletionTimestamp
	// is not set.
	if !controllerutil.ContainsFinalizer(obj, sourcev1.SourceFinalizer) {
		controllerutil.AddFinalizer(obj, sourcev1.SourceFinalizer)
		recResult = sreconcile.ResultRequeue
		return
	}

	// Return if the object is suspended.
	if obj.Spec.Suspend {
		log.Info("reconciliation is suspended for this object")
		recResult, retErr = sreconcile.ResultEmpty, nil
		return
	}

	// Reconcile actual object
	reconcilers := []gitRepositoryReconcileFunc{
		r.reconcileStorage,
		r.reconcileSource,
		r.reconcileInclude,
		r.reconcileArtifact,
	}
	recResult, retErr = r.reconcile(ctx, serialPatcher, obj, reconcilers)
	return
}

// reconcile iterates through the gitRepositoryReconcileFunc tasks for the
// object. It returns early on the first call that returns
// reconcile.ResultRequeue, or produces an error.
func (r *GitRepositoryReconciler) reconcile(ctx context.Context, sp *patch.SerialPatcher,
	obj *sourcev1.GitRepository, reconcilers []gitRepositoryReconcileFunc) (sreconcile.Result, error) {
	oldObj := obj.DeepCopy()

	rreconcile.ProgressiveStatus(false, obj, meta.ProgressingReason, "reconciliation in progress")

	var recAtVal string
	if v, ok := meta.ReconcileAnnotationValue(obj.GetAnnotations()); ok {
		recAtVal = v
	}

	// Persist reconciling if generation differs or reconciliation is requested.
	switch {
	case obj.Generation != obj.Status.ObservedGeneration:
		rreconcile.ProgressiveStatus(false, obj, meta.ProgressingReason,
			"processing object: new generation %d -> %d", obj.Status.ObservedGeneration, obj.Generation)
		if err := sp.Patch(ctx, obj, r.patchOptions...); err != nil {
			return sreconcile.ResultEmpty, serror.NewGeneric(err, sourcev1.PatchOperationFailedReason)
		}
	case recAtVal != obj.Status.GetLastHandledReconcileRequest():
		if err := sp.Patch(ctx, obj, r.patchOptions...); err != nil {
			return sreconcile.ResultEmpty, serror.NewGeneric(err, sourcev1.PatchOperationFailedReason)
		}
	}

	// Create temp dir for Git clone
	tmpDir, err := util.TempDirForObj("", obj)
	if err != nil {
		e := serror.NewGeneric(
			fmt.Errorf("failed to create temporary working directory: %w", err),
			sourcev1.DirCreationFailedReason,
		)
		conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, e.Reason, "%s", e)
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
		recResult, err := rec(ctx, sp, obj, &commit, &includes, tmpDir)
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

	r.notify(ctx, oldObj, obj, commit, res, resErr)

	return res, resErr
}

// notify emits notification related to the result of reconciliation.
func (r *GitRepositoryReconciler) notify(ctx context.Context, oldObj, newObj *sourcev1.GitRepository, commit git.Commit, res sreconcile.Result, resErr error) {
	// Notify successful reconciliation for new artifact, no-op reconciliation
	// and recovery from any failure.
	if r.shouldNotify(oldObj, newObj, res, resErr) {
		annotations := map[string]string{
			fmt.Sprintf("%s/%s", sourcev1.GroupVersion.Group, eventv1.MetaRevisionKey): newObj.Status.Artifact.Revision,
			fmt.Sprintf("%s/%s", sourcev1.GroupVersion.Group, eventv1.MetaDigestKey):   newObj.Status.Artifact.Digest,
		}

		// A partial commit due to no-op clone doesn't contain the commit
		// message information. Have separate message for it.
		var message string
		if git.IsConcreteCommit(commit) {
			message = fmt.Sprintf("stored artifact for commit '%s'", commit.ShortMessage())
		} else {
			message = fmt.Sprintf("stored artifact for commit '%s'", commitReference(newObj, &commit))
		}

		// Notify on new artifact and failure recovery.
		if !oldObj.GetArtifact().HasDigest(newObj.GetArtifact().Digest) {
			r.AnnotatedEventf(newObj, annotations, corev1.EventTypeNormal,
				"NewArtifact", message)
			ctrl.LoggerFrom(ctx).Info(message)
		} else {
			if sreconcile.FailureRecovery(oldObj, newObj, gitRepositoryFailConditions) {
				r.AnnotatedEventf(newObj, annotations, corev1.EventTypeNormal,
					meta.SucceededReason, message)
				ctrl.LoggerFrom(ctx).Info(message)
			}
		}
	}
}

// shouldNotify analyzes the result of subreconcilers and determines if a
// notification should be sent. It decides about the final informational
// notifications after the reconciliation. Failure notification and in-line
// notifications are not handled here.
func (r *GitRepositoryReconciler) shouldNotify(oldObj, newObj *sourcev1.GitRepository, res sreconcile.Result, resErr error) bool {
	// Notify for successful reconciliation.
	if resErr == nil && res == sreconcile.ResultSuccess && newObj.Status.Artifact != nil {
		return true
	}
	// Notify for no-op reconciliation with ignore error.
	if resErr != nil && res == sreconcile.ResultEmpty && newObj.Status.Artifact != nil {
		// Convert to Generic error and check for ignore.
		if ge, ok := resErr.(*serror.Generic); ok {
			return ge.Ignore
		}
	}
	return false
}

// reconcileStorage ensures the current state of the storage matches the
// desired and previously observed state.
//
// The garbage collection is executed based on the flag configured settings and
// may remove files that are beyond their TTL or the maximum number of files
// to survive a collection cycle.
// If the Artifact in the Status of the object disappeared from the Storage,
// it is removed from the object.
// If the object does not have an Artifact in its Status, a Reconciling
// condition is added.
// The hostname of the Artifact in the Status of the object is updated, to
// ensure it matches the Storage server hostname of current runtime.
func (r *GitRepositoryReconciler) reconcileStorage(ctx context.Context, sp *patch.SerialPatcher,
	obj *sourcev1.GitRepository, _ *git.Commit, _ *artifactSet, _ string) (sreconcile.Result, error) {
	// Garbage collect previous advertised artifact(s) from storage
	_ = r.garbageCollect(ctx, obj)

	var artifactMissing bool
	if artifact := obj.GetArtifact(); artifact != nil {
		// Determine if the advertised artifact is still in storage
		if !r.Storage.ArtifactExist(*artifact) {
			artifactMissing = true
		}

		// If the artifact is in storage, verify if the advertised digest still
		// matches the actual artifact
		if !artifactMissing {
			if err := r.Storage.VerifyArtifact(*artifact); err != nil {
				r.Eventf(obj, corev1.EventTypeWarning, "ArtifactVerificationFailed", "failed to verify integrity of artifact: %s", err.Error())

				if err = r.Storage.Remove(*artifact); err != nil {
					return sreconcile.ResultEmpty, fmt.Errorf("failed to remove artifact after digest mismatch: %w", err)
				}

				artifactMissing = true
			}
		}

		// If the artifact is missing, remove it from the object
		if artifactMissing {
			obj.Status.Artifact = nil
		}
	}

	// Record that we do not have an artifact
	if obj.GetArtifact() == nil {
		msg := "building artifact"
		if artifactMissing {
			msg += ": disappeared from storage"
		}
		rreconcile.ProgressiveStatus(true, obj, meta.ProgressingReason, "%s", msg)
		conditions.Delete(obj, sourcev1.ArtifactInStorageCondition)
		if err := sp.Patch(ctx, obj, r.patchOptions...); err != nil {
			return sreconcile.ResultEmpty, serror.NewGeneric(err, sourcev1.PatchOperationFailedReason)
		}
		return sreconcile.ResultSuccess, nil
	}

	// Always update URLs to ensure hostname is up-to-date
	// TODO(hidde): we may want to send out an event only if we notice the URL has changed
	r.Storage.SetArtifactURL(obj.GetArtifact())

	return sreconcile.ResultSuccess, nil
}

// reconcileSource ensures the upstream Git repository and reference can be
// cloned and checked out using the specified configuration, and observes its
// state. It also checks if the included repositories are available for use.
//
// The included repositories are fetched and their metadata are stored. In case
// one of the included repositories isn't ready, it records
// v1.IncludeUnavailableCondition=True and returns early. When all the
// included repositories are ready, it removes
// v1.IncludeUnavailableCondition from the object.
// When the included artifactSet differs from the current set in the Status of
// the object, it marks the object with v1.ArtifactOutdatedCondition=True.
// The repository is cloned to the given dir, using the specified configuration
// to check out the reference. In case of an error during this process
// (including transient errors), it records v1.FetchFailedCondition=True
// and returns early.
// On a successful checkout, it removes v1.FetchFailedCondition and
// compares the current revision of HEAD to the revision of the Artifact in the
// Status of the object. It records v1.ArtifactOutdatedCondition=True when
// they differ.
// If specified, the signature of the Git commit is verified. If the signature
// can not be verified or the verification fails, it records
// v1.SourceVerifiedCondition=False and returns early. When successful,
// it records v1.SourceVerifiedCondition=True.
// When all the above is successful, the given Commit pointer is set to the
// commit of the checked out Git repository.
//
// If the optimized git clone feature is enabled, it checks if the remote repo
// and the local artifact are on the same revision, and no other source content
// related configurations have changed since last reconciliation. If there's a
// change, it short-circuits the whole reconciliation with an early return.
func (r *GitRepositoryReconciler) reconcileSource(ctx context.Context, sp *patch.SerialPatcher,
	obj *sourcev1.GitRepository, commit *git.Commit, includes *artifactSet, dir string) (sreconcile.Result, error) {
	// Remove previously failed source verification status conditions. The
	// failing verification should be recalculated. But an existing successful
	// verification need not be removed as it indicates verification of previous
	// version.
	if conditions.IsFalse(obj, sourcev1.SourceVerifiedCondition) {
		conditions.Delete(obj, sourcev1.SourceVerifiedCondition)
	}

	var proxyOpts *transport.ProxyOptions
	var proxyURL *url.URL
	if obj.Spec.ProxySecretRef != nil {
		var err error
		secretRef := types.NamespacedName{
			Name:      obj.Spec.ProxySecretRef.Name,
			Namespace: obj.GetNamespace(),
		}
		proxyURL, err = secrets.ProxyURLFromSecretRef(ctx, r.Client, secretRef)
		if err != nil {
			e := serror.NewGeneric(
				fmt.Errorf("failed to configure proxy options: %w", err),
				sourcev1.AuthenticationFailedReason,
			)
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
			// Return error as the world as observed may change
			return sreconcile.ResultEmpty, e
		}
		proxyOpts = &transport.ProxyOptions{URL: proxyURL.String()}
	}

	u, err := url.Parse(obj.Spec.URL)
	if err != nil {
		e := serror.NewStalling(
			fmt.Errorf("failed to parse url '%s': %w", obj.Spec.URL, err),
			sourcev1.URLInvalidReason,
		)
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
		return sreconcile.ResultEmpty, e
	}

	authOpts, err := r.getAuthOpts(ctx, obj, *u, proxyURL)
	if err != nil {
		// Return error as the world as observed may change
		return sreconcile.ResultEmpty, err
	}

	// Fetch the included artifact metadata.
	artifacts, err := r.fetchIncludes(ctx, obj)
	if err != nil {
		return sreconcile.ResultEmpty, err
	}

	// Observe if the artifacts still match the previous included ones
	if artifacts.Diff(obj.Status.IncludedArtifacts) {
		message := "included artifacts differ from last observed includes"
		if obj.Status.IncludedArtifacts != nil {
			conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "IncludeChange", "%s", message)
		}
		rreconcile.ProgressiveStatus(true, obj, meta.ProgressingReason, "building artifact: %s", message)
		if err := sp.Patch(ctx, obj, r.patchOptions...); err != nil {
			return sreconcile.ResultEmpty, serror.NewGeneric(err, sourcev1.PatchOperationFailedReason)
		}
	}
	conditions.Delete(obj, sourcev1.ArtifactOutdatedCondition)

	// Persist the ArtifactSet.
	*includes = *artifacts

	c, err := r.gitCheckout(ctx, obj, authOpts, proxyOpts, dir, true)
	if err != nil {
		return sreconcile.ResultEmpty, err
	}
	if c == nil {
		e := serror.NewGeneric(
			fmt.Errorf("git repository is empty"),
			"EmptyGitRepository",
		)
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
		return sreconcile.ResultEmpty, e
	}
	// Assign the commit to the shared commit reference.
	*commit = *c

	// If it's a partial commit obtained from an existing artifact, check if the
	// reconciliation can be skipped if other configurations have not changed.
	if !git.IsConcreteCommit(*commit) {
		// Check if the content config contributing to the artifact has changed.
		if !gitContentConfigChanged(obj, includes) {
			ge := serror.NewGeneric(
				fmt.Errorf("no changes since last reconcilation: observed revision '%s'",
					commitReference(obj, commit)), sourcev1.GitOperationSucceedReason,
			)
			ge.Notification = false
			ge.Ignore = true
			// Log it as this will not be passed to the runtime.
			ge.Log = true
			ge.Event = corev1.EventTypeNormal
			// Remove any stale fetch failed condition.
			conditions.Delete(obj, sourcev1.FetchFailedCondition)
			// IMPORTANT: This must be set to ensure that the observed
			// generation of this condition is updated. In case of full
			// reconciliation reconcileArtifact() ensures that it's set at the
			// very end.
			conditions.MarkTrue(obj, sourcev1.ArtifactInStorageCondition, meta.SucceededReason,
				"stored artifact for revision '%s'", commitReference(obj, commit))
			// TODO: Find out if such condition setting is needed when commit
			// signature verification is enabled.
			return sreconcile.ResultEmpty, ge
		}

		// If we can't skip the reconciliation, checkout again without any
		// optimization.
		c, err := r.gitCheckout(ctx, obj, authOpts, proxyOpts, dir, false)
		if err != nil {
			return sreconcile.ResultEmpty, err
		}
		*commit = *c
	}
	ctrl.LoggerFrom(ctx).V(logger.DebugLevel).Info("git repository checked out", "url", obj.Spec.URL, "revision", commitReference(obj, commit))
	conditions.Delete(obj, sourcev1.FetchFailedCondition)

	// Validate sparse checkout paths after successful checkout.
	if err := r.validateSparseCheckoutPaths(ctx, obj, dir); err != nil {
		e := serror.NewGeneric(
			fmt.Errorf("failed to sparse checkout directories : %w", err),
			sourcev1.GitOperationFailedReason,
		)
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
		return sreconcile.ResultEmpty, e
	}

	// Verify commit signature
	if result, err := r.verifySignature(ctx, obj, *commit); err != nil || result == sreconcile.ResultEmpty {
		return result, err
	}

	// Mark observations about the revision on the object
	if !obj.GetArtifact().HasRevision(commitReference(obj, commit)) {
		message := fmt.Sprintf("new upstream revision '%s'", commitReference(obj, commit))
		if obj.GetArtifact() != nil {
			conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "NewRevision", "%s", message)
		}
		rreconcile.ProgressiveStatus(true, obj, meta.ProgressingReason, "building artifact: %s", message)
		if err := sp.Patch(ctx, obj, r.patchOptions...); err != nil {
			return sreconcile.ResultEmpty, serror.NewGeneric(err, sourcev1.PatchOperationFailedReason)
		}
	}
	return sreconcile.ResultSuccess, nil
}

// getAuthOpts fetches the secret containing the auth options (if specified),
// constructs a git.AuthOptions object using those options along with the provided
// URL and returns it.
func (r *GitRepositoryReconciler) getAuthOpts(ctx context.Context, obj *sourcev1.GitRepository,
	u url.URL, proxyURL *url.URL) (*git.AuthOptions, error) {
	var secret *corev1.Secret
	var authData map[string][]byte
	if obj.Spec.SecretRef != nil {
		var err error
		secret, err = r.getSecret(ctx, obj.Spec.SecretRef.Name, obj.GetNamespace())
		if err != nil {
			e := serror.NewGeneric(
				fmt.Errorf("failed to get secret '%s/%s': %w", obj.GetNamespace(), obj.Spec.SecretRef.Name, err),
				sourcev1.AuthenticationFailedReason,
			)
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
			return nil, e
		}
		authData = secret.Data
	}

	// Configure authentication strategy to access the source
	opts, err := git.NewAuthOptions(u, authData)
	if err != nil {
		e := serror.NewGeneric(
			fmt.Errorf("failed to configure authentication options: %w", err),
			sourcev1.AuthenticationFailedReason,
		)
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
		return nil, e
	}

	// Configure provider authentication if specified.
	var getCreds func() (*authutils.GitCredentials, error)
	switch provider := obj.GetProvider(); provider {
	case sourcev1.GitProviderAzure: // If AWS or GCP are added in the future they can be added here separated by a comma.
		getCreds = func() (*authutils.GitCredentials, error) {
			opts := []auth.Option{
				auth.WithClient(r.Client),
				auth.WithServiceAccountNamespace(obj.GetNamespace()),
			}

			if obj.Spec.ServiceAccountName != "" {
				// Check object-level workload identity feature gate.
				if !auth.IsObjectLevelWorkloadIdentityEnabled() {
					const gate = auth.FeatureGateObjectLevelWorkloadIdentity
					const msgFmt = "to use spec.serviceAccountName for provider authentication please enable the %s feature gate in the controller"
					err := serror.NewStalling(fmt.Errorf(msgFmt, gate), meta.FeatureGateDisabledReason)
					conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, meta.FeatureGateDisabledReason, "%s", err)
					return nil, err
				}
				// Set ServiceAccountName only if explicitly specified
				opts = append(opts, auth.WithServiceAccountName(obj.Spec.ServiceAccountName))
			}

			if r.TokenCache != nil {
				involvedObject := cache.InvolvedObject{
					Kind:      sourcev1.GitRepositoryKind,
					Name:      obj.GetName(),
					Namespace: obj.GetNamespace(),
					Operation: cache.OperationReconcile,
				}
				opts = append(opts, auth.WithCache(*r.TokenCache, involvedObject))
			}

			if proxyURL != nil {
				opts = append(opts, auth.WithProxyURL(*proxyURL))
			}

			return authutils.GetGitCredentials(ctx, provider, opts...)
		}
	case sourcev1.GitProviderGitHub:
		// if provider is github, but secret ref is not specified
		if obj.Spec.SecretRef == nil {
			e := serror.NewStalling(
				fmt.Errorf("secretRef with github app data must be specified when provider is set to github"),
				sourcev1.InvalidProviderConfigurationReason,
			)
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
			return nil, e
		}
		authMethods, err := secrets.AuthMethodsFromSecret(ctx, secret, secrets.WithTLSSystemCertPool())
		if err != nil {
			return nil, err
		}
		if !authMethods.HasGitHubAppData() {
			e := serror.NewGeneric(
				fmt.Errorf("secretRef with github app data must be specified when provider is set to github"),
				sourcev1.InvalidProviderConfigurationReason,
			)
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
			return nil, e
		}
		getCreds = func() (*authutils.GitCredentials, error) {
			var appOpts []github.OptFunc

			appOpts = append(appOpts, github.WithAppData(authMethods.GitHubAppData))

			if proxyURL != nil {
				appOpts = append(appOpts, github.WithProxyURL(proxyURL))
			}

			if r.TokenCache != nil {
				appOpts = append(appOpts, github.WithCache(r.TokenCache, sourcev1.GitRepositoryKind,
					obj.GetName(), obj.GetNamespace(), cache.OperationReconcile))
			}

			if authMethods.HasTLS() {
				appOpts = append(appOpts, github.WithTLSConfig(authMethods.TLS))
			}

			username, password, err := github.GetCredentials(ctx, appOpts...)
			if err != nil {
				return nil, err
			}
			return &authutils.GitCredentials{
				Username: username,
				Password: password,
			}, nil
		}
	default:
		// analyze secret, if it has github app data, perhaps provider should have been github.
		if appID := authData[github.KeyAppID]; len(appID) != 0 {
			e := serror.NewGeneric(
				fmt.Errorf("secretRef '%s/%s' has github app data but provider is not set to github", obj.GetNamespace(), obj.Spec.SecretRef.Name),
				sourcev1.InvalidProviderConfigurationReason,
			)
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
			return nil, e
		}
	}
	if getCreds != nil {
		creds, err := getCreds()
		if err != nil {
			// Check if it's already a structured error and preserve it
			switch err.(type) {
			case *serror.Stalling, *serror.Generic:
				return nil, err
			}

			e := serror.NewGeneric(
				fmt.Errorf("failed to configure authentication options: %w", err),
				sourcev1.AuthenticationFailedReason,
			)
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
			return nil, e
		}
		opts.BearerToken = creds.BearerToken
		opts.Username = creds.Username
		opts.Password = creds.Password
	}
	return opts, nil
}

func (r *GitRepositoryReconciler) getSecret(ctx context.Context, name, namespace string) (*corev1.Secret, error) {
	key := types.NamespacedName{
		Namespace: namespace,
		Name:      name,
	}
	secret := &corev1.Secret{}
	if err := r.Client.Get(ctx, key, secret); err != nil {
		return nil, fmt.Errorf("failed to get secret '%s/%s': %w", namespace, name, err)
	}
	return secret, nil
}

// reconcileArtifact archives a new Artifact to the Storage, if the current
// (Status) data on the object does not match the given.
//
// The inspection of the given data to the object is differed, ensuring any
// stale observations like v1.ArtifactOutdatedCondition are removed.
// If the given Artifact and/or artifactSet (includes) and observed artifact
// content config do not differ from the object's current, it returns early.
// Source ignore patterns are loaded, and the given directory is archived while
// taking these patterns into account.
// On a successful archive, the Artifact, Includes, observed ignore, recurse
// submodules and observed include in the Status of the object are set.
func (r *GitRepositoryReconciler) reconcileArtifact(ctx context.Context, sp *patch.SerialPatcher,
	obj *sourcev1.GitRepository, commit *git.Commit, includes *artifactSet, dir string) (sreconcile.Result, error) {

	// Create potential new artifact with current available metadata
	artifact := r.Storage.NewArtifactFor(obj.Kind, obj.GetObjectMeta(), commitReference(obj, commit), fmt.Sprintf("%s.tar.gz", commit.Hash.String()))

	// Set the ArtifactInStorageCondition if there's no drift.
	defer func() {
		if curArtifact := obj.GetArtifact(); curArtifact.HasRevision(artifact.Revision) &&
			!includes.Diff(obj.Status.IncludedArtifacts) &&
			!gitContentConfigChanged(obj, includes) {
			conditions.Delete(obj, sourcev1.ArtifactOutdatedCondition)
			conditions.MarkTrue(obj, sourcev1.ArtifactInStorageCondition, meta.SucceededReason,
				"stored artifact for revision '%s'", curArtifact.Revision)
		}
	}()

	// The artifact is up-to-date
	if curArtifact := obj.GetArtifact(); curArtifact.HasRevision(artifact.Revision) &&
		!includes.Diff(obj.Status.IncludedArtifacts) &&
		!gitContentConfigChanged(obj, includes) {
		r.eventLogf(ctx, obj, eventv1.EventTypeTrace, sourcev1.ArtifactUpToDateReason, "artifact up-to-date with remote revision: '%s'", curArtifact.Revision)
		return sreconcile.ResultSuccess, nil
	}

	// Ensure target path exists and is a directory
	if f, err := os.Stat(dir); err != nil {
		e := serror.NewGeneric(
			fmt.Errorf("failed to stat target artifact path: %w", err),
			sourcev1.StatOperationFailedReason,
		)
		conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, e.Reason, "%s", e)
		return sreconcile.ResultEmpty, e
	} else if !f.IsDir() {
		e := serror.NewGeneric(
			fmt.Errorf("invalid target path: '%s' is not a directory", dir),
			sourcev1.InvalidPathReason,
		)
		conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, e.Reason, "%s", e)
		return sreconcile.ResultEmpty, e
	}

	// Ensure artifact directory exists and acquire lock
	if err := r.Storage.MkdirAll(artifact); err != nil {
		e := serror.NewGeneric(
			fmt.Errorf("failed to create artifact directory: %w", err),
			sourcev1.DirCreationFailedReason,
		)
		conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, e.Reason, "%s", e)
		return sreconcile.ResultEmpty, e
	}
	unlock, err := r.Storage.Lock(artifact)
	if err != nil {
		return sreconcile.ResultEmpty, serror.NewGeneric(
			fmt.Errorf("failed to acquire lock for artifact: %w", err),
			meta.FailedReason,
		)
	}
	defer unlock()

	// Load ignore rules for archiving
	ignoreDomain := strings.Split(dir, string(filepath.Separator))
	ps, err := sourceignore.LoadIgnorePatterns(dir, ignoreDomain)
	if err != nil {
		return sreconcile.ResultEmpty, serror.NewGeneric(
			fmt.Errorf("failed to load source ignore patterns from repository: %w", err),
			"SourceIgnoreError",
		)
	}
	if obj.Spec.Ignore != nil {
		ps = append(ps, sourceignore.ReadPatterns(strings.NewReader(*obj.Spec.Ignore), ignoreDomain)...)
	}

	// Archive directory to storage
	if err := r.Storage.Archive(&artifact, dir, storage.SourceIgnoreFilter(ps, ignoreDomain)); err != nil {
		e := serror.NewGeneric(
			fmt.Errorf("unable to archive artifact to storage: %w", err),
			sourcev1.ArchiveOperationFailedReason,
		)
		conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, e.Reason, "%s", e)
		return sreconcile.ResultEmpty, e
	}

	// Record the observations on the object.
	obj.Status.Artifact = artifact.DeepCopy()
	obj.Status.IncludedArtifacts = *includes
	obj.Status.ObservedIgnore = obj.Spec.Ignore
	obj.Status.ObservedRecurseSubmodules = obj.Spec.RecurseSubmodules
	obj.Status.ObservedInclude = obj.Spec.Include
	obj.Status.ObservedSparseCheckout = obj.Spec.SparseCheckout

	// Remove the deprecated symlink.
	// TODO(hidde): remove 2 minor versions from introduction of v1.
	symArtifact := artifact.DeepCopy()
	symArtifact.Path = filepath.Join(filepath.Dir(symArtifact.Path), "latest.tar.gz")
	if fi, err := os.Lstat(r.Storage.LocalPath(artifact)); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			if err := os.Remove(r.Storage.LocalPath(*symArtifact)); err != nil {
				r.eventLogf(ctx, obj, eventv1.EventTypeTrace, sourcev1.SymlinkUpdateFailedReason,
					"failed to remove (deprecated) symlink: %s", err)
			}
		}
	}

	conditions.Delete(obj, sourcev1.StorageOperationFailedCondition)
	return sreconcile.ResultSuccess, nil
}

// reconcileInclude reconciles the on the object specified
// v1.GitRepositoryInclude list by copying their Artifact (sub)contents to
// the specified paths in the given directory.
//
// When one of the includes is unavailable, it marks the object with
// v1.IncludeUnavailableCondition=True and returns early.
// When the copy operations are successful, it removes the
// v1.IncludeUnavailableCondition from the object.
// When the composed artifactSet differs from the current set in the Status of
// the object, it marks the object with v1.ArtifactOutdatedCondition=True.
func (r *GitRepositoryReconciler) reconcileInclude(ctx context.Context, sp *patch.SerialPatcher,
	obj *sourcev1.GitRepository, _ *git.Commit, includes *artifactSet, dir string) (sreconcile.Result, error) {

	for i, incl := range obj.Spec.Include {
		// Do this first as it is much cheaper than copy operations
		toPath, err := securejoin.SecureJoin(dir, incl.GetToPath())
		if err != nil {
			e := serror.NewGeneric(
				fmt.Errorf("path calculation for include '%s' failed: %w", incl.GitRepositoryRef.Name, err),
				"IllegalPath",
			)
			conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, e.Reason, "%s", e)
			return sreconcile.ResultEmpty, e
		}

		// Get artifact at the same include index. The artifactSet is created
		// such that the index of artifactSet matches with the index of Include.
		// Hence, index is used here to pick the associated artifact from
		// includes.
		var artifact *meta.Artifact
		for j, art := range *includes {
			if i == j {
				artifact = art
			}
		}

		// Copy artifact (sub)contents to configured directory.
		if err := r.Storage.CopyToPath(artifact, incl.GetFromPath(), toPath); err != nil {
			e := serror.NewGeneric(
				fmt.Errorf("failed to copy '%s' include from %s to %s: %w", incl.GitRepositoryRef.Name, incl.GetFromPath(), incl.GetToPath(), err),
				"CopyFailure",
			)
			conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, e.Reason, "%s", e)
			return sreconcile.ResultEmpty, e
		}
	}
	conditions.Delete(obj, sourcev1.IncludeUnavailableCondition)
	return sreconcile.ResultSuccess, nil
}

// gitCheckout builds checkout options with the given configurations and
// performs a git checkout.
func (r *GitRepositoryReconciler) gitCheckout(ctx context.Context, obj *sourcev1.GitRepository,
	authOpts *git.AuthOptions, proxyOpts *transport.ProxyOptions, dir string, optimized bool) (*git.Commit, error) {

	// Configure checkout strategy.
	cloneOpts := repository.CloneConfig{
		RecurseSubmodules: obj.Spec.RecurseSubmodules,
		ShallowClone:      true,
	}
	if ref := obj.Spec.Reference; ref != nil {
		cloneOpts.Branch = ref.Branch
		cloneOpts.Commit = ref.Commit
		cloneOpts.Tag = ref.Tag
		cloneOpts.SemVer = ref.SemVer
		cloneOpts.RefName = ref.Name
	}
	if obj.Spec.SparseCheckout != nil {
		// Trim any leading "./" in the directory paths since underlying go-git API does not honor them.
		sparseCheckoutDirs := make([]string, len(obj.Spec.SparseCheckout))
		for i, path := range obj.Spec.SparseCheckout {
			sparseCheckoutDirs[i] = strings.TrimPrefix(path, "./")
		}
		cloneOpts.SparseCheckoutDirectories = sparseCheckoutDirs
	}
	// Only if the object has an existing artifact in storage, attempt to
	// short-circuit clone operation. reconcileStorage has already verified
	// that the artifact exists.
	if optimized && conditions.IsTrue(obj, sourcev1.ArtifactInStorageCondition) {
		if artifact := obj.GetArtifact(); artifact != nil {
			cloneOpts.LastObservedCommit = artifact.Revision
		}
	}

	gitCtx, cancel := context.WithTimeout(ctx, obj.Spec.Timeout.Duration)
	defer cancel()

	clientOpts := []gogit.ClientOption{gogit.WithDiskStorage()}
	if authOpts.Transport == git.HTTP {
		clientOpts = append(clientOpts, gogit.WithInsecureCredentialsOverHTTP())
	}
	if proxyOpts != nil {
		clientOpts = append(clientOpts, gogit.WithProxy(*proxyOpts))
	}

	gitReader, err := gogit.NewClient(dir, authOpts, clientOpts...)
	if err != nil {
		e := serror.NewGeneric(
			fmt.Errorf("failed to create Git client: %w", err),
			sourcev1.GitOperationFailedReason,
		)
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
		return nil, e
	}
	defer gitReader.Close()

	commit, err := gitReader.Clone(gitCtx, obj.Spec.URL, cloneOpts)
	if err != nil {
		e := serror.NewGeneric(
			fmt.Errorf("failed to checkout and determine revision: %w", err),
			sourcev1.GitOperationFailedReason,
		)
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
		return nil, e
	}

	return commit, nil
}

// fetchIncludes fetches artifact metadata of all the included repos.
func (r *GitRepositoryReconciler) fetchIncludes(ctx context.Context, obj *sourcev1.GitRepository) (*artifactSet, error) {
	artifacts := make(artifactSet, len(obj.Spec.Include))
	for i, incl := range obj.Spec.Include {
		// Retrieve the included GitRepository.
		dep := &sourcev1.GitRepository{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: obj.Namespace, Name: incl.GitRepositoryRef.Name}, dep); err != nil {
			e := serror.NewWaiting(
				fmt.Errorf("could not get resource for include '%s': %w", incl.GitRepositoryRef.Name, err),
				"NotFound",
			)
			e.RequeueAfter = r.requeueDependency
			conditions.MarkTrue(obj, sourcev1.IncludeUnavailableCondition, e.Reason, "%s", e)
			return nil, e
		}

		// Confirm include has an artifact
		if dep.GetArtifact() == nil {
			e := serror.NewWaiting(
				fmt.Errorf("no artifact available for include '%s'", incl.GitRepositoryRef.Name),
				"NoArtifact",
			)
			e.RequeueAfter = r.requeueDependency
			conditions.MarkTrue(obj, sourcev1.IncludeUnavailableCondition, e.Reason, "%s", e)
			return nil, e
		}

		artifacts[i] = dep.GetArtifact().DeepCopy()
	}

	// We now know all the includes are available.
	conditions.Delete(obj, sourcev1.IncludeUnavailableCondition)

	return &artifacts, nil
}

// verifySignature verifies the signature of the given Git commit and/or its referencing tag
// depending on the verification mode specified on the object.
// If the signature can not be verified or the verification fails, it records
// v1.SourceVerifiedCondition=False and returns.
// When successful, it records v1.SourceVerifiedCondition=True.
// If no verification mode is specified on the object, the
// v1.SourceVerifiedCondition Condition is removed.
func (r *GitRepositoryReconciler) verifySignature(ctx context.Context, obj *sourcev1.GitRepository, commit git.Commit) (sreconcile.Result, error) {
	// Check if there is a commit verification is configured and remove any old
	// observations if there is none
	if obj.Spec.Verification == nil || obj.Spec.Verification.Mode == "" {
		obj.Status.SourceVerificationMode = nil
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
		e := serror.NewGeneric(
			fmt.Errorf("PGP public keys secret error: %w", err),
			"VerificationError",
		)
		conditions.MarkFalse(obj, sourcev1.SourceVerifiedCondition, e.Reason, "%s", e)
		return sreconcile.ResultEmpty, e
	}

	var keyRings []string
	for _, v := range secret.Data {
		keyRings = append(keyRings, string(v))
	}

	var message strings.Builder
	if obj.Spec.Verification.VerifyTag() {
		// If we need to verify a tag object, then the commit must have a tag
		// that points to it. If it does not, then its safe to asssume that
		// the checkout didn't happen via a tag reference, thus the object can
		// be marked as stalled.
		tag := commit.ReferencingTag
		if tag == nil {
			err := serror.NewStalling(
				errors.New("cannot verify tag object's signature if a tag reference is not specified"),
				"InvalidVerificationMode",
			)
			conditions.MarkFalse(obj, sourcev1.SourceVerifiedCondition, err.Reason, "%s", err)
			return sreconcile.ResultEmpty, err
		}
		if !git.IsSignedTag(*tag) {
			// If the tag was not signed then we can't verify its signature
			// but since the upstream tag object can change at any time, we can't
			// mark the object as stalled.
			err := serror.NewGeneric(
				fmt.Errorf("cannot verify signature of tag '%s' since it is not signed", commit.ReferencingTag.String()),
				"InvalidGitObject",
			)
			conditions.MarkFalse(obj, sourcev1.SourceVerifiedCondition, err.Reason, "%s", err)
			return sreconcile.ResultEmpty, err
		}

		// Verify tag with GPG data from secret
		tagEntity, err := tag.Verify(keyRings...)
		if err != nil {
			e := serror.NewGeneric(
				fmt.Errorf("signature verification of tag '%s' failed: %w", tag.String(), err),
				"InvalidTagSignature",
			)
			conditions.MarkFalse(obj, sourcev1.SourceVerifiedCondition, e.Reason, "%s", e)
			// Return error in the hope the secret changes
			return sreconcile.ResultEmpty, e
		}

		message.WriteString(fmt.Sprintf("verified signature of\n\t- tag '%s' with key '%s'", tag.String(), tagEntity))
	}

	if obj.Spec.Verification.VerifyHEAD() {
		// Verify commit with GPG data from secret
		headEntity, err := commit.Verify(keyRings...)
		if err != nil {
			e := serror.NewGeneric(
				fmt.Errorf("signature verification of commit '%s' failed: %w", commit.Hash.String(), err),
				"InvalidCommitSignature",
			)
			conditions.MarkFalse(obj, sourcev1.SourceVerifiedCondition, e.Reason, "%s", e)
			// Return error in the hope the secret changes
			return sreconcile.ResultEmpty, e
		}
		// If we also verified the tag previously, then append to the message.
		if message.Len() > 0 {
			message.WriteString(fmt.Sprintf("\n\t- commit '%s' with key '%s'", commit.Hash.String(), headEntity))
		} else {
			message.WriteString(fmt.Sprintf("verified signature of\n\t- commit '%s' with key '%s'", commit.Hash.String(), headEntity))
		}
	}

	reason := meta.SucceededReason
	mode := obj.Spec.Verification.GetMode()
	obj.Status.SourceVerificationMode = &mode
	conditions.MarkTrue(obj, sourcev1.SourceVerifiedCondition, reason, "%s", message.String())
	r.eventLogf(ctx, obj, eventv1.EventTypeTrace, reason, "%s", message.String())
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

	// Cleanup caches.
	r.TokenCache.DeleteEventsForObject(sourcev1.GitRepositoryKind,
		obj.GetName(), obj.GetNamespace(), cache.OperationReconcile)

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
			return serror.NewGeneric(
				fmt.Errorf("garbage collection for deleted resource failed: %w", err),
				"GarbageCollectionFailed",
			)
		} else if deleted != "" {
			r.eventLogf(ctx, obj, eventv1.EventTypeTrace, "GarbageCollectionSucceeded",
				"garbage collected artifacts for deleted resource")
		}
		obj.Status.Artifact = nil
		return nil
	}
	if obj.GetArtifact() != nil {
		delFiles, err := r.Storage.GarbageCollect(ctx, *obj.GetArtifact(), time.Second*5)
		if err != nil {
			return serror.NewGeneric(
				fmt.Errorf("garbage collection of artifacts failed: %w", err),
				"GarbageCollectionFailed",
			)
		}
		if len(delFiles) > 0 {
			r.eventLogf(ctx, obj, eventv1.EventTypeTrace, "GarbageCollectionSucceeded",
				"garbage collected %d artifacts", len(delFiles))
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

// gitContentConfigChanged evaluates the current spec with the observations of
// the artifact in the status to determine if artifact content configuration has
// changed and requires rebuilding the artifact. Rebuilding the artifact is also
// required if the object needs to be (re)verified.
func gitContentConfigChanged(obj *sourcev1.GitRepository, includes *artifactSet) bool {
	if !ptr.Equal(obj.Spec.Ignore, obj.Status.ObservedIgnore) {
		return true
	}
	if obj.Spec.RecurseSubmodules != obj.Status.ObservedRecurseSubmodules {
		return true
	}
	if len(obj.Spec.Include) != len(obj.Status.ObservedInclude) {
		return true
	}
	if requiresVerification(obj) {
		return true
	}
	if len(obj.Spec.SparseCheckout) != len(obj.Status.ObservedSparseCheckout) {
		return true
	}
	for index, dir := range obj.Spec.SparseCheckout {
		if dir != obj.Status.ObservedSparseCheckout[index] {
			return true
		}
	}

	// Convert artifactSet to index addressable artifacts and ensure that it and
	// the included artifacts include all the include from the spec.
	artifacts := []*meta.Artifact(*includes)
	if len(obj.Spec.Include) != len(artifacts) {
		return true
	}
	if len(obj.Spec.Include) != len(obj.Status.IncludedArtifacts) {
		return true
	}

	// The order of spec.include, status.IncludeArtifacts and
	// status.observedInclude are the same. Compare the values by index.
	for index, incl := range obj.Spec.Include {
		observedIncl := obj.Status.ObservedInclude[index]
		observedInclArtifact := obj.Status.IncludedArtifacts[index]
		currentIncl := artifacts[index]

		// Check if include is the same in spec and status.
		if !gitRepositoryIncludeEqual(incl, observedIncl) {
			return true
		}

		// Check if the included repositories are still the same.
		if !observedInclArtifact.HasRevision(currentIncl.Revision) {
			return true
		}
		if !observedInclArtifact.HasDigest(currentIncl.Digest) {
			return true
		}
	}
	return false
}

// validateSparseCheckoutPaths checks if the sparse checkout paths exist in the cloned repository.
func (r *GitRepositoryReconciler) validateSparseCheckoutPaths(ctx context.Context, obj *sourcev1.GitRepository, dir string) error {
	if obj.Spec.SparseCheckout != nil {
		for _, path := range obj.Spec.SparseCheckout {
			fullPath := filepath.Join(dir, path)
			if _, err := os.Lstat(fullPath); err != nil {
				return fmt.Errorf("sparse checkout dir '%s' does not exist in repository: %w", path, err)
			}
		}
	}
	return nil
}

// Returns true if both GitRepositoryIncludes are equal.
func gitRepositoryIncludeEqual(a, b sourcev1.GitRepositoryInclude) bool {
	if a.GitRepositoryRef != b.GitRepositoryRef {
		return false
	}
	if a.FromPath != b.FromPath {
		return false
	}
	if a.ToPath != b.ToPath {
		return false
	}
	return true
}

func commitReference(obj *sourcev1.GitRepository, commit *git.Commit) string {
	if obj.Spec.Reference != nil && obj.Spec.Reference.Name != "" {
		return commit.AbsoluteReference()
	}
	return commit.String()
}

// requiresVerification inspects a GitRepository's verification spec and its status
// to determine whether the Git repository needs to be verified again. It does so by
// first checking if the GitRepository has a verification spec. If it does, then
// it returns true based on the following three conditions:
//
//   - If the object does not have a observed verification mode in its status.
//   - If the observed verification mode indicates that only the tag had been
//     verified earlier and the HEAD also needs to be verified now.
//   - If the observed verification mode indicates that only the HEAD had been
//     verified earlier and the tag also needs to be verified now.
func requiresVerification(obj *sourcev1.GitRepository) bool {
	if obj.Spec.Verification != nil {
		observedMode := obj.Status.SourceVerificationMode
		mode := obj.Spec.Verification.GetMode()
		if observedMode == nil {
			return true
		}
		if (*observedMode == sourcev1.ModeGitTag && (mode == sourcev1.ModeGitHEAD || mode == sourcev1.ModeGitTagAndHEAD)) ||
			(*observedMode == sourcev1.ModeGitHEAD && (mode == sourcev1.ModeGitTag || mode == sourcev1.ModeGitTagAndHEAD)) {
			return true
		}
	}
	return false
}
