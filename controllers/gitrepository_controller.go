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
	"fmt"
	"os"
	"strings"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
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
	"github.com/fluxcd/source-controller/pkg/sourceignore"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
	"github.com/fluxcd/source-controller/pkg/git"
	"github.com/fluxcd/source-controller/pkg/git/strategy"
)

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
		log.Info("Reconciliation is suspended for this object")
		return ctrl.Result{}, nil
	}

	// Initialize the patch helper
	patchHelper, err := patch.NewHelper(obj, r.Client)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Always attempt to patch the object and status after each reconciliation
	defer func() {
		// Record the value of the reconciliation request, if any
		if v, ok := meta.ReconcileAnnotationValue(obj.GetAnnotations()); ok {
			obj.Status.SetLastHandledReconcileRequest(v)
		}

		// Summarize the Ready condition based on abnormalities that may have been observed.
		conditions.SetSummary(obj,
			meta.ReadyCondition,
			conditions.WithConditions(
				sourcev1.IncludeUnavailableCondition,
				sourcev1.SourceVerifiedCondition,
				sourcev1.FetchFailedCondition,
				sourcev1.ArtifactOutdatedCondition,
				sourcev1.ArtifactUnavailableCondition,
			),
			conditions.WithNegativePolarityConditions(
				sourcev1.ArtifactUnavailableCondition,
				sourcev1.FetchFailedCondition,
				sourcev1.SourceVerifiedCondition,
				sourcev1.IncludeUnavailableCondition,
				sourcev1.ArtifactOutdatedCondition,
			),
		)

		// Patch the object, ignoring conflicts on the conditions owned by this controller
		patchOpts := []patch.Option{
			patch.WithOwnedConditions{
				Conditions: []string{
					sourcev1.ArtifactUnavailableCondition,
					sourcev1.FetchFailedCondition,
					sourcev1.IncludeUnavailableCondition,
					sourcev1.ArtifactOutdatedCondition,
					meta.ReadyCondition,
					meta.ReconcilingCondition,
					meta.StalledCondition,
				},
			},
		}

		// Determine if the resource is still being reconciled, or if it has stalled, and record this observation
		if retErr == nil && (result.IsZero() || !result.Requeue) {
			// We are no longer reconciling
			conditions.Delete(obj, meta.ReconcilingCondition)

			// We have now observed this generation
			patchOpts = append(patchOpts, patch.WithStatusObservedGeneration{})

			readyCondition := conditions.Get(obj, meta.ReadyCondition)
			switch readyCondition.Status {
			case metav1.ConditionFalse:
				// As we are no longer reconciling and the end-state is not ready, the reconciliation has stalled
				conditions.MarkStalled(obj, readyCondition.Reason, readyCondition.Message)
			case metav1.ConditionTrue:
				// As we are no longer reconciling and the end-state is ready, the reconciliation is no longer stalled
				conditions.Delete(obj, meta.StalledCondition)
			}
		}

		// Finally, patch the resource
		if err := patchHelper.Patch(ctx, obj, patchOpts...); err != nil {
			retErr = kerrors.NewAggregate([]error{retErr, err})
		}

		// Always record readiness and duration metrics
		r.Metrics.RecordReadiness(ctx, obj)
		r.Metrics.RecordDuration(ctx, obj, start)
	}()

	// Add finalizer first if not exist to avoid the race condition
	// between init and delete
	if !controllerutil.ContainsFinalizer(obj, sourcev1.SourceFinalizer) {
		controllerutil.AddFinalizer(obj, sourcev1.SourceFinalizer)
		return ctrl.Result{Requeue: true}, nil
	}

	// Examine if the object is under deletion
	if !obj.ObjectMeta.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, obj)
	}

	// Reconcile actual object
	return r.reconcile(ctx, obj)
}

// reconcile steps through the actual reconciliation tasks for the object, it returns early on the first step that
// produces an error.
func (r *GitRepositoryReconciler) reconcile(ctx context.Context, obj *sourcev1.GitRepository) (ctrl.Result, error) {
	// Mark the resource as under reconciliation
	conditions.MarkReconciling(obj, meta.ProgressingReason, "")

	// Reconcile the storage data
	if result, err := r.reconcileStorage(ctx, obj); err != nil || result.IsZero() {
		return result, err
	}

	// Create temp dir for Git clone
	tmpDir, err := os.MkdirTemp("", fmt.Sprintf("%s-%s-%s-", obj.Kind, obj.Namespace, obj.Name))
	if err != nil {
		r.Eventf(obj, events.EventSeverityError, sourcev1.StorageOperationFailedReason, "Failed to create temporary directory: %s", err)
		return ctrl.Result{}, err
	}
	defer os.RemoveAll(tmpDir)

	// Reconcile the source from upstream
	var artifact sourcev1.Artifact
	if result, err := r.reconcileSource(ctx, obj, &artifact, tmpDir); err != nil || result.IsZero() {
		return ctrl.Result{RequeueAfter: obj.GetRequeueAfter()}, err
	}

	// Reconcile includes from the storage
	var includes artifactSet
	if result, err := r.reconcileInclude(ctx, obj, includes, tmpDir); err != nil || result.IsZero() {
		return ctrl.Result{RequeueAfter: r.requeueDependency}, err
	}

	// Reconcile the artifact to storage
	if result, err := r.reconcileArtifact(ctx, obj, artifact, includes, tmpDir); err != nil || result.IsZero() {
		return result, err
	}

	return ctrl.Result{RequeueAfter: obj.GetRequeueAfter()}, nil
}

// reconcileStorage ensures the current state of the storage matches the desired and previously observed state.
//
// All artifacts for the resource except for the current one are garbage collected from the storage.
// If the artifact in the Status object of the resource disappeared from storage, it is removed from the object.
// If the object does not have an artifact in its Status object, a v1beta1.ArtifactUnavailableCondition is set.
// If the hostname of any of the URLs on the object do not match the current storage server hostname, they are updated.
//
// The caller should assume a failure if an error is returned, or the Result is zero.
func (r *GitRepositoryReconciler) reconcileStorage(ctx context.Context, obj *sourcev1.GitRepository) (ctrl.Result, error) {
	// Garbage collect previous advertised artifact(s) from storage
	_ = r.garbageCollect(ctx, obj)

	// Determine if the advertised artifact is still in storage
	if artifact := obj.GetArtifact(); artifact != nil && !r.Storage.ArtifactExist(*artifact) {
		obj.Status.Artifact = nil
		obj.Status.URL = ""
	}

	// Record that we do not have an artifact
	if obj.GetArtifact() == nil {
		conditions.MarkTrue(obj, sourcev1.ArtifactUnavailableCondition, "NoArtifact", "No artifact for resource in storage")
		return ctrl.Result{Requeue: true}, nil
	}
	conditions.Delete(obj, sourcev1.ArtifactUnavailableCondition)

	// Always update URLs to ensure hostname is up-to-date
	// TODO(hidde): we may want to send out an event only if we notice the URL has changed
	r.Storage.SetArtifactURL(obj.GetArtifact())
	obj.Status.URL = r.Storage.SetHostname(obj.Status.URL)

	return ctrl.Result{RequeueAfter: obj.GetRequeueAfter()}, nil
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
//
// The caller should assume a failure if an error is returned, or the Result is zero.
func (r *GitRepositoryReconciler) reconcileSource(ctx context.Context,
	obj *sourcev1.GitRepository, artifact *sourcev1.Artifact, dir string) (ctrl.Result, error) {
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
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason,
				"Failed to get secret '%s': %s", name.String(), err.Error())
			r.Eventf(obj, events.EventSeverityError, sourcev1.AuthenticationFailedReason,
				"Failed to get secret '%s': %s", name.String(), err.Error())
			// Return error as the world as observed may change
			return ctrl.Result{}, err
		}

		// Configure strategy with secret
		authOpts, err = git.AuthOptionsFromSecret(obj.Spec.URL, &secret)
	} else {
		// Set the minimal auth options for valid transport.
		authOpts, err = git.AuthOptionsWithoutSecret(obj.Spec.URL)
	}
	if err != nil {
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason,
			"Failed to configure auth strategy for Git implementation '%s': %s", obj.Spec.GitImplementation, err)
		r.Eventf(obj, events.EventSeverityError, sourcev1.AuthenticationFailedReason,
			"Failed to configure auth strategy for Git implementation '%s': %s", obj.Spec.GitImplementation, err)
		// Return error as the contents of the secret may change
		return ctrl.Result{}, err
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
		ctrl.LoggerFrom(ctx).Error(err, fmt.Sprintf("Failed to configure checkout strategy for Git implementation '%s'", obj.Spec.GitImplementation))
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.GitOperationFailedReason,
			"Failed to configure checkout strategy for Git implementation '%s': %s", obj.Spec.GitImplementation, err)
		// Do not return err as recovery without changes is impossible
		return ctrl.Result{}, nil
	}

	// Checkout HEAD of reference in object
	gitCtx, cancel := context.WithTimeout(ctx, obj.Spec.Timeout.Duration)
	defer cancel()
	commit, err := checkoutStrategy.Checkout(gitCtx, dir, obj.Spec.URL, authOpts)
	if err != nil {
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.GitOperationFailedReason,
			"Failed to checkout and determine revision: %s", err)
		r.Eventf(obj, events.EventSeverityError, sourcev1.GitOperationFailedReason,
			"Failed to checkout and determine revision: %s", err)
		// Coin flip on transient or persistent error, return error and hope for the best
		return ctrl.Result{}, err
	}
	r.Eventf(obj, events.EventSeverityInfo, sourcev1.GitOperationSucceedReason,
		"Cloned repository '%s' and checked out revision '%s'", obj.Spec.URL, commit.String())
	conditions.Delete(obj, sourcev1.FetchFailedCondition)

	// Verify commit signature
	if result, err := r.verifyCommitSignature(ctx, obj, *commit); err != nil || result.IsZero() {
		return result, err
	}

	// Create potential new artifact with current available metadata
	*artifact = r.Storage.NewArtifactFor(obj.Kind, obj.GetObjectMeta(), commit.String(), fmt.Sprintf("%s.tar.gz", commit.Hash.String()))

	// Mark observations about the revision on the object
	if !obj.GetArtifact().HasRevision(commit.String()) {
		conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "NewRevision", "New upstream revision '%s'", commit.String())
	}
	return ctrl.Result{RequeueAfter: obj.GetRequeueAfter()}, nil
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
//
// The caller should assume a failure if an error is returned, or the Result is zero.
func (r *GitRepositoryReconciler) reconcileArtifact(ctx context.Context, obj *sourcev1.GitRepository, artifact sourcev1.Artifact, includes artifactSet, dir string) (ctrl.Result, error) {
	// Always restore the Ready condition in case it got removed due to a transient error
	defer func() {
		if obj.GetArtifact() != nil {
			conditions.Delete(obj, sourcev1.ArtifactUnavailableCondition)
		}
		if obj.GetArtifact().HasRevision(artifact.Revision) && !includes.Diff(obj.Status.IncludedArtifacts) {
			conditions.Delete(obj, sourcev1.ArtifactOutdatedCondition)
			conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason,
				"Stored artifact for revision '%s'", artifact.Revision)
		}
	}()

	// The artifact is up-to-date
	if obj.GetArtifact().HasRevision(artifact.Revision) && !includes.Diff(obj.Status.IncludedArtifacts) {
		ctrl.LoggerFrom(ctx).Info(fmt.Sprintf("Already up to date, current revision '%s'", artifact.Revision))
		return ctrl.Result{RequeueAfter: obj.GetRequeueAfter()}, nil
	}

	// Ensure target path exists and is a directory
	if f, err := os.Stat(dir); err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "failed to stat source path")
		return ctrl.Result{}, err
	} else if !f.IsDir() {
		err := fmt.Errorf("source path '%s' is not a directory", dir)
		ctrl.LoggerFrom(ctx).Error(err, "invalid target path")
		return ctrl.Result{}, err
	}

	// Ensure artifact directory exists and acquire lock
	if err := r.Storage.MkdirAll(artifact); err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "failed to create artifact directory")
		return ctrl.Result{}, err
	}
	unlock, err := r.Storage.Lock(artifact)
	if err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "failed to acquire lock for artifact")
		return ctrl.Result{}, err
	}
	defer unlock()

	// Load ignore rules for archiving
	ps, err := sourceignore.LoadIgnorePatterns(dir, nil)
	if err != nil {
		r.Eventf(obj, events.EventSeverityError,
			"SourceIgnoreError", "Failed to load source ignore patterns from repository: %s", err)
		return ctrl.Result{}, err
	}
	if obj.Spec.Ignore != nil {
		ps = append(ps, sourceignore.ReadPatterns(strings.NewReader(*obj.Spec.Ignore), nil)...)
	}

	// Archive directory to storage
	if err := r.Storage.Archive(&artifact, dir, SourceIgnoreFilter(ps, nil)); err != nil {
		r.Eventf(obj, events.EventSeverityError, sourcev1.StorageOperationFailedReason,
			"Unable to archive artifact to storage: %s", err)
		return ctrl.Result{}, err
	}
	r.AnnotatedEventf(obj, map[string]string{
		"revision": artifact.Revision,
		"checksum": artifact.Checksum,
	}, events.EventSeverityInfo, "NewArtifact", "Stored artifact for revision '%s'", artifact.Revision)

	// Record it on the object
	obj.Status.Artifact = artifact.DeepCopy()
	obj.Status.IncludedArtifacts = includes

	// Update symlink on a "best effort" basis
	url, err := r.Storage.Symlink(artifact, "latest.tar.gz")
	if err != nil {
		r.Eventf(obj, events.EventSeverityError, sourcev1.StorageOperationFailedReason,
			"Failed to update status URL symlink: %s", err)
	}
	if url != "" {
		obj.Status.URL = url
	}
	return ctrl.Result{RequeueAfter: obj.GetRequeueAfter()}, nil
}

// reconcileInclude reconciles the declared includes from the object by copying their artifact (sub)contents to the
// declared paths in the given directory.
//
// If an include is unavailable, it marks the object with v1beta1.IncludeUnavailableCondition and returns early.
// If the copy operations are successful, it deletes the v1beta1.IncludeUnavailableCondition from the object.
// If the artifactSet differs from the current set, it marks the object with v1beta1.ArtifactOutdatedCondition.
//
// The caller should assume a failure if an error is returned, or the Result is zero.
func (r *GitRepositoryReconciler) reconcileInclude(ctx context.Context, obj *sourcev1.GitRepository, artifacts artifactSet, dir string) (ctrl.Result, error) {
	artifacts = make(artifactSet, len(obj.Spec.Include))
	for i, incl := range obj.Spec.Include {
		// Do this first as it is much cheaper than copy operations
		toPath, err := securejoin.SecureJoin(dir, incl.GetToPath())
		if err != nil {
			conditions.MarkTrue(obj, sourcev1.IncludeUnavailableCondition, "IllegalPath",
				"Path calculation for include '%s' failed: %s", incl.GitRepositoryRef.Name, err.Error())
			return ctrl.Result{}, err
		}

		// Retrieve the included GitRepository
		dep := &sourcev1.GitRepository{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: obj.Namespace, Name: incl.GitRepositoryRef.Name}, dep); err != nil {
			conditions.MarkTrue(obj, sourcev1.IncludeUnavailableCondition, "NotFound",
				"Could not get resource for include '%s': %s", incl.GitRepositoryRef.Name, err.Error())
			return ctrl.Result{}, err
		}

		// Confirm include has an artifact
		if dep.GetArtifact() == nil {
			ctrl.LoggerFrom(ctx).Error(nil, fmt.Sprintf("No artifact available for include '%s'", incl.GitRepositoryRef.Name))
			conditions.MarkTrue(obj, sourcev1.IncludeUnavailableCondition, "NoArtifact",
				"No artifact available for include '%s'", incl.GitRepositoryRef.Name)
			return ctrl.Result{}, nil
		}

		// Copy artifact (sub)contents to configured directory
		if err := r.Storage.CopyToPath(dep.GetArtifact(), incl.GetFromPath(), toPath); err != nil {
			conditions.MarkTrue(obj, sourcev1.IncludeUnavailableCondition, "CopyFailure",
				"Failed to copy '%s' include from %s to %s: %s", incl.GitRepositoryRef.Name, incl.GetFromPath(), incl.GetToPath(), err.Error())
			r.Eventf(obj, events.EventSeverityError, sourcev1.IncludeUnavailableCondition,
				"Failed to copy '%s' include from %s to %s: %s", incl.GitRepositoryRef.Name, incl.GetFromPath(), incl.GetToPath(), err.Error())
			return ctrl.Result{}, err
		}
		artifacts[i] = dep.GetArtifact().DeepCopy()
	}

	// We now know all includes are available
	conditions.Delete(obj, sourcev1.IncludeUnavailableCondition)

	// Observe if the artifacts still match the previous included ones
	if artifacts.Diff(obj.Status.IncludedArtifacts) {
		conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "IncludeChange", "Included artifacts differ from last observed includes")
	}
	return ctrl.Result{RequeueAfter: obj.GetRequeueAfter()}, nil
}

// reconcileDelete handles the delete of an object. It first garbage collects all artifacts for the object from the
// artifact storage, if successful, the finalizer is removed from the object.
func (r *GitRepositoryReconciler) reconcileDelete(ctx context.Context, obj *sourcev1.GitRepository) (ctrl.Result, error) {
	// Garbage collect the resource's artifacts
	if err := r.garbageCollect(ctx, obj); err != nil {
		// Return the error so we retry the failed garbage collection
		return ctrl.Result{}, err
	}

	// Remove our finalizer from the list
	controllerutil.RemoveFinalizer(obj, sourcev1.SourceFinalizer)

	// Stop reconciliation as the object is being deleted
	return ctrl.Result{}, nil
}

// verifyCommitSignature verifies the signature of the given commit if a verification mode is configured on the object.
func (r *GitRepositoryReconciler) verifyCommitSignature(ctx context.Context, obj *sourcev1.GitRepository, commit git.Commit) (ctrl.Result, error) {
	// Check if there is a commit verification is configured and remove any old observations if there is none
	if obj.Spec.Verification == nil || obj.Spec.Verification.Mode == "" {
		conditions.Delete(obj, sourcev1.SourceVerifiedCondition)
		return ctrl.Result{RequeueAfter: obj.GetRequeueAfter()}, nil
	}

	// Get secret with GPG data
	publicKeySecret := types.NamespacedName{
		Namespace: obj.Namespace,
		Name:      obj.Spec.Verification.SecretRef.Name,
	}
	secret := &corev1.Secret{}
	if err := r.Client.Get(ctx, publicKeySecret, secret); err != nil {
		conditions.MarkFalse(obj, sourcev1.SourceVerifiedCondition, meta.FailedReason, "PGP public keys secret error: %s", err.Error())
		r.Eventf(obj, events.EventSeverityError, "VerificationError", "PGP public keys secret error: %s", err.Error())
		return ctrl.Result{}, err
	}

	var keyRings []string
	for _, v := range secret.Data {
		keyRings = append(keyRings, string(v))
	}
	// Verify commit with GPG data from secret
	if _, err := commit.Verify(keyRings...); err != nil {
		conditions.MarkFalse(obj, sourcev1.SourceVerifiedCondition, meta.FailedReason, "Signature verification of commit '%s' failed: %s", commit.Hash.String(), err)
		r.Eventf(obj, events.EventSeverityError, "InvalidCommitSignature", "Signature verification of commit '%s' failed: %s", commit.Hash.String(), err)
		// Return error in the hope the secret changes
		return ctrl.Result{}, err
	}

	conditions.MarkTrue(obj, sourcev1.SourceVerifiedCondition, meta.SucceededReason, "Verified signature of commit '%s'", commit.Hash.String())
	r.Eventf(obj, events.EventSeverityInfo, "VerifiedCommit", "Verified signature of commit '%s'", commit.Hash.String())
	return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
}

// garbageCollect performs a garbage collection for the given v1beta1.GitRepository. It removes all but the current
// artifact except for when the deletion timestamp is set, which will result in the removal of all artifacts for the
// resource.
func (r *GitRepositoryReconciler) garbageCollect(ctx context.Context, obj *sourcev1.GitRepository) error {
	if !obj.DeletionTimestamp.IsZero() {
		if err := r.Storage.RemoveAll(r.Storage.NewArtifactFor(obj.Kind, obj.GetObjectMeta(), "", "*")); err != nil {
			r.Eventf(obj, events.EventSeverityError, "GarbageCollectionFailed",
				"Garbage collection for deleted resource failed: %s", err)
			return err
		}
		obj.Status.Artifact = nil
		// TODO(hidde): we should only push this event if we actually garbage collected something
		r.Eventf(obj, events.EventSeverityInfo, "GarbageCollectionSucceeded",
			"Garbage collected artifacts for deleted resource")
		return nil
	}
	if obj.GetArtifact() != nil {
		if err := r.Storage.RemoveAllButCurrent(*obj.GetArtifact()); err != nil {
			r.Eventf(obj, events.EventSeverityError, "GarbageCollectionFailed", "Garbage collection of old artifacts failed: %s", err)
			return err
		}
		// TODO(hidde): we should only push this event if we actually garbage collected something
		r.Eventf(obj, events.EventSeverityInfo, "GarbageCollectionSucceeded", "Garbage collected old artifacts")
	}
	return nil
}
