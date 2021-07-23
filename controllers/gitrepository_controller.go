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
	"io/ioutil"
	"os"
	"strings"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/patch"
	"github.com/fluxcd/source-controller/pkg/sourceignore"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/fluxcd/pkg/apis/meta"
	helper "github.com/fluxcd/pkg/runtime/controller"
	"github.com/fluxcd/pkg/runtime/events"
	"github.com/fluxcd/pkg/runtime/predicates"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
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
	helper.Events
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
	log := logr.FromContext(ctx)

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

	// Always attempt to patch the object and status after each
	// reconciliation
	defer func() {
		// Record the value of the reconciliation request, if any
		if v, ok := meta.ReconcileAnnotationValue(obj.GetAnnotations()); ok {
			obj.Status.SetLastHandledReconcileRequest(v)
		}

		// Summarize Ready condition
		conditions.SetSummary(obj,
			meta.ReadyCondition,
			conditions.WithConditions(
				sourcev1.ArtifactAvailableCondition,
				sourcev1.SourceVerifiedCondition,
				sourcev1.SourceAvailableCondition,
			),
		)

		// Patch the object, ignoring conflicts on the conditions owned by
		// this controller
		patchOpts := []patch.Option{
			patch.WithOwnedConditions{
				Conditions: []string{
					sourcev1.ArtifactAvailableCondition,
					sourcev1.SourceVerifiedCondition,
					sourcev1.SourceAvailableCondition,
					meta.ReadyCondition,
					meta.ReconcilingCondition,
					meta.StalledCondition,
				},
			},
		}

		// Determine if the resource is still being reconciled, or if
		// it has stalled, and record this observation
		if retErr == nil && (result.IsZero() || !result.Requeue) {
			// We are no longer reconciling
			conditions.Delete(obj, meta.ReconcilingCondition)

			// We have now observed this generation
			patchOpts = append(patchOpts, patch.WithStatusObservedGeneration{})

			readyCondition := conditions.Get(obj, meta.ReadyCondition)
			switch readyCondition.Status {
			case metav1.ConditionFalse:
				// As we are no longer reconciling and the end-state
				// is not ready, the reconciliation has stalled
				conditions.MarkTrue(obj, meta.StalledCondition, readyCondition.Reason, readyCondition.Message)
			case metav1.ConditionTrue:
				// As we are no longer reconciling and the end-state
				// is ready, the reconciliation is no longer stalled
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

func (r *GitRepositoryReconciler) reconcile(ctx context.Context, obj *sourcev1.GitRepository) (ctrl.Result, error) {
	// Reconcile the storage data
	if result, err := r.reconcileStorage(ctx, obj); err != nil {
		return result, err
	}

	// Create temp dir for Git clone
	tmpDir, err := ioutil.TempDir("", fmt.Sprintf("%s-%s-%s-", obj.Kind, obj.Namespace, obj.Name))
	if err != nil {
		conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.StorageOperationFailedReason, "Failed to create temporary directory: %s", err)
		return ctrl.Result{}, err
	}
	defer os.RemoveAll(tmpDir)

	// Reconcile the source from upstream
	var artifact sourcev1.Artifact
	if result, err := r.reconcileSource(ctx, obj, &artifact, tmpDir); err != nil || conditions.IsFalse(obj, sourcev1.SourceAvailableCondition) {
		return result, err
	}

	// Reconcile includes from the storage
	var includes artifactSet
	if result, err := r.reconcileInclude(ctx, obj, includes, tmpDir); err != nil || len(includes) != len(obj.Spec.Include) {
		return result, err
	}

	// Reconcile the artifact to storage
	if result, err := r.reconcileArtifact(ctx, obj, artifact, includes, tmpDir); err != nil {
		return result, err
	}

	return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
}

// reconcileStorage reconciles the storage data for the given object
// by garbage collecting previous advertised artifact(s) from storage,
// observing if the artifact in the status still exists, and
// ensuring the URLs are up-to-date with the current hostname
// configuration.
func (r *GitRepositoryReconciler) reconcileStorage(ctx context.Context, obj *sourcev1.GitRepository) (ctrl.Result, error) {
	// Garbage collect previous advertised artifact(s) from storage
	if err := r.garbageCollect(obj); err != nil {
		r.Events.Eventf(ctx, obj, events.EventSeverityError, "GarbageCollectionFailed", "Garbage collection failed: %s", err)
	}

	// Determine if the advertised artifact is still in storage
	if artifact := obj.GetArtifact(); artifact != nil && !r.Storage.ArtifactExist(*artifact) {
		obj.Status.Artifact = nil
		obj.Status.URL = ""
	}

	// Record that we do not have an artifact
	if obj.GetArtifact() == nil {
		conditions.MarkFalse(obj, sourcev1.ArtifactAvailableCondition, "NoArtifactFound", "No artifact for resource in storage")
		return ctrl.Result{Requeue: true}, nil
	}

	// Always update URLs to ensure hostname is up-to-date
	r.Storage.SetArtifactURL(obj.GetArtifact())
	obj.Status.URL = r.Storage.SetHostname(obj.Status.URL)

	return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
}

// reconcileSource reconciles the Git repository from upstream to the
// given directory path while using the information on the object to
// determine authentication and checkout strategies.
// On a successful checkout of HEAD the artifact metadata the given
// pointer is set to a new artifact.
func (r *GitRepositoryReconciler) reconcileSource(ctx context.Context, obj *sourcev1.GitRepository, artifact *sourcev1.Artifact, dir string) (ctrl.Result, error) {
	log := logr.FromContext(ctx)

	// Configure authentication strategy to access the source
	auth := &git.Auth{}
	if obj.Spec.SecretRef != nil {
		// Determine the auth strategy
		authStrategy, err := strategy.AuthSecretStrategyForURL(obj.Spec.URL, git.CheckoutOptions{
			GitImplementation: obj.Spec.GitImplementation,
			RecurseSubmodules: obj.Spec.RecurseSubmodules,
		})
		if err != nil {
			log.Error(err, "failed to get auth strategy")
			conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.AuthenticationFailedReason, "Failed to get auth strategy: %s", err)
			// Do not return err as recovery without changes is impossible
			return ctrl.Result{}, nil
		}

		// Attempt to retrieve secret
		name := types.NamespacedName{
			Namespace: obj.GetNamespace(),
			Name:      obj.Spec.SecretRef.Name,
		}
		var secret corev1.Secret
		if err = r.Client.Get(ctx, name, &secret); err != nil {
			conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.AuthenticationFailedReason, "Failed to get secret %s: %s", name.String(), err.Error())
			r.Events.Event(ctx, obj, events.EventSeverityError, sourcev1.AuthenticationFailedReason, conditions.Get(obj, sourcev1.SourceAvailableCondition).Message)
			// Return transient errors but wait for next interval on not found
			return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, client.IgnoreNotFound(err)
		}

		// Configure strategy with secret
		auth, err = authStrategy.Method(secret)
		if err != nil {
			conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.AuthenticationFailedReason, "Failed to configure auth strategy: %s", err)
			r.Events.Event(ctx, obj, events.EventSeverityError, sourcev1.AuthenticationFailedReason, conditions.Get(obj, sourcev1.SourceAvailableCondition).Message)
			// Return err as the content of the secret may change
			return ctrl.Result{}, err
		}
	}

	// Configure checkout strategy
	checkoutStrategy, err := strategy.CheckoutStrategyForRef(obj.Spec.Reference, git.CheckoutOptions{
		GitImplementation: obj.Spec.GitImplementation,
		RecurseSubmodules: obj.Spec.RecurseSubmodules,
	})
	if err != nil {
		conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.GitOperationFailedReason, "Failed to configure checkout strategy: %s", err)
		r.Events.Event(ctx, obj, events.EventSeverityError, sourcev1.AuthenticationFailedReason, conditions.Get(obj, sourcev1.SourceAvailableCondition).Message)
		// Do not return err as recovery without changes is impossible
		return ctrl.Result{}, nil
	}

	// Checkout HEAD of commit referenced in object
	gitCtx, cancel := context.WithTimeout(ctx, obj.Spec.Timeout.Duration)
	defer cancel()
	commit, revision, err := checkoutStrategy.Checkout(gitCtx, dir, obj.Spec.URL, auth)
	if err != nil {
		conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.GitOperationFailedReason, "Failed to checkout and determine HEAD revision: %s", err)
		r.Events.Eventf(ctx, obj, events.EventSeverityError, "GitCheckoutFailed", conditions.Get(obj, sourcev1.SourceAvailableCondition).Message)
		// Coin flip on transient or persistent error, requeue
		// TODO(hidde): likely better to detect the err type
		return ctrl.Result{}, err
	}

	// Verify commit signature
	if result, err := r.verifyCommitSignature(ctx, obj, commit); err != nil || conditions.IsFalse(obj, sourcev1.SourceVerifiedCondition) {
		return result, err
	}

	// Create potential new artifact
	*artifact = r.Storage.NewArtifactFor(obj.Kind, obj, revision, fmt.Sprintf("%s.tar.gz", commit.Hash()))
	conditions.MarkTrue(obj, sourcev1.SourceAvailableCondition, sourcev1.GitOperationSucceedReason, "Checked out revision %s", revision)

	return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
}

// reconcileArtifact reconciles the Git checkout and includes in the
// given directory path to the artifact storage by archiving the
// directory while taking into account the ignore patterns in the
// directory and object.
// On a successful archive, the artifact and includes in the status of
// the given object are set, and the symlink in the storage is updated
// to its path.
func (r *GitRepositoryReconciler) reconcileArtifact(ctx context.Context, obj *sourcev1.GitRepository, artifact sourcev1.Artifact, includes artifactSet, dir string) (ctrl.Result, error) {
	// The artifact is up-to-date
	if obj.GetArtifact().HasRevision(artifact.Revision) && !includes.Diff(obj.Status.IncludedArtifacts) {
		logr.FromContext(ctx).Info("Artifact is up-to-date")
		conditions.MarkTrue(obj, sourcev1.ArtifactAvailableCondition, "ArchivedArtifact", "Artifact revision %s", artifact.Revision)
		return ctrl.Result{RequeueAfter: obj.GetInterval().Duration}, nil
	}

	// Ensure target path exists and is a directory
	if f, err := os.Stat(dir); err != nil {
		conditions.MarkFalse(obj, sourcev1.ArtifactAvailableCondition, sourcev1.StorageOperationFailedReason, "Failed to stat source path: %s", err.Error())
		return ctrl.Result{}, err
	} else if !f.IsDir() {
		err = fmt.Errorf("source path %q is not a directory", dir)
		conditions.MarkFalse(obj, sourcev1.ArtifactAvailableCondition, sourcev1.StorageOperationFailedReason, "Failed to reconcile artifact: %s", err.Error())
		return ctrl.Result{}, err
	}

	// Ensure artifact directory exists and acquire lock
	if err := r.Storage.MkdirAll(artifact); err != nil {
		conditions.MarkFalse(obj, sourcev1.ArtifactAvailableCondition, sourcev1.StorageOperationFailedReason, "Failed to create directory: %s", err)
		return ctrl.Result{}, err
	}
	unlock, err := r.Storage.Lock(artifact)
	if err != nil {
		conditions.MarkFalse(obj, sourcev1.ArtifactAvailableCondition, sourcev1.StorageOperationFailedReason, "Failed to acquire lock: %s", err)
		return ctrl.Result{}, err
	}
	defer unlock()

	// Load ignore rules for archiving
	ps, err := sourceignore.LoadIgnorePatterns(dir, nil)
	if err != nil {
		conditions.MarkFalse(obj, sourcev1.ArtifactAvailableCondition, "SourceIgnoreError", "Failed to load source ignore patterns: %s", err)
		return ctrl.Result{}, err
	}
	if obj.Spec.Ignore != nil {
		ps = append(ps, sourceignore.ReadPatterns(strings.NewReader(*obj.Spec.Ignore), nil)...)
	}

	// Archive directory to storage
	if err := r.Storage.Archive(&artifact, dir, SourceIgnoreFilter(ps, nil)); err != nil {
		conditions.MarkFalse(obj, sourcev1.ArtifactAvailableCondition, sourcev1.StorageOperationFailedReason, "Unable to archive artifact to storage: %s", err)
		return ctrl.Result{}, err
	}

	// Record it on the object
	obj.Status.Artifact = artifact.DeepCopy()
	obj.Status.IncludedArtifacts = includes
	conditions.MarkTrue(obj, sourcev1.ArtifactAvailableCondition, "ArchivedArtifact", "Compressed source to artifact with revision %s", artifact.Revision)
	r.Events.EventWithMetaf(ctx, obj, map[string]string{
		"revision": obj.GetArtifact().Revision,
	}, events.EventSeverityInfo, sourcev1.GitOperationSucceedReason, conditions.Get(obj, sourcev1.ArtifactAvailableCondition).Message)

	// Update symlink on a "best effort" basis
	url, err := r.Storage.Symlink(artifact, "latest.tar.gz")
	if err != nil {
		r.Events.Eventf(ctx, obj, events.EventSeverityError, sourcev1.StorageOperationFailedReason, "Failed to update status URL symlink: %s", err)
	}
	if url != "" {
		obj.Status.URL = url
	}

	return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
}

// reconcileInclude reconciles the declared includes from the object
// by copying their artifact (sub)contents to the declared paths in the
// given directory.
// It returns early if an object can not be found, or does not have an
// artifact.
// If all includes can be found, an aggregation of all their Ready
// statuses is recorded in a condition on the given object.
func (r *GitRepositoryReconciler) reconcileInclude(ctx context.Context, obj *sourcev1.GitRepository, artifacts artifactSet, dir string) (ctrl.Result, error) {
	includes := make([]conditions.Getter, len(obj.Spec.Include))
	artifacts = make(artifactSet, len(obj.Spec.Include))

	for i, incl := range obj.Spec.Include {
		dep := &sourcev1.GitRepository{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: obj.Namespace, Name: incl.GitRepositoryRef.Name}, dep); err != nil {
			if apierrors.IsNotFound(err) {
				conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, "IncludeNotFound", "Could not find resource for include %q: %s", incl.GitRepositoryRef.Name, err.Error())
			}
			return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, client.IgnoreNotFound(err)
		}

		// Confirm include has an artifact
		if dep.GetArtifact() == nil {
			conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, "IncludeUnavailable", "No artifact available for include %q", incl.GitRepositoryRef.Name)
			return ctrl.Result{RequeueAfter: r.requeueDependency}, nil
		}

		includes[i] = dep.DeepCopy()

		// Copy artifact (sub)contents to configured directory
		toPath, err := securejoin.SecureJoin(dir, incl.GetToPath())
		if err != nil {
			conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, "IncludeFailure", "Failed to calculate path for include %q: %s", incl.GitRepositoryRef.Name, err.Error())
			return ctrl.Result{}, err
		}
		if err = r.Storage.CopyToPath(dep.GetArtifact(), incl.GetFromPath(), toPath); err != nil {
			conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, "IncludeCopyFailure", "Failed to copy %q include from %s to %s: %s", incl.GitRepositoryRef.Name, incl.GetFromPath(), incl.GetToPath(), err.Error())
			return ctrl.Result{}, err
		}

		artifacts[i] = dep.GetArtifact().DeepCopy()
	}

	// Record an aggregation of all includes Stalled or Ready state to
	// the object condition
	conditions.SetAggregate(obj, sourcev1.SourceAvailableCondition, includes,
		conditions.WithConditions(meta.StalledCondition, meta.ReadyCondition),
		conditions.WithNegativePolarityConditions(meta.StalledCondition),
		conditions.WithSourceRefIf(meta.StalledCondition),
		conditions.WithCounter(),
		conditions.WithCounterIfOnly(meta.ReadyCondition))

	return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
}

// reconcileDelete reconciles the delete of an object by garbage
// collecting all artifacts for the object in the artifact storage,
// if successful, the finalizer is removed from the object.
func (r *GitRepositoryReconciler) reconcileDelete(ctx context.Context, obj *sourcev1.GitRepository) (ctrl.Result, error) {
	// Garbage collect the resource's artifacts
	if err := r.garbageCollect(obj); err != nil {
		r.Events.Eventf(ctx, obj, events.EventSeverityError, "GarbageCollectionFailed", "Garbage collection for deleted resource failed: %s", err)
		// Return the error so we retry the failed garbage collection
		return ctrl.Result{}, err
	}

	// Remove our finalizer from the list
	controllerutil.RemoveFinalizer(obj, sourcev1.SourceFinalizer)

	// Stop reconciliation as the object is being deleted
	return ctrl.Result{}, nil
}

// verifyCommitSignature verifies the signature of the given commit if
// a verification mode is configured on the object.
func (r *GitRepositoryReconciler) verifyCommitSignature(ctx context.Context, obj *sourcev1.GitRepository, commit git.Commit) (ctrl.Result, error) {
	// Check if there is a commit verification is configured,
	// and remove old observation if there is none
	if obj.Spec.Verification == nil || obj.Spec.Verification.Mode == "" {
		conditions.Delete(obj, sourcev1.SourceVerifiedCondition)
		return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
	}

	// Get secret with GPG data
	publicKeySecret := types.NamespacedName{
		Namespace: obj.Namespace,
		Name:      obj.Spec.Verification.SecretRef.Name,
	}
	var secret corev1.Secret
	if err := r.Client.Get(ctx, publicKeySecret, &secret); err != nil {
		conditions.MarkFalse(obj, sourcev1.SourceVerifiedCondition, "FailedToGetSecret", "PGP public keys secret error: %s", err)
		return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, client.IgnoreNotFound(err)
	}

	// Verify commit with GPG data from secret
	if err := commit.Verify(secret); err != nil {
		conditions.MarkFalse(obj, sourcev1.SourceVerifiedCondition, "InvalidCommitSignature", "Commit signature verification failed: %s", err)
		// We will not be able to recover from this error but HEAD
		// may change in the future
		logr.FromContext(ctx).Error(err, "PGP commit verification failed")
		return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
	}
	conditions.MarkTrue(obj, sourcev1.SourceVerifiedCondition, "ValidCommitSignature", "Verified signature of commit %q", commit.Hash())

	return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
}

// garbageCollect performs a garbage collection for the given
// v1beta1.GitRepository. It removes all but the current artifact
// except for when the deletion timestamp is set, which will result
// in the removal of all artifacts for the resource.
func (r *GitRepositoryReconciler) garbageCollect(obj *sourcev1.GitRepository) error {
	if !obj.DeletionTimestamp.IsZero() {
		if err := r.Storage.RemoveAll(r.Storage.NewArtifactFor(obj.Kind, obj.GetObjectMeta(), "", "*")); err != nil {
			return err
		}
		obj.Status.Artifact = nil
		return nil
	}
	if obj.GetArtifact() != nil {
		return r.Storage.RemoveAllButCurrent(*obj.GetArtifact())
	}
	return nil
}
