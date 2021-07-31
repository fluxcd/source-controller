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
	"net/url"
	"os"
	"time"

	helmgetter "helm.sh/helm/v3/pkg/getter"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	kuberecorder "k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/conditions"
	helper "github.com/fluxcd/pkg/runtime/controller"
	"github.com/fluxcd/pkg/runtime/patch"
	"github.com/fluxcd/pkg/runtime/predicates"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
	"github.com/fluxcd/source-controller/internal/helm/getter"
	"github.com/fluxcd/source-controller/internal/helm/repository"
)

// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=helmrepositories,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=helmrepositories/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=helmrepositories/finalizers,verbs=get;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// HelmRepositoryReconciler reconciles a HelmRepository object
type HelmRepositoryReconciler struct {
	client.Client
	kuberecorder.EventRecorder
	helper.Metrics

	Getters helmgetter.Providers
	Storage *Storage
}

type HelmRepositoryReconcilerOptions struct {
	MaxConcurrentReconciles int
}

func (r *HelmRepositoryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return r.SetupWithManagerAndOptions(mgr, HelmRepositoryReconcilerOptions{})
}

func (r *HelmRepositoryReconciler) SetupWithManagerAndOptions(mgr ctrl.Manager, opts HelmRepositoryReconcilerOptions) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sourcev1.HelmRepository{}).
		WithEventFilter(predicate.Or(predicate.GenerationChangedPredicate{}, predicates.ReconcileRequestedPredicate{})).
		WithOptions(controller.Options{MaxConcurrentReconciles: opts.MaxConcurrentReconciles}).
		Complete(r)
}

func (r *HelmRepositoryReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, retErr error) {
	start := time.Now()
	log := ctrl.LoggerFrom(ctx)

	// Fetch the HelmRepository
	obj := &sourcev1.HelmRepository{}
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

		// Summarize Ready condition
		conditions.SetSummary(obj,
			meta.ReadyCondition,
			conditions.WithConditions(
				sourcev1.FetchFailedCondition,
				sourcev1.ArtifactOutdatedCondition,
				sourcev1.ArtifactUnavailableCondition,
			),
			conditions.WithNegativePolarityConditions(
				sourcev1.FetchFailedCondition,
				sourcev1.ArtifactOutdatedCondition,
				sourcev1.ArtifactUnavailableCondition,
			),
		)

		// Patch the object, ignoring conflicts on the conditions owned by this controller
		patchOpts := []patch.Option{
			patch.WithOwnedConditions{
				Conditions: []string{
					sourcev1.FetchFailedCondition,
					sourcev1.ArtifactOutdatedCondition,
					sourcev1.ArtifactUnavailableCondition,
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
				// As we are no longer reconciling and the end-state
				// is not ready, the reconciliation has stalled
				conditions.MarkStalled(obj, readyCondition.Reason, readyCondition.Message)
			case metav1.ConditionTrue:
				// As we are no longer reconciling and the end-state
				// is ready, the reconciliation is no longer stalled
				conditions.Delete(obj, meta.StalledCondition)
			}
		}

		// Finally, patch the resource
		if err := patchHelper.Patch(ctx, obj, patchOpts...); err != nil {
			// Ignore patch error "not found" when the object is being deleted.
			if !obj.ObjectMeta.DeletionTimestamp.IsZero() {
				err = kerrors.FilterOut(err, func(e error) bool { return apierrors.IsNotFound(e) })
			}
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
func (r *HelmRepositoryReconciler) reconcile(ctx context.Context, obj *sourcev1.HelmRepository) (ctrl.Result, error) {
	// Mark the resource as under reconciliation
	conditions.MarkReconciling(obj, meta.ProgressingReason, "")

	// Reconcile the storage data
	if result, err := r.reconcileStorage(ctx, obj); err != nil {
		return result, err
	}

	var chartRepo repository.ChartRepository
	var artifact sourcev1.Artifact
	// Reconcile the source from upstream
	if result, err := r.reconcileSource(ctx, obj, &artifact, &chartRepo); err != nil || result.IsZero() {
		return result, err
	}

	// Reconcile the artifact.
	if result, err := r.reconcileArtifact(ctx, obj, artifact, &chartRepo); err != nil || result.IsZero() {
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
func (r *HelmRepositoryReconciler) reconcileStorage(ctx context.Context, obj *sourcev1.HelmRepository) (ctrl.Result, error) {
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

// reconcileSource ensures the upstream Helm repository can be reached and downloaded out using the declared
// configuration, and stores a new artifact in the storage.
//
// The Helm repository index is downloaded using the defined configuration, and in case of an error during this process
// (including transient errors), it records v1beta1.FetchFailedCondition=True and returns early.
// On a successful write of a new artifact, the artifact in the status of the given object is set, and the symlink in
// the storage is updated to its path.
//
// The caller should assume a failure if an error is returned, or the Result is zero.
func (r *HelmRepositoryReconciler) reconcileSource(ctx context.Context, obj *sourcev1.HelmRepository, artifact *sourcev1.Artifact, chartRepo *repository.ChartRepository) (ctrl.Result, error) {
	// Configure Helm client to access repository
	clientOpts := []helmgetter.Option{
		helmgetter.WithTimeout(obj.Spec.Timeout.Duration),
		helmgetter.WithURL(obj.Spec.URL),
		helmgetter.WithPassCredentialsAll(obj.Spec.PassCredentials),
	}

	// Configure any authentication related options
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
			r.Eventf(obj, corev1.EventTypeWarning, sourcev1.AuthenticationFailedReason,
				"Failed to get secret '%s': %s", name.String(), err.Error())
			// Return error as the world as observed may change
			return ctrl.Result{}, err
		}

		// Get client options from secret
		tmpDir, err := os.MkdirTemp("", fmt.Sprintf("%s-%s-auth-", obj.Name, obj.Namespace))
		if err != nil {
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.StorageOperationFailedReason,
				"Failed to create temporary directory for credentials: %s", err.Error())
			r.Eventf(obj, corev1.EventTypeWarning, sourcev1.StorageOperationFailedReason,
				"Failed to create temporary directory for credentials: %s", err.Error())
			return ctrl.Result{}, err
		}
		defer os.RemoveAll(tmpDir)

		// Construct actual options
		opts, err := getter.ClientOptionsFromSecret(tmpDir, secret)
		if err != nil {
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason,
				"Failed to configure Helm client with secret data: %s", err)
			r.Eventf(obj, corev1.EventTypeWarning, sourcev1.AuthenticationFailedReason,
				"Failed to configure Helm client with secret data: %s", err)
			// Return err as the content of the secret may change
			return ctrl.Result{}, err
		}
		clientOpts = append(clientOpts, opts...)
	}

	// Construct Helm chart repository with options and download index
	newChartRepo, err := repository.NewChartRepository(obj.Spec.URL, "", r.Getters, clientOpts)
	if err != nil {
		switch err.(type) {
		case *url.Error:
			ctrl.LoggerFrom(ctx).Error(err, "invalid Helm repository URL")
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.URLInvalidReason,
				"Invalid Helm repository URL: %s", err.Error())
			return ctrl.Result{}, nil
		default:
			ctrl.LoggerFrom(ctx).Error(err, "failed to construct Helm client")
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, meta.FailedReason,
				"Failed to construct Helm client: %s", err.Error())
			return ctrl.Result{}, nil
		}
	}
	checksum, err := newChartRepo.CacheIndex()
	if err != nil {
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, meta.FailedReason,
			"Failed to download Helm repository index: %s", err.Error())
		r.Eventf(obj, corev1.EventTypeWarning, sourcev1.FetchFailedCondition,
			"Failed to download Helm repository index: %s", err.Error())
		// Coin flip on transient or persistent error, return error and hope for the best
		return ctrl.Result{}, err
	}
	*chartRepo = *newChartRepo

	// Load the cached repository index to ensure it passes validation.
	if err := chartRepo.LoadFromCache(); err != nil {
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.IndexationFailedReason,
			"Failed to load Helm repository from cache: %s", err.Error())
		r.Eventf(obj, corev1.EventTypeWarning, sourcev1.FetchFailedCondition,
			"Failed to load Helm repository from cache: %s", err.Error())
		return ctrl.Result{}, err
	}
	defer chartRepo.Unload()

	// Mark observations about the revision on the object.
	if !obj.GetArtifact().HasRevision(checksum) {
		conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "NewRevision",
			"New index revision '%s'", checksum)
	}

	conditions.Delete(obj, sourcev1.FetchFailedCondition)

	// Create potential new artifact.
	*artifact = r.Storage.NewArtifactFor(obj.Kind,
		obj.ObjectMeta.GetObjectMeta(),
		chartRepo.Checksum,
		fmt.Sprintf("index-%s.yaml", checksum))

	return ctrl.Result{RequeueAfter: obj.GetRequeueAfter()}, nil
}

func (r *HelmRepositoryReconciler) reconcileArtifact(ctx context.Context, obj *sourcev1.HelmRepository, artifact sourcev1.Artifact, chartRepo *repository.ChartRepository) (ctrl.Result, error) {
	// Always restore the Ready condition in case it got removed due to a transient error.
	defer func() {
		if obj.GetArtifact() != nil {
			conditions.Delete(obj, sourcev1.ArtifactUnavailableCondition)
		}
		if obj.GetArtifact().HasRevision(artifact.Revision) {
			conditions.Delete(obj, sourcev1.ArtifactOutdatedCondition)
			conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason,
				"Stored artifact for revision '%s'", artifact.Revision)
		}
	}()

	if obj.GetArtifact().HasRevision(artifact.Revision) {
		ctrl.LoggerFrom(ctx).Info(fmt.Sprintf("Already up to date, current revision '%s'", artifact.Revision))
		return ctrl.Result{RequeueAfter: obj.GetRequeueAfter()}, nil
	}

	// Clear cache at the very end.
	defer chartRepo.RemoveCache()

	// Create artifact dir.
	if err := r.Storage.MkdirAll(artifact); err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "failed to create artifact directory")
		return ctrl.Result{}, err
	}

	// Acquire lock.
	unlock, err := r.Storage.Lock(artifact)
	if err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "failed to acquire lock for artifact")
		return ctrl.Result{}, err
	}
	defer unlock()

	// Save artifact to storage.
	if err = r.Storage.CopyFromPath(&artifact, chartRepo.CachePath); err != nil {
		r.Eventf(obj, corev1.EventTypeWarning, sourcev1.StorageOperationFailedReason,
			"Unable to save artifact to storage: %s", err)
		return ctrl.Result{}, err
	}

	// Record it on the object.
	obj.Status.Artifact = artifact.DeepCopy()

	// Update index symlink.
	indexURL, err := r.Storage.Symlink(artifact, "index.yaml")
	if err != nil {
		r.Eventf(obj, corev1.EventTypeWarning, sourcev1.StorageOperationFailedReason,
			"Failed to update status URL symlink: %s", err)
	}

	if indexURL != "" {
		obj.Status.URL = indexURL
	}
	return ctrl.Result{RequeueAfter: obj.GetRequeueAfter()}, nil
}

// reconcileDelete handles the delete of an object. It first garbage collects all artifacts for the object from the
// artifact storage, if successful, the finalizer is removed from the object.
func (r *HelmRepositoryReconciler) reconcileDelete(ctx context.Context, obj *sourcev1.HelmRepository) (ctrl.Result, error) {
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

// garbageCollect performs a garbage collection for the given v1beta1.HelmRepository. It removes all but the current
// artifact except for when the deletion timestamp is set, which will result in the removal of all artifacts for the
// resource.
func (r *HelmRepositoryReconciler) garbageCollect(ctx context.Context, obj *sourcev1.HelmRepository) error {
	if !obj.DeletionTimestamp.IsZero() {
		if err := r.Storage.RemoveAll(r.Storage.NewArtifactFor(obj.Kind, obj.GetObjectMeta(), "", "*")); err != nil {
			r.Eventf(obj, corev1.EventTypeWarning, "GarbageCollectionFailed",
				"Garbage collection for deleted resource failed: %s", err)
			return err
		}
		obj.Status.Artifact = nil
		// TODO(hidde): we should only push this event if we actually garbage collected something
		r.Eventf(obj, corev1.EventTypeNormal, "GarbageCollectionSucceeded",
			"Garbage collected artifacts for deleted resource")
		return nil
	}
	if obj.GetArtifact() != nil {
		if err := r.Storage.RemoveAllButCurrent(*obj.GetArtifact()); err != nil {
			r.Eventf(obj, corev1.EventTypeWarning, "GarbageCollectionFailed",
				"Garbage collection of old artifacts failed: %s", err)
			return err
		}
		// TODO(hidde): we should only push this event if we actually garbage collected something
		r.Eventf(obj, corev1.EventTypeNormal, "GarbageCollectionSucceeded",
			"Garbage collected old artifacts")
	}
	return nil
}
