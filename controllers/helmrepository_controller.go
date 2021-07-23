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
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"time"

	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/patch"
	"github.com/go-logr/logr"
	"helm.sh/helm/v3/pkg/getter"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/yaml"

	"github.com/fluxcd/pkg/apis/meta"
	helper "github.com/fluxcd/pkg/runtime/controller"
	"github.com/fluxcd/pkg/runtime/events"
	"github.com/fluxcd/pkg/runtime/predicates"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	"github.com/fluxcd/source-controller/internal/helm"
)

// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=helmrepositories,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=helmrepositories/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=helmrepositories/finalizers,verbs=get;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// HelmRepositoryReconciler reconciles a HelmRepository object
type HelmRepositoryReconciler struct {
	client.Client
	helper.Events
	helper.Metrics

	Getters getter.Providers
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
	log := logr.FromContext(ctx)

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
				sourcev1.SourceAvailableCondition,
			),
		)

		// Patch the object, ignoring conflicts on the conditions owned by
		// this controller
		patchOpts := []patch.Option{
			patch.WithOwnedConditions{
				Conditions: []string{
					sourcev1.ArtifactAvailableCondition,
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

func (r *HelmRepositoryReconciler) reconcile(ctx context.Context, obj *sourcev1.HelmRepository) (ctrl.Result, error) {
	// Mark the resource as under reconciliation
	conditions.MarkTrue(obj, meta.ReconcilingCondition, "Reconciling", "")

	// Reconcile the storage data
	if result, err := r.reconcileStorage(ctx, obj); err != nil {
		return result, err
	}

	// Reconcile the source from upstream
	var index helm.ChartRepository
	var artifact sourcev1.Artifact
	if result, err := r.reconcileSource(ctx, obj, &artifact, &index); err != nil || conditions.IsFalse(obj, sourcev1.SourceAvailableCondition) {
		return result, err
	}

	// Reconcile the artifact to storage
	if result, err := r.reconcileArtifact(ctx, obj, artifact, index); err != nil {
		return result, err
	}

	return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
}

// reconcileStorage reconciles the storage data for the given object
// by observing if the artifact in the status still exists, and
// ensuring the URLs are up-to-date with the current hostname
// configuration.
func (r *HelmRepositoryReconciler) reconcileStorage(ctx context.Context, obj *sourcev1.HelmRepository) (ctrl.Result, error) {
	// Purge old artifacts from the storage
	if err := r.garbageCollect(obj); err != nil {
		r.Events.Eventf(ctx, obj, events.EventSeverityError, "GarbageCollectionFailed", "Garbage collection failed: %s", err)
	}

	// Determine if the artifact is still in storage
	if artifact := obj.GetArtifact(); artifact != nil && !r.Storage.ArtifactExist(*artifact) {
		obj.Status.Artifact = nil
		obj.Status.URL = ""
	}

	// Record that we have no artifact
	if obj.GetArtifact() == nil {
		conditions.MarkFalse(obj, sourcev1.ArtifactAvailableCondition, "NoArtifactFound", "No artifact for resource in storage")
		return ctrl.Result{Requeue: true}, nil
	}

	// Always update URLs to ensure hostname is up-to-date
	r.Storage.SetArtifactURL(obj.GetArtifact())
	obj.Status.URL = r.Storage.SetHostname(obj.Status.URL)

	return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
}

// reconcileSource reconciles the Helm repository index from upstream
// to the
// given directory path while using the information on the object to
// determine authentication and checkout strategies.
// On a successful checkout of HEAD the artifact metadata the given
// pointer is set to a new artifact.
func (r *HelmRepositoryReconciler) reconcileSource(ctx context.Context, obj *sourcev1.HelmRepository, artifact *sourcev1.Artifact, index *helm.ChartRepository) (ctrl.Result, error) {
	// Configure Helm client to access repository
	clientOpts := []getter.Option{
		getter.WithTimeout(obj.Spec.Timeout.Duration),
		getter.WithURL(obj.Spec.URL),
		getter.WithPassCredentialsAll(obj.Spec.PassCredentials),
	}
	if obj.Spec.SecretRef != nil {
		// Attempt to retrieve secret
		name := types.NamespacedName{
			Namespace: obj.GetNamespace(),
			Name:      obj.Spec.SecretRef.Name,
		}
		var secret corev1.Secret
		if err := r.Client.Get(ctx, name, &secret); err != nil {
			conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.AuthenticationFailedReason, "Failed to get secret %s: %s", name.String(), err.Error())
			r.Events.Event(ctx, obj, events.EventSeverityError, sourcev1.AuthenticationFailedReason, conditions.Get(obj, sourcev1.SourceAvailableCondition).Message)
			// Return transient errors but wait for next interval on not found
			return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, client.IgnoreNotFound(err)
		}

		// Get client options from secret
		tmpDir, err := ioutil.TempDir("", fmt.Sprintf("%s-%s-source-", obj.Name, obj.Namespace))
		if err != nil {
			conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.StorageOperationFailedReason, "Could not create temporary directory for credentials: %s", err.Error())
			r.Events.Event(ctx, obj, events.EventSeverityError, sourcev1.AuthenticationFailedReason, conditions.Get(obj, sourcev1.SourceAvailableCondition).Message)
			return ctrl.Result{}, err
		}
		defer os.RemoveAll(tmpDir)
		opts, err := helm.ClientOptionsFromSecret(secret, tmpDir)
		if err != nil {
			conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.AuthenticationFailedReason, "Failed to configure Helm client with secret data: %s", err)
			r.Events.Event(ctx, obj, events.EventSeverityError, sourcev1.AuthenticationFailedReason, conditions.Get(obj, sourcev1.SourceAvailableCondition).Message)
			// Return err as the content of the secret may change
			return ctrl.Result{}, err
		}
		clientOpts = append(clientOpts, opts...)
	}

	// Construct Helm chart repository with options and download index
	newIndex, err := helm.NewChartRepository(obj.Spec.URL, r.Getters, clientOpts)
	if err != nil {
		switch err.(type) {
		case *url.Error:
			conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.URLInvalidReason, "Invalid Helm repository URL: %s", err.Error())
			return ctrl.Result{}, nil
		default:
			conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.URLInvalidReason, "Failed to construct Helm client: %s", err.Error())
			return ctrl.Result{}, nil
		}
	}
	if err := newIndex.DownloadIndex(); err != nil {
		conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.URLInvalidReason, "Failed to download Helm repository index: %s", err.Error())
		return ctrl.Result{}, err
	}

	*index = *newIndex

	// Create potential new artifact
	*artifact = r.Storage.NewArtifactFor(obj.Kind,
		obj.ObjectMeta.GetObjectMeta(),
		index.Checksum,
		fmt.Sprintf("index-%s.yaml", index.Checksum))
	conditions.MarkTrue(obj, sourcev1.SourceAvailableCondition, sourcev1.IndexationSucceededReason, "Downloaded index revision %s from %s", artifact.Revision, obj.Spec.URL)

	return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
}

// reconcileArtifact reconciles the Helm repository index to the artifact
// storage.
// On a successful archive, the artifact and includes in the status of
// the given object are set, and the symlink in the storage is updated
// to its path.
func (r *HelmRepositoryReconciler) reconcileArtifact(ctx context.Context, obj *sourcev1.HelmRepository, artifact sourcev1.Artifact, index helm.ChartRepository) (ctrl.Result, error) {
	// The artifact is up-to-date
	if obj.GetArtifact().HasRevision(artifact.Revision) {
		logr.FromContext(ctx).Info("Artifact is up-to-date")
		conditions.MarkTrue(obj, sourcev1.ArtifactAvailableCondition, "ArchivedArtifact", "Compressed source to artifact with revision %s", artifact.Revision)
		return ctrl.Result{RequeueAfter: obj.GetInterval().Duration}, nil
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

	// Save artifact to storage
	b, err := yaml.Marshal(index.Index)
	if err != nil {
		return ctrl.Result{}, err
	}
	if err := r.Storage.AtomicWriteFile(&artifact, bytes.NewReader(b), 0644); err != nil {
		conditions.MarkFalse(obj, sourcev1.ArtifactAvailableCondition, sourcev1.StorageOperationFailedReason, "Failed to write Helm repository index to storage: %s", err.Error())
		return ctrl.Result{}, err
	}

	// Record it on the object
	obj.Status.Artifact = artifact.DeepCopy()
	conditions.MarkTrue(obj, sourcev1.ArtifactAvailableCondition, sourcev1.IndexationSucceededReason, "Artifact revision %s", artifact.Revision)
	r.Events.EventWithMetaf(ctx, obj, map[string]string{
		"revision": obj.GetArtifact().Revision,
	}, events.EventSeverityInfo, sourcev1.GitOperationSucceedReason, conditions.Get(obj, sourcev1.ArtifactAvailableCondition).Message)

	// Update symlink on a "best effort" basis
	url, err := r.Storage.Symlink(artifact, "index.yaml")
	if err != nil {
		r.Events.Eventf(ctx, obj, events.EventSeverityError, sourcev1.StorageOperationFailedReason, "Failed to update status URL symlink: %s", err)
	}
	if url != "" {
		obj.Status.URL = url
	}

	return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
}

// reconcileDelete reconciles the delete of an object by garbage
// collecting all artifacts for the object in the artifact storage,
// if successful, the finalizer is removed from the object.
func (r *HelmRepositoryReconciler) reconcileDelete(ctx context.Context, obj *sourcev1.HelmRepository) (ctrl.Result, error) {
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

// garbageCollect performs a garbage collection for the given v1beta1.HelmRepository.
// It removes all but the current artifact except for when the
// deletion timestamp is set, which will result in the removal of
// all artifacts for the resource.
func (r *HelmRepositoryReconciler) garbageCollect(obj *sourcev1.HelmRepository) error {
	if !obj.DeletionTimestamp.IsZero() {
		return r.Storage.RemoveAll(r.Storage.NewArtifactFor(obj.Kind, obj.GetObjectMeta(), "", "*"))
	}
	if obj.GetArtifact() != nil {
		return r.Storage.RemoveAllButCurrent(*obj.GetArtifact())
	}
	return nil
}
