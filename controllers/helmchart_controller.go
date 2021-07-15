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
	"regexp"
	"time"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/conditions"
	helper "github.com/fluxcd/pkg/runtime/controller"
	"github.com/fluxcd/pkg/runtime/events"
	"github.com/fluxcd/pkg/runtime/patch"
	"github.com/fluxcd/pkg/runtime/predicates"
	"github.com/go-logr/logr"
	"helm.sh/helm/v3/pkg/getter"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	"github.com/fluxcd/source-controller/internal/helm"
	"github.com/fluxcd/source-controller/internal/util"
)

// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=helmcharts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=helmcharts/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=helmcharts/finalizers,verbs=get;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// HelmChartReconciler reconciles a HelmChart object
type HelmChartReconciler struct {
	client.Client
	helper.Events
	helper.Metrics

	Getters getter.Providers
	Storage *Storage
}

type HelmChartReconcilerOptions struct {
	MaxConcurrentReconciles int
}

type unsupportedSourceKindError struct {
	Kind      string
	Supported []string
}

func (e unsupportedSourceKindError) Error() string {
	return fmt.Sprintf("unsupported source kind %q, must be one of: %v", e.Kind, e.Supported)
}

func (r *HelmChartReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return r.SetupWithManagerAndOptions(mgr, HelmChartReconcilerOptions{})
}

func (r *HelmChartReconciler) SetupWithManagerAndOptions(mgr ctrl.Manager, opts HelmChartReconcilerOptions) error {
	if err := mgr.GetCache().IndexField(context.TODO(), &sourcev1.HelmRepository{}, sourcev1.HelmRepositoryURLIndexKey,
		r.indexHelmRepositoryByURL); err != nil {
		return fmt.Errorf("failed setting index fields: %w", err)
	}
	if err := mgr.GetCache().IndexField(context.TODO(), &sourcev1.HelmChart{}, sourcev1.SourceIndexKey,
		r.indexHelmChartBySource); err != nil {
		return fmt.Errorf("failed setting index fields: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&sourcev1.HelmChart{}, builder.WithPredicates(
			predicate.Or(predicate.GenerationChangedPredicate{}, predicates.ReconcileRequestedPredicate{}),
		)).
		Watches(
			&source.Kind{Type: &sourcev1.HelmRepository{}},
			handler.EnqueueRequestsFromMapFunc(r.requestsForHelmRepositoryChange),
			builder.WithPredicates(SourceRevisionChangePredicate{}),
		).
		Watches(
			&source.Kind{Type: &sourcev1.GitRepository{}},
			handler.EnqueueRequestsFromMapFunc(r.requestsForGitRepositoryChange),
			builder.WithPredicates(SourceRevisionChangePredicate{}),
		).
		Watches(
			&source.Kind{Type: &sourcev1.Bucket{}},
			handler.EnqueueRequestsFromMapFunc(r.requestsForBucketChange),
			builder.WithPredicates(SourceRevisionChangePredicate{}),
		).
		WithOptions(controller.Options{MaxConcurrentReconciles: opts.MaxConcurrentReconciles}).
		Complete(r)
}

func (r *HelmChartReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, retErr error) {
	start := time.Now()
	log := logr.FromContext(ctx)

	// Fetch the HelmChart
	obj := &sourcev1.HelmChart{}
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
				sourcev1.ChartReconciled,
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
					sourcev1.ValuesFilesMergedCondition,
					sourcev1.DependenciesBuildCondition,
					sourcev1.ChartPackagedCondition,
					sourcev1.ChartReconciled,
					meta.ReadyCondition,
					meta.ReconcilingCondition,
					meta.ProgressingReason,
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

func (r *HelmChartReconciler) reconcile(ctx context.Context, obj *sourcev1.HelmChart) (ctrl.Result, error) {
	// Mark the resource as under reconciliation
	conditions.MarkTrue(obj, meta.ReconcilingCondition, "Reconciling", "")

	// Reconcile the storage data
	if result, err := r.reconcileStorage(ctx, obj); err != nil {
		return result, err
	}

	// Reconcile the source
	var sourcePath string
	defer func() {
		os.RemoveAll(sourcePath)
	}()
	if result, err := r.reconcileSource(ctx, obj, &sourcePath); err != nil || conditions.IsFalse(obj, sourcev1.SourceAvailableCondition) {
		return result, err
	}

	// Reconcile the chart using the source data
	var artifact sourcev1.Artifact
	var resultPath string
	defer func() {
		os.RemoveAll(resultPath)
	}()
	if result, err := r.reconcileChart(ctx, obj, sourcePath, &artifact, &resultPath); err != nil {
		return result, err
	}

	// Reconcile artifact to storage
	return r.reconcileArtifact(ctx, obj, artifact, resultPath)
}

// reconcileStorage reconciles the storage data for the given object
// by garbage collecting previous advertised artifact(s) from storage,
// observing if the artifact in the status still exists, and
// ensuring the URLs are up-to-date with the current hostname
// configuration.
func (r *HelmChartReconciler) reconcileStorage(ctx context.Context, obj *sourcev1.HelmChart) (ctrl.Result, error) {
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

func (r *HelmChartReconciler) reconcileArtifact(ctx context.Context, obj *sourcev1.HelmChart, artifact sourcev1.Artifact, path string) (ctrl.Result, error) {
	// Ensure artifact directory exists and acquire lock
	if err := r.Storage.MkdirAll(artifact); err != nil {
		conditions.MarkFalse(obj, sourcev1.ArtifactAvailableCondition, sourcev1.StorageOperationFailedReason, "Failed to create directory: %s", err.Error())
		return ctrl.Result{}, err
	}
	unlock, err := r.Storage.Lock(artifact)
	if err != nil {
		conditions.MarkFalse(obj, sourcev1.ArtifactAvailableCondition, sourcev1.StorageOperationFailedReason, "Failed to acquire lock: %s", err.Error())
		return ctrl.Result{}, err
	}
	defer unlock()

	// Copy the packaged chart to the artifact path
	if err := r.Storage.CopyFromPath(&artifact, path); err != nil {
		conditions.MarkFalse(obj, sourcev1.ArtifactAvailableCondition, sourcev1.StorageOperationFailedReason, "Unable to write chart to storage: %s", err.Error())
		return ctrl.Result{}, err
	}

	// Record it on the object
	obj.Status.Artifact = artifact.DeepCopy()
	conditions.MarkTrue(obj, sourcev1.ArtifactAvailableCondition, sourcev1.ChartPackageSucceededReason, "Artifact revision %s", artifact.Revision)
	r.Events.EventWithMetaf(ctx, obj, map[string]string{
		"revision": obj.GetArtifact().Revision,
	}, events.EventSeverityInfo, sourcev1.ChartPackageSucceededReason, conditions.Get(obj, sourcev1.ArtifactAvailableCondition).Message)

	// Update symlink on a "best effort" basis
	u, err := r.Storage.Symlink(artifact, "latest.tar.gz")
	if err != nil {
		r.Events.Eventf(ctx, obj, events.EventSeverityError, sourcev1.StorageOperationFailedReason, "Failed to update status URL symlink: %s", err)
	}
	if u != "" {
		obj.Status.URL = u
	}

	return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
}

func (r *HelmChartReconciler) reconcileDelete(ctx context.Context, obj *sourcev1.HelmChart) (ctrl.Result, error) {
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

// garbageCollect performs a garbage collection for the given
// v1beta1.HelmChart. It removes all but the current artifact except
// for when the deletion timestamp is set, which will result in the
// removal of all artifacts for the resource.
func (r *HelmChartReconciler) garbageCollect(chart *sourcev1.HelmChart) error {
	if !chart.DeletionTimestamp.IsZero() {
		return r.Storage.RemoveAll(r.Storage.NewArtifactFor(chart.Kind, chart.GetObjectMeta(), "", "*"))
	}
	if chart.GetArtifact() != nil {
		return r.Storage.RemoveAllButCurrent(*chart.GetArtifact())
	}
	return nil
}

func (r *HelmChartReconciler) indexHelmRepositoryByURL(o client.Object) []string {
	repo, ok := o.(*sourcev1.HelmRepository)
	if !ok {
		panic(fmt.Sprintf("Expected a HelmRepository, got %T", o))
	}
	u := helm.NormalizeChartRepositoryURL(repo.Spec.URL)
	if u != "" {
		return []string{u}
	}
	return nil
}

func (r *HelmChartReconciler) indexHelmChartBySource(o client.Object) []string {
	hc, ok := o.(*sourcev1.HelmChart)
	if !ok {
		panic(fmt.Sprintf("Expected a HelmChart, got %T", o))
	}
	return []string{fmt.Sprintf("%s/%s", hc.Spec.SourceRef.Kind, hc.Spec.SourceRef.Name)}
}

func (r *HelmChartReconciler) requestsForHelmRepositoryChange(o client.Object) []reconcile.Request {
	repo, ok := o.(*sourcev1.HelmRepository)
	if !ok {
		panic(fmt.Sprintf("Expected a HelmRepository, got %T", o))
	}
	// If we do not have an artifact, we have no requests to make
	if repo.GetArtifact() == nil {
		return nil
	}

	ctx := context.Background()
	var list sourcev1.HelmChartList
	if err := r.List(ctx, &list, client.MatchingFields{
		sourcev1.SourceIndexKey: fmt.Sprintf("%s/%s", sourcev1.HelmRepositoryKind, repo.Name),
	}); err != nil {
		return nil
	}

	// TODO(hidde): unlike other places (e.g. the helm-controller),
	//  we have no reference here to determine if the request is coming
	//  from the _old_ or _new_ update event, and resources are thus
	//  enqueued twice.
	var reqs []reconcile.Request
	for _, i := range list.Items {
		reqs = append(reqs, reconcile.Request{NamespacedName: util.ObjectKey(&i)})
	}
	return reqs
}

func (r *HelmChartReconciler) requestsForGitRepositoryChange(o client.Object) []reconcile.Request {
	repo, ok := o.(*sourcev1.GitRepository)
	if !ok {
		panic(fmt.Sprintf("Expected a GitRepository, got %T", o))
	}

	// If we do not have an artifact, we have no requests to make
	if repo.GetArtifact() == nil {
		return nil
	}

	var list sourcev1.HelmChartList
	if err := r.List(context.TODO(), &list, client.MatchingFields{
		sourcev1.SourceIndexKey: fmt.Sprintf("%s/%s", sourcev1.GitRepositoryKind, repo.Name),
	}); err != nil {
		return nil
	}

	// TODO(hidde): unlike other places (e.g. the helm-controller),
	//  we have no reference here to determine if the request is coming
	//  from the _old_ or _new_ update event, and resources are thus
	//  enqueued twice.
	var reqs []reconcile.Request
	for _, i := range list.Items {
		reqs = append(reqs, reconcile.Request{NamespacedName: util.ObjectKey(&i)})
	}
	return reqs
}

func (r *HelmChartReconciler) requestsForBucketChange(o client.Object) []reconcile.Request {
	bucket, ok := o.(*sourcev1.Bucket)
	if !ok {
		panic(fmt.Sprintf("Expected a Bucket, got %T", o))
	}

	// If we do not have an artifact, we have no requests to make
	if bucket.GetArtifact() == nil {
		return nil
	}

	var list sourcev1.HelmChartList
	if err := r.List(context.TODO(), &list, client.MatchingFields{
		sourcev1.SourceIndexKey: fmt.Sprintf("%s/%s", sourcev1.BucketKind, bucket.Name),
	}); err != nil {
		return nil
	}

	// TODO(hidde): unlike other places (e.g. the helm-controller),
	//  we have no reference here to determine if the request is coming
	//  from the _old_ or _new_ update event, and resources are thus
	//  enqueued twice.
	var reqs []reconcile.Request
	for _, i := range list.Items {
		reqs = append(reqs, reconcile.Request{NamespacedName: util.ObjectKey(&i)})
	}
	return reqs
}

// validHelmChartName returns an error if the given string is not a
// valid Helm chart name; a valid name must be lower case letters
// and numbers, words may be separated with dashes (-).
// Ref: https://helm.sh/docs/chart_best_practices/conventions/#chart-names
func validHelmChartName(s string) error {
	chartFmt := regexp.MustCompile("^([-a-z0-9]*)$")
	if !chartFmt.MatchString(s) {
		return fmt.Errorf("invalid chart name %q, a valid name must be lower case letters and numbers and MAY be separated with dashes (-)", s)
	}
	return nil
}
