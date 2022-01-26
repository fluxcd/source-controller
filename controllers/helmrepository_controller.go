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
	"net/url"
	"os"
	"time"

	helmgetter "helm.sh/helm/v3/pkg/getter"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
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
	"github.com/fluxcd/pkg/runtime/events"
	"github.com/fluxcd/pkg/runtime/patch"
	"github.com/fluxcd/pkg/runtime/predicates"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
	serror "github.com/fluxcd/source-controller/internal/error"
	"github.com/fluxcd/source-controller/internal/helm/getter"
	"github.com/fluxcd/source-controller/internal/helm/repository"
	sreconcile "github.com/fluxcd/source-controller/internal/reconcile"
)

// Status conditions owned by HelmRepository reconciler.
var helmRepoOwnedConditions = []string{
	sourcev1.FetchFailedCondition,
	sourcev1.ArtifactOutdatedCondition,
	meta.ReadyCondition,
	meta.ReconcilingCondition,
	meta.StalledCondition,
}

// Conditions that Ready condition is influenced by in descending order of their
// priority.
var helmRepoReadyDeps = []string{
	sourcev1.FetchFailedCondition,
	sourcev1.ArtifactOutdatedCondition,
	meta.StalledCondition,
	meta.ReconcilingCondition,
}

// Negative conditions that Ready condition is influenced by.
var helmRepoReadyDepsNegative = []string{
	sourcev1.FetchFailedCondition,
	sourcev1.ArtifactOutdatedCondition,
	meta.StalledCondition,
	meta.ReconcilingCondition,
}

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

// helmRepoReconcilerFunc is the function type for all the helm repository
// reconciler functions. The reconciler functions are grouped together and
// executed serially to perform the main operation of the reconciler.
type helmRepoReconcilerFunc func(ctx context.Context, obj *sourcev1.HelmRepository, artifact *sourcev1.Artifact, repo *repository.ChartRepository) (sreconcile.Result, error)

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
		log.Info("reconciliation is suspended for this object")
		return ctrl.Result{}, nil
	}

	// Initialize the patch helper
	patchHelper, err := patch.NewHelper(obj, r.Client)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Result of the sub-reconciliation.
	var recResult sreconcile.Result

	// Always attempt to patch the object after each reconciliation.
	// NOTE: This deferred block only modifies the named return error. The
	// result from the reconciliation remains the same. Any requeue attributes
	// set in the result will continue to be effective.
	defer func() {
		retErr = r.summarizeAndPatch(ctx, obj, patchHelper, recResult, retErr)

		// Always record readiness and duration metrics
		r.Metrics.RecordReadiness(ctx, obj)
		r.Metrics.RecordDuration(ctx, obj, start)
	}()

	// Add finalizer first if not exist to avoid the race condition
	// between init and delete
	if !controllerutil.ContainsFinalizer(obj, sourcev1.SourceFinalizer) {
		controllerutil.AddFinalizer(obj, sourcev1.SourceFinalizer)
		recResult = sreconcile.ResultRequeue
		return ctrl.Result{Requeue: true}, nil
	}

	// Examine if the object is under deletion
	if !obj.ObjectMeta.DeletionTimestamp.IsZero() {
		res, err := r.reconcileDelete(ctx, obj)
		return sreconcile.BuildRuntimeResult(ctx, r.EventRecorder, obj, res, err)
	}

	// Reconcile actual object
	reconcilers := []helmRepoReconcilerFunc{
		r.reconcileStorage,
		r.reconcileSource,
		r.reconcileArtifact,
	}
	recResult, err = r.reconcile(ctx, obj, reconcilers)
	return sreconcile.BuildRuntimeResult(ctx, r.EventRecorder, obj, recResult, err)
}

// summarizeAndPatch analyzes the object conditions to create a summary of the
// status conditions and patches the object with the calculated summary. The
// reconciler error type is also used to determine the conditions and the
// returned error.
func (r *HelmRepositoryReconciler) summarizeAndPatch(ctx context.Context, obj *sourcev1.HelmRepository, patchHelper *patch.Helper, res sreconcile.Result, recErr error) error {
	// Record the value of the reconciliation request, if any.
	if v, ok := meta.ReconcileAnnotationValue(obj.GetAnnotations()); ok {
		obj.Status.SetLastHandledReconcileRequest(v)
	}

	// Compute the reconcile results, obtain patch options and reconcile error.
	var patchOpts []patch.Option
	patchOpts, recErr = sreconcile.ComputeReconcileResult(obj, res, recErr, helmRepoOwnedConditions)

	// Summarize Ready condition.
	conditions.SetSummary(obj,
		meta.ReadyCondition,
		conditions.WithConditions(
			helmRepoReadyDeps...,
		),
		conditions.WithNegativePolarityConditions(
			helmRepoReadyDepsNegative...,
		),
	)

	// Finally, patch the resource.
	if err := patchHelper.Patch(ctx, obj, patchOpts...); err != nil {
		// Ignore patch error "not found" when the object is being deleted.
		if !obj.ObjectMeta.DeletionTimestamp.IsZero() {
			err = kerrors.FilterOut(err, func(e error) bool { return apierrors.IsNotFound(e) })
		}
		recErr = kerrors.NewAggregate([]error{recErr, err})
	}

	return recErr
}

// reconcile iterates through the sub-reconcilers and processes the source
// object. The sub-reconcilers are run sequentially. The result and error  of
// the sub-reconciliation are collected and returned. For multiple results
// from different sub-reconcilers, the results are combined to return the
// result with the shortest requeue period.
func (r *HelmRepositoryReconciler) reconcile(ctx context.Context, obj *sourcev1.HelmRepository, reconcilers []helmRepoReconcilerFunc) (sreconcile.Result, error) {
	if obj.Generation != obj.Status.ObservedGeneration {
		conditions.MarkReconciling(obj, "NewGeneration", "reconciling new generation %d", obj.Generation)
	}

	var chartRepo repository.ChartRepository
	var artifact sourcev1.Artifact

	// Run the sub-reconcilers and build the result of reconciliation.
	var res sreconcile.Result
	var resErr error
	for _, rec := range reconcilers {
		recResult, err := rec(ctx, obj, &artifact, &chartRepo)
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
		// Prioritize requeue request in the result for successful results.
		res = sreconcile.LowestRequeuingResult(res, recResult)
	}
	return res, resErr
}

// reconcileStorage ensures the current state of the storage matches the desired and previously observed state.
//
// All artifacts for the resource except for the current one are garbage collected from the storage.
// If the artifact in the Status object of the resource disappeared from storage, it is removed from the object.
// If the hostname of the URLs on the object do not match the current storage server hostname, they are updated.
func (r *HelmRepositoryReconciler) reconcileStorage(ctx context.Context, obj *sourcev1.HelmRepository, artifact *sourcev1.Artifact, chartRepo *repository.ChartRepository) (sreconcile.Result, error) {
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

// reconcileSource ensures the upstream Helm repository can be reached and downloaded out using the declared
// configuration, and stores a new artifact in the storage.
//
// The Helm repository index is downloaded using the defined configuration, and in case of an error during this process
// (including transient errors), it records v1beta1.FetchFailedCondition=True and returns early.
// If the download is successful, the given artifact pointer is set to a new artifact with the available metadata, and
// the index pointer is set to the newly downloaded index.
func (r *HelmRepositoryReconciler) reconcileSource(ctx context.Context, obj *sourcev1.HelmRepository, artifact *sourcev1.Artifact, chartRepo *repository.ChartRepository) (sreconcile.Result, error) {
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
			e := &serror.Event{
				Err:    fmt.Errorf("failed to get secret '%s': %w", name.String(), err),
				Reason: sourcev1.AuthenticationFailedReason,
			}
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, e.Err.Error())
			return sreconcile.ResultEmpty, e
		}

		// Get client options from secret
		tmpDir, err := os.MkdirTemp("", fmt.Sprintf("%s-%s-auth-", obj.Name, obj.Namespace))
		if err != nil {
			return sreconcile.ResultEmpty, &serror.Event{
				Err:    fmt.Errorf("failed to create temporary directory for credentials: %w", err),
				Reason: sourcev1.StorageOperationFailedReason,
			}
		}
		defer os.RemoveAll(tmpDir)

		// Construct actual options
		opts, err := getter.ClientOptionsFromSecret(tmpDir, secret)
		if err != nil {
			e := &serror.Event{
				Err:    fmt.Errorf("failed to configure Helm client with secret data: %w", err),
				Reason: sourcev1.AuthenticationFailedReason,
			}
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, e.Err.Error())
			// Return err as the content of the secret may change.
			return sreconcile.ResultEmpty, e
		}
		clientOpts = append(clientOpts, opts...)
	}

	// Construct Helm chart repository with options and download index
	newChartRepo, err := repository.NewChartRepository(obj.Spec.URL, "", r.Getters, clientOpts)
	if err != nil {
		switch err.(type) {
		case *url.Error:
			e := &serror.Stalling{
				Err:    fmt.Errorf("invalid Helm repository URL: %w", err),
				Reason: sourcev1.URLInvalidReason,
			}
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.URLInvalidReason, e.Err.Error())
			return sreconcile.ResultEmpty, e
		default:
			e := &serror.Stalling{
				Err:    fmt.Errorf("failed to construct Helm client: %w", err),
				Reason: meta.FailedReason,
			}
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, meta.FailedReason, e.Err.Error())
			return sreconcile.ResultEmpty, e
		}
	}
	checksum, err := newChartRepo.CacheIndex()
	if err != nil {
		e := &serror.Event{
			Err:    fmt.Errorf("failed to download Helm repository index: %w", err),
			Reason: meta.FailedReason,
		}
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, meta.FailedReason, e.Err.Error())
		// Coin flip on transient or persistent error, return error and hope for the best
		return sreconcile.ResultEmpty, e
	}
	*chartRepo = *newChartRepo

	// Load the cached repository index to ensure it passes validation.
	if err := chartRepo.LoadFromCache(); err != nil {
		e := &serror.Event{
			Err:    fmt.Errorf("failed to load Helm repository from cache: %w", err),
			Reason: sourcev1.FetchFailedCondition,
		}
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.IndexationFailedReason, e.Err.Error())
		return sreconcile.ResultEmpty, e
	}
	defer chartRepo.Unload()

	// Mark observations about the revision on the object.
	if !obj.GetArtifact().HasRevision(checksum) {
		message := fmt.Sprintf("new index revision '%s'", checksum)
		conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "NewRevision", message)
		conditions.MarkReconciling(obj, "NewRevision", message)
	}

	conditions.Delete(obj, sourcev1.FetchFailedCondition)

	// Create potential new artifact.
	*artifact = r.Storage.NewArtifactFor(obj.Kind,
		obj.ObjectMeta.GetObjectMeta(),
		chartRepo.Checksum,
		fmt.Sprintf("index-%s.yaml", checksum))

	return sreconcile.ResultSuccess, nil
}

// reconcileArtifact stores a new artifact in the storage, if the current observation on the object does not match the
// given data.
//
// The inspection of the given data to the object is differed, ensuring any stale observations as
// v1beta1.ArtifactUnavailableCondition and v1beta1.ArtifactOutdatedCondition are always deleted.
// If the given artifact does not differ from the object's current, it returns early.
// On a successful write of a new artifact, the artifact in the status of the given object is set, and the symlink in
// the storage is updated to its path.
func (r *HelmRepositoryReconciler) reconcileArtifact(ctx context.Context, obj *sourcev1.HelmRepository, artifact *sourcev1.Artifact, chartRepo *repository.ChartRepository) (sreconcile.Result, error) {
	// Always restore the Ready condition in case it got removed due to a transient error.
	defer func() {
		if obj.GetArtifact().HasRevision(artifact.Revision) {
			conditions.Delete(obj, sourcev1.ArtifactOutdatedCondition)
			conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason,
				"stored artifact for revision '%s'", artifact.Revision)
		}
	}()

	if obj.GetArtifact().HasRevision(artifact.Revision) {
		ctrl.LoggerFrom(ctx).Info("artifact up-to-date", "revision", artifact.Revision)
		return sreconcile.ResultSuccess, nil
	}

	// Mark reconciling because the artifact and remote source are different.
	// and they have to be reconciled.
	conditions.MarkReconciling(obj, "NewRevision", "new index revision '%s'", artifact.Revision)

	// Clear cache at the very end.
	defer chartRepo.RemoveCache()

	// Create artifact dir.
	if err := r.Storage.MkdirAll(*artifact); err != nil {
		return sreconcile.ResultEmpty, &serror.Event{
			Err:    fmt.Errorf("failed to create artifact directory: %w", err),
			Reason: sourcev1.StorageOperationFailedReason,
		}
	}

	// Acquire lock.
	unlock, err := r.Storage.Lock(*artifact)
	if err != nil {
		return sreconcile.ResultEmpty, &serror.Event{
			Err:    fmt.Errorf("failed to acquire lock for artifact: %w", err),
			Reason: meta.FailedReason,
		}
	}
	defer unlock()

	// Save artifact to storage.
	if err = r.Storage.CopyFromPath(artifact, chartRepo.CachePath); err != nil {
		return sreconcile.ResultEmpty, &serror.Event{
			Err:    fmt.Errorf("unable to save artifact to storage: %w", err),
			Reason: sourcev1.StorageOperationFailedReason,
		}
	}

	r.AnnotatedEventf(obj, map[string]string{
		"revision": artifact.Revision,
		"checksum": artifact.Checksum,
	}, corev1.EventTypeNormal, "NewArtifact", "stored artifact for revision '%s'", artifact.Revision)

	// Record it on the object.
	obj.Status.Artifact = artifact.DeepCopy()

	// Update index symlink.
	indexURL, err := r.Storage.Symlink(*artifact, "index.yaml")
	if err != nil {
		r.eventLogf(ctx, obj, corev1.EventTypeWarning, sourcev1.StorageOperationFailedReason,
			"failed to update status URL symlink: %s", err)
	}

	if indexURL != "" {
		obj.Status.URL = indexURL
	}
	return sreconcile.ResultSuccess, nil
}

// reconcileDelete handles the delete of an object. It first garbage collects all artifacts for the object from the
// artifact storage, if successful, the finalizer is removed from the object.
func (r *HelmRepositoryReconciler) reconcileDelete(ctx context.Context, obj *sourcev1.HelmRepository) (sreconcile.Result, error) {
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

// garbageCollect performs a garbage collection for the given v1beta1.HelmRepository. It removes all but the current
// artifact except for when the deletion timestamp is set, which will result in the removal of all artifacts for the
// resource.
func (r *HelmRepositoryReconciler) garbageCollect(ctx context.Context, obj *sourcev1.HelmRepository) error {
	if !obj.DeletionTimestamp.IsZero() {
		if err := r.Storage.RemoveAll(r.Storage.NewArtifactFor(obj.Kind, obj.GetObjectMeta(), "", "*")); err != nil {
			return &serror.Event{
				Err:    fmt.Errorf("garbage collection for deleted resource failed: %w", err),
				Reason: "GarbageCollectionFailed",
			}
		}
		obj.Status.Artifact = nil
		// TODO(hidde): we should only push this event if we actually garbage collected something
		r.eventLogf(ctx, obj, events.EventTypeTrace, "GarbageCollectionSucceeded",
			"garbage collected artifacts for deleted resource")
		return nil
	}
	if obj.GetArtifact() != nil {
		if err := r.Storage.RemoveAllButCurrent(*obj.GetArtifact()); err != nil {
			return &serror.Event{
				Err:    fmt.Errorf("garbage collection of old artifacts failed: %w", err),
				Reason: "GarbageCollectionFailed",
			}
		}
		// TODO(hidde): we should only push this event if we actually garbage collected something
		r.eventLogf(ctx, obj, events.EventTypeTrace, "GarbageCollectionSucceeded",
			"garbage collected old artifacts")
	}
	return nil
}

// eventLog records event and logs at the same time. This log is different from
// the debug log in the event recorder in the sense that this is a simple log,
// the event recorder debug log contains complete details about the event.
func (r *HelmRepositoryReconciler) eventLogf(ctx context.Context, obj runtime.Object, eventType string, reason string, messageFmt string, args ...interface{}) {
	msg := fmt.Sprintf(messageFmt, args...)
	// Log and emit event.
	if eventType == corev1.EventTypeWarning {
		ctrl.LoggerFrom(ctx).Error(errors.New(reason), msg)
	} else {
		ctrl.LoggerFrom(ctx).Info(msg)
	}
	r.Eventf(obj, eventType, reason, msg)
}
