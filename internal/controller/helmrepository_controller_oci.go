/*
Copyright 2022 The Flux authors

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
	"crypto/tls"
	"errors"
	"fmt"
	qhelm "github.com/hossainemruz/qdrant-cloud-apis/api/helm/v1"
	"net/url"
	"os"
	"time"

	helmreg "helm.sh/helm/v3/pkg/registry"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	kuberecorder "k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	eventv1 "github.com/fluxcd/pkg/apis/event/v1beta1"
	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/conditions"
	helper "github.com/fluxcd/pkg/runtime/controller"
	"github.com/fluxcd/pkg/runtime/jitter"
	"github.com/fluxcd/pkg/runtime/patch"
	"github.com/fluxcd/pkg/runtime/predicates"
	rreconcile "github.com/fluxcd/pkg/runtime/reconcile"

	sourcev1 "github.com/fluxcd/source-controller/api/v1"
	helmv1 "github.com/fluxcd/source-controller/api/v1beta2"
	"github.com/fluxcd/source-controller/internal/helm/getter"
	"github.com/fluxcd/source-controller/internal/helm/repository"
	"github.com/fluxcd/source-controller/internal/object"
	intpredicates "github.com/fluxcd/source-controller/internal/predicates"
)

var helmRepositoryOCIOwnedConditions = []string{
	meta.ReadyCondition,
	meta.ReconcilingCondition,
	meta.StalledCondition,
}

var helmRepositoryOCINegativeConditions = []string{
	meta.StalledCondition,
	meta.ReconcilingCondition,
}

// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=helmrepositories,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=helmrepositories/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=helmrepositories/finalizers,verbs=get;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// HelmRepositoryOCI Reconciler reconciles a v1beta2.HelmRepository object of type OCI.
type HelmRepositoryOCIReconciler struct {
	client.Client
	kuberecorder.EventRecorder
	helper.Metrics

	ControllerName          string
	RegistryClientGenerator RegistryClientGeneratorFunc

	patchOptions []patch.Option

	// unmanagedConditions are the conditions that are not managed by this
	// reconciler and need to be removed from the object before taking ownership
	// of the object being reconciled.
	unmanagedConditions []string
}

// RegistryClientGeneratorFunc is a function that returns a registry client
// and an optional file name.
// The file is used to store the registry client credentials.
// The caller is responsible for deleting the file.
type RegistryClientGeneratorFunc func(tlsConfig *tls.Config, isLogin bool) (*helmreg.Client, string, error)

func (r *HelmRepositoryOCIReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return r.SetupWithManagerAndOptions(mgr, HelmRepositoryReconcilerOptions{})
}

func (r *HelmRepositoryOCIReconciler) SetupWithManagerAndOptions(mgr ctrl.Manager, opts HelmRepositoryReconcilerOptions) error {
	r.unmanagedConditions = conditionsDiff(helmRepositoryReadyCondition.Owned, helmRepositoryOCIOwnedConditions)
	r.patchOptions = getPatchOptions(helmRepositoryOCIOwnedConditions, r.ControllerName)

	return ctrl.NewControllerManagedBy(mgr).
		For(&qhelm.HelmRepository{}).
		WithEventFilter(
			predicate.And(
				intpredicates.HelmRepositoryTypePredicate{RepositoryType: helmv1.HelmRepositoryTypeOCI},
				predicate.Or(predicate.GenerationChangedPredicate{}, predicates.ReconcileRequestedPredicate{}),
			),
		).
		WithOptions(controller.Options{
			RateLimiter: opts.RateLimiter,
		}).
		Complete(r)
}

func (r *HelmRepositoryOCIReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, retErr error) {
	start := time.Now()
	log := ctrl.LoggerFrom(ctx)

	// Fetch the HelmRepository
	obj := &qhelm.HelmRepository{}
	if err := r.Get(ctx, req.NamespacedName, obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// If the object contains any of the unmanaged conditions, requeue and wait
	// for those conditions to be removed first before processing the object.
	// NOTE: This will happen only when a HelmRepository's spec.type is switched
	// from "default" to "oci".
	if conditions.HasAny(obj, r.unmanagedConditions) {
		r.eventLogf(ctx, obj, eventv1.EventTypeTrace, "IncompleteTransition",
			"object contains conditions managed by other reconciler")
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}

	// Initialize the patch helper with the current version of the object.
	serialPatcher := patch.NewSerialPatcher(obj, r.Client)

	// Always attempt to patch the object after each reconciliation.
	defer func() {
		// If a reconcile annotation value is found, set it in the object status
		// as status.lastHandledReconcileAt.
		if v, ok := meta.ReconcileAnnotationValue(obj.GetAnnotations()); ok {
			object.SetStatusLastHandledReconcileAt(obj, v)
		}

		patchOpts := []patch.Option{}
		patchOpts = append(patchOpts, r.patchOptions...)

		// Set status observed generation option if the object is stalled, or
		// if the object is ready.
		if conditions.IsStalled(obj) || conditions.IsReady(obj) {
			patchOpts = append(patchOpts, patch.WithStatusObservedGeneration{})
		}

		if err := serialPatcher.Patch(ctx, obj, patchOpts...); err != nil {
			// Ignore patch error "not found" when the object is being deleted.
			if !obj.GetDeletionTimestamp().IsZero() {
				err = kerrors.FilterOut(err, func(e error) bool { return apierrors.IsNotFound(e) })
			}
			retErr = kerrors.NewAggregate([]error{retErr, err})
		}

		// Always record suspend, readiness and duration metrics.
		r.Metrics.RecordSuspend(ctx, obj, obj.Spec.Suspend)
		r.Metrics.RecordReadiness(ctx, obj)
		r.Metrics.RecordDuration(ctx, obj, start)
	}()

	// Examine if the object is under deletion.
	if !obj.ObjectMeta.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, obj)
	}

	// Add finalizer first if it doesn't exist to avoid the race condition
	// between init and delete.
	// Note: Finalizers in general can only be added when the deletionTimestamp
	// is not set.
	if !controllerutil.ContainsFinalizer(obj, sourcev1.SourceFinalizer) {
		controllerutil.AddFinalizer(obj, sourcev1.SourceFinalizer)
		return ctrl.Result{Requeue: true}, nil
	}

	// Return if the object is suspended.
	if obj.Spec.Suspend {
		log.Info("reconciliation is suspended for this object")
		return ctrl.Result{}, nil
	}

	// Examine if a type change has happened and act accordingly
	if obj.Spec.Type != helmv1.HelmRepositoryTypeOCI {
		// Remove any stale condition and ignore the object if the type has
		// changed.
		obj.Status.Conditions = nil
		return ctrl.Result{}, nil
	}

	result, retErr = r.reconcile(ctx, serialPatcher, obj)
	return
}

// reconcile reconciles the HelmRepository object. While reconciling, when an
// error is encountered, it sets the failure details in the appropriate status
// condition type and returns the error with appropriate ctrl.Result. The object
// status conditions and the returned results are evaluated in the deferred
// block at the very end to summarize the conditions to be in a consistent
// state.
func (r *HelmRepositoryOCIReconciler) reconcile(ctx context.Context, sp *patch.SerialPatcher, obj *qhelm.HelmRepository) (result ctrl.Result, retErr error) {
	ctxTimeout, cancel := context.WithTimeout(ctx, obj.Spec.Timeout.Duration)
	defer cancel()

	oldObj := obj.DeepCopy()

	defer func() {
		// If it's stalled, ensure reconciling is removed.
		if sc := conditions.Get(obj, meta.StalledCondition); sc != nil && sc.Status == metav1.ConditionTrue {
			conditions.Delete(obj, meta.ReconcilingCondition)
		}

		// Check if it's a successful reconciliation.
		if result.RequeueAfter == obj.GetRequeueAfter() && !result.Requeue &&
			retErr == nil {
			// Remove reconciling condition if the reconciliation was successful.
			conditions.Delete(obj, meta.ReconcilingCondition)
			// If it's not ready even though it's not reconciling or stalled,
			// set the ready failure message as the error.
			// Based on isNonStalledSuccess() from internal/reconcile/summarize.
			if ready := conditions.Get(obj, meta.ReadyCondition); ready != nil &&
				ready.Status == metav1.ConditionFalse && !conditions.IsStalled(obj) {
				retErr = errors.New(conditions.GetMessage(obj, meta.ReadyCondition))
			}
		}

		// Presence of reconciling means that the reconciliation didn't succeed.
		// Set the Reconciling reason to ProgressingWithRetry to indicate a
		// failure retry.
		if conditions.IsReconciling(obj) {
			reconciling := conditions.Get(obj, meta.ReconcilingCondition)
			reconciling.Reason = meta.ProgressingWithRetryReason
			conditions.Set(obj, reconciling)
		}

		// If it's still a successful reconciliation and it's not reconciling or
		// stalled, mark Ready=True.
		if !conditions.IsReconciling(obj) && !conditions.IsStalled(obj) &&
			retErr == nil && result.RequeueAfter == obj.GetRequeueAfter() {
			conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason, "Helm repository is ready")
		}

		// Emit events when object's state changes.
		ready := conditions.Get(obj, meta.ReadyCondition)
		// Became ready from not ready.
		if !conditions.IsReady(oldObj) && conditions.IsReady(obj) {
			r.eventLogf(ctx, obj, corev1.EventTypeNormal, ready.Reason, ready.Message)
		}
		// Became not ready from ready.
		if conditions.IsReady(oldObj) && !conditions.IsReady(obj) {
			r.eventLogf(ctx, obj, corev1.EventTypeWarning, ready.Reason, ready.Message)
		}

		// Apply jitter.
		if result.RequeueAfter == obj.GetRequeueAfter() {
			result.RequeueAfter = jitter.JitteredIntervalDuration(result.RequeueAfter)
		}
	}()

	// Set reconciling condition.
	rreconcile.ProgressiveStatus(false, obj, meta.ProgressingReason, "reconciliation in progress")

	var reconcileAtVal string
	if v, ok := meta.ReconcileAnnotationValue(obj.GetAnnotations()); ok {
		reconcileAtVal = v
	}

	// Persist reconciling if generation differs or reconciliation is requested.
	switch {
	case obj.Generation != obj.Status.ObservedGeneration:
		rreconcile.ProgressiveStatus(false, obj, meta.ProgressingReason,
			"processing object: new generation %d -> %d", obj.Status.ObservedGeneration, obj.Generation)
		if err := sp.Patch(ctx, obj, r.patchOptions...); err != nil {
			result, retErr = ctrl.Result{}, err
			return
		}
	case reconcileAtVal != obj.Status.GetLastHandledReconcileRequest():
		if err := sp.Patch(ctx, obj, r.patchOptions...); err != nil {
			result, retErr = ctrl.Result{}, err
			return
		}
	}

	// Ensure that it's an OCI URL before continuing.
	if !helmreg.IsOCI(obj.Spec.URL) {
		u, err := url.Parse(obj.Spec.URL)
		if err != nil {
			err = fmt.Errorf("failed to parse URL: %w", err)
		} else {
			err = fmt.Errorf("URL scheme '%s' in '%s' is not supported", u.Scheme, obj.Spec.URL)
		}
		conditions.MarkStalled(obj, sourcev1.URLInvalidReason, err.Error())
		conditions.MarkFalse(obj, meta.ReadyCondition, sourcev1.URLInvalidReason, err.Error())
		ctrl.LoggerFrom(ctx).Error(err, "reconciliation stalled")
		result, retErr = ctrl.Result{}, nil
		return
	}

	normalizedURL, err := repository.NormalizeURL(obj.Spec.URL)
	if err != nil {
		conditions.MarkStalled(obj, sourcev1.URLInvalidReason, err.Error())
		conditions.MarkFalse(obj, meta.ReadyCondition, sourcev1.URLInvalidReason, err.Error())
		result, retErr = ctrl.Result{}, nil
		return
	}

	conditions.Delete(obj, meta.StalledCondition)

	clientOpts, certsTmpDir, err := getter.GetClientOpts(ctxTimeout, r.Client, obj, normalizedURL)
	if err != nil {
		conditions.MarkFalse(obj, meta.ReadyCondition, sourcev1.AuthenticationFailedReason, err.Error())
		result, retErr = ctrl.Result{}, err
		return
	}
	if certsTmpDir != "" {
		defer func() {
			if err := os.RemoveAll(certsTmpDir); err != nil {
				r.eventLogf(ctx, obj, corev1.EventTypeWarning, meta.FailedReason,
					"failed to delete temporary certs directory: %s", err)
			}
		}()
	}

	// Create registry client and login if needed.
	registryClient, file, err := r.RegistryClientGenerator(clientOpts.TlsConfig, clientOpts.MustLoginToRegistry())
	if err != nil {
		e := fmt.Errorf("failed to create registry client: %w", err)
		conditions.MarkFalse(obj, meta.ReadyCondition, meta.FailedReason, e.Error())
		result, retErr = ctrl.Result{}, e
		return
	}
	if file != "" {
		defer func() {
			if err := os.Remove(file); err != nil {
				r.eventLogf(ctx, obj, corev1.EventTypeWarning, meta.FailedReason,
					"failed to delete temporary credentials file: %s", err)
			}
		}()
	}

	chartRepo, err := repository.NewOCIChartRepository(obj.Spec.URL, repository.WithOCIRegistryClient(registryClient))
	if err != nil {
		e := fmt.Errorf("failed to parse URL '%s': %w", obj.Spec.URL, err)
		conditions.MarkStalled(obj, sourcev1.URLInvalidReason, e.Error())
		conditions.MarkFalse(obj, meta.ReadyCondition, sourcev1.URLInvalidReason, e.Error())
		result, retErr = ctrl.Result{}, nil
		return
	}
	conditions.Delete(obj, meta.StalledCondition)

	// Attempt to login to the registry if credentials are provided.
	if clientOpts.MustLoginToRegistry() {
		err = chartRepo.Login(clientOpts.RegLoginOpts...)
		if err != nil {
			e := fmt.Errorf("failed to login to registry '%s': %w", obj.Spec.URL, err)
			conditions.MarkFalse(obj, meta.ReadyCondition, sourcev1.AuthenticationFailedReason, e.Error())
			result, retErr = ctrl.Result{}, e
			return
		}
	}

	// Remove any stale Ready condition, most likely False, set above. Its value
	// is derived from the overall result of the reconciliation in the deferred
	// block at the very end.
	conditions.Delete(obj, meta.ReadyCondition)

	result, retErr = ctrl.Result{RequeueAfter: obj.GetRequeueAfter()}, nil
	return
}

func (r *HelmRepositoryOCIReconciler) reconcileDelete(ctx context.Context, obj *qhelm.HelmRepository) (ctrl.Result, error) {
	// Remove our finalizer from the list
	controllerutil.RemoveFinalizer(obj, sourcev1.SourceFinalizer)

	// Stop reconciliation as the object is being deleted
	return ctrl.Result{}, nil
}

// eventLogf records events, and logs at the same time.
//
// This log is different from the debug log in the EventRecorder, in the sense
// that this is a simple log. While the debug log contains complete details
// about the event.
func (r *HelmRepositoryOCIReconciler) eventLogf(ctx context.Context, obj runtime.Object, eventType string, reason string, messageFmt string, args ...interface{}) {
	msg := fmt.Sprintf(messageFmt, args...)
	// Log and emit event.
	if eventType == corev1.EventTypeWarning {
		ctrl.LoggerFrom(ctx).Error(errors.New(reason), msg)
	} else {
		ctrl.LoggerFrom(ctx).Info(msg)
	}
	r.Eventf(obj, eventType, reason, msg)
}

func conditionsDiff(a, b []string) []string {
	bMap := make(map[string]struct{}, len(b))
	for _, j := range b {
		bMap[j] = struct{}{}
	}

	r := []string{}
	for _, i := range a {
		if _, exists := bMap[i]; !exists {
			r = append(r, i)
		}
	}
	return r
}
