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

package controllers

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"

	helmgetter "helm.sh/helm/v3/pkg/getter"
	helmreg "helm.sh/helm/v3/pkg/registry"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	"github.com/fluxcd/pkg/oci"
	"github.com/fluxcd/pkg/runtime/conditions"
	helper "github.com/fluxcd/pkg/runtime/controller"
	"github.com/fluxcd/pkg/runtime/patch"
	"github.com/fluxcd/pkg/runtime/predicates"

	"github.com/fluxcd/source-controller/api/v1beta2"
	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
	"github.com/fluxcd/source-controller/internal/helm/registry"
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
	Getters                 helmgetter.Providers
	ControllerName          string
	RegistryClientGenerator RegistryClientGeneratorFunc
}

// RegistryClientGeneratorFunc is a function that returns a registry client
// and an optional file name.
// The file is used to store the registry client credentials.
// The caller is responsible for deleting the file.
type RegistryClientGeneratorFunc func(isLogin bool) (*helmreg.Client, string, error)

func (r *HelmRepositoryOCIReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return r.SetupWithManagerAndOptions(mgr, HelmRepositoryReconcilerOptions{})
}

func (r *HelmRepositoryOCIReconciler) SetupWithManagerAndOptions(mgr ctrl.Manager, opts HelmRepositoryReconcilerOptions) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sourcev1.HelmRepository{}).
		WithEventFilter(
			predicate.And(
				intpredicates.HelmRepositoryTypePredicate{RepositoryType: sourcev1.HelmRepositoryTypeOCI},
				predicate.Or(predicate.GenerationChangedPredicate{}, predicates.ReconcileRequestedPredicate{}),
			),
		).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: opts.MaxConcurrentReconciles,
			RateLimiter:             opts.RateLimiter,
			RecoverPanic:            true,
		}).
		Complete(r)
}

func (r *HelmRepositoryOCIReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, retErr error) {
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

	// Initialize the patch helper with the current version of the object.
	patchHelper, err := patch.NewHelper(obj, r.Client)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Always attempt to patch the object after each reconciliation.
	defer func() {
		// Patch the object, prioritizing the conditions owned by the controller in
		// case of any conflicts.
		patchOpts := []patch.Option{
			patch.WithOwnedConditions{
				Conditions: helmRepositoryOCIOwnedConditions,
			},
		}
		patchOpts = append(patchOpts, patch.WithFieldOwner(r.ControllerName))
		// If a reconcile annotation value is found, set it in the object status
		// as status.lastHandledReconcileAt.
		if v, ok := meta.ReconcileAnnotationValue(obj.GetAnnotations()); ok {
			object.SetStatusLastHandledReconcileAt(obj, v)
		}

		// Set status observed generation option if the object is stalled, or
		// if the object is ready.
		if conditions.IsStalled(obj) || conditions.IsReady(obj) {
			patchOpts = append(patchOpts, patch.WithStatusObservedGeneration{})
		}

		if err = patchHelper.Patch(ctx, obj, patchOpts...); err != nil {
			// Ignore patch error "not found" when the object is being deleted.
			if !obj.GetDeletionTimestamp().IsZero() {
				err = kerrors.FilterOut(err, func(e error) bool { return apierrors.IsNotFound(e) })
			}
			retErr = kerrors.NewAggregate([]error{retErr, err})
		}

		// Always record readiness and duration metrics
		r.Metrics.RecordReadiness(ctx, obj)
		r.Metrics.RecordDuration(ctx, obj, start)
	}()

	// Add finalizer first if it doesn't exist to avoid the race condition
	// between init and delete.
	if !controllerutil.ContainsFinalizer(obj, sourcev1.SourceFinalizer) {
		controllerutil.AddFinalizer(obj, sourcev1.SourceFinalizer)
		return ctrl.Result{Requeue: true}, nil
	}

	// Examine if the object is under deletion.
	if !obj.ObjectMeta.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, obj)
	}

	// Examine if a type change has happened and act accordingly
	if obj.Spec.Type != sourcev1.HelmRepositoryTypeOCI {
		// Remove any stale condition and ignore the object if the type has
		// changed.
		obj.Status.Conditions = nil
		return ctrl.Result{}, nil
	}

	result, retErr = r.reconcile(ctx, obj)
	return
}

// reconcile reconciles the HelmRepository object. While reconciling, when an
// error is encountered, it sets the failure details in the appropriate status
// condition type and returns the error with appropriate ctrl.Result. The object
// status conditions and the returned results are evaluated in the deferred
// block at the very end to summarize the conditions to be in a consistent
// state.
func (r *HelmRepositoryOCIReconciler) reconcile(ctx context.Context, obj *v1beta2.HelmRepository) (result ctrl.Result, retErr error) {
	ctxTimeout, cancel := context.WithTimeout(ctx, obj.Spec.Timeout.Duration)
	defer cancel()

	oldObj := obj.DeepCopy()

	defer func() {
		// If it's stalled, ensure reconciling is removed.
		if sc := conditions.Get(obj, meta.StalledCondition); sc != nil && sc.Status == metav1.ConditionTrue {
			conditions.Delete(obj, meta.ReconcilingCondition)
		}

		// Check if it's a successful reconciliation.
		if result.RequeueAfter == obj.GetRequeueAfter() && result.Requeue == false &&
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
	}()

	// Set reconciling condition.
	if obj.Generation != obj.Status.ObservedGeneration {
		conditions.MarkReconciling(obj, "NewGeneration", "reconciling new object generation (%d)", obj.Generation)
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
	conditions.Delete(obj, meta.StalledCondition)

	var loginOpts []helmreg.LoginOption
	// Configure any authentication related options.
	if obj.Spec.SecretRef != nil {
		// Attempt to retrieve secret.
		name := types.NamespacedName{
			Namespace: obj.GetNamespace(),
			Name:      obj.Spec.SecretRef.Name,
		}
		var secret corev1.Secret
		if err := r.Client.Get(ctx, name, &secret); err != nil {
			e := fmt.Errorf("failed to get secret '%s': %w", name.String(), err)
			conditions.MarkFalse(obj, meta.ReadyCondition, sourcev1.AuthenticationFailedReason, e.Error())
			result, retErr = ctrl.Result{}, e
			return
		}

		// Construct login options.
		loginOpt, err := registry.LoginOptionFromSecret(obj.Spec.URL, secret)
		if err != nil {
			e := fmt.Errorf("failed to configure Helm client with secret data: %w", err)
			conditions.MarkFalse(obj, meta.ReadyCondition, sourcev1.AuthenticationFailedReason, e.Error())
			result, retErr = ctrl.Result{}, e
			return
		}

		if loginOpt != nil {
			loginOpts = append(loginOpts, loginOpt)
		}
	} else if obj.Spec.Provider != sourcev1.GenericOCIProvider && obj.Spec.Type == sourcev1.HelmRepositoryTypeOCI {
		auth, authErr := oidcAuthFromAdapter(ctxTimeout, obj.Spec.URL, obj.Spec.Provider)
		if authErr != nil && !errors.Is(authErr, oci.ErrUnconfiguredProvider) {
			e := fmt.Errorf("failed to get credential from %s: %w", obj.Spec.Provider, authErr)
			conditions.MarkFalse(obj, meta.ReadyCondition, sourcev1.AuthenticationFailedReason, e.Error())
			result, retErr = ctrl.Result{}, e
			return
		}
		if auth != nil {
			loginOpts = append(loginOpts, auth)
		}
	}

	// Create registry client and login if needed.
	registryClient, file, err := r.RegistryClientGenerator(loginOpts != nil)
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
	if loginOpts != nil {
		err = chartRepo.Login(loginOpts...)
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

func (r *HelmRepositoryOCIReconciler) reconcileDelete(ctx context.Context, obj *sourcev1.HelmRepository) (ctrl.Result, error) {
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

// oidcAuthFromAdapter generates the OIDC credential authenticator based on the specified cloud provider.
func oidcAuthFromAdapter(ctx context.Context, url, provider string) (helmreg.LoginOption, error) {
	auth, err := oidcAuth(ctx, url, provider)
	if err != nil {
		return nil, err
	}

	return registry.OIDCAdaptHelper(auth)
}
