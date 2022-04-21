package controllers

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/conditions"
	helper "github.com/fluxcd/pkg/runtime/controller"
	"github.com/fluxcd/pkg/runtime/patch"
	"github.com/fluxcd/pkg/runtime/predicates"
	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
	serror "github.com/fluxcd/source-controller/internal/error"
	sreconcile "github.com/fluxcd/source-controller/internal/reconcile"
	"github.com/fluxcd/source-controller/internal/reconcile/summarize"
	helmgetter "helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/registry"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	kuberecorder "k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

var helmRepositoryOCIReadyCondition = summarize.Conditions{
	Target: meta.ReadyCondition,
	Owned: []string{
		sourcev1.FetchFailedCondition,
		sourcev1.SourceValidCondition,
		meta.ReadyCondition,
		meta.ReconcilingCondition,
		meta.StalledCondition,
	},
	Summarize: []string{
		sourcev1.FetchFailedCondition,
		sourcev1.SourceValidCondition,
		meta.StalledCondition,
		meta.ReconcilingCondition,
	},
	NegativePolarity: []string{
		sourcev1.FetchFailedCondition,
		meta.StalledCondition,
		meta.ReconcilingCondition,
	},
}

// helmRepositoryOCIFailConditions contains the conditions that represent a
// failure.
var helmRepositoryOCIFailConditions = []string{
	sourcev1.FetchFailedCondition,
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
	Getters helmgetter.Providers
	// Storage        *Storage
	ControllerName string
	RegistryClient *registry.Client
}

// helmRepositoryOCIReconcileFunc is the function type for all the
// v1beta2.HelmRepository (sub)reconcile functions for OCI type. The type implementations
// are grouped and executed serially to perform the complete reconcile of the
// object.
type helmRepositoryOCIReconcileFunc func(ctx context.Context, obj *sourcev1.HelmRepository) (sreconcile.Result, error)

func (r *HelmRepositoryOCIReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return r.SetupWithManagerAndOptions(mgr, HelmRepositoryReconcilerOptions{})
}

func (r *HelmRepositoryOCIReconciler) SetupWithManagerAndOptions(mgr ctrl.Manager, opts HelmRepositoryReconcilerOptions) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sourcev1.HelmRepository{}).
		WithEventFilter(
			predicate.And(
				predicate.NewPredicateFuncs(HelmRepositoryTypeFilter(sourcev1.HelmRepositoryTypeOCI)),
				predicate.Or(predicate.GenerationChangedPredicate{}, predicates.ReconcileRequestedPredicate{})),
		).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: opts.MaxConcurrentReconciles,
			RateLimiter:             opts.RateLimiter,
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

	// recResult stores the abstracted reconcile result.
	var recResult sreconcile.Result

	// Always attempt to patch the object after each reconciliation.
	// NOTE: The final runtime result and error are set in this block.
	defer func() {
		summarizeHelper := summarize.NewHelper(r.EventRecorder, patchHelper)
		summarizeOpts := []summarize.Option{
			summarize.WithConditions(helmRepositoryOCIReadyCondition),
			summarize.WithReconcileResult(recResult),
			summarize.WithReconcileError(retErr),
			summarize.WithIgnoreNotFound(),
			summarize.WithProcessors(
				summarize.RecordContextualError,
				summarize.RecordReconcileReq,
			),
			summarize.WithResultBuilder(sreconcile.AlwaysRequeueResultBuilder{RequeueAfter: obj.GetRequeueAfter()}),
			summarize.WithPatchFieldOwner(r.ControllerName),
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
	reconcilers := []helmRepositoryOCIReconcileFunc{
		r.reconcileSource,
	}
	recResult, retErr = r.reconcile(ctx, obj, reconcilers)
	return
}

// reconcileDelete handles the deletion of the object.
// Removing the finalizer from the object if successful.
func (r *HelmRepositoryOCIReconciler) reconcileDelete(ctx context.Context, obj *sourcev1.HelmRepository) (sreconcile.Result, error) {
	// Remove our finalizer from the list
	controllerutil.RemoveFinalizer(obj, sourcev1.SourceFinalizer)

	// Stop reconciliation as the object is being deleted
	return sreconcile.ResultEmpty, nil
}

// notify emits notification related to the reconciliation.
func (r *HelmRepositoryOCIReconciler) notify(oldObj, newObj *sourcev1.HelmRepository, res sreconcile.Result, resErr error) {
	// Notify successful recovery from any failure.
	if resErr == nil && res == sreconcile.ResultSuccess {
		if sreconcile.FailureRecovery(oldObj, newObj, helmRepositoryOCIFailConditions) {
			r.Eventf(newObj, corev1.EventTypeNormal,
				meta.SucceededReason, "Helm repository %q has been successfully reconciled", newObj.Name)
		}
	}
}

func (r *HelmRepositoryOCIReconciler) reconcile(ctx context.Context, obj *sourcev1.HelmRepository, reconcilers []helmRepositoryOCIReconcileFunc) (sreconcile.Result, error) {
	oldObj := obj.DeepCopy()

	// Mark as reconciling if generation differs.
	if obj.Generation != obj.Status.ObservedGeneration {
		conditions.MarkReconciling(obj, "NewGeneration", "reconciling new object generation (%d)", obj.Generation)
	}

	// Run the sub-reconcilers and build the result of reconciliation.
	var res sreconcile.Result
	var resErr error
	for _, rec := range reconcilers {
		recResult, err := rec(ctx, obj)
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

	r.notify(oldObj, obj, res, resErr)

	return res, resErr
}

func (r *HelmRepositoryOCIReconciler) reconcileSource(ctx context.Context, obj *sourcev1.HelmRepository) (sreconcile.Result, error) {
	var logOpts []registry.LoginOption
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
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, e.Err.Error())
			return sreconcile.ResultEmpty, e
		}

		// Construct actual options
		logOpt, err := r.loginOptionFromSecret(secret)
		if err != nil {
			e := &serror.Event{
				Err:    fmt.Errorf("failed to configure Helm client with secret data: %w", err),
				Reason: sourcev1.AuthenticationFailedReason,
			}
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, e.Err.Error())
			// Return err as the content of the secret may change.
			return sreconcile.ResultEmpty, e
		}

		logOpts = append(logOpts, logOpt)
	}

	if result, err := r.validateSource(ctx, obj, logOpts...); err != nil || result == sreconcile.ResultEmpty {
		return result, err
	}

	return sreconcile.ResultSuccess, nil
}

// validateSource the HelmRepository object by checking the url and connecting to the underlying registry
// with he provided credentials.
func (r *HelmRepositoryOCIReconciler) validateSource(ctx context.Context, obj *sourcev1.HelmRepository, loginOpts ...registry.LoginOption) (sreconcile.Result, error) {
	target, err := url.Parse(obj.Spec.URL)
	if err != nil {
		e := &serror.Event{
			Err:    fmt.Errorf("failed to parse URL '%s': %w", obj.Spec.URL, err),
			Reason: "ValidationError",
		}
		conditions.MarkFalse(obj, sourcev1.SourceValidCondition, e.Reason, e.Err.Error())
		return sreconcile.ResultEmpty, e
	}

	// Check if the registry is supported
	if target.Scheme != registry.OCIScheme {
		e := &serror.Event{
			Err:    fmt.Errorf("unsupported registry scheme '%s'", target.Scheme),
			Reason: "ValidationError",
		}
		conditions.MarkFalse(obj, sourcev1.SourceValidCondition, e.Reason, e.Err.Error())
		return sreconcile.ResultEmpty, e
	}

	err = r.RegistryClient.Login(target.Host+target.Path, loginOpts...)
	if err != nil {
		e := &serror.Event{
			Err:    fmt.Errorf("failed to login to registry '%s': %w", target.String(), err),
			Reason: "ValidationError",
		}
		conditions.MarkFalse(obj, sourcev1.SourceValidCondition, e.Reason, e.Err.Error())
		return sreconcile.ResultEmpty, e
	}

	conditions.MarkTrue(obj, sourcev1.SourceValidCondition, meta.SucceededReason, "Helm repository %q is valid", obj.Name)

	return sreconcile.ResultSuccess, nil
}

func (r *HelmRepositoryOCIReconciler) loginOptionFromSecret(secret corev1.Secret) (registry.LoginOption, error) {
	username, password := string(secret.Data["username"]), string(secret.Data["password"])
	switch {
	case username == "" && password == "":
		return nil, nil
	case username == "" || password == "":
		return nil, fmt.Errorf("invalid '%s' secret data: required fields 'username' and 'password'", secret.Name)
	}
	return registry.LoginOptBasicAuth(username, password), nil
}
