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
	"net/http"
	"path"
	"time"

	"github.com/go-logr/logr"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kuberecorder "k8s.io/client-go/tools/record"
	"k8s.io/client-go/tools/reference"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/events"
	"github.com/fluxcd/pkg/runtime/metrics"
	"github.com/fluxcd/pkg/runtime/predicates"
	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	sourcev1beta1 "github.com/fluxcd/source-controller/api/v1beta1"
	goomaha "github.com/kinvolk/go-omaha/omaha"
	oclient "github.com/kinvolk/go-omaha/omaha/client"
)

//+kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=omahas,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=omahas/status,verbs=get;update;patch

// OmahaReconciler reconciles a Omaha object
type OmahaReconciler struct {
	client.Client
	Scheme                *runtime.Scheme
	Storage               *Storage
	EventRecorder         kuberecorder.EventRecorder
	ExternalEventRecorder *events.Recorder
	MetricsRecorder       *metrics.Recorder
}

type OmahaReconcilerOptions struct {
	MaxConcurrentReconciles int
}

func (r *OmahaReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	start := time.Now()
	log := logr.FromContext(ctx)

	var omaha sourcev1beta1.Omaha
	if err := r.Get(ctx, req.NamespacedName, &omaha); err != nil {
		log.Error(err, "can't get Omaha", "Object", req.NamespacedName)
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Record suspended status metric
	defer r.recordSuspension(ctx, omaha)

	// Add our finalizer if it does not exist
	if !controllerutil.ContainsFinalizer(&omaha, sourcev1beta1.SourceFinalizer) {
		controllerutil.AddFinalizer(&omaha, sourcev1beta1.SourceFinalizer)
		if err := r.Update(ctx, &omaha); err != nil {
			log.Error(err, "unable to register finalizer")
			return ctrl.Result{}, err
		}
	}

	// Examine if the object is under deletion
	if !omaha.ObjectMeta.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, omaha)
	}

	// Return early if the object is suspended.
	if omaha.Spec.Suspend {
		log.Info("Reconciliation is suspended for this object")
		return ctrl.Result{}, nil
	}

	if r.MetricsRecorder != nil {
		objRef, err := reference.GetReference(r.Scheme, &omaha)
		if err != nil {
			return ctrl.Result{}, err
		}
		defer r.MetricsRecorder.RecordDuration(*objRef, start)
	}

	// set initial status
	if resetOmaha, ok := r.resetStatus(omaha); ok {
		log.Info("status reset")
		omaha = resetOmaha
		if err := r.updateStatus(ctx, req, omaha.Status); err != nil {
			log.Error(err, "unable to update status")
			return ctrl.Result{Requeue: true}, err
		}
		r.recordReadiness(ctx, omaha)
	}

	// record the value of the reconciliation request, if any
	// TODO(hidde): would be better to defer this in combination with
	//   always patching the status sub-resource after a reconciliation.
	if v, ok := meta.ReconcileAnnotationValue(omaha.GetAnnotations()); ok {
		omaha.Status.SetLastHandledReconcileRequest(v)
	}

	// purge old artifacts from storage
	if err := r.gc(omaha); err != nil {
		log.Error(err, "unable to purge old artifacts")
	}

	// reconcile omaha by downloading its content
	reconciledOmaha, reconcileErr := r.reconcile(ctx, *omaha.DeepCopy())

	// update status with the reconciliation result
	if err := r.updateStatus(ctx, req, reconciledOmaha.Status); err != nil {
		log.Error(err, "unable to update status")
		return ctrl.Result{Requeue: true}, err
	}

	// if reconciliation failed, record the failure and requeue immediately
	if reconcileErr != nil {
		r.event(ctx, reconciledOmaha, events.EventSeverityError, reconcileErr.Error())
		r.recordReadiness(ctx, reconciledOmaha)
		return ctrl.Result{Requeue: true}, reconcileErr
	}

	// emit revision change event
	if omaha.Status.Artifact == nil || reconciledOmaha.Status.Artifact.Revision != omaha.Status.Artifact.Revision {
		log.Info("event")
		r.event(ctx, reconciledOmaha, events.EventSeverityInfo, sourcev1beta1.OmahaReadyMessage(reconciledOmaha))
	}
	r.recordReadiness(ctx, reconciledOmaha)

	log.Info(fmt.Sprintf("Reconciliation finished in %s, next run in %s",
		time.Now().Sub(start).String(),
		omaha.GetInterval().Duration.String(),
	))

	return ctrl.Result{RequeueAfter: omaha.GetInterval().Duration}, nil
}

func (r *OmahaReconciler) reconcile(ctx context.Context, omaha sourcev1beta1.Omaha) (sourcev1beta1.Omaha, error) {
	log := logr.FromContext(ctx)

	// oc, err := oclient.New(omaha.Spec.URL, string(omaha.UID))
	// if err != nil {
	// 	return sourcev1beta1.OmahaNotReady(omaha, sourcev1beta1.URLInvalidReason, err.Error()), err
	// }

	version := omaha.Status.AppVersion
	if version == "" {
		version = "0.0.0"
	}

	appc, err := oclient.NewAppClient(omaha.Spec.URL, string(omaha.UID), omaha.Spec.AppID, version)
	if err != nil {
		return sourcev1beta1.OmahaNotReady(omaha, sourcev1beta1.URLInvalidReason, err.Error()), err
	}

	if omaha.Spec.Arch == "" {
		appc.SetArch("all")
	} else {
		appc.SetArch(omaha.Spec.Arch)
	}

	appc.SetMachine(false)

	if err := appc.SetTrack(omaha.Spec.Track); err != nil {
		return sourcev1beta1.OmahaNotReady(omaha, sourcev1beta1.OmahaOperationFailedReason, err.Error()), err
	}

	upd, err := appc.UpdateCheck()
	if err != nil {
		log.Error(err, "updatecheck fail", "url", omaha.Spec.URL, "appID", omaha.Spec.AppID, "version", version)
		return sourcev1beta1.OmahaNotReady(omaha, sourcev1beta1.OmahaOperationFailedReason, err.Error()), err
	}

	switch upd.Status {
	case goomaha.NoUpdate:
		log.Info("no update")
		return omaha, nil
	case goomaha.UpdateOK:
		break
	default:
		err := fmt.Errorf("omaha status '%s': %w", upd.Status, err)
		return sourcev1beta1.OmahaNotReady(omaha, sourcev1beta1.OmahaOperationFailedReason, err.Error()), err
	}

	var url string

	switch l := len(upd.URLs); {
	case l == 0:
		err := errors.New("can't find URL")
		return sourcev1beta1.OmahaNotReady(omaha, sourcev1beta1.OmahaOperationFailedReason, err.Error()), err
	case l > 1:
		log.Info("answer with more than 1 url, keep only one")
		fallthrough
	case l == 1:
		url = upd.URLs[0].CodeBase
	}

	// for _, url := range upd.URLs {
	resp, err := http.Get(url)
	if err != nil {
		log.Error(err, "can't download file", "url", url)
		return sourcev1beta1.OmahaNotReady(omaha, sourcev1beta1.StorageOperationFailedReason, err.Error()), err
	}
	defer resp.Body.Close()

	newVersion := upd.Manifest.Version

	artifact := r.Storage.NewArtifactFor(omaha.Kind,
		omaha.GetObjectMeta(),
		newVersion,
		fmt.Sprintf("%s-%s", newVersion, path.Base(url)))

	// create artifact dir

	if err := r.Storage.MkdirAll(artifact); err != nil {
		err = fmt.Errorf("unable to create repository index directory: %w", err)
		return sourcev1.OmahaNotReady(omaha, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// acquire lock
	unlock, err := r.Storage.Lock(artifact)
	if err != nil {
		err = fmt.Errorf("unable to acquire lock: %w", err)
		return sourcev1.OmahaNotReady(omaha, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	defer unlock()

	if err := r.Storage.AtomicWriteFile(&artifact, resp.Body, 0644); err != nil {
		err := fmt.Errorf("can't store file: %w", err)
		return sourcev1beta1.OmahaNotReady(omaha, sourcev1beta1.StorageOperationFailedReason, err.Error()), err
	}

	storageURL, err := r.Storage.Symlink(artifact, "latest.tar.gz")
	if err != nil {
		err = fmt.Errorf("storage symlink error: %w", err)
		return sourcev1beta1.OmahaNotReady(omaha, sourcev1beta1.StorageOperationFailedReason, err.Error()), err
	}

	message := fmt.Sprintf("Fetched revision: %s", artifact.Revision)
	return sourcev1beta1.OmahaReady(omaha, &artifact, storageURL, sourcev1beta1.OmahaOperationSucceedReason, message), nil
}

func (r *OmahaReconciler) reconcileDelete(ctx context.Context, omaha sourcev1beta1.Omaha) (ctrl.Result, error) {
	if err := r.gc(omaha); err != nil {
		r.event(ctx, omaha, events.EventSeverityError,
			fmt.Sprintf("garbage collection for deleted resource failed: %s", err.Error()))
		// Return the error so we retry the failed garbage collection
		return ctrl.Result{}, err
	}

	// Record deleted status
	r.recordReadiness(ctx, omaha)

	// Remove our finalizer from the list and update it
	controllerutil.RemoveFinalizer(&omaha, sourcev1.SourceFinalizer)
	if err := r.Update(ctx, &omaha); err != nil {
		return ctrl.Result{}, err
	}

	// Stop reconciliation as the object is being deleted
	return ctrl.Result{}, nil
}

// resetStatus returns a modified v1beta1.Omaha and a boolean indicating
// if the status field has been reset.
func (r *OmahaReconciler) resetStatus(omaha sourcev1beta1.Omaha) (sourcev1beta1.Omaha, bool) {
	// We do not have an artifact, or it does no longer exist
	if omaha.GetArtifact() == nil || !r.Storage.ArtifactExist(*omaha.GetArtifact()) {
		omaha = sourcev1beta1.OmahaProgressing(omaha)
		omaha.Status.Artifact = nil
		return omaha, true
	}
	if omaha.Generation != omaha.Status.ObservedGeneration {
		return sourcev1beta1.OmahaProgressing(omaha), true
	}
	return omaha, false
}

// gc performs a garbage collection for the given v1beta1.Omaha.
// It removes all but the current artifact except for when the
// deletion timestamp is set, which will result in the removal of
// all artifacts for the resource.
func (r *OmahaReconciler) gc(omaha sourcev1beta1.Omaha) error {
	if !omaha.DeletionTimestamp.IsZero() {
		return r.Storage.RemoveAll(r.Storage.NewArtifactFor(omaha.Kind, omaha.GetObjectMeta(), "", "*"))
	}
	if omaha.GetArtifact() != nil {
		return r.Storage.RemoveAllButCurrent(*omaha.GetArtifact())
	}
	return nil
}

// event emits a Kubernetes event and forwards the event to notification controller if configured
func (r *OmahaReconciler) event(ctx context.Context, omaha sourcev1beta1.Omaha, severity, msg string) {
	log := logr.FromContext(ctx)
	if r.EventRecorder != nil {
		r.EventRecorder.Eventf(&omaha, "Normal", severity, msg)
	}
	if r.ExternalEventRecorder != nil {
		objRef, err := reference.GetReference(r.Scheme, &omaha)
		if err != nil {
			log.Error(err, "unable to send event")
			return
		}

		if err := r.ExternalEventRecorder.Eventf(*objRef, nil, severity, severity, msg); err != nil {
			log.Error(err, "unable to send event")
			return
		}
	}
}

func (r *OmahaReconciler) recordReadiness(ctx context.Context, omaha sourcev1beta1.Omaha) {
	log := logr.FromContext(ctx)
	if r.MetricsRecorder == nil {
		return
	}
	objRef, err := reference.GetReference(r.Scheme, &omaha)
	if err != nil {
		log.Error(err, "unable to record readiness metric")
		return
	}
	if rc := apimeta.FindStatusCondition(omaha.Status.Conditions, meta.ReadyCondition); rc != nil {
		r.MetricsRecorder.RecordCondition(*objRef, *rc, !omaha.DeletionTimestamp.IsZero())
	} else {
		r.MetricsRecorder.RecordCondition(*objRef, metav1.Condition{
			Type:   meta.ReadyCondition,
			Status: metav1.ConditionUnknown,
		}, !omaha.DeletionTimestamp.IsZero())
	}
}

func (r *OmahaReconciler) recordSuspension(ctx context.Context, omaha sourcev1beta1.Omaha) {
	if r.MetricsRecorder == nil {
		return
	}
	log := logr.FromContext(ctx)

	objRef, err := reference.GetReference(r.Scheme, &omaha)
	if err != nil {
		log.Error(err, "unable to record suspended metric")
		return
	}

	if !omaha.DeletionTimestamp.IsZero() {
		r.MetricsRecorder.RecordSuspend(*objRef, false)
	} else {
		r.MetricsRecorder.RecordSuspend(*objRef, omaha.Spec.Suspend)
	}
}

func (r *OmahaReconciler) updateStatus(ctx context.Context, req ctrl.Request, newStatus sourcev1beta1.OmahaStatus) error {
	var omaha sourcev1beta1.Omaha
	if err := r.Get(ctx, req.NamespacedName, &omaha); err != nil {
		return err
	}

	patch := client.MergeFrom(omaha.DeepCopy())
	omaha.Status = newStatus

	return r.Status().Patch(ctx, &omaha, patch)
}

// SetupWithManager sets up the controller with the Manager.
func (r *OmahaReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return r.SetupWithManagerAndOptions(mgr, OmahaReconcilerOptions{})
}

func (r *OmahaReconciler) SetupWithManagerAndOptions(mgr ctrl.Manager, opts OmahaReconcilerOptions) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sourcev1beta1.Omaha{}).
		WithEventFilter(predicate.Or(predicate.GenerationChangedPredicate{}, predicates.ReconcileRequestedPredicate{})).
		WithOptions(controller.Options{MaxConcurrentReconciles: opts.MaxConcurrentReconciles}).
		Complete(r)
}
