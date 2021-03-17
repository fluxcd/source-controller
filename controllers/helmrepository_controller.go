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
	"net/url"
	"time"

	"github.com/go-logr/logr"
	"helm.sh/helm/v3/pkg/getter"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kuberecorder "k8s.io/client-go/tools/record"
	"k8s.io/client-go/tools/reference"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/yaml"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/events"
	"github.com/fluxcd/pkg/runtime/metrics"
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
	Scheme                *runtime.Scheme
	Storage               *Storage
	Getters               getter.Providers
	EventRecorder         kuberecorder.EventRecorder
	ExternalEventRecorder *events.Recorder
	MetricsRecorder       *metrics.Recorder
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

func (r *HelmRepositoryReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	start := time.Now()
	log := logr.FromContext(ctx)

	var repository sourcev1.HelmRepository
	if err := r.Get(ctx, req.NamespacedName, &repository); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Add our finalizer if it does not exist
	if !controllerutil.ContainsFinalizer(&repository, sourcev1.SourceFinalizer) {
		controllerutil.AddFinalizer(&repository, sourcev1.SourceFinalizer)
		if err := r.Update(ctx, &repository); err != nil {
			log.Error(err, "unable to register finalizer")
			return ctrl.Result{}, err
		}
	}

	// Examine if the object is under deletion
	if !repository.ObjectMeta.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, repository)
	}

	// Return early if the object is suspended.
	if repository.Spec.Suspend {
		log.Info("Reconciliation is suspended for this object")
		return ctrl.Result{}, nil
	}

	// record reconciliation duration
	if r.MetricsRecorder != nil {
		objRef, err := reference.GetReference(r.Scheme, &repository)
		if err != nil {
			return ctrl.Result{}, err
		}
		defer r.MetricsRecorder.RecordDuration(*objRef, start)
	}

	// set initial status
	if resetRepository, ok := r.resetStatus(repository); ok {
		repository = resetRepository
		if err := r.updateStatus(ctx, req, repository.Status); err != nil {
			log.Error(err, "unable to update status")
			return ctrl.Result{Requeue: true}, err
		}
		r.recordReadiness(ctx, repository)
	}

	// record the value of the reconciliation request, if any
	// TODO(hidde): would be better to defer this in combination with
	//   always patching the status sub-resource after a reconciliation.
	if v, ok := meta.ReconcileAnnotationValue(repository.GetAnnotations()); ok {
		repository.Status.SetLastHandledReconcileRequest(v)
	}

	// purge old artifacts from storage
	if err := r.gc(repository); err != nil {
		log.Error(err, "unable to purge old artifacts")
	}

	// reconcile repository by downloading the index.yaml file
	reconciledRepository, reconcileErr := r.reconcile(ctx, *repository.DeepCopy())

	// update status with the reconciliation result
	if err := r.updateStatus(ctx, req, reconciledRepository.Status); err != nil {
		log.Error(err, "unable to update status")
		return ctrl.Result{Requeue: true}, err
	}

	// if reconciliation failed, record the failure and requeue immediately
	if reconcileErr != nil {
		r.event(ctx, reconciledRepository, events.EventSeverityError, reconcileErr.Error())
		r.recordReadiness(ctx, reconciledRepository)
		return ctrl.Result{Requeue: true}, reconcileErr
	}

	// emit revision change event
	if repository.Status.Artifact == nil || reconciledRepository.Status.Artifact.Revision != repository.Status.Artifact.Revision {
		r.event(ctx, reconciledRepository, events.EventSeverityInfo, sourcev1.HelmRepositoryReadyMessage(reconciledRepository))
	}
	r.recordReadiness(ctx, reconciledRepository)

	log.Info(fmt.Sprintf("Reconciliation finished in %s, next run in %s",
		time.Now().Sub(start).String(),
		repository.GetInterval().Duration.String(),
	))

	return ctrl.Result{RequeueAfter: repository.GetInterval().Duration}, nil
}

func (r *HelmRepositoryReconciler) reconcile(ctx context.Context, repository sourcev1.HelmRepository) (sourcev1.HelmRepository, error) {
	var clientOpts []getter.Option
	if repository.Spec.SecretRef != nil {
		name := types.NamespacedName{
			Namespace: repository.GetNamespace(),
			Name:      repository.Spec.SecretRef.Name,
		}

		var secret corev1.Secret
		err := r.Client.Get(ctx, name, &secret)
		if err != nil {
			err = fmt.Errorf("auth secret error: %w", err)
			return sourcev1.HelmRepositoryNotReady(repository, sourcev1.AuthenticationFailedReason, err.Error()), err
		}

		opts, cleanup, err := helm.ClientOptionsFromSecret(secret)
		if err != nil {
			err = fmt.Errorf("auth options error: %w", err)
			return sourcev1.HelmRepositoryNotReady(repository, sourcev1.AuthenticationFailedReason, err.Error()), err
		}
		defer cleanup()
		clientOpts = opts
	}
	clientOpts = append(clientOpts, getter.WithTimeout(repository.Spec.Timeout.Duration))

	chartRepo, err := helm.NewChartRepository(repository.Spec.URL, r.Getters, clientOpts)
	if err != nil {
		switch err.(type) {
		case *url.Error:
			return sourcev1.HelmRepositoryNotReady(repository, sourcev1.URLInvalidReason, err.Error()), err
		default:
			return sourcev1.HelmRepositoryNotReady(repository, sourcev1.IndexationFailedReason, err.Error()), err
		}
	}
	if err := chartRepo.DownloadIndex(); err != nil {
		err = fmt.Errorf("failed to download repository index: %w", err)
		return sourcev1.HelmRepositoryNotReady(repository, sourcev1.IndexationFailedReason, err.Error()), err
	}

	indexBytes, err := yaml.Marshal(&chartRepo.Index)
	if err != nil {
		return sourcev1.HelmRepositoryNotReady(repository, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	hash := r.Storage.Checksum(bytes.NewReader(indexBytes))
	artifact := r.Storage.NewArtifactFor(repository.Kind,
		repository.ObjectMeta.GetObjectMeta(),
		hash,
		fmt.Sprintf("index-%s.yaml", hash))
	// return early on unchanged index
	if apimeta.IsStatusConditionTrue(repository.Status.Conditions, meta.ReadyCondition) && repository.GetArtifact().HasRevision(artifact.Revision) {
		if artifact.URL != repository.GetArtifact().URL {
			r.Storage.SetArtifactURL(repository.GetArtifact())
			repository.Status.URL = r.Storage.SetHostname(repository.Status.URL)
		}
		return repository, nil
	}

	// create artifact dir
	err = r.Storage.MkdirAll(artifact)
	if err != nil {
		err = fmt.Errorf("unable to create repository index directory: %w", err)
		return sourcev1.HelmRepositoryNotReady(repository, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// acquire lock
	unlock, err := r.Storage.Lock(artifact)
	if err != nil {
		err = fmt.Errorf("unable to acquire lock: %w", err)
		return sourcev1.HelmRepositoryNotReady(repository, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	defer unlock()

	// save artifact to storage
	if err := r.Storage.AtomicWriteFile(&artifact, bytes.NewReader(indexBytes), 0644); err != nil {
		err = fmt.Errorf("unable to write repository index file: %w", err)
		return sourcev1.HelmRepositoryNotReady(repository, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// update index symlink
	indexURL, err := r.Storage.Symlink(artifact, "index.yaml")
	if err != nil {
		err = fmt.Errorf("storage error: %w", err)
		return sourcev1.HelmRepositoryNotReady(repository, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	message := fmt.Sprintf("Fetched revision: %s", artifact.Revision)
	return sourcev1.HelmRepositoryReady(repository, artifact, indexURL, sourcev1.IndexationSucceededReason, message), nil
}

func (r *HelmRepositoryReconciler) reconcileDelete(ctx context.Context, repository sourcev1.HelmRepository) (ctrl.Result, error) {
	// Our finalizer is still present, so lets handle garbage collection
	if err := r.gc(repository); err != nil {
		r.event(ctx, repository, events.EventSeverityError,
			fmt.Sprintf("garbage collection for deleted resource failed: %s", err.Error()))
		// Return the error so we retry the failed garbage collection
		return ctrl.Result{}, err
	}

	// Record deleted status
	r.recordReadiness(ctx, repository)

	// Remove our finalizer from the list and update it
	controllerutil.RemoveFinalizer(&repository, sourcev1.SourceFinalizer)
	if err := r.Update(ctx, &repository); err != nil {
		return ctrl.Result{}, err
	}

	// Stop reconciliation as the object is being deleted
	return ctrl.Result{}, nil
}

// resetStatus returns a modified v1beta1.HelmRepository and a boolean indicating
// if the status field has been reset.
func (r *HelmRepositoryReconciler) resetStatus(repository sourcev1.HelmRepository) (sourcev1.HelmRepository, bool) {
	// We do not have an artifact, or it does no longer exist
	if repository.GetArtifact() == nil || !r.Storage.ArtifactExist(*repository.GetArtifact()) {
		repository = sourcev1.HelmRepositoryProgressing(repository)
		repository.Status.Artifact = nil
		return repository, true
	}
	if repository.Generation != repository.Status.ObservedGeneration {
		return sourcev1.HelmRepositoryProgressing(repository), true
	}
	return repository, false
}

// gc performs a garbage collection for the given v1beta1.HelmRepository.
// It removes all but the current artifact except for when the
// deletion timestamp is set, which will result in the removal of
// all artifacts for the resource.
func (r *HelmRepositoryReconciler) gc(repository sourcev1.HelmRepository) error {
	if !repository.DeletionTimestamp.IsZero() {
		return r.Storage.RemoveAll(r.Storage.NewArtifactFor(repository.Kind, repository.GetObjectMeta(), "", "*"))
	}
	if repository.GetArtifact() != nil {
		return r.Storage.RemoveAllButCurrent(*repository.GetArtifact())
	}
	return nil
}

// event emits a Kubernetes event and forwards the event to notification controller if configured
func (r *HelmRepositoryReconciler) event(ctx context.Context, repository sourcev1.HelmRepository, severity, msg string) {
	log := logr.FromContext(ctx)
	if r.EventRecorder != nil {
		r.EventRecorder.Eventf(&repository, "Normal", severity, msg)
	}
	if r.ExternalEventRecorder != nil {
		objRef, err := reference.GetReference(r.Scheme, &repository)
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

func (r *HelmRepositoryReconciler) recordReadiness(ctx context.Context, repository sourcev1.HelmRepository) {
	log := logr.FromContext(ctx)
	if r.MetricsRecorder == nil {
		return
	}
	objRef, err := reference.GetReference(r.Scheme, &repository)
	if err != nil {
		log.Error(err, "unable to record readiness metric")
		return
	}
	if rc := apimeta.FindStatusCondition(repository.Status.Conditions, meta.ReadyCondition); rc != nil {
		r.MetricsRecorder.RecordCondition(*objRef, *rc, !repository.DeletionTimestamp.IsZero())
	} else {
		r.MetricsRecorder.RecordCondition(*objRef, metav1.Condition{
			Type:   meta.ReadyCondition,
			Status: metav1.ConditionUnknown,
		}, !repository.DeletionTimestamp.IsZero())
	}
}

func (r *HelmRepositoryReconciler) updateStatus(ctx context.Context, req ctrl.Request, newStatus sourcev1.HelmRepositoryStatus) error {
	var repository sourcev1.HelmRepository
	if err := r.Get(ctx, req.NamespacedName, &repository); err != nil {
		return err
	}

	patch := client.MergeFrom(repository.DeepCopy())
	repository.Status = newStatus

	return r.Status().Patch(ctx, &repository, patch)
}

func (r *HelmRepositoryReconciler) recordSuspension(ctx context.Context, hr sourcev1.HelmRepository) {
	if r.MetricsRecorder == nil {
		return
	}
	log := logr.FromContext(ctx)

	objRef, err := reference.GetReference(r.Scheme, &hr)
	if err != nil {
		log.Error(err, "unable to record suspended metric")
		return
	}

	if !hr.DeletionTimestamp.IsZero() {
		r.MetricsRecorder.RecordSuspend(*objRef, false)
	} else {
		r.MetricsRecorder.RecordSuspend(*objRef, hr.Spec.Suspend)
	}
}
