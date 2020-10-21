/*
Copyright 2020 The Flux CD contributors.

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
	"strings"
	"time"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/go-logr/logr"
	"helm.sh/helm/v3/pkg/getter"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kuberecorder "k8s.io/client-go/tools/record"
	"k8s.io/client-go/tools/reference"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/yaml"

	"github.com/fluxcd/pkg/runtime/events"
	"github.com/fluxcd/pkg/runtime/metrics"
	"github.com/fluxcd/pkg/runtime/predicates"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	"github.com/fluxcd/source-controller/internal/helm"
)

// HelmRepositoryReconciler reconciles a HelmRepository object
type HelmRepositoryReconciler struct {
	client.Client
	Log                   logr.Logger
	Scheme                *runtime.Scheme
	Storage               *Storage
	Getters               getter.Providers
	EventRecorder         kuberecorder.EventRecorder
	ExternalEventRecorder *events.Recorder
	MetricsRecorder       *metrics.Recorder
}

// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=helmrepositories,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=helmrepositories/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=helmcharts/finalizers,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

func (r *HelmRepositoryReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	start := time.Now()

	var repository sourcev1.HelmRepository
	if err := r.Get(ctx, req.NamespacedName, &repository); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log := r.Log.WithValues("controller", strings.ToLower(sourcev1.HelmRepositoryKind), "request", req.NamespacedName)

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
		if err := r.Status().Update(ctx, &repository); err != nil {
			log.Error(err, "unable to update status")
			return ctrl.Result{Requeue: true}, err
		}
		r.recordReadiness(repository, false)
	}

	// purge old artifacts from storage
	if err := r.gc(repository, false); err != nil {
		log.Error(err, "unable to purge old artifacts")
	}

	// reconcile repository by downloading the index.yaml file
	reconciledRepository, reconcileErr := r.reconcile(ctx, *repository.DeepCopy())

	// update status with the reconciliation result
	if err := r.Status().Update(ctx, &reconciledRepository); err != nil {
		log.Error(err, "unable to update status")
		return ctrl.Result{Requeue: true}, err
	}

	// if reconciliation failed, record the failure and requeue immediately
	if reconcileErr != nil {
		r.event(reconciledRepository, events.EventSeverityError, reconcileErr.Error())
		r.recordReadiness(reconciledRepository, false)
		return ctrl.Result{Requeue: true}, reconcileErr
	}

	// emit revision change event
	if repository.Status.Artifact == nil || reconciledRepository.Status.Artifact.Revision != repository.Status.Artifact.Revision {
		r.event(reconciledRepository, events.EventSeverityInfo, sourcev1.HelmRepositoryReadyMessage(reconciledRepository))
	}
	r.recordReadiness(reconciledRepository, false)

	log.Info(fmt.Sprintf("Reconciliation finished in %s, next run in %s",
		time.Now().Sub(start).String(),
		repository.GetInterval().Duration.String(),
	))

	return ctrl.Result{RequeueAfter: repository.GetInterval().Duration}, nil
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
		WithEventFilter(predicates.ChangePredicate{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: opts.MaxConcurrentReconciles}).
		Complete(r)
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
	clientOpts = append(clientOpts, getter.WithTimeout(repository.GetTimeout()))

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

	// return early on unchanged generation
	artifact := r.Storage.NewArtifactFor(repository.Kind,
		repository.ObjectMeta.GetObjectMeta(),
		chartRepo.Index.Generated.Format(time.RFC3339Nano),
		fmt.Sprintf("index-%s.yaml", url.PathEscape(chartRepo.Index.Generated.Format(time.RFC3339Nano))))
	if meta.HasReadyCondition(repository.Status.Conditions) && repository.GetArtifact().HasRevision(artifact.Revision) {
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
	b, err := yaml.Marshal(&chartRepo.Index)
	if err != nil {
		return sourcev1.HelmRepositoryNotReady(repository, sourcev1.IndexationFailedReason, err.Error()), err
	}
	if err := r.Storage.AtomicWriteFile(&artifact, bytes.NewReader(b), 0644); err != nil {
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
	if err := r.gc(repository, true); err != nil {
		r.event(repository, events.EventSeverityError, fmt.Sprintf("garbage collection for deleted resource failed: %s", err.Error()))
		// Return the error so we retry the failed garbage collection
		return ctrl.Result{}, err
	}

	// Record deleted status
	r.recordReadiness(repository, true)

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

// gc performs a garbage collection on all but current artifacts of
// the given repository.
func (r *HelmRepositoryReconciler) gc(repository sourcev1.HelmRepository, all bool) error {
	if all {
		return r.Storage.RemoveAll(r.Storage.NewArtifactFor(repository.Kind, repository.GetObjectMeta(), "", ""))
	}
	if repository.GetArtifact() != nil {
		return r.Storage.RemoveAllButCurrent(*repository.GetArtifact())
	}
	return nil
}

// event emits a Kubernetes event and forwards the event to notification controller if configured
func (r *HelmRepositoryReconciler) event(repository sourcev1.HelmRepository, severity, msg string) {
	if r.EventRecorder != nil {
		r.EventRecorder.Eventf(&repository, "Normal", severity, msg)
	}
	if r.ExternalEventRecorder != nil {
		objRef, err := reference.GetReference(r.Scheme, &repository)
		if err != nil {
			r.Log.WithValues(
				"request",
				fmt.Sprintf("%s/%s", repository.GetNamespace(), repository.GetName()),
			).Error(err, "unable to send event")
			return
		}

		if err := r.ExternalEventRecorder.Eventf(*objRef, nil, severity, severity, msg); err != nil {
			r.Log.WithValues(
				"request",
				fmt.Sprintf("%s/%s", repository.GetNamespace(), repository.GetName()),
			).Error(err, "unable to send event")
			return
		}
	}
}

func (r *HelmRepositoryReconciler) recordReadiness(repository sourcev1.HelmRepository, deleted bool) {
	if r.MetricsRecorder == nil {
		return
	}

	objRef, err := reference.GetReference(r.Scheme, &repository)
	if err != nil {
		r.Log.WithValues(
			strings.ToLower(repository.Kind),
			fmt.Sprintf("%s/%s", repository.GetNamespace(), repository.GetName()),
		).Error(err, "unable to record readiness metric")
		return
	}
	if rc := meta.GetCondition(repository.Status.Conditions, meta.ReadyCondition); rc != nil {
		r.MetricsRecorder.RecordCondition(*objRef, *rc, deleted)
	} else {
		r.MetricsRecorder.RecordCondition(*objRef, meta.Condition{
			Type:   meta.ReadyCondition,
			Status: corev1.ConditionUnknown,
		}, deleted)
	}
}
