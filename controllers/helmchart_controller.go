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
	"context"
	"fmt"
	"io/ioutil"
	"net/url"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/repo"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kuberecorder "k8s.io/client-go/tools/record"
	"k8s.io/client-go/tools/reference"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/yaml"

	"github.com/fluxcd/pkg/recorder"
	sourcev1 "github.com/fluxcd/source-controller/api/v1alpha1"
	"github.com/fluxcd/source-controller/internal/helm"
)

// HelmChartReconciler reconciles a HelmChart object
type HelmChartReconciler struct {
	client.Client
	Log                   logr.Logger
	Scheme                *runtime.Scheme
	Storage               *Storage
	Getters               getter.Providers
	EventRecorder         kuberecorder.EventRecorder
	ExternalEventRecorder *recorder.EventRecorder
}

// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=helmcharts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=helmcharts/status,verbs=get;update;patch

func (r *HelmChartReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	start := time.Now()

	var chart sourcev1.HelmChart
	if err := r.Get(ctx, req.NamespacedName, &chart); err != nil {
		return ctrl.Result{Requeue: true}, client.IgnoreNotFound(err)
	}

	log := r.Log.WithValues("controller", strings.ToLower(sourcev1.HelmChartKind), "request", req.NamespacedName)

	// Examine if the object is under deletion
	if chart.ObjectMeta.DeletionTimestamp.IsZero() {
		// The object is not being deleted, so if it does not have our finalizer,
		// then lets add the finalizer and update the object. This is equivalent
		// registering our finalizer.
		if !containsString(chart.ObjectMeta.Finalizers, sourcev1.SourceFinalizer) {
			chart.ObjectMeta.Finalizers = append(chart.ObjectMeta.Finalizers, sourcev1.SourceFinalizer)
			if err := r.Update(ctx, &chart); err != nil {
				log.Error(err, "unable to register finalizer")
				return ctrl.Result{}, err
			}
		}
	} else {
		// The object is being deleted
		if containsString(chart.ObjectMeta.Finalizers, sourcev1.SourceFinalizer) {
			// Our finalizer is still present, so lets handle garbage collection
			if err := r.gc(chart, true); err != nil {
				r.event(chart, recorder.EventSeverityError, fmt.Sprintf("garbage collection for deleted resource failed: %s", err.Error()))
				// Return the error so we retry the failed garbage collection
				return ctrl.Result{}, err
			}
			// Remove our finalizer from the list and update it
			chart.ObjectMeta.Finalizers = removeString(chart.ObjectMeta.Finalizers, sourcev1.SourceFinalizer)
			if err := r.Update(ctx, &chart); err != nil {
				return ctrl.Result{}, err
			}
			// Stop reconciliation as the object is being deleted
			return ctrl.Result{}, nil
		}
	}

	// set initial status
	if reset, status := r.shouldResetStatus(chart); reset {
		chart.Status = status
		if err := r.Status().Update(ctx, &chart); err != nil {
			log.Error(err, "unable to update status")
			return ctrl.Result{Requeue: true}, err
		}
	} else {
		chart = sourcev1.HelmChartProgressing(chart)
		if err := r.Status().Update(ctx, &chart); err != nil {
			log.Error(err, "unable to update status")
			return ctrl.Result{Requeue: true}, err
		}
	}

	// purge old artifacts from storage
	if err := r.gc(chart, false); err != nil {
		log.Error(err, "unable to purge old artifacts")
	}

	// get referenced chart repository
	repository, err := r.getChartRepositoryWithArtifact(ctx, chart)
	if err != nil {
		chart = sourcev1.HelmChartNotReady(*chart.DeepCopy(), sourcev1.ChartPullFailedReason, err.Error())
		if err := r.Status().Update(ctx, &chart); err != nil {
			log.Error(err, "unable to update status")
		}
		return ctrl.Result{Requeue: true}, err
	}

	// reconcile repository by downloading the chart tarball
	reconciledChart, reconcileErr := r.reconcile(ctx, repository, *chart.DeepCopy())

	// update status with the reconciliation result
	if err := r.Status().Update(ctx, &reconciledChart); err != nil {
		log.Error(err, "unable to update status")
		return ctrl.Result{Requeue: true}, err
	}

	// if reconciliation failed, record the failure and requeue immediately
	if reconcileErr != nil {
		r.event(reconciledChart, recorder.EventSeverityError, reconcileErr.Error())
		return ctrl.Result{Requeue: true}, reconcileErr
	}

	// emit revision change event
	if chart.Status.Artifact == nil || reconciledChart.Status.Artifact.Revision != chart.Status.Artifact.Revision {
		r.event(reconciledChart, recorder.EventSeverityInfo, sourcev1.HelmChartReadyMessage(reconciledChart))
	}

	log.Info(fmt.Sprintf("Reconciliation finished in %s, next run in %s",
		time.Now().Sub(start).String(),
		chart.GetInterval().Duration.String(),
	))

	return ctrl.Result{RequeueAfter: chart.GetInterval().Duration}, nil
}

type HelmChartReconcilerOptions struct {
	MaxConcurrentReconciles int
}

func (r *HelmChartReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return r.SetupWithManagerAndOptions(mgr, HelmChartReconcilerOptions{})
}

func (r *HelmChartReconciler) SetupWithManagerAndOptions(mgr ctrl.Manager, opts HelmChartReconcilerOptions) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sourcev1.HelmChart{}).
		WithEventFilter(SourceChangePredicate{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: opts.MaxConcurrentReconciles}).
		Complete(r)
}

func (r *HelmChartReconciler) reconcile(ctx context.Context, repository sourcev1.HelmRepository, chart sourcev1.HelmChart) (sourcev1.HelmChart, error) {
	indexBytes, err := ioutil.ReadFile(repository.Status.Artifact.Path)
	if err != nil {
		err = fmt.Errorf("failed to read Helm repository index file: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	index := &repo.IndexFile{}
	if err := yaml.Unmarshal(indexBytes, index); err != nil {
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// find referenced chart in index
	cv, err := index.Get(chart.Spec.Name, chart.Spec.Version)
	if err != nil {
		switch err {
		case repo.ErrNoChartName:
			err = fmt.Errorf("chart '%s' could not be found in Helm repository '%s'", chart.Spec.Name, repository.Name)
		case repo.ErrNoChartVersion:
			err = fmt.Errorf("no chart with version '%s' found for '%s'", chart.Spec.Version, chart.Spec.Name)
		}
		return sourcev1.HelmChartNotReady(chart, sourcev1.ChartPullFailedReason, err.Error()), err
	}

	if len(cv.URLs) == 0 {
		err = fmt.Errorf("chart '%s' has no downloadable URLs", cv.Name)
		return sourcev1.HelmChartNotReady(chart, sourcev1.ChartPullFailedReason, err.Error()), err
	}

	// TODO(hidde): according to the Helm source the first item is not
	//  always the correct one to pick, check for updates once in awhile.
	ref := cv.URLs[0]
	u, err := url.Parse(ref)
	if err != nil {
		err = fmt.Errorf("invalid chart URL format '%s': %w", ref, err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.ChartPullFailedReason, err.Error()), err
	}

	c, err := r.Getters.ByScheme(u.Scheme)
	if err != nil {
		return sourcev1.HelmChartNotReady(chart, sourcev1.ChartPullFailedReason, err.Error()), err
	}

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
			return sourcev1.HelmChartNotReady(chart, sourcev1.AuthenticationFailedReason, err.Error()), err
		}

		opts, cleanup, err := helm.ClientOptionsFromSecret(secret)
		if err != nil {
			err = fmt.Errorf("auth options error: %w", err)
			return sourcev1.HelmChartNotReady(chart, sourcev1.AuthenticationFailedReason, err.Error()), err
		}
		if cleanup != nil {
			defer cleanup()
		}
		clientOpts = opts
	}

	// TODO(hidde): implement timeout from the HelmRepository
	//  https://github.com/helm/helm/pull/7950
	res, err := c.Get(u.String(), clientOpts...)
	if err != nil {
		return sourcev1.HelmChartNotReady(chart, sourcev1.ChartPullFailedReason, err.Error()), err
	}

	chartBytes, err := ioutil.ReadAll(res)
	if err != nil {
		return sourcev1.HelmChartNotReady(chart, sourcev1.ChartPullFailedReason, err.Error()), err
	}

	sum := r.Storage.Checksum(chartBytes)
	artifact := r.Storage.ArtifactFor(chart.Kind, chart.GetObjectMeta(),
		fmt.Sprintf("%s-%s-%s.tgz", cv.Name, cv.Version, sum), cv.Version)

	// create artifact dir
	err = r.Storage.MkdirAll(artifact)
	if err != nil {
		err = fmt.Errorf("unable to create chart directory: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.ChartPullFailedReason, err.Error()), err
	}

	// acquire lock
	unlock, err := r.Storage.Lock(artifact)
	if err != nil {
		err = fmt.Errorf("unable to acquire lock: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.ChartPullFailedReason, err.Error()), err
	}
	defer unlock()

	// save artifact to storage
	err = r.Storage.WriteFile(artifact, chartBytes)
	if err != nil {
		err = fmt.Errorf("unable to write chart file: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.ChartPullFailedReason, err.Error()), err
	}

	// update index symlink
	chartUrl, err := r.Storage.Symlink(artifact, fmt.Sprintf("%s-latest.tgz", cv.Name))
	if err != nil {
		err = fmt.Errorf("storage error: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	message := fmt.Sprintf("Fetched revision: %s", artifact.Revision)
	return sourcev1.HelmChartReady(chart, artifact, chartUrl, sourcev1.ChartPullSucceededReason, message), nil
}

// getChartRepositoryWithArtifact attempts to get the ChartRepository
// for the given chart. It returns an error if the HelmRepository could
// not be retrieved or if does not have an artifact.
func (r *HelmChartReconciler) getChartRepositoryWithArtifact(ctx context.Context, chart sourcev1.HelmChart) (sourcev1.HelmRepository, error) {
	if chart.Spec.HelmRepositoryRef.Name == "" {
		return sourcev1.HelmRepository{}, fmt.Errorf("no HelmRepository reference given")
	}

	name := types.NamespacedName{
		Namespace: chart.GetNamespace(),
		Name:      chart.Spec.HelmRepositoryRef.Name,
	}

	var repository sourcev1.HelmRepository
	err := r.Client.Get(ctx, name, &repository)
	if err != nil {
		err = fmt.Errorf("failed to get HelmRepository '%s': %w", name, err)
		return repository, err
	}

	if repository.Status.Artifact == nil {
		err = fmt.Errorf("no repository index artifect found in HelmRepository '%s'", repository.Name)
	}

	return repository, err
}

// shouldResetStatus returns a boolean indicating if the status of the
// given chart should be reset and a reset HelmChartStatus.
func (r *HelmChartReconciler) shouldResetStatus(chart sourcev1.HelmChart) (bool, sourcev1.HelmChartStatus) {
	resetStatus := false
	if chart.Status.Artifact != nil {
		if !r.Storage.ArtifactExist(*chart.Status.Artifact) {
			resetStatus = true
		}
	}

	// set initial status
	if len(chart.Status.Conditions) == 0 {
		resetStatus = true
	}

	return resetStatus, sourcev1.HelmChartStatus{
		Conditions: []sourcev1.SourceCondition{
			{
				Type:               sourcev1.ReadyCondition,
				Status:             corev1.ConditionUnknown,
				Reason:             sourcev1.InitializingReason,
				LastTransitionTime: metav1.Now(),
			},
		},
	}
}

// gc performs a garbage collection on all but current artifacts of
// the given chart.
func (r *HelmChartReconciler) gc(chart sourcev1.HelmChart, all bool) error {
	if chart.Status.Artifact != nil {
		if all {
			return r.Storage.RemoveAll(*chart.Status.Artifact)
		}
		return r.Storage.RemoveAllButCurrent(*chart.Status.Artifact)
	}
	return nil
}

// event emits a Kubernetes event and forwards the event to notification controller if configured
func (r *HelmChartReconciler) event(chart sourcev1.HelmChart, severity, msg string) {
	if r.EventRecorder != nil {
		r.EventRecorder.Eventf(&chart, "Normal", severity, msg)
	}
	if r.ExternalEventRecorder != nil {
		objRef, err := reference.GetReference(r.Scheme, &chart)
		if err != nil {
			r.Log.WithValues(
				"request",
				fmt.Sprintf("%s/%s", chart.GetNamespace(), chart.GetName()),
			).Error(err, "unable to send event")
			return
		}

		if err := r.ExternalEventRecorder.Eventf(*objRef, nil, severity, severity, msg); err != nil {
			r.Log.WithValues(
				"request",
				fmt.Sprintf("%s/%s", chart.GetNamespace(), chart.GetName()),
			).Error(err, "unable to send event")
			return
		}
	}
}
