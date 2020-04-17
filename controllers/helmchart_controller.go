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
	"time"

	"github.com/go-logr/logr"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/repo"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	sourcev1 "github.com/fluxcd/source-controller/api/v1alpha1"
	"github.com/fluxcd/source-controller/internal/helm"
)

// HelmChartReconciler reconciles a HelmChart object
type HelmChartReconciler struct {
	client.Client
	Log     logr.Logger
	Scheme  *runtime.Scheme
	Storage *Storage
	Getters getter.Providers
}

// +kubebuilder:rbac:groups=source.fluxcd.io,resources=helmcharts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=source.fluxcd.io,resources=helmcharts/status,verbs=get;update;patch

func (r *HelmChartReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var chart sourcev1.HelmChart
	if err := r.Get(ctx, req.NamespacedName, &chart); err != nil {
		return ctrl.Result{Requeue: true}, client.IgnoreNotFound(err)
	}

	log := r.Log.WithValues(chart.Kind, req.NamespacedName)

	// set initial status
	if reset, status := r.shouldResetStatus(chart); reset {
		log.Info("Initializing Helm chart")
		chart.Status = status
		if err := r.Status().Update(ctx, &chart); err != nil {
			log.Error(err, "unable to update HelmChart status")
			return ctrl.Result{Requeue: true}, err
		}
	}

	// try to remove old artifacts
	if err := r.gc(chart); err != nil {
		log.Error(err, "artifacts GC failed")
	}

	// get referenced chart repository
	repository, err := r.chartRepository(ctx, chart)
	if err != nil {
		chart = sourcev1.HelmChartNotReady(*chart.DeepCopy(), sourcev1.ChartPullFailedReason, err.Error())
		if err := r.Status().Update(ctx, &chart); err != nil {
			log.Error(err, "unable to update HelmChart status")
		}
		return ctrl.Result{Requeue: true}, err
	}

	// set ownership reference so chart is garbage collected on
	// repository removal
	if err := r.setOwnerRef(ctx, &chart, repository); err != nil {
		log.Error(err, "failed to set owner reference")
	}

	// try to pull chart
	pulledChart, err := r.sync(repository, *chart.DeepCopy())
	if err != nil {
		log.Error(err, "Helm chart sync failed")
		if err := r.Status().Update(ctx, &pulledChart); err != nil {
			log.Error(err, "unable to update HelmChart status")
		}
		return ctrl.Result{Requeue: true}, err
	}

	// update status
	if err := r.Status().Update(ctx, &pulledChart); err != nil {
		log.Error(err, "unable to update HelmChart status")
		return ctrl.Result{Requeue: true}, err
	}

	log.Info("Helm chart sync succeeded", "msg", sourcev1.HelmChartReadyMessage(pulledChart))

	// requeue chart
	return ctrl.Result{RequeueAfter: chart.GetInterval().Duration}, nil
}

func (r *HelmChartReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sourcev1.HelmChart{}).
		WithEventFilter(SourceChangePredicate{}).
		WithEventFilter(GarbageCollectPredicate{Scheme: r.Scheme, Log: r.Log, Storage: r.Storage}).
		Complete(r)
}

func (r *HelmChartReconciler) sync(repository sourcev1.HelmRepository, chart sourcev1.HelmChart) (sourcev1.HelmChart, error) {
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
		err := r.Client.Get(context.TODO(), name, &secret)
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

	message := fmt.Sprintf("Helm chart is available at: %s", artifact.Path)
	return sourcev1.HelmChartReady(chart, artifact, chartUrl, sourcev1.ChartPullSucceededReason, message), nil
}

func (r *HelmChartReconciler) chartRepository(ctx context.Context, chart sourcev1.HelmChart) (sourcev1.HelmRepository, error) {
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

func (r *HelmChartReconciler) shouldResetStatus(chart sourcev1.HelmChart) (bool, sourcev1.HelmChartStatus) {
	resetStatus := false
	if chart.Status.Artifact != nil {
		if !r.Storage.ArtifactExist(*chart.Status.Artifact) {
			resetStatus = true
		}
	}

	// set initial status
	if len(chart.Status.Conditions) == 0 || resetStatus {
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

func (r *HelmChartReconciler) gc(chart sourcev1.HelmChart) error {
	if chart.Status.Artifact != nil {
		return r.Storage.RemoveAllButCurrent(*chart.Status.Artifact)
	}
	return nil
}

func (r *HelmChartReconciler) setOwnerRef(ctx context.Context, chart *sourcev1.HelmChart, repository sourcev1.HelmRepository) error {
	if !metav1.IsControlledBy(chart.GetObjectMeta(), repository.GetObjectMeta()) {
		chart.SetOwnerReferences(append(chart.GetOwnerReferences(),
			*metav1.NewControllerRef(repository.GetObjectMeta(), repository.GroupVersionKind())))
		return r.Update(ctx, chart)
	}
	return nil
}
