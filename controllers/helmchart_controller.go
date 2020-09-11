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
	"os"
	"path"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/getter"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kuberecorder "k8s.io/client-go/tools/record"
	"k8s.io/client-go/tools/reference"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	"github.com/fluxcd/pkg/recorder"
	"github.com/fluxcd/pkg/runtime/predicates"
	"github.com/fluxcd/pkg/untar"

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
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

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
	if resetChart, ok := r.resetStatus(chart); ok {
		chart = resetChart
		if err := r.Status().Update(ctx, &chart); err != nil {
			log.Error(err, "unable to update status")
			return ctrl.Result{Requeue: true}, err
		}
	}

	// purge old artifacts from storage
	if err := r.gc(chart, false); err != nil {
		log.Error(err, "unable to purge old artifacts")
	}

	var reconciledChart sourcev1.HelmChart
	var reconcileErr error
	switch chart.Spec.SourceRef.Kind {
	case sourcev1.HelmRepositoryKind:
		repository, err := r.getChartRepositoryWithArtifact(ctx, chart)
		if err != nil {
			chart = sourcev1.HelmChartNotReady(*chart.DeepCopy(), sourcev1.ChartPullFailedReason, err.Error())
			if err := r.Status().Update(ctx, &chart); err != nil {
				log.Error(err, "unable to update status")
			}
			return ctrl.Result{Requeue: true}, err
		}
		reconciledChart, reconcileErr = r.reconcileFromHelmRepository(ctx, repository, *chart.DeepCopy())
	case sourcev1.GitRepositoryKind:
		repository, err := r.getGitRepositoryWithArtifact(ctx, chart)
		if err != nil {
			chart = sourcev1.HelmChartNotReady(*chart.DeepCopy(), sourcev1.ChartPullFailedReason, err.Error())
			if err := r.Status().Update(ctx, &chart); err != nil {
				log.Error(err, "unable to update status")
			}
			return ctrl.Result{Requeue: true}, err
		}
		reconciledChart, reconcileErr = r.reconcileFromGitRepository(ctx, repository, *chart.DeepCopy())
	default:
		err := fmt.Errorf("unable to reconcile unsupported source reference kind '%s'", chart.Spec.SourceRef.Kind)
		return ctrl.Result{}, err
	}

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
		WithEventFilter(predicates.ChangePredicate{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: opts.MaxConcurrentReconciles}).
		Complete(r)
}

func (r *HelmChartReconciler) reconcileFromHelmRepository(ctx context.Context,
	repository sourcev1.HelmRepository, chart sourcev1.HelmChart) (sourcev1.HelmChart, error) {
	cv, err := helm.GetDownloadableChartVersionFromIndex(r.Storage.LocalPath(*repository.GetArtifact()),
		chart.Spec.Chart, chart.Spec.Version)
	if err != nil {
		return sourcev1.HelmChartNotReady(chart, sourcev1.ChartPullFailedReason, err.Error()), err
	}

	// return early on unchanged chart version
	artifact := r.Storage.NewArtifactFor(chart.Kind, chart.GetObjectMeta(), cv.Version, fmt.Sprintf("%s-%s.tgz", cv.Name, cv.Version))
	if repository.GetArtifact() != nil && repository.GetArtifact().Revision == cv.Version {
		if artifact.URL != repository.GetArtifact().URL {
			r.Storage.SetArtifactURL(repository.GetArtifact())
			repository.Status.URL = r.Storage.SetHostname(repository.Status.URL)
		}
		return chart, nil
	}

	// TODO(hidde): according to the Helm source the first item is not
	//  always the correct one to pick, check for updates once in awhile.
	//  Ref: https://github.com/helm/helm/blob/v3.3.0/pkg/downloader/chart_downloader.go#L241
	ref := cv.URLs[0]
	u, err := url.Parse(ref)
	if err != nil {
		err = fmt.Errorf("invalid chart URL format '%s': %w", ref, err)
	}

	// Prepend the chart repository base URL if the URL is relative
	if !u.IsAbs() {
		repoURL, err := url.Parse(repository.Spec.URL)
		if err != nil {
			err = fmt.Errorf("invalid repository URL format '%s': %w", repository.Spec.URL, err)
			return sourcev1.HelmChartNotReady(chart, sourcev1.ChartPullFailedReason, err.Error()), err
		}
		q := repoURL.Query()
		// Trailing slash is required for ResolveReference to work
		repoURL.Path = strings.TrimSuffix(repoURL.Path, "/") + "/"
		u = repoURL.ResolveReference(u)
		u.RawQuery = q.Encode()
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

	// create artifact dir
	err = r.Storage.MkdirAll(artifact)
	if err != nil {
		err = fmt.Errorf("unable to create chart directory: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// acquire lock
	unlock, err := r.Storage.Lock(artifact)
	if err != nil {
		err = fmt.Errorf("unable to acquire lock: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	defer unlock()

	// save artifact to storage
	if err := r.Storage.AtomicWriteFile(&artifact, res, 0644); err != nil {
		err = fmt.Errorf("unable to write chart file: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// update symlink
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
	if chart.Spec.SourceRef.Name == "" {
		return sourcev1.HelmRepository{}, fmt.Errorf("no HelmRepository reference given")
	}

	name := types.NamespacedName{
		Namespace: chart.GetNamespace(),
		Name:      chart.Spec.SourceRef.Name,
	}

	var repository sourcev1.HelmRepository
	err := r.Client.Get(ctx, name, &repository)
	if err != nil {
		err = fmt.Errorf("failed to get HelmRepository '%s': %w", name, err)
		return repository, err
	}

	if repository.GetArtifact() == nil {
		err = fmt.Errorf("no repository index artifact found in HelmRepository '%s'", repository.Name)
	}

	return repository, err
}

func (r *HelmChartReconciler) reconcileFromGitRepository(ctx context.Context,
	repository sourcev1.GitRepository, chart sourcev1.HelmChart) (sourcev1.HelmChart, error) {
	// create tmp dir
	tmpDir, err := ioutil.TempDir("", fmt.Sprintf("%s-%s", chart.Namespace, chart.Name))
	if err != nil {
		err = fmt.Errorf("tmp dir error: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	defer os.RemoveAll(tmpDir)

	// open file
	f, err := os.Open(r.Storage.LocalPath(*repository.GetArtifact()))
	if err != nil {
		err = fmt.Errorf("artifact open error: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// extract artifact files
	if _, err = untar.Untar(f, tmpDir); err != nil {
		err = fmt.Errorf("artifact untar error: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// ensure configured path is a chart directory
	chartPath := path.Join(tmpDir, chart.Spec.Chart)
	if _, err := chartutil.IsChartDir(chartPath); err != nil {
		err = fmt.Errorf("chart path error: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// read chart metadata
	chartMetadata, err := chartutil.LoadChartfile(path.Join(chartPath, chartutil.ChartfileName))
	if err != nil {
		err = fmt.Errorf("load chart metadata error: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// return early on unchanged chart version
	artifact := r.Storage.NewArtifactFor(chart.Kind, chart.ObjectMeta.GetObjectMeta(), chartMetadata.Version, fmt.Sprintf("%s-%s.tgz", chartMetadata.Name, chartMetadata.Version))
	if chart.GetArtifact() != nil && chart.GetArtifact().Revision == chartMetadata.Version {
		if artifact.URL != repository.GetArtifact().URL {
			r.Storage.SetArtifactURL(repository.GetArtifact())
			repository.Status.URL = r.Storage.SetHostname(repository.Status.URL)
		}
		return chart, nil
	}

	// create artifact dir
	err = r.Storage.MkdirAll(artifact)
	if err != nil {
		err = fmt.Errorf("unable to create artifact directory: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// acquire lock
	unlock, err := r.Storage.Lock(artifact)
	if err != nil {
		err = fmt.Errorf("unable to acquire lock: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	defer unlock()

	// package chart
	pkg := action.NewPackage()
	pkg.Destination = tmpDir
	src, err := pkg.Run(chartPath, nil)
	if err != nil {
		err = fmt.Errorf("chart package error: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.ChartPackageFailedReason, err.Error()), err
	}

	// copy chart package
	cf, err := os.Open(src)
	if err != nil {
		err = fmt.Errorf("failed to open chart package: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	if err := r.Storage.Copy(&artifact, cf); err != nil {
		cf.Close()
		err = fmt.Errorf("failed to copy chart package to storage: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	cf.Close()

	// update symlink
	cUrl, err := r.Storage.Symlink(artifact, fmt.Sprintf("%s-latest.tgz", chartMetadata.Name))
	if err != nil {
		err = fmt.Errorf("storage error: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	message := fmt.Sprintf("Fetched and packaged revision: %s", artifact.Revision)
	return sourcev1.HelmChartReady(chart, artifact, cUrl, sourcev1.ChartPackageSucceededReason, message), nil
}

// getGitRepositoryWithArtifact attempts to get the GitRepository for the given
// chart. It returns an error if the GitRepository could not be retrieved or
// does not have an artifact.
func (r *HelmChartReconciler) getGitRepositoryWithArtifact(ctx context.Context, chart sourcev1.HelmChart) (sourcev1.GitRepository, error) {
	if chart.Spec.SourceRef.Name == "" {
		return sourcev1.GitRepository{}, fmt.Errorf("no GitRepository reference given")
	}

	name := types.NamespacedName{
		Namespace: chart.GetNamespace(),
		Name:      chart.Spec.SourceRef.Name,
	}

	var repository sourcev1.GitRepository
	err := r.Client.Get(ctx, name, &repository)
	if err != nil {
		err = fmt.Errorf("failed to get GitRepository '%s': %w", name, err)
		return repository, err
	}

	if repository.GetArtifact() == nil {
		err = fmt.Errorf("no artifact found for GitRepository '%s'", repository.Name)
	}

	return repository, err
}

// resetStatus returns a modified v1alpha1.HelmChart and a boolean indicating
// if the status field has been reset.
func (r *HelmChartReconciler) resetStatus(chart sourcev1.HelmChart) (sourcev1.HelmChart, bool) {
	if chart.GetArtifact() != nil && !r.Storage.ArtifactExist(*chart.GetArtifact()) {
		chart = sourcev1.HelmChartProgressing(chart)
		chart.Status.Artifact = nil
		return chart, true
	}
	if chart.Generation != chart.Status.ObservedGeneration {
		return sourcev1.HelmChartProgressing(chart), true
	}
	return chart, false
}

// gc performs a garbage collection on all but current artifacts of
// the given chart.
func (r *HelmChartReconciler) gc(chart sourcev1.HelmChart, all bool) error {
	if all {
		return r.Storage.RemoveAll(r.Storage.NewArtifactFor(chart.Kind, chart.GetObjectMeta(), "", ""))
	}
	if chart.GetArtifact() != nil {
		return r.Storage.RemoveAllButCurrent(*chart.GetArtifact())
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
