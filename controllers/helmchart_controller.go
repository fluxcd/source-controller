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
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/go-logr/logr"
	"helm.sh/helm/v3/pkg/chart/loader"
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
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/fluxcd/pkg/runtime/events"
	"github.com/fluxcd/pkg/runtime/metrics"
	"github.com/fluxcd/pkg/runtime/predicates"
	"github.com/fluxcd/pkg/untar"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
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
	ExternalEventRecorder *events.Recorder
	MetricsRecorder       *metrics.Recorder
}

// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=helmcharts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=helmcharts/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=helmcharts/finalizers,verbs=get;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

func (r *HelmChartReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	start := time.Now()

	var chart sourcev1.HelmChart
	if err := r.Get(ctx, req.NamespacedName, &chart); err != nil {
		return ctrl.Result{Requeue: true}, client.IgnoreNotFound(err)
	}

	log := r.Log.WithValues("controller", strings.ToLower(sourcev1.HelmChartKind), "request", req.NamespacedName)

	// Add our finalizer if it does not exist
	if !controllerutil.ContainsFinalizer(&chart, sourcev1.SourceFinalizer) {
		controllerutil.AddFinalizer(&chart, sourcev1.SourceFinalizer)
		if err := r.Update(ctx, &chart); err != nil {
			log.Error(err, "unable to register finalizer")
			return ctrl.Result{}, err
		}
	}

	// Examine if the object is under deletion
	if !chart.ObjectMeta.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, chart)
	}

	// record reconciliation duration
	if r.MetricsRecorder != nil {
		objRef, err := reference.GetReference(r.Scheme, &chart)
		if err != nil {
			return ctrl.Result{}, err
		}
		defer r.MetricsRecorder.RecordDuration(*objRef, start)
	}

	// Conditionally set progressing condition in status
	resetChart, changed := r.resetStatus(chart)
	if changed {
		chart = resetChart
		if err := r.Status().Update(ctx, &chart); err != nil {
			log.Error(err, "unable to update status")
			return ctrl.Result{Requeue: true}, err
		}
		r.recordReadiness(chart, false)
	}

	// Purge all but current artifact from storage
	if err := r.gc(chart, false); err != nil {
		log.Error(err, "unable to purge old artifacts")
	}

	// Retrieve the source
	source, err := r.getSource(ctx, chart)
	if err != nil {
		chart = sourcev1.HelmChartNotReady(*chart.DeepCopy(), sourcev1.ChartPullFailedReason, err.Error())
		if err := r.Status().Update(ctx, &chart); err != nil {
			log.Error(err, "unable to update status")
		}
		return ctrl.Result{Requeue: true}, err
	}

	// Assert source is ready
	if source.GetArtifact() == nil {
		err = fmt.Errorf("no artifact found for source `%s` kind '%s'",
			chart.Spec.SourceRef.Name, chart.Spec.SourceRef.Kind)
		chart = sourcev1.HelmChartNotReady(*chart.DeepCopy(), sourcev1.ChartPullFailedReason, err.Error())
		if err := r.Status().Update(ctx, &chart); err != nil {
			log.Error(err, "unable to update status")
		}
		r.recordReadiness(chart, false)
		return ctrl.Result{Requeue: true}, err
	}

	// Perform the reconciliation for the chart source type
	var reconciledChart sourcev1.HelmChart
	var reconcileErr error
	switch typedSource := source.(type) {
	case *sourcev1.HelmRepository:
		reconciledChart, reconcileErr = r.reconcileFromHelmRepository(ctx, *typedSource, *chart.DeepCopy(), changed)
	case *sourcev1.GitRepository, *sourcev1.Bucket:
		reconciledChart, reconcileErr = r.reconcileFromTarballArtifact(ctx, *typedSource.GetArtifact(),
			*chart.DeepCopy(), changed)
	default:
		err := fmt.Errorf("unable to reconcile unsupported source reference kind '%s'", chart.Spec.SourceRef.Kind)
		return ctrl.Result{Requeue: false}, err
	}

	// Update status with the reconciliation result
	if err := r.Status().Update(ctx, &reconciledChart); err != nil {
		log.Error(err, "unable to update status")
		return ctrl.Result{Requeue: true}, err
	}

	// If reconciliation failed, record the failure and requeue immediately
	if reconcileErr != nil {
		r.event(reconciledChart, events.EventSeverityError, reconcileErr.Error())
		r.recordReadiness(reconciledChart, false)
		return ctrl.Result{Requeue: true}, reconcileErr
	}

	// Emit an event if we did not have an artifact before, or the revision has changed
	if chart.Status.Artifact == nil || reconciledChart.Status.Artifact.Revision != chart.Status.Artifact.Revision {
		r.event(reconciledChart, events.EventSeverityInfo, sourcev1.HelmChartReadyMessage(reconciledChart))
	}
	r.recordReadiness(reconciledChart, false)

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

func (r *HelmChartReconciler) getSource(ctx context.Context, chart sourcev1.HelmChart) (sourcev1.Source, error) {
	var source sourcev1.Source
	namespacedName := types.NamespacedName{
		Namespace: chart.GetNamespace(),
		Name:      chart.Spec.SourceRef.Name,
	}
	switch chart.Spec.SourceRef.Kind {
	case sourcev1.HelmRepositoryKind:
		var repository sourcev1.HelmRepository
		err := r.Client.Get(ctx, namespacedName, &repository)
		if err != nil {
			return source, fmt.Errorf("failed to retrieve source: %w", err)
		}
		source = &repository
	case sourcev1.GitRepositoryKind:
		var repository sourcev1.GitRepository
		err := r.Client.Get(ctx, namespacedName, &repository)
		if err != nil {
			return source, fmt.Errorf("failed to retrieve source: %w", err)
		}
		source = &repository
	case sourcev1.BucketKind:
		var bucket sourcev1.Bucket
		err := r.Client.Get(ctx, namespacedName, &bucket)
		if err != nil {
			return source, fmt.Errorf("failed to retrieve source: %w", err)
		}
		source = &bucket
	default:
		return source, fmt.Errorf("source `%s` kind '%s' not supported",
			chart.Spec.SourceRef.Name, chart.Spec.SourceRef.Kind)
	}
	return source, nil
}

func (r *HelmChartReconciler) reconcileFromHelmRepository(ctx context.Context,
	repository sourcev1.HelmRepository, chart sourcev1.HelmChart, force bool) (sourcev1.HelmChart, error) {
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
		defer cleanup()
		clientOpts = opts
	}
	clientOpts = append(clientOpts, getter.WithTimeout(repository.GetTimeout()))

	// Initialize the chart repository and load the index file
	chartRepo, err := helm.NewChartRepository(repository.Spec.URL, r.Getters, clientOpts)
	if err != nil {
		switch err.(type) {
		case *url.Error:
			return sourcev1.HelmChartNotReady(chart, sourcev1.URLInvalidReason, err.Error()), err
		default:
			return sourcev1.HelmChartNotReady(chart, sourcev1.ChartPullFailedReason, err.Error()), err
		}
	}
	indexFile, err := os.Open(r.Storage.LocalPath(*repository.GetArtifact()))
	if err != nil {
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	b, err := ioutil.ReadAll(indexFile)
	if err != nil {
		return sourcev1.HelmChartNotReady(chart, sourcev1.ChartPullFailedReason, err.Error()), err
	}
	if err = chartRepo.LoadIndex(b); err != nil {
		return sourcev1.HelmChartNotReady(chart, sourcev1.ChartPullFailedReason, err.Error()), err
	}

	// Lookup the chart version in the chart repository index
	chartVer, err := chartRepo.Get(chart.Spec.Chart, chart.Spec.Version)
	if err != nil {
		return sourcev1.HelmChartNotReady(chart, sourcev1.ChartPullFailedReason, err.Error()), err
	}

	// Return early if the revision is still the same as the current artifact
	newArtifact := r.Storage.NewArtifactFor(chart.Kind, chart.GetObjectMeta(), chartVer.Version,
		fmt.Sprintf("%s-%s.tgz", chartVer.Name, chartVer.Version))
	if !force && repository.GetArtifact().HasRevision(newArtifact.Revision) {
		if newArtifact.URL != chart.GetArtifact().URL {
			r.Storage.SetArtifactURL(chart.GetArtifact())
			chart.Status.URL = r.Storage.SetHostname(chart.Status.URL)
		}
		return chart, nil
	}

	// Ensure artifact directory exists
	err = r.Storage.MkdirAll(newArtifact)
	if err != nil {
		err = fmt.Errorf("unable to create chart directory: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// Acquire a lock for the artifact
	unlock, err := r.Storage.Lock(newArtifact)
	if err != nil {
		err = fmt.Errorf("unable to acquire lock: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	defer unlock()

	// Attempt to download the chart
	res, err := chartRepo.DownloadChart(chartVer)
	if err != nil {
		return sourcev1.HelmChartNotReady(chart, sourcev1.ChartPullFailedReason, err.Error()), err
	}

	// Either repackage the chart with the declared default values file,
	// or write the chart directly to storage.
	var (
		readyReason  = sourcev1.ChartPullSucceededReason
		readyMessage = fmt.Sprintf("Fetched revision: %s", newArtifact.Revision)
	)
	switch {
	case chart.Spec.ValuesFile != "" && chart.Spec.ValuesFile != chartutil.ValuesfileName:
		var (
			tmpDir  string
			pkgPath string
		)
		// Load the chart
		helmChart, err := loader.LoadArchive(res)
		if err != nil {
			err = fmt.Errorf("load chart error: %w", err)
			return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
		}

		// Overwrite values file
		if changed, err := helm.OverwriteChartDefaultValues(helmChart, chart.Spec.ValuesFile); err != nil {
			return sourcev1.HelmChartNotReady(chart, sourcev1.ChartPackageFailedReason, err.Error()), err
		} else if !changed {
			// No changes, skip to write original package to storage
			goto skipToDefault
		}

		// Create temporary working directory
		tmpDir, err = ioutil.TempDir("", fmt.Sprintf("%s-%s-", chart.Namespace, chart.Name))
		if err != nil {
			err = fmt.Errorf("tmp dir error: %w", err)
			return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
		}
		defer os.RemoveAll(tmpDir)

		// Package the chart with the new default values
		pkgPath, err = chartutil.Save(helmChart, tmpDir)
		if err != nil {
			err = fmt.Errorf("chart package error: %w", err)
			return sourcev1.HelmChartNotReady(chart, sourcev1.ChartPackageFailedReason, err.Error()), err
		}

		// Copy the packaged chart to the artifact path
		if err := r.Storage.CopyFromPath(&newArtifact, pkgPath); err != nil {
			err = fmt.Errorf("failed to write chart package to storage: %w", err)
			return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
		}

		readyMessage = fmt.Sprintf("Fetched and packaged revision: %s", newArtifact.Revision)
		readyReason = sourcev1.ChartPackageSucceededReason
	skipToDefault:
		fallthrough
	default:
		// Write artifact to storage
		if err := r.Storage.AtomicWriteFile(&newArtifact, res, 0644); err != nil {
			err = fmt.Errorf("unable to write chart file: %w", err)
			return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
		}
	}

	// Update symlink
	chartUrl, err := r.Storage.Symlink(newArtifact, fmt.Sprintf("%s-latest.tgz", chartVer.Name))
	if err != nil {
		err = fmt.Errorf("storage error: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	return sourcev1.HelmChartReady(chart, newArtifact, chartUrl, readyReason, readyMessage), nil
}

func (r *HelmChartReconciler) reconcileFromTarballArtifact(ctx context.Context,
	artifact sourcev1.Artifact, chart sourcev1.HelmChart, force bool) (sourcev1.HelmChart, error) {
	// Create temporary working directory
	tmpDir, err := ioutil.TempDir("", fmt.Sprintf("%s-%s-", chart.Namespace, chart.Name))
	if err != nil {
		err = fmt.Errorf("tmp dir error: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	defer os.RemoveAll(tmpDir)

	// Open the tarball artifact file and untar files into working directory
	f, err := os.Open(r.Storage.LocalPath(artifact))
	if err != nil {
		err = fmt.Errorf("artifact open error: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	if _, err = untar.Untar(f, tmpDir); err != nil {
		f.Close()
		err = fmt.Errorf("artifact untar error: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	f.Close()

	// Load the chart
	chartPath := path.Join(tmpDir, chart.Spec.Chart)
	chartFileInfo, err := os.Stat(chartPath)
	if err != nil {
		err = fmt.Errorf("chart location read error: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	helmChart, err := loader.Load(chartPath)
	if err != nil {
		err = fmt.Errorf("load chart error: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// Return early if the revision is still the same as the current chart artifact
	newArtifact := r.Storage.NewArtifactFor(chart.Kind, chart.ObjectMeta.GetObjectMeta(), helmChart.Metadata.Version,
		fmt.Sprintf("%s-%s.tgz", helmChart.Metadata.Name, helmChart.Metadata.Version))
	if !force && meta.HasReadyCondition(chart.Status.Conditions) && chart.GetArtifact().HasRevision(newArtifact.Revision) {
		if newArtifact.URL != artifact.URL {
			r.Storage.SetArtifactURL(chart.GetArtifact())
			chart.Status.URL = r.Storage.SetHostname(chart.Status.URL)
		}
		return chart, nil
	}

	// Either (re)package the chart with the declared default values file,
	// or write the chart directly to storage.
	pkgPath := chartPath
	isDir := chartFileInfo.IsDir()
	if isDir || (chart.Spec.ValuesFile != "" && chart.Spec.ValuesFile != chartutil.ValuesfileName) {
		// Overwrite default values if configured
		if changed, err := helm.OverwriteChartDefaultValues(helmChart, chart.Spec.ValuesFile); err != nil {
			return sourcev1.HelmChartNotReady(chart, sourcev1.ChartPackageFailedReason, err.Error()), err
		} else if isDir || changed {
			// Package the chart
			pkgPath, err = chartutil.Save(helmChart, tmpDir)
			if err != nil {
				err = fmt.Errorf("chart package error: %w", err)
				return sourcev1.HelmChartNotReady(chart, sourcev1.ChartPackageFailedReason, err.Error()), err
			}
		}
	}

	// Ensure artifact directory exists
	err = r.Storage.MkdirAll(newArtifact)
	if err != nil {
		err = fmt.Errorf("unable to create artifact directory: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// Acquire a lock for the artifact
	unlock, err := r.Storage.Lock(newArtifact)
	if err != nil {
		err = fmt.Errorf("unable to acquire lock: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	defer unlock()

	// Copy the packaged chart to the artifact path
	if err := r.Storage.CopyFromPath(&newArtifact, pkgPath); err != nil {
		err = fmt.Errorf("failed to write chart package to storage: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// Update symlink
	cUrl, err := r.Storage.Symlink(newArtifact, fmt.Sprintf("%s-latest.tgz", helmChart.Metadata.Name))
	if err != nil {
		err = fmt.Errorf("storage error: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	message := fmt.Sprintf("Fetched and packaged revision: %s", newArtifact.Revision)
	return sourcev1.HelmChartReady(chart, newArtifact, cUrl, sourcev1.ChartPackageSucceededReason, message), nil
}

func (r *HelmChartReconciler) reconcileDelete(ctx context.Context, chart sourcev1.HelmChart) (ctrl.Result, error) {
	// Our finalizer is still present, so lets handle garbage collection
	if err := r.gc(chart, true); err != nil {
		r.event(chart, events.EventSeverityError, fmt.Sprintf("garbage collection for deleted resource failed: %s", err.Error()))
		// Return the error so we retry the failed garbage collection
		return ctrl.Result{}, err
	}

	// Record deleted status
	r.recordReadiness(chart, true)

	// Remove our finalizer from the list and update it
	controllerutil.RemoveFinalizer(&chart, sourcev1.SourceFinalizer)
	if err := r.Update(ctx, &chart); err != nil {
		return ctrl.Result{}, err
	}

	// Stop reconciliation as the object is being deleted
	return ctrl.Result{}, nil
}

// resetStatus returns a modified v1beta1.HelmChart and a boolean indicating
// if the status field has been reset.
func (r *HelmChartReconciler) resetStatus(chart sourcev1.HelmChart) (sourcev1.HelmChart, bool) {
	// We do not have an artifact, or it does no longer exist
	if chart.GetArtifact() == nil || !r.Storage.ArtifactExist(*chart.GetArtifact()) {
		chart = sourcev1.HelmChartProgressing(chart)
		chart.Status.Artifact = nil
		return chart, true
	}
	// The chart specification has changed
	if chart.Generation != chart.Status.ObservedGeneration {
		return sourcev1.HelmChartProgressing(chart), true
	}
	return chart, false
}

// gc performs a garbage collection on all but the current artifact of
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

// event emits a Kubernetes event and forwards the event to notification
// controller if configured.
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

func (r *HelmChartReconciler) recordReadiness(chart sourcev1.HelmChart, deleted bool) {
	if r.MetricsRecorder == nil {
		return
	}

	objRef, err := reference.GetReference(r.Scheme, &chart)
	if err != nil {
		r.Log.WithValues(
			strings.ToLower(chart.Kind),
			fmt.Sprintf("%s/%s", chart.GetNamespace(), chart.GetName()),
		).Error(err, "unable to record readiness metric")
		return
	}
	if rc := meta.GetCondition(chart.Status.Conditions, meta.ReadyCondition); rc != nil {
		r.MetricsRecorder.RecordCondition(*objRef, *rc, deleted)
	} else {
		r.MetricsRecorder.RecordCondition(*objRef, meta.Condition{
			Type:   meta.ReadyCondition,
			Status: corev1.ConditionUnknown,
		}, deleted)
	}
}
