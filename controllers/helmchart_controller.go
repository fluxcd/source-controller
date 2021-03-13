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
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/go-logr/logr"
	helmchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/getter"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kuberecorder "k8s.io/client-go/tools/record"
	"k8s.io/client-go/tools/reference"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
	"sigs.k8s.io/yaml"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/events"
	"github.com/fluxcd/pkg/runtime/metrics"
	"github.com/fluxcd/pkg/runtime/predicates"
	"github.com/fluxcd/pkg/runtime/transform"
	"github.com/fluxcd/pkg/untar"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	"github.com/fluxcd/source-controller/internal/helm"
	"github.com/fluxcd/source-controller/internal/util"
)

// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=helmcharts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=helmcharts/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=helmcharts/finalizers,verbs=get;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// HelmChartReconciler reconciles a HelmChart object
type HelmChartReconciler struct {
	client.Client
	Scheme                *runtime.Scheme
	Storage               *Storage
	Getters               getter.Providers
	EventRecorder         kuberecorder.EventRecorder
	ExternalEventRecorder *events.Recorder
	MetricsRecorder       *metrics.Recorder
}

func (r *HelmChartReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return r.SetupWithManagerAndOptions(mgr, HelmChartReconcilerOptions{})
}

func (r *HelmChartReconciler) SetupWithManagerAndOptions(mgr ctrl.Manager, opts HelmChartReconcilerOptions) error {
	if err := mgr.GetCache().IndexField(context.TODO(), &sourcev1.HelmRepository{}, sourcev1.HelmRepositoryURLIndexKey,
		r.indexHelmRepositoryByURL); err != nil {
		return fmt.Errorf("failed setting index fields: %w", err)
	}
	if err := mgr.GetCache().IndexField(context.TODO(), &sourcev1.HelmChart{}, sourcev1.SourceIndexKey,
		r.indexHelmChartBySource); err != nil {
		return fmt.Errorf("failed setting index fields: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&sourcev1.HelmChart{}, builder.WithPredicates(
			predicate.Or(predicate.GenerationChangedPredicate{}, predicates.ReconcileRequestedPredicate{}),
		)).
		Watches(
			&source.Kind{Type: &sourcev1.HelmRepository{}},
			handler.EnqueueRequestsFromMapFunc(r.requestsForHelmRepositoryChange),
			builder.WithPredicates(SourceRevisionChangePredicate{}),
		).
		Watches(
			&source.Kind{Type: &sourcev1.GitRepository{}},
			handler.EnqueueRequestsFromMapFunc(r.requestsForGitRepositoryChange),
			builder.WithPredicates(SourceRevisionChangePredicate{}),
		).
		Watches(
			&source.Kind{Type: &sourcev1.Bucket{}},
			handler.EnqueueRequestsFromMapFunc(r.requestsForBucketChange),
			builder.WithPredicates(SourceRevisionChangePredicate{}),
		).
		WithOptions(controller.Options{MaxConcurrentReconciles: opts.MaxConcurrentReconciles}).
		Complete(r)
}

func (r *HelmChartReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	start := time.Now()
	log := logr.FromContext(ctx)

	var chart sourcev1.HelmChart
	if err := r.Get(ctx, req.NamespacedName, &chart); err != nil {
		return ctrl.Result{Requeue: true}, client.IgnoreNotFound(err)
	}

	// Record suspended status metric
	defer r.recordSuspension(ctx, chart)

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

	// Return early if the object is suspended.
	if chart.Spec.Suspend {
		log.Info("Reconciliation is suspended for this object")
		return ctrl.Result{}, nil
	}

	// Record reconciliation duration
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
		if err := r.updateStatus(ctx, req, chart.Status); err != nil {
			log.Error(err, "unable to update status")
			return ctrl.Result{Requeue: true}, err
		}
		r.recordReadiness(ctx, chart)
	}

	// Record the value of the reconciliation request, if any
	// TODO(hidde): would be better to defer this in combination with
	//   always patching the status sub-resource after a reconciliation.
	if v, ok := meta.ReconcileAnnotationValue(chart.GetAnnotations()); ok {
		chart.Status.SetLastHandledReconcileRequest(v)
	}

	// Purge all but current artifact from storage
	if err := r.gc(chart); err != nil {
		log.Error(err, "unable to purge old artifacts")
	}

	// Retrieve the source
	source, err := r.getSource(ctx, chart)
	if err != nil {
		chart = sourcev1.HelmChartNotReady(*chart.DeepCopy(), sourcev1.ChartPullFailedReason, err.Error())
		if err := r.updateStatus(ctx, req, chart.Status); err != nil {
			log.Error(err, "unable to update status")
		}
		return ctrl.Result{Requeue: true}, err
	}

	// Assert source is ready
	if source.GetArtifact() == nil {
		err = fmt.Errorf("no artifact found for source `%s` kind '%s'",
			chart.Spec.SourceRef.Name, chart.Spec.SourceRef.Kind)
		chart = sourcev1.HelmChartNotReady(*chart.DeepCopy(), sourcev1.ChartPullFailedReason, err.Error())
		if err := r.updateStatus(ctx, req, chart.Status); err != nil {
			log.Error(err, "unable to update status")
		}
		r.recordReadiness(ctx, chart)
		return ctrl.Result{Requeue: true}, err
	}

	// Perform the reconciliation for the chart source type
	var reconciledChart sourcev1.HelmChart
	var reconcileErr error
	switch typedSource := source.(type) {
	case *sourcev1.HelmRepository:
		// TODO: move this to a validation webhook once the discussion around
		//  certificates has settled: https://github.com/fluxcd/image-reflector-controller/issues/69
		if err := validHelmChartName(chart.Spec.Chart); err != nil {
			reconciledChart = sourcev1.HelmChartNotReady(chart, sourcev1.ChartPullFailedReason, err.Error())
			log.Error(err, "validation failed")
			if err := r.updateStatus(ctx, req, reconciledChart.Status); err != nil {
				log.Info(fmt.Sprintf("%v", reconciledChart.Status))
				log.Error(err, "unable to update status")
				return ctrl.Result{Requeue: true}, err
			}
			r.event(ctx, reconciledChart, events.EventSeverityError, err.Error())
			r.recordReadiness(ctx, reconciledChart)
			// Do not requeue as there is no chance on recovery.
			return ctrl.Result{Requeue: false}, nil
		}
		reconciledChart, reconcileErr = r.reconcileFromHelmRepository(ctx, *typedSource, *chart.DeepCopy(), changed)
	case *sourcev1.GitRepository, *sourcev1.Bucket:
		reconciledChart, reconcileErr = r.reconcileFromTarballArtifact(ctx, *typedSource.GetArtifact(),
			*chart.DeepCopy(), changed)
	default:
		err := fmt.Errorf("unable to reconcile unsupported source reference kind '%s'", chart.Spec.SourceRef.Kind)
		return ctrl.Result{Requeue: false}, err
	}

	// Update status with the reconciliation result
	if err := r.updateStatus(ctx, req, reconciledChart.Status); err != nil {
		log.Error(err, "unable to update status")
		return ctrl.Result{Requeue: true}, err
	}

	// If reconciliation failed, record the failure and requeue immediately
	if reconcileErr != nil {
		r.event(ctx, reconciledChart, events.EventSeverityError, reconcileErr.Error())
		r.recordReadiness(ctx, reconciledChart)
		return ctrl.Result{Requeue: true}, reconcileErr
	}

	// Emit an event if we did not have an artifact before, or the revision has changed
	if (chart.GetArtifact() == nil && reconciledChart.GetArtifact() != nil) ||
		(chart.GetArtifact() != nil && reconciledChart.GetArtifact() != nil && reconciledChart.GetArtifact().Revision != chart.GetArtifact().Revision) {
		r.event(ctx, reconciledChart, events.EventSeverityInfo, sourcev1.HelmChartReadyMessage(reconciledChart))
	}
	r.recordReadiness(ctx, reconciledChart)

	log.Info(fmt.Sprintf("Reconciliation finished in %s, next run in %s",
		time.Now().Sub(start).String(),
		chart.GetInterval().Duration.String(),
	))
	return ctrl.Result{RequeueAfter: chart.GetInterval().Duration}, nil
}

type HelmChartReconcilerOptions struct {
	MaxConcurrentReconciles int
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
	// Configure ChartRepository getter options
	clientOpts := []getter.Option{
		getter.WithURL(repository.Spec.URL),
		getter.WithTimeout(repository.Spec.Timeout.Duration),
		getter.WithPassCredentialsAll(repository.Spec.PassCredentials),
	}
	if secret, err := r.getHelmRepositorySecret(ctx, &repository); err != nil {
		return sourcev1.HelmChartNotReady(chart, sourcev1.AuthenticationFailedReason, err.Error()), err
	} else if secret != nil {
		opts, cleanup, err := helm.ClientOptionsFromSecret(*secret)
		if err != nil {
			err = fmt.Errorf("auth options error: %w", err)
			return sourcev1.HelmChartNotReady(chart, sourcev1.AuthenticationFailedReason, err.Error()), err
		}
		defer cleanup()
		clientOpts = append(clientOpts, opts...)
	}

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
	tmpFile, err := ioutil.TempFile("", fmt.Sprintf("%s-%s-", chart.Namespace, chart.Name))
	if err != nil {
		return sourcev1.HelmChartNotReady(chart, sourcev1.ChartPullFailedReason, err.Error()), err
	}
	defer os.RemoveAll(tmpFile.Name())
	if _, err = io.Copy(tmpFile, res); err != nil {
		tmpFile.Close()
		return sourcev1.HelmChartNotReady(chart, sourcev1.ChartPullFailedReason, err.Error()), err
	}
	tmpFile.Close()

	// Check if we need to repackage the chart with the declared defaults files.
	var (
		pkgPath      = tmpFile.Name()
		readyReason  = sourcev1.ChartPullSucceededReason
		readyMessage = fmt.Sprintf("Fetched revision: %s", newArtifact.Revision)
	)

	switch {
	case len(chart.GetValuesFiles()) > 0:
		valuesMap := make(map[string]interface{})

		// Load the chart
		helmChart, err := loader.LoadFile(pkgPath)
		if err != nil {
			err = fmt.Errorf("load chart error: %w", err)
			return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
		}

		for _, v := range chart.GetValuesFiles() {
			if v == "values.yaml" {
				valuesMap = transform.MergeMaps(valuesMap, helmChart.Values)
				continue
			}

			var valuesData []byte
			cfn := filepath.Clean(v)
			for _, f := range helmChart.Files {
				if f.Name == cfn {
					valuesData = f.Data
					break
				}
			}
			if valuesData == nil {
				err = fmt.Errorf("invalid values file path: %s", v)
				return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
			}

			yamlMap := make(map[string]interface{})
			err = yaml.Unmarshal(valuesData, &yamlMap)
			if err != nil {
				err = fmt.Errorf("unmarshaling values from %s failed: %w", v, err)
				return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
			}

			valuesMap = transform.MergeMaps(valuesMap, yamlMap)
		}

		yamlBytes, err := yaml.Marshal(valuesMap)
		if err != nil {
			err = fmt.Errorf("marshaling values failed: %w", err)
			return sourcev1.HelmChartNotReady(chart, sourcev1.ChartPackageFailedReason, err.Error()), err
		}

		// Overwrite values file
		if changed, err := helm.OverwriteChartDefaultValues(helmChart, yamlBytes); err != nil {
			return sourcev1.HelmChartNotReady(chart, sourcev1.ChartPackageFailedReason, err.Error()), err
		} else if !changed {
			break
		}

		// Create temporary working directory
		tmpDir, err := ioutil.TempDir("", fmt.Sprintf("%s-%s-", chart.Namespace, chart.Name))
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
	}

	// Write artifact to storage
	if err := r.Storage.CopyFromPath(&newArtifact, pkgPath); err != nil {
		err = fmt.Errorf("unable to write chart file: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
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
	chartPath, err := securejoin.SecureJoin(tmpDir, chart.Spec.Chart)
	if err != nil {
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
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

	version, err := semver.NewVersion(helmChart.Metadata.Version)
	if err != nil {
		err = fmt.Errorf("load chart error: %w", err)
		return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	// Replace / with - in version metadata for SemVer spec
	version.SetMetadata(strings.Replace(artifact.Revision, "/", "-", -1))
	helmChart.Metadata.Version = version.String()

	revision := version.Original()
	if chart.Spec.IgnoreVersion {
		revision = version.String()
	}

	// Return early if the revision is still the same as the current chart artifact
	newArtifact := r.Storage.NewArtifactFor(chart.Kind, chart.ObjectMeta.GetObjectMeta(), revision,
		fmt.Sprintf("%s-%s.tgz", helmChart.Metadata.Name, revision))
	if !force && apimeta.IsStatusConditionTrue(chart.Status.Conditions, meta.ReadyCondition) && chart.GetArtifact().HasRevision(newArtifact.Revision) {
		if newArtifact.URL != artifact.URL {
			r.Storage.SetArtifactURL(chart.GetArtifact())
			chart.Status.URL = r.Storage.SetHostname(chart.Status.URL)
		}
		return chart, nil
	}

	// Either (re)package the chart with the declared default values file,
	// or write the chart directly to storage.
	pkgPath := chartPath
	isValuesFileOverriden := false
	if len(chart.GetValuesFiles()) > 0 {
		valuesMap := make(map[string]interface{})
		for _, v := range chart.GetValuesFiles() {
			srcPath, err := securejoin.SecureJoin(tmpDir, v)
			if err != nil {
				return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
			}
			if f, err := os.Stat(srcPath); os.IsNotExist(err) || !f.Mode().IsRegular() {
				err = fmt.Errorf("invalid values file path: %s", v)
				return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
			}

			valuesData, err := ioutil.ReadFile(srcPath)
			if err != nil {
				err = fmt.Errorf("failed to read from values file '%s': %w", v, err)
				return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
			}

			yamlMap := make(map[string]interface{})
			err = yaml.Unmarshal(valuesData, &yamlMap)
			if err != nil {
				err = fmt.Errorf("unmarshaling values from %s failed: %w", v, err)
				return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
			}

			valuesMap = transform.MergeMaps(valuesMap, yamlMap)
		}

		yamlBytes, err := yaml.Marshal(valuesMap)
		if err != nil {
			err = fmt.Errorf("marshaling values failed: %w", err)
			return sourcev1.HelmChartNotReady(chart, sourcev1.ChartPackageFailedReason, err.Error()), err
		}

		isValuesFileOverriden, err = helm.OverwriteChartDefaultValues(helmChart, yamlBytes)
		if err != nil {
			return sourcev1.HelmChartNotReady(chart, sourcev1.ChartPackageFailedReason, err.Error()), err
		}
	}

	isDir := chartFileInfo.IsDir()
	switch {
	case isDir:
		// Determine chart dependencies
		deps := helmChart.Dependencies()
		reqs := helmChart.Metadata.Dependencies
		lock := helmChart.Lock
		if lock != nil {
			// Load from lockfile if exists
			reqs = lock.Dependencies
		}
		var dwr []*helm.DependencyWithRepository
		for _, dep := range reqs {
			// Exclude existing dependencies
			found := false
			for _, existing := range deps {
				if existing.Name() == dep.Name {
					found = true
				}
			}
			if found {
				continue
			}

			// Continue loop if file scheme detected
			if dep.Repository == "" || strings.HasPrefix(dep.Repository, "file://") {
				dwr = append(dwr, &helm.DependencyWithRepository{
					Dependency: dep,
					Repository: nil,
				})
				continue
			}

			// Discover existing HelmRepository by URL
			repository, err := r.resolveDependencyRepository(ctx, dep, chart.Namespace)
			if err != nil {
				repository = &sourcev1.HelmRepository{
					Spec: sourcev1.HelmRepositorySpec{
						URL:     dep.Repository,
						Timeout: &metav1.Duration{Duration: 60 * time.Second},
					},
				}
			}

			// Configure ChartRepository getter options
			clientOpts := []getter.Option{
				getter.WithURL(repository.Spec.URL),
				getter.WithTimeout(repository.Spec.Timeout.Duration),
				getter.WithPassCredentialsAll(repository.Spec.PassCredentials),
			}
			if secret, err := r.getHelmRepositorySecret(ctx, repository); err != nil {
				return sourcev1.HelmChartNotReady(chart, sourcev1.AuthenticationFailedReason, err.Error()), err
			} else if secret != nil {
				opts, cleanup, err := helm.ClientOptionsFromSecret(*secret)
				if err != nil {
					err = fmt.Errorf("auth options error: %w", err)
					return sourcev1.HelmChartNotReady(chart, sourcev1.AuthenticationFailedReason, err.Error()), err
				}
				defer cleanup()
				clientOpts = append(clientOpts, opts...)
			}

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
			if repository.Status.Artifact != nil {
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
			} else {
				// Download index
				err = chartRepo.DownloadIndex()
				if err != nil {
					return sourcev1.HelmChartNotReady(chart, sourcev1.ChartPullFailedReason, err.Error()), err
				}
			}

			dwr = append(dwr, &helm.DependencyWithRepository{
				Dependency: dep,
				Repository: chartRepo,
			})
		}

		// Construct dependencies for chart if any
		if len(dwr) > 0 {
			dm := &helm.DependencyManager{
				WorkingDir:   tmpDir,
				ChartPath:    chart.Spec.Chart,
				Chart:        helmChart,
				Dependencies: dwr,
			}
			err = dm.Build(ctx)
			if err != nil {
				return sourcev1.HelmChartNotReady(chart, sourcev1.StorageOperationFailedReason, err.Error()), err
			}
		}

		fallthrough
	case isValuesFileOverriden:
		pkgPath, err = chartutil.Save(helmChart, tmpDir)
		if err != nil {
			err = fmt.Errorf("chart package error: %w", err)
			return sourcev1.HelmChartNotReady(chart, sourcev1.ChartPackageFailedReason, err.Error()), err
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
	if err := r.gc(chart); err != nil {
		r.event(ctx, chart, events.EventSeverityError,
			fmt.Sprintf("garbage collection for deleted resource failed: %s", err.Error()))
		// Return the error so we retry the failed garbage collection
		return ctrl.Result{}, err
	}

	// Record deleted status
	r.recordReadiness(ctx, chart)

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

// gc performs a garbage collection for the given v1beta1.HelmChart.
// It removes all but the current artifact except for when the
// deletion timestamp is set, which will result in the removal of
// all artifacts for the resource.
func (r *HelmChartReconciler) gc(chart sourcev1.HelmChart) error {
	if !chart.DeletionTimestamp.IsZero() {
		return r.Storage.RemoveAll(r.Storage.NewArtifactFor(chart.Kind, chart.GetObjectMeta(), "", "*"))
	}
	if chart.GetArtifact() != nil {
		return r.Storage.RemoveAllButCurrent(*chart.GetArtifact())
	}
	return nil
}

// event emits a Kubernetes event and forwards the event to notification
// controller if configured.
func (r *HelmChartReconciler) event(ctx context.Context, chart sourcev1.HelmChart, severity, msg string) {
	log := logr.FromContext(ctx)
	if r.EventRecorder != nil {
		r.EventRecorder.Eventf(&chart, "Normal", severity, msg)
	}
	if r.ExternalEventRecorder != nil {
		objRef, err := reference.GetReference(r.Scheme, &chart)
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

func (r *HelmChartReconciler) recordReadiness(ctx context.Context, chart sourcev1.HelmChart) {
	log := logr.FromContext(ctx)
	if r.MetricsRecorder == nil {
		return
	}
	objRef, err := reference.GetReference(r.Scheme, &chart)
	if err != nil {
		log.Error(err, "unable to record readiness metric")
		return
	}
	if rc := apimeta.FindStatusCondition(chart.Status.Conditions, meta.ReadyCondition); rc != nil {
		r.MetricsRecorder.RecordCondition(*objRef, *rc, !chart.DeletionTimestamp.IsZero())
	} else {
		r.MetricsRecorder.RecordCondition(*objRef, metav1.Condition{
			Type:   meta.ReadyCondition,
			Status: metav1.ConditionUnknown,
		}, !chart.DeletionTimestamp.IsZero())
	}
}

func (r *HelmChartReconciler) updateStatus(ctx context.Context, req ctrl.Request, newStatus sourcev1.HelmChartStatus) error {
	var chart sourcev1.HelmChart
	if err := r.Get(ctx, req.NamespacedName, &chart); err != nil {
		return err
	}

	patch := client.MergeFrom(chart.DeepCopy())
	chart.Status = newStatus

	return r.Status().Patch(ctx, &chart, patch)
}

func (r *HelmChartReconciler) indexHelmRepositoryByURL(o client.Object) []string {
	repo, ok := o.(*sourcev1.HelmRepository)
	if !ok {
		panic(fmt.Sprintf("Expected a HelmRepository, got %T", o))
	}
	u := helm.NormalizeChartRepositoryURL(repo.Spec.URL)
	if u != "" {
		return []string{u}
	}
	return nil
}

func (r *HelmChartReconciler) indexHelmChartBySource(o client.Object) []string {
	hc, ok := o.(*sourcev1.HelmChart)
	if !ok {
		panic(fmt.Sprintf("Expected a HelmChart, got %T", o))
	}
	return []string{fmt.Sprintf("%s/%s", hc.Spec.SourceRef.Kind, hc.Spec.SourceRef.Name)}
}

func (r *HelmChartReconciler) resolveDependencyRepository(ctx context.Context, dep *helmchart.Dependency, namespace string) (*sourcev1.HelmRepository, error) {
	u := helm.NormalizeChartRepositoryURL(dep.Repository)
	if u == "" {
		return nil, fmt.Errorf("invalid repository URL")
	}

	listOpts := []client.ListOption{
		client.InNamespace(namespace),
		client.MatchingFields{sourcev1.HelmRepositoryURLIndexKey: u},
	}
	var list sourcev1.HelmRepositoryList
	err := r.Client.List(ctx, &list, listOpts...)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve HelmRepositoryList: %w", err)
	}
	if len(list.Items) > 0 {
		return &list.Items[0], nil
	}

	return nil, fmt.Errorf("no HelmRepository found")
}

func (r *HelmChartReconciler) getHelmRepositorySecret(ctx context.Context, repository *sourcev1.HelmRepository) (*corev1.Secret, error) {
	if repository.Spec.SecretRef != nil {
		name := types.NamespacedName{
			Namespace: repository.GetNamespace(),
			Name:      repository.Spec.SecretRef.Name,
		}

		var secret corev1.Secret
		err := r.Client.Get(ctx, name, &secret)
		if err != nil {
			err = fmt.Errorf("auth secret error: %w", err)
			return nil, err
		}
		return &secret, nil
	}

	return nil, nil
}

func (r *HelmChartReconciler) requestsForHelmRepositoryChange(o client.Object) []reconcile.Request {
	repo, ok := o.(*sourcev1.HelmRepository)
	if !ok {
		panic(fmt.Sprintf("Expected a HelmRepository, got %T", o))
	}
	// If we do not have an artifact, we have no requests to make
	if repo.GetArtifact() == nil {
		return nil
	}

	ctx := context.Background()
	var list sourcev1.HelmChartList
	if err := r.List(ctx, &list, client.MatchingFields{
		sourcev1.SourceIndexKey: fmt.Sprintf("%s/%s", sourcev1.HelmRepositoryKind, repo.Name),
	}); err != nil {
		return nil
	}

	// TODO(hidde): unlike other places (e.g. the helm-controller),
	//  we have no reference here to determine if the request is coming
	//  from the _old_ or _new_ update event, and resources are thus
	//  enqueued twice.
	var reqs []reconcile.Request
	for _, i := range list.Items {
		reqs = append(reqs, reconcile.Request{NamespacedName: util.ObjectKey(&i)})
	}
	return reqs
}

func (r *HelmChartReconciler) requestsForGitRepositoryChange(o client.Object) []reconcile.Request {
	repo, ok := o.(*sourcev1.GitRepository)
	if !ok {
		panic(fmt.Sprintf("Expected a GitRepository, got %T", o))
	}

	// If we do not have an artifact, we have no requests to make
	if repo.GetArtifact() == nil {
		return nil
	}

	var list sourcev1.HelmChartList
	if err := r.List(context.TODO(), &list, client.MatchingFields{
		sourcev1.SourceIndexKey: fmt.Sprintf("%s/%s", sourcev1.GitRepositoryKind, repo.Name),
	}); err != nil {
		return nil
	}

	// TODO(hidde): unlike other places (e.g. the helm-controller),
	//  we have no reference here to determine if the request is coming
	//  from the _old_ or _new_ update event, and resources are thus
	//  enqueued twice.
	var reqs []reconcile.Request
	for _, i := range list.Items {
		reqs = append(reqs, reconcile.Request{NamespacedName: util.ObjectKey(&i)})
	}
	return reqs
}

func (r *HelmChartReconciler) requestsForBucketChange(o client.Object) []reconcile.Request {
	bucket, ok := o.(*sourcev1.Bucket)
	if !ok {
		panic(fmt.Sprintf("Expected a Bucket, got %T", o))
	}

	// If we do not have an artifact, we have no requests to make
	if bucket.GetArtifact() == nil {
		return nil
	}

	var list sourcev1.HelmChartList
	if err := r.List(context.TODO(), &list, client.MatchingFields{
		sourcev1.SourceIndexKey: fmt.Sprintf("%s/%s", sourcev1.BucketKind, bucket.Name),
	}); err != nil {
		return nil
	}

	// TODO(hidde): unlike other places (e.g. the helm-controller),
	//  we have no reference here to determine if the request is coming
	//  from the _old_ or _new_ update event, and resources are thus
	//  enqueued twice.
	var reqs []reconcile.Request
	for _, i := range list.Items {
		reqs = append(reqs, reconcile.Request{NamespacedName: util.ObjectKey(&i)})
	}
	return reqs
}

// validHelmChartName returns an error if the given string is not a
// valid Helm chart name; a valid name must be lower case letters
// and numbers, words may be separated with dashes (-).
// Ref: https://helm.sh/docs/chart_best_practices/conventions/#chart-names
func validHelmChartName(s string) error {
	chartFmt := regexp.MustCompile("^([-a-z0-9]*)$")
	if !chartFmt.MatchString(s) {
		return fmt.Errorf("invalid chart name %q, a valid name must be lower case letters and numbers and MAY be separated with dashes (-)", s)
	}
	return nil
}

func (r *HelmChartReconciler) recordSuspension(ctx context.Context, chart sourcev1.HelmChart) {
	if r.MetricsRecorder == nil {
		return
	}
	log := logr.FromContext(ctx)

	objRef, err := reference.GetReference(r.Scheme, &chart)
	if err != nil {
		log.Error(err, "unable to record suspended metric")
		return
	}

	if !chart.DeletionTimestamp.IsZero() {
		r.MetricsRecorder.RecordSuspend(*objRef, false)
	} else {
		r.MetricsRecorder.RecordSuspend(*objRef, chart.Spec.Suspend)
	}
}
