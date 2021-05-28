/*
Copyright 2021 The Flux authors

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
	"os"
	"path/filepath"
	"strings"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/events"
	"github.com/fluxcd/pkg/runtime/transform"
	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	"github.com/fluxcd/source-controller/internal/helm"
	"github.com/go-logr/logr"
	helmchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/getter"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

func (r *HelmChartReconciler) reconcileChart(ctx context.Context, obj *sourcev1.HelmChart, path string, artifact *sourcev1.Artifact, result *string) (ctrl.Result, error) {
	if path == "" {
		logr.FromContext(ctx).Info("No chart: skipping chart reconciliation")
	}

	// Determine exact chart path
	pathInfo, err := os.Stat(path)
	if err != nil {
		conditions.MarkFalse(obj, sourcev1.ChartReconciled, sourcev1.StorageOperationFailedReason, "Could not stat path %s: %s", path, err.Error())
		return ctrl.Result{}, err
	}
	chartPath := path
	if pathInfo.IsDir() {
		var err error
		if chartPath, err = securejoin.SecureJoin(chartPath, obj.Spec.Chart); err != nil {
			return ctrl.Result{}, nil
		}
	}

	// Attempt to load chart from the determined path
	chart, err := loader.Load(chartPath)
	if err != nil {
		conditions.MarkFalse(obj, sourcev1.ChartReconciled, sourcev1.StorageOperationFailedReason, "Could not load Helm chart %s: %s", obj.Spec.Chart, err.Error())
		return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
	}

	// The artifact is up-to-date
	if obj.GetArtifact().HasRevision(chart.Metadata.Version) {
		logr.FromContext(ctx).Info("Artifact up-to-date: skipping chart reconciliation")
		return ctrl.Result{RequeueAfter: obj.GetInterval().Duration}, nil
	}

	// Ensure we have all the dependencies and merge any values files
	if result, err := r.buildChartDependencies(ctx, obj, chart, path, chartPath); err != nil || conditions.IsFalse(obj, sourcev1.ChartReconciled) {
		return result, err
	}
	if result, err := r.mergeChartValuesFiles(ctx, obj, chart, path); err != nil || conditions.IsFalse(obj, sourcev1.ChartReconciled) {
		return result, err
	}

	// We need to (re)package the chart
	if conditions.IsTrue(obj, sourcev1.DependenciesBuildCondition) || conditions.IsTrue(obj, sourcev1.ValuesFilesMergedCondition) {
		tmpDir, err := ioutil.TempDir("", "helm-chart-pkg-")
		if err != nil {
			conditions.MarkFalse(obj, sourcev1.ChartPackagedCondition, sourcev1.StorageOperationFailedReason, "Could not create temporary directory for packaging operation: %s", err.Error())
			return ctrl.Result{}, err
		}
		chartPath, err = chartutil.Save(chart, tmpDir)
		if err != nil {
			conditions.MarkFalse(obj, sourcev1.ChartPackagedCondition, sourcev1.StorageOperationFailedReason, "Could not package chart: %s", err.Error())
			return ctrl.Result{}, err
		}
	} else {
		conditions.Delete(obj, sourcev1.ChartPackagedCondition)
	}

	// Create potential new artifact
	*artifact = r.Storage.NewArtifactFor(obj.Kind, obj, chart.Metadata.Version, fmt.Sprintf("%s-%s.tgz", chart.Name(), chart.Metadata.Version))
	*result = chartPath
	conditions.MarkTrue(obj, sourcev1.ChartReconciled, "Success", "Reconciled Helm chart with revision %s", chart.Metadata.Version)

	return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
}

func (r *HelmChartReconciler) buildChartDependencies(ctx context.Context, obj *sourcev1.HelmChart, chart *helmchart.Chart, path, chartPath string) (ctrl.Result, error) {
	// Gather information about the chart path
	chartPathInfo, err := os.Stat(chartPath)
	if err != nil {
		conditions.MarkFalse(obj, sourcev1.ChartReconciled, sourcev1.StorageOperationFailedReason, "Could not stat path %q: %s", chartPath, err.Error())
		return ctrl.Result{}, err
	}

	// We only want to build dependencies for chart directories
	if !chartPathInfo.IsDir() {
		logr.FromContext(ctx).Info("Chart is already packaged: skipping dependency build")
		conditions.Delete(obj, sourcev1.DependenciesBuildCondition)
		return ctrl.Result{}, nil
	}

	// Collect chart dependency metadata
	var (
		deps = chart.Dependencies()
		reqs = chart.Metadata.Dependencies
		lock = chart.Lock
	)
	if lock != nil {
		// Load from lockfile if exists
		reqs = lock.Dependencies
	}

	// If the number of dependencies equals the number of requests
	// we already do have all dependencies.
	if len(deps) == len(reqs) {
		logr.FromContext(ctx).Info("Chart does already have all dependencies: skipping dependency build")
		conditions.Delete(obj, sourcev1.DependenciesBuildCondition)
		return ctrl.Result{}, nil
	}

	dm := &helm.DependencyManager{
		WorkingDir: path,
		ChartPath:  obj.Spec.Chart,
		Chart:      chart,
	}

	tmpDir, err := ioutil.TempDir("", "build-chart-deps-")
	if err != nil {
		conditions.MarkFalse(obj, sourcev1.ChartReconciled, sourcev1.StorageOperationFailedReason, "Could not create temporary directory for dependency credentials: %s", err.Error())
		return ctrl.Result{}, err
	}

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

		dwr, err := r.getRepositoryIndex(ctx, obj, dep, tmpDir)
		if err != nil {
			conditions.MarkFalse(obj, sourcev1.ChartReconciled, "IndexFailure", "Could not construct Helm repository index for dependency %q: %s", dep.Name, err.Error())
			return ctrl.Result{}, err
		}
		dm.Dependencies = append(dm.Dependencies, dwr)
	}

	if len(dm.Dependencies) == 0 {
		// This should theoretically never happen due to the check we did earlier
		logr.FromContext(ctx).Info("Chart does already have all dependencies")
		conditions.Delete(obj, sourcev1.DependenciesBuildCondition)
		return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
	}
	if err := dm.Build(ctx); err != nil {
		conditions.MarkFalse(obj, sourcev1.ChartReconciled, "BuildFailure", "Failed to build dependencies for %q: %s", chart.Name(), err.Error())
		return ctrl.Result{}, err
	}

	conditions.MarkTrue(obj, sourcev1.DependenciesBuildCondition, "Success", "Downloaded %d dependencies", len(dm.Dependencies))
	return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
}

func (r *HelmChartReconciler) getRepositoryIndex(ctx context.Context, obj *sourcev1.HelmChart, dep *helmchart.Dependency, dir string) (*helm.DependencyWithRepository, error) {
	// Return early if file schema detected
	if dep.Repository == "" || strings.HasPrefix(dep.Repository, "file://") {
		return &helm.DependencyWithRepository{
			Dependency: dep,
			Repository: nil,
		}, nil
	}

	// Discover existing HelmRepository by URL,
	// if no repository is found a mock is created to attempt to
	// download the index without any custom configuration.
	repository, err := r.resolveDependencyRepository(ctx, dep, obj.Namespace)
	if err != nil {
		repository = &sourcev1.HelmRepository{
			Spec: sourcev1.HelmRepositorySpec{
				URL: dep.Repository,
			},
		}
	}

	// Configure Helm client getter options
	clientOpts := []getter.Option{
		getter.WithTimeout(obj.Spec.Interval.Duration),
	}
	if repository.Spec.SecretRef != nil {
		name := types.NamespacedName{
			Namespace: repository.GetNamespace(),
			Name:      repository.Spec.SecretRef.Name,
		}
		secret := &corev1.Secret{}
		if err := r.Client.Get(ctx, name, secret); err != nil {
			return nil, err
		}
		opts, err := helm.ClientOptionsFromSecret(*secret, dir)
		if err != nil {
			return nil, err
		}
		clientOpts = append(clientOpts, opts...)
	}

	// Initialize the chart repository and load the index file
	index, err := helm.NewChartRepository(repository.Spec.URL, r.Getters, clientOpts)
	if err != nil {
		return nil, err
	}

	// Load or download the repository index
	switch repository.Status.Artifact {
	case nil:
		err = index.DownloadIndex()
	default:
		err = index.LoadIndexFile(r.Storage.LocalPath(*repository.GetArtifact()))
	}
	if err != nil {
		return nil, err
	}

	return &helm.DependencyWithRepository{
		Dependency: dep,
		Repository: index,
	}, nil
}

func (r *HelmChartReconciler) mergeChartValuesFiles(ctx context.Context, obj *sourcev1.HelmChart, chart *helmchart.Chart, path string) (ctrl.Result, error) {
	valuesFiles := obj.GetValuesFiles()
	if len(valuesFiles) < 1 {
		logr.FromContext(ctx).Info("No values files defined: skipping merge and overwrite of values")
		return ctrl.Result{}, nil
	}

	var values map[string]interface{}
	var err error
	if path == "" {
		values, err = mergeChartValues(chart, valuesFiles)
	} else {
		values, err = mergeFileValues(path, valuesFiles)
	}
	if err != nil {
		conditions.MarkFalse(obj, sourcev1.ChartReconciled, "MergeFailure", "Merge of %v values failed: %s", valuesFiles, err.Error())
		return ctrl.Result{}, err
	}

	b, err := yaml.Marshal(values)
	if err != nil {
		conditions.MarkFalse(obj, sourcev1.ChartReconciled, "MarshalFailure", "Marshalling of merged values failed: %s", err.Error())
		return ctrl.Result{}, err
	}

	modifiedValues, err := helm.OverwriteChartDefaultValues(chart, b)
	if err != nil {
		conditions.MarkFalse(obj, sourcev1.ChartReconciled, "OverwriteFailure", "Overwrite of chart default values with merged values failed: %s", err.Error())
		return ctrl.Result{}, err
	}
	if !modifiedValues {
		return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
	}

	conditions.MarkTrue(obj, sourcev1.ValuesFilesMergedCondition, "ModifiedValues", "Replaced chart values with merged values from: %v", valuesFiles)
	r.Events.Eventf(ctx, obj, nil, events.EventSeverityInfo, "ModifiedValues", "Replaced chart values with merged values from: %v", valuesFiles)
	return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
}

func (r *HelmChartReconciler) resolveDependencyRepository(ctx context.Context, dep *helmchart.Dependency, namespace string) (*sourcev1.HelmRepository, error) {
	u := helm.NormalizeChartRepositoryURL(dep.Repository)
	if u == "" {
		return nil, fmt.Errorf("empty repository dependency URL")
	}
	listOpts := []client.ListOption{
		client.InNamespace(namespace),
		client.MatchingFields{sourcev1.HelmRepositoryURLIndexKey: u},
	}
	var list sourcev1.HelmRepositoryList
	if err := r.Client.List(ctx, &list, listOpts...); err != nil {
		return nil, fmt.Errorf("unable to retrieve HelmRepositoryList: %w", err)
	}
	if len(list.Items) > 0 {
		return &list.Items[0], nil
	}
	return nil, fmt.Errorf("no HelmRepository found")
}

func mergeChartValues(chart *helmchart.Chart, valuesFiles []string) (map[string]interface{}, error) {
	mergedValues := make(map[string]interface{})
	for _, p := range valuesFiles {
		cfn := filepath.Clean(p)
		if cfn == chartutil.ValuesfileName {
			mergedValues = transform.MergeMaps(mergedValues, chart.Values)
		}
		var b []byte
		for _, f := range chart.Files {
			if f.Name == cfn {
				b = f.Data
			}
		}
		if b == nil {
			return nil, fmt.Errorf("no values file found at path %q", p)
		}
		values := make(map[string]interface{})
		if err := yaml.Unmarshal(b, values); err != nil {
			return nil, fmt.Errorf("unmarshaling values from %q failed: %w", p, err)
		}
		mergedValues = transform.MergeMaps(mergedValues, values)
	}
	return mergedValues, nil
}

func mergeFileValues(dir string, valuesFiles []string) (map[string]interface{}, error) {
	mergedValues := make(map[string]interface{})
	for _, p := range valuesFiles {
		secureP, err := securejoin.SecureJoin(dir, p)
		if err != nil {
			return nil, err
		}
		if f, err := os.Stat(secureP); os.IsNotExist(err) || !f.Mode().IsRegular() {
			return nil, fmt.Errorf("invalid values file path %q", p)
		}

		b, err := ioutil.ReadFile(secureP)
		if err != nil {
			return nil, fmt.Errorf("could not read values from file %q: %w", p, err)
		}
		values := make(map[string]interface{})
		err = yaml.Unmarshal(b, &values)
		if err != nil {
			return nil, fmt.Errorf("unmarshaling values from %q failed: %w", p, err)
		}
		mergedValues = transform.MergeMaps(mergedValues, values)
	}
	return mergedValues, nil
}
