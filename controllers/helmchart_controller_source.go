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
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"

	"github.com/go-logr/logr"
	"helm.sh/helm/v3/pkg/getter"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/fluxcd/pkg/runtime/conditions"
	"github.com/fluxcd/pkg/runtime/events"
	"github.com/fluxcd/pkg/untar"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	"github.com/fluxcd/source-controller/internal/helm"
)

func (r *HelmChartReconciler) reconcileSource(ctx context.Context, obj *sourcev1.HelmChart, path *string) (ctrl.Result, error) {
	// Attempt to get the source
	sourceObj, err := r.getSource(ctx, obj)
	if err != nil {
		switch {
		case errors.Is(err, unsupportedSourceKindError{}):
			return ctrl.Result{}, nil
		case apierrors.IsNotFound(err):
			return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
		default:
			return ctrl.Result{}, err
		}
	}

	// Mirror source readiness
	conditions.SetMirror(obj, sourcev1.SourceRefReadyCondition, sourceObj)

	// Confirm source has an artifact
	if sourceObj.GetArtifact() == nil {
		conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, "NoArtifact", "No artifact available for %s %q", obj.Spec.SourceRef.Kind, obj.Spec.SourceRef.Name)
		// The watcher should notice an artifact change
		return ctrl.Result{}, nil
	}

	// Retrieve the contents from the source
	switch typedSource := sourceObj.(type) {
	case *sourcev1.HelmRepository:
		return r.reconcileFromHelmRepository(ctx, obj, typedSource, path)
	case *sourcev1.GitRepository, *sourcev1.Bucket:
		return r.reconcileFromTarballArtifact(ctx, obj, *typedSource.GetArtifact(), path)
	default:
		// This should never happen
		return ctrl.Result{}, fmt.Errorf("missing target for typed source object")
	}
}

func (r *HelmChartReconciler) reconcileFromHelmRepository(ctx context.Context, obj *sourcev1.HelmChart, repository *sourcev1.HelmRepository, path *string) (_ ctrl.Result, retErr error) {
	// TODO: move this to a validation webhook once the discussion around
	//  certificates has settled: https://github.com/fluxcd/image-reflector-controller/issues/69
	if err := validHelmChartName(obj.Spec.Chart); err != nil {
		conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, "InvalidChartName", "Validation error: %s", err.Error())
		return ctrl.Result{}, nil
	}

	// Configure Helm client to access repository
	clientOpts := []getter.Option{
		getter.WithTimeout(repository.Spec.Timeout.Duration),
	}
	if repository.Spec.SecretRef != nil {
		// Attempt to retrieve secret
		name := types.NamespacedName{
			Namespace: repository.GetNamespace(),
			Name:      repository.Spec.SecretRef.Name,
		}
		var secret corev1.Secret
		if err := r.Client.Get(ctx, name, &secret); err != nil {
			conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.AuthenticationFailedReason, "Failed to get secret %s: %s", name.String(), err.Error())
			// Return transient errors but wait for next interval on not found
			return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, client.IgnoreNotFound(err)
		}

		// Get client options from secret
		tmpDir, err := ioutil.TempDir("", "helm-client-")
		if err != nil {
			conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.AuthenticationFailedReason, "Could not create temporary directory for : %s", err.Error())
			return ctrl.Result{}, err
		}
		defer os.RemoveAll(tmpDir)
		opts, err := helm.ClientOptionsFromSecret(secret, tmpDir)
		if err != nil {
			conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.AuthenticationFailedReason, "Failed to configure Helm client with secret data: %s", err)
			// Return err as the content of the secret may change
			return ctrl.Result{}, err
		}
		clientOpts = append(clientOpts, opts...)
	}

	// Construct Helm chart repository with options and load the index
	index, err := helm.NewChartRepository(repository.Spec.URL, r.Getters, clientOpts)
	if err != nil {
		switch err.(type) {
		case *url.Error:
			conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.URLInvalidReason, "Invalid Helm repository URL: %s", err.Error())
			return ctrl.Result{}, nil
		default:
			conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.URLInvalidReason, "Helm client construction failed: %s", err.Error())
			return ctrl.Result{}, nil
		}
	}
	if err = index.LoadIndexFile(r.Storage.LocalPath(*repository.GetArtifact())); err != nil {
		conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.ChartPullFailedReason, "Helm repository index load from artifact failed: %s", err.Error())
		return ctrl.Result{}, err
	}

	// Lookup the chart version in the chart repository index
	chartVer, err := index.Get(obj.Spec.Chart, obj.Spec.Version)
	if err != nil {
		conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.ChartPullFailedReason, "Could not find %q chart with version %q: %s", obj.Spec.Chart, obj.Spec.Version, err.Error())
		return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
	}

	// The artifact is up-to-date
	if obj.GetArtifact().HasRevision(chartVer.Version) {
		logr.FromContext(ctx).Info("Artifact up-to-date: skipping chart download")
		return ctrl.Result{RequeueAfter: obj.GetInterval().Duration}, nil
	}

	// Create a new temporary file for the chart and download it
	f, err := ioutil.TempFile("", fmt.Sprintf("%s-%s-", obj.Name, obj.Namespace))
	if err != nil {
		conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.ChartPullFailedReason, "Chart download for %q version %q failed: %s", obj.Spec.Chart, chartVer.Version, err.Error())
		return ctrl.Result{}, err
	}
	b, err := index.DownloadChart(chartVer)
	if err != nil {
		f.Close()
		conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.ChartPullFailedReason, "Chart download for %q version %q failed: %s", obj.Spec.Chart, chartVer.Version, err.Error())
		return ctrl.Result{}, err
	}
	if _, err = io.Copy(f, b); err != nil {
		f.Close()
		conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.ChartPullFailedReason, "Chart download for %q version %q failed: %s", obj.Spec.Chart, chartVer.Version, err.Error())
		return ctrl.Result{}, err
	}
	f.Close()

	*path = f.Name()
	conditions.MarkTrue(obj, sourcev1.SourceAvailableCondition, sourcev1.ChartPullSucceededReason, "Pulled chart version %s", chartVer.Version)
	return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
}

func (r *HelmChartReconciler) reconcileFromTarballArtifact(ctx context.Context, obj *sourcev1.HelmChart, artifact sourcev1.Artifact, path *string) (_ ctrl.Result, retErr error) {
	f, err := os.Open(r.Storage.LocalPath(artifact))
	if err != nil {
		conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.StorageOperationFailedReason, "Could not open artifact: %s", err.Error())
		r.Events.Event(ctx, obj, nil, events.EventSeverityError, sourcev1.StorageOperationFailedReason, conditions.Get(obj, sourcev1.SourceAvailableCondition).Message)
		return ctrl.Result{}, err
	}

	dir, err := ioutil.TempDir("", fmt.Sprintf("%s-%s-", obj.Name, obj.Namespace))
	if err != nil {
		conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.StorageOperationFailedReason, "Could not create temporary working directory: %s", err.Error())
		return ctrl.Result{}, err
	}
	*path = dir

	if _, err = untar.Untar(f, dir); err != nil {
		f.Close()
		conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.StorageOperationFailedReason, "Decompression of artifact failed: %s", err.Error())
		r.Events.Event(ctx, obj, nil, events.EventSeverityError, sourcev1.StorageOperationFailedReason, conditions.Get(obj, sourcev1.SourceAvailableCondition).Message)
		return ctrl.Result{}, err
	}
	f.Close()

	conditions.MarkTrue(obj, sourcev1.SourceAvailableCondition, sourcev1.ChartPullSucceededReason, "Decompressed artifact %s", artifact.Revision)
	return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
}

// getSource attempts to get the source referenced in the given object,
// if the referenced source kind is not supported it returns an
// unsupportedSourceKindError.
func (r *HelmChartReconciler) getSource(ctx context.Context, obj *sourcev1.HelmChart) (sourcev1.Source, error) {
	var s sourcev1.Source
	namespacedName := types.NamespacedName{
		Namespace: obj.GetNamespace(),
		Name:      obj.Spec.SourceRef.Name,
	}
	switch obj.Spec.SourceRef.Kind {
	case sourcev1.HelmRepositoryKind:
		repository := &sourcev1.HelmRepository{}
		err := r.Client.Get(ctx, namespacedName, repository)
		if err != nil {
			return nil, err
		}
		s = repository
	case sourcev1.GitRepositoryKind:
		repository := &sourcev1.GitRepository{}
		err := r.Client.Get(ctx, namespacedName, repository)
		if err != nil {
			return nil, err
		}
		s = repository
	case sourcev1.BucketKind:
		bucket := &sourcev1.Bucket{}
		err := r.Client.Get(ctx, namespacedName, bucket)
		if err != nil {
			return nil, err
		}
		s = bucket
	default:
		return nil, unsupportedSourceKindError{
			Kind:      obj.Spec.SourceRef.Kind,
			Supported: []string{sourcev1.HelmRepositoryKind, sourcev1.GitRepositoryKind, sourcev1.BucketKind},
		}
	}
	return s, nil
}
