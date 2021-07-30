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
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
	helmgetter "helm.sh/helm/v3/pkg/getter"
	corev1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
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

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/events"
	"github.com/fluxcd/pkg/runtime/metrics"
	"github.com/fluxcd/pkg/runtime/predicates"
	"github.com/fluxcd/pkg/untar"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
	"github.com/fluxcd/source-controller/internal/helm/chart"
	"github.com/fluxcd/source-controller/internal/helm/getter"
	"github.com/fluxcd/source-controller/internal/helm/repository"
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
	Getters               helmgetter.Providers
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
	log := ctrl.LoggerFrom(ctx)

	var chart sourcev1.HelmChart
	if err := r.Get(ctx, req.NamespacedName, &chart); err != nil {
		return ctrl.Result{Requeue: true}, client.IgnoreNotFound(err)
	}

	// Record suspended status metric
	defer r.recordSuspension(ctx, chart)

	// Add our finalizer if it does not exist
	if !controllerutil.ContainsFinalizer(&chart, sourcev1.SourceFinalizer) {
		patch := client.MergeFrom(chart.DeepCopy())
		controllerutil.AddFinalizer(&chart, sourcev1.SourceFinalizer)
		if err := r.Patch(ctx, &chart, patch); err != nil {
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

	// Create working directory
	workDir, err := os.MkdirTemp("", chart.Kind+"-"+chart.Namespace+"-"+chart.Name+"-")
	if err != nil {
		err = fmt.Errorf("failed to create temporary working directory: %w", err)
		chart = sourcev1.HelmChartNotReady(*chart.DeepCopy(), sourcev1.ChartPullFailedReason, err.Error())
		if err := r.updateStatus(ctx, req, chart.Status); err != nil {
			log.Error(err, "unable to update status")
		}
		r.recordReadiness(ctx, chart)
		return ctrl.Result{Requeue: true}, err
	}
	defer func() {
		if err := os.RemoveAll(workDir); err != nil {
			log.Error(err, "failed to remove working directory", "path", workDir)
		}
	}()

	// Perform the reconciliation for the chart source type
	var reconciledChart sourcev1.HelmChart
	var reconcileErr error
	switch typedSource := source.(type) {
	case *sourcev1.HelmRepository:
		reconciledChart, reconcileErr = r.fromHelmRepository(ctx, *typedSource, *chart.DeepCopy(), workDir, changed)
	case *sourcev1.GitRepository, *sourcev1.Bucket:
		reconciledChart, reconcileErr = r.fromTarballArtifact(ctx, *typedSource.GetArtifact(), *chart.DeepCopy(),
			workDir, changed)
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
		time.Since(start).String(),
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

func (r *HelmChartReconciler) fromHelmRepository(ctx context.Context, repo sourcev1.HelmRepository, c sourcev1.HelmChart,
	workDir string, force bool) (sourcev1.HelmChart, error) {
	// Configure Index getter options
	clientOpts := []helmgetter.Option{
		helmgetter.WithURL(repo.Spec.URL),
		helmgetter.WithTimeout(repo.Spec.Timeout.Duration),
		helmgetter.WithPassCredentialsAll(repo.Spec.PassCredentials),
	}
	if secret, err := r.getHelmRepositorySecret(ctx, &repo); err != nil {
		return sourcev1.HelmChartNotReady(c, sourcev1.AuthenticationFailedReason, err.Error()), err
	} else if secret != nil {
		// Create temporary working directory for credentials
		authDir := filepath.Join(workDir, "creds")
		if err := os.Mkdir(authDir, 0700); err != nil {
			err = fmt.Errorf("failed to create temporary directory for repository credentials: %w", err)
			return sourcev1.HelmChartNotReady(c, sourcev1.StorageOperationFailedReason, err.Error()), err
		}
		opts, err := getter.ClientOptionsFromSecret(authDir, *secret)
		if err != nil {
			err = fmt.Errorf("failed to create client options for HelmRepository '%s': %w", repo.Name, err)
			return sourcev1.HelmChartNotReady(c, sourcev1.AuthenticationFailedReason, err.Error()), err
		}
		clientOpts = append(clientOpts, opts...)
	}

	// Initialize the chart repository
	chartRepo, err := repository.NewChartRepository(repo.Spec.URL, r.Storage.LocalPath(*repo.GetArtifact()), r.Getters, clientOpts)
	if err != nil {
		switch err.(type) {
		case *url.Error:
			return sourcev1.HelmChartNotReady(c, sourcev1.URLInvalidReason, err.Error()), err
		default:
			return sourcev1.HelmChartNotReady(c, sourcev1.ChartPullFailedReason, err.Error()), err
		}
	}

	// Build the chart
	cb := chart.NewRemoteBuilder(chartRepo)
	ref := chart.RemoteReference{Name: c.Spec.Chart, Version: c.Spec.Version}
	opts := chart.BuildOptions{
		ValuesFiles: c.GetValuesFiles(),
		Force:       force,
	}
	if artifact := c.GetArtifact(); artifact != nil {
		opts.CachedChart = r.Storage.LocalPath(*artifact)
	}

	// Set the VersionMetadata to the object's Generation if ValuesFiles is defined
	// This ensures changes can be noticed by the Artifact consumer
	if len(opts.GetValuesFiles()) > 0 {
		opts.VersionMetadata = strconv.FormatInt(c.Generation, 10)
	}
	b, err := cb.Build(ctx, ref, filepath.Join(workDir, "chart.tgz"), opts)
	if err != nil {
		return sourcev1.HelmChartNotReady(c, sourcev1.ChartPullFailedReason, err.Error()), err
	}

	newArtifact := r.Storage.NewArtifactFor(c.Kind, c.GetObjectMeta(), b.Version,
		fmt.Sprintf("%s-%s.tgz", b.Name, b.Version))

	// If the path of the returned build equals the cache path,
	// there are no changes to the chart
	if b.Path == opts.CachedChart {
		// Ensure hostname is updated
		if c.GetArtifact().URL != newArtifact.URL {
			r.Storage.SetArtifactURL(c.GetArtifact())
			c.Status.URL = r.Storage.SetHostname(c.Status.URL)
		}
		return c, nil
	}

	// Ensure artifact directory exists
	err = r.Storage.MkdirAll(newArtifact)
	if err != nil {
		err = fmt.Errorf("unable to create chart directory: %w", err)
		return sourcev1.HelmChartNotReady(c, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// Acquire a lock for the artifact
	unlock, err := r.Storage.Lock(newArtifact)
	if err != nil {
		err = fmt.Errorf("unable to acquire lock: %w", err)
		return sourcev1.HelmChartNotReady(c, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	defer unlock()

	// Copy the packaged chart to the artifact path
	if err = r.Storage.CopyFromPath(&newArtifact, b.Path); err != nil {
		err = fmt.Errorf("failed to write chart package to storage: %w", err)
		return sourcev1.HelmChartNotReady(c, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// Update symlink
	cUrl, err := r.Storage.Symlink(newArtifact, fmt.Sprintf("%s-latest.tgz", b.Name))
	if err != nil {
		err = fmt.Errorf("storage error: %w", err)
		return sourcev1.HelmChartNotReady(c, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	return sourcev1.HelmChartReady(c, newArtifact, cUrl, sourcev1.ChartPullSucceededReason, b.Summary()), nil
}

func (r *HelmChartReconciler) fromTarballArtifact(ctx context.Context, source sourcev1.Artifact, c sourcev1.HelmChart,
	workDir string, force bool) (sourcev1.HelmChart, error) {
	// Create temporary working directory to untar into
	sourceDir := filepath.Join(workDir, "source")
	if err := os.Mkdir(sourceDir, 0700); err != nil {
		err = fmt.Errorf("failed to create temporary directory to untar source into: %w", err)
		return sourcev1.HelmChartNotReady(c, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// Open the tarball artifact file and untar files into working directory
	f, err := os.Open(r.Storage.LocalPath(source))
	if err != nil {
		err = fmt.Errorf("artifact open error: %w", err)
		return sourcev1.HelmChartNotReady(c, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	if _, err = untar.Untar(f, sourceDir); err != nil {
		_ = f.Close()
		err = fmt.Errorf("artifact untar error: %w", err)
		return sourcev1.HelmChartNotReady(c, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	if err = f.Close(); err != nil {
		err = fmt.Errorf("artifact close error: %w", err)
		return sourcev1.HelmChartNotReady(c, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	chartPath, err := securejoin.SecureJoin(sourceDir, c.Spec.Chart)
	if err != nil {
		return sourcev1.HelmChartNotReady(c, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// Setup dependency manager
	authDir := filepath.Join(workDir, "creds")
	if err = os.Mkdir(authDir, 0700); err != nil {
		err = fmt.Errorf("failed to create temporaRy directory for dependency credentials: %w", err)
		return sourcev1.HelmChartNotReady(c, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	dm := chart.NewDependencyManager(
		chart.WithRepositoryCallback(r.namespacedChartRepositoryCallback(ctx, authDir, c.GetNamespace())),
	)
	defer dm.Clear()

	// Configure builder options, including any previously cached chart
	opts := chart.BuildOptions{
		ValuesFiles: c.GetValuesFiles(),
		Force:       force,
	}
	if artifact := c.Status.Artifact; artifact != nil {
		opts.CachedChart = artifact.Path
	}

	// Configure revision metadata for chart build if we should react to revision changes
	if c.Spec.ReconcileStrategy == sourcev1.ReconcileStrategyRevision {
		rev := source.Revision
		if c.Spec.SourceRef.Kind == sourcev1.GitRepositoryKind {
			// Split the reference by the `/` delimiter which may be present,
			// and take the last entry which contains the SHA.
			split := strings.Split(source.Revision, "/")
			rev = split[len(split)-1]
		}
		if kind := c.Spec.SourceRef.Kind; kind == sourcev1.GitRepositoryKind || kind == sourcev1.BucketKind {
			// The SemVer from the metadata is at times used in e.g. the label metadata for a resource
			// in a chart, which has a limited length of 63 characters.
			// To not fill most of this space with a full length SHA hex (40 characters for SHA-1, and
			// even more for SHA-2 for a chart from a Bucket), we shorten this to the first 12
			// characters taken from the hex.
			// For SHA-1, this has proven to be unique in the Linux kernel with over 875.000 commits
			// (http://git-scm.com/book/en/v2/Git-Tools-Revision-Selection#Short-SHA-1).
			// Note that for a collision to be problematic, it would need to happen right after the
			// previous SHA for the artifact, which is highly unlikely, if not virtually impossible.
			// Ref: https://en.wikipedia.org/wiki/Birthday_attack
			rev = rev[0:12]
		}
		opts.VersionMetadata = rev
	}
	// Set the VersionMetadata to the object's Generation if ValuesFiles is defined,
	// this ensures changes can be noticed by the Artifact consumer
	if len(opts.GetValuesFiles()) > 0 {
		if opts.VersionMetadata != "" {
			opts.VersionMetadata += "."
		}
		opts.VersionMetadata += strconv.FormatInt(c.Generation, 10)
	}

	// Build chart
	cb := chart.NewLocalBuilder(dm)
	b, err := cb.Build(ctx, chart.LocalReference{WorkDir: sourceDir, Path: chartPath}, filepath.Join(workDir, "chart.tgz"), opts)
	if err != nil {
		return sourcev1.HelmChartNotReady(c, reasonForBuildError(err), err.Error()), err
	}

	newArtifact := r.Storage.NewArtifactFor(c.Kind, c.GetObjectMeta(), b.Version,
		fmt.Sprintf("%s-%s.tgz", b.Name, b.Version))

	// If the path of the returned build equals the cache path,
	// there are no changes to the chart
	if apimeta.IsStatusConditionTrue(c.Status.Conditions, meta.ReadyCondition) &&
		b.Path == opts.CachedChart {
		// Ensure hostname is updated
		if c.GetArtifact().URL != newArtifact.URL {
			r.Storage.SetArtifactURL(c.GetArtifact())
			c.Status.URL = r.Storage.SetHostname(c.Status.URL)
		}
		return c, nil
	}

	// Ensure artifact directory exists
	err = r.Storage.MkdirAll(newArtifact)
	if err != nil {
		err = fmt.Errorf("unable to create chart directory: %w", err)
		return sourcev1.HelmChartNotReady(c, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// Acquire a lock for the artifact
	unlock, err := r.Storage.Lock(newArtifact)
	if err != nil {
		err = fmt.Errorf("unable to acquire lock: %w", err)
		return sourcev1.HelmChartNotReady(c, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	defer unlock()

	// Copy the packaged chart to the artifact path
	if err = r.Storage.CopyFromPath(&newArtifact, b.Path); err != nil {
		err = fmt.Errorf("failed to write chart package to storage: %w", err)
		return sourcev1.HelmChartNotReady(c, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// Update symlink
	cUrl, err := r.Storage.Symlink(newArtifact, fmt.Sprintf("%s-latest.tgz", b.Name))
	if err != nil {
		err = fmt.Errorf("storage error: %w", err)
		return sourcev1.HelmChartNotReady(c, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	return sourcev1.HelmChartReady(c, newArtifact, cUrl, reasonForBuildSuccess(b), b.Summary()), nil
}

// namespacedChartRepositoryCallback returns a chart.GetChartRepositoryCallback
// scoped to the given namespace. Credentials for retrieved v1beta1.HelmRepository
// objects are stored in the given directory.
// The returned callback returns a repository.ChartRepository configured with the
// retrieved v1beta1.HelmRepository, or a shim with defaults if no object could
// be found.
func (r *HelmChartReconciler) namespacedChartRepositoryCallback(ctx context.Context, dir, namespace string) chart.GetChartRepositoryCallback {
	return func(url string) (*repository.ChartRepository, error) {
		repo, err := r.resolveDependencyRepository(ctx, url, namespace)
		if err != nil {
			// Return Kubernetes client errors, but ignore others
			if apierrs.ReasonForError(err) != metav1.StatusReasonUnknown {
				return nil, err
			}
			repo = &sourcev1.HelmRepository{
				Spec: sourcev1.HelmRepositorySpec{
					URL:     url,
					Timeout: &metav1.Duration{Duration: 60 * time.Second},
				},
			}
		}
		clientOpts := []helmgetter.Option{
			helmgetter.WithURL(repo.Spec.URL),
			helmgetter.WithTimeout(repo.Spec.Timeout.Duration),
			helmgetter.WithPassCredentialsAll(repo.Spec.PassCredentials),
		}
		if secret, err := r.getHelmRepositorySecret(ctx, repo); err != nil {
			return nil, err
		} else if secret != nil {
			opts, err := getter.ClientOptionsFromSecret(dir, *secret)
			if err != nil {
				return nil, err
			}
			clientOpts = append(clientOpts, opts...)
		}
		chartRepo, err := repository.NewChartRepository(repo.Spec.URL, "", r.Getters, clientOpts)
		if err != nil {
			return nil, err
		}
		if repo.Status.Artifact != nil {
			chartRepo.CachePath = r.Storage.LocalPath(*repo.GetArtifact())
		}
		return chartRepo, nil
	}
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
	if r.EventRecorder != nil {
		r.EventRecorder.Eventf(&chart, corev1.EventTypeNormal, severity, msg)
	}
	if r.ExternalEventRecorder != nil {
		r.ExternalEventRecorder.Eventf(&chart, corev1.EventTypeNormal, severity, msg)
	}
}

func (r *HelmChartReconciler) recordReadiness(ctx context.Context, chart sourcev1.HelmChart) {
	log := ctrl.LoggerFrom(ctx)
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
	u := repository.NormalizeURL(repo.Spec.URL)
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

func (r *HelmChartReconciler) resolveDependencyRepository(ctx context.Context, url string, namespace string) (*sourcev1.HelmRepository, error) {
	listOpts := []client.ListOption{
		client.InNamespace(namespace),
		client.MatchingFields{sourcev1.HelmRepositoryURLIndexKey: url},
	}
	var list sourcev1.HelmRepositoryList
	err := r.Client.List(ctx, &list, listOpts...)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve HelmRepositoryList: %w", err)
	}
	if len(list.Items) > 0 {
		return &list.Items[0], nil
	}
	return nil, fmt.Errorf("no HelmRepository found for '%s' in '%s' namespace", url, namespace)
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
		reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&i)})
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
		reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&i)})
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
		reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&i)})
	}
	return reqs
}

func (r *HelmChartReconciler) recordSuspension(ctx context.Context, chart sourcev1.HelmChart) {
	if r.MetricsRecorder == nil {
		return
	}
	log := ctrl.LoggerFrom(ctx)

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

func reasonForBuildError(err error) string {
	var buildErr *chart.BuildError
	if ok := errors.As(err, &buildErr); !ok {
		return sourcev1.ChartPullFailedReason
	}
	switch buildErr.Reason {
	case chart.ErrChartMetadataPatch, chart.ErrValuesFilesMerge, chart.ErrDependencyBuild, chart.ErrChartPackage:
		return sourcev1.ChartPackageFailedReason
	default:
		return sourcev1.ChartPullFailedReason
	}
}

func reasonForBuildSuccess(result *chart.Build) string {
	if result.Packaged {
		return sourcev1.ChartPackageSucceededReason
	}
	return sourcev1.ChartPullSucceededReason
}
