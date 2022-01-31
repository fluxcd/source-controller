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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	kuberecorder "k8s.io/client-go/tools/record"
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
	"github.com/fluxcd/pkg/runtime/conditions"
	helper "github.com/fluxcd/pkg/runtime/controller"
	"github.com/fluxcd/pkg/runtime/events"
	"github.com/fluxcd/pkg/runtime/patch"
	"github.com/fluxcd/pkg/runtime/predicates"
	"github.com/fluxcd/pkg/untar"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
	serror "github.com/fluxcd/source-controller/internal/error"
	"github.com/fluxcd/source-controller/internal/helm/chart"
	"github.com/fluxcd/source-controller/internal/helm/getter"
	"github.com/fluxcd/source-controller/internal/helm/repository"
	sreconcile "github.com/fluxcd/source-controller/internal/reconcile"
	"github.com/fluxcd/source-controller/internal/util"
)

// Status conditions owned by the HelmChart reconciler.
var helmChartOwnedConditions = []string{
	sourcev1.BuildFailedCondition,
	sourcev1.FetchFailedCondition,
	sourcev1.ArtifactOutdatedCondition,
	meta.ReadyCondition,
	meta.ReconcilingCondition,
	meta.StalledCondition,
}

// Conditions that Ready condition is influenced by in descending order of their
// priority.
var helmChartReadyDeps = []string{
	sourcev1.BuildFailedCondition,
	sourcev1.FetchFailedCondition,
	sourcev1.ArtifactOutdatedCondition,
	meta.StalledCondition,
	meta.ReconcilingCondition,
}

// Negative conditions that Ready condition is influenced by.
var helmChartReadyDepsNegative = []string{
	sourcev1.BuildFailedCondition,
	sourcev1.FetchFailedCondition,
	sourcev1.ArtifactOutdatedCondition,
	meta.StalledCondition,
	meta.ReconcilingCondition,
}

// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=helmcharts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=helmcharts/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=helmcharts/finalizers,verbs=get;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// HelmChartReconciler reconciles a HelmChart object
type HelmChartReconciler struct {
	client.Client
	kuberecorder.EventRecorder
	helper.Metrics

	Storage *Storage
	Getters helmgetter.Providers
}

func (r *HelmChartReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return r.SetupWithManagerAndOptions(mgr, HelmChartReconcilerOptions{})
}

type HelmChartReconcilerOptions struct {
	MaxConcurrentReconciles int
}

type helmChartReconcilerFunc func(ctx context.Context, obj *sourcev1.HelmChart, build *chart.Build) (sreconcile.Result, error)

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

func (r *HelmChartReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, retErr error) {
	start := time.Now()
	log := ctrl.LoggerFrom(ctx)

	// Fetch the HelmChart
	obj := &sourcev1.HelmChart{}
	if err := r.Get(ctx, req.NamespacedName, obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Record suspended status metric
	r.RecordSuspend(ctx, obj, obj.Spec.Suspend)

	// Return early if the object is suspended
	if obj.Spec.Suspend {
		log.Info("Reconciliation is suspended for this object")
		return ctrl.Result{}, nil
	}

	// Initialize the patch helper with the current version of the object.
	patchHelper, err := patch.NewHelper(obj, r.Client)
	if err != nil {
		return ctrl.Result{}, err
	}

	// recResult stores the abstracted reconcile result.
	var recResult sreconcile.Result

	// Always attempt to patch the object after each reconciliation.
	// NOTE: The final runtime result and error are set in this block.
	defer func() {
		result, retErr = r.summarizeAndPatch(ctx, obj, patchHelper, recResult, retErr)

		// Always record readiness and duration metrics
		r.Metrics.RecordReadiness(ctx, obj)
		r.Metrics.RecordDuration(ctx, obj, start)
	}()

	// Add finalizer first if not exist to avoid the race condition
	// between init and delete
	if !controllerutil.ContainsFinalizer(obj, sourcev1.SourceFinalizer) {
		controllerutil.AddFinalizer(obj, sourcev1.SourceFinalizer)
		recResult = sreconcile.ResultRequeue
		return
	}

	// Examine if the object is under deletion
	if !obj.ObjectMeta.DeletionTimestamp.IsZero() {
		recResult, retErr = r.reconcileDelete(ctx, obj)
		return
	}

	// Reconcile actual object
	reconcilers := []helmChartReconcilerFunc{
		r.reconcileStorage,
		r.reconcileSource,
		r.reconcileArtifact,
	}
	recResult, retErr = r.reconcile(ctx, obj, reconcilers)
	return
}

// summarizeAndPatch analyzes the object conditions to create a summary of the
// status conditions, computes runtime results and patches the object in the K8s
// API server.
func (r *HelmChartReconciler) summarizeAndPatch(
	ctx context.Context,
	obj *sourcev1.HelmChart,
	patchHelper *patch.Helper,
	res sreconcile.Result,
	recErr error) (ctrl.Result, error) {
	sreconcile.RecordContextualError(ctx, r.EventRecorder, obj, recErr)

	// Record the value of the reconciliation request, if any
	if v, ok := meta.ReconcileAnnotationValue(obj.GetAnnotations()); ok {
		obj.Status.SetLastHandledReconcileRequest(v)
	}

	// Compute the reconcile results, obtain patch options and reconcile error.
	var patchOpts []patch.Option
	var result ctrl.Result
	patchOpts, result, recErr = sreconcile.ComputeReconcileResult(obj, obj.GetRequeueAfter(), res, recErr, helmChartOwnedConditions)

	// Summarize Ready condition
	conditions.SetSummary(obj,
		meta.ReadyCondition,
		conditions.WithConditions(
			helmChartReadyDeps...,
		),
		conditions.WithNegativePolarityConditions(
			helmChartReadyDepsNegative...,
		),
	)

	// Finally, patch the resource
	if err := patchHelper.Patch(ctx, obj, patchOpts...); err != nil {
		// Ignore patch error "not found" when the object is being deleted.
		if !obj.ObjectMeta.DeletionTimestamp.IsZero() {
			err = kerrors.FilterOut(err, func(e error) bool { return apierrs.IsNotFound(err) })
		}
		recErr = kerrors.NewAggregate([]error{recErr, err})
	}
	return result, recErr
}

// reconcile steps through the actual reconciliation tasks for the object, it returns early on the first step that
// produces an error.
func (r *HelmChartReconciler) reconcile(ctx context.Context, obj *sourcev1.HelmChart, reconcilers []helmChartReconcilerFunc) (sreconcile.Result, error) {
	if obj.Generation != obj.Status.ObservedGeneration {
		conditions.MarkReconciling(obj, "NewGeneration", "reconciling new generation %d", obj.Generation)
	}

	// Run the sub-reconcilers and build the result of reconciliation.
	var (
		build  chart.Build
		res    sreconcile.Result
		resErr error
	)
	for _, rec := range reconcilers {
		recResult, err := rec(ctx, obj, &build)
		// Exit immediately on ResultRequeue.
		if recResult == sreconcile.ResultRequeue {
			return sreconcile.ResultRequeue, nil
		}
		// If an error is received, prioritize the returned results because an
		// error also means immediate requeue.
		if err != nil {
			resErr = err
			res = recResult
			break
		}
		// Prioritize requeue request in the result.
		res = sreconcile.LowestRequeuingResult(res, recResult)
	}
	return res, resErr
}

// reconcileStorage ensures the current state of the storage matches the desired and previously observed state.
//
// All artifacts for the resource except for the current one are garbage collected from the storage.
// If the artifact in the Status object of the resource disappeared from storage, it is removed from the object.
// If the object does not have an artifact in its Status object, a v1beta1.ArtifactUnavailableCondition is set.
// If the hostname of the URLs on the object do not match the current storage server hostname, they are updated.
//
// The caller should assume a failure if an error is returned, or the BuildResult is zero.
func (r *HelmChartReconciler) reconcileStorage(ctx context.Context, obj *sourcev1.HelmChart, build *chart.Build) (sreconcile.Result, error) {
	// Garbage collect previous advertised artifact(s) from storage
	_ = r.garbageCollect(ctx, obj)

	// Determine if the advertised artifact is still in storage
	if artifact := obj.GetArtifact(); artifact != nil && !r.Storage.ArtifactExist(*artifact) {
		obj.Status.Artifact = nil
		obj.Status.URL = ""
	}

	// Record that we do not have an artifact
	if obj.GetArtifact() == nil {
		conditions.MarkReconciling(obj, "NoArtifact", "no artifact for resource in storage")
		return sreconcile.ResultSuccess, nil
	}

	// Always update URLs to ensure hostname is up-to-date
	// TODO(hidde): we may want to send out an event only if we notice the URL has changed
	r.Storage.SetArtifactURL(obj.GetArtifact())
	obj.Status.URL = r.Storage.SetHostname(obj.Status.URL)

	return sreconcile.ResultSuccess, nil
}

func (r *HelmChartReconciler) reconcileSource(ctx context.Context, obj *sourcev1.HelmChart, build *chart.Build) (_ sreconcile.Result, retErr error) {
	// Retrieve the source
	s, err := r.getSource(ctx, obj)
	if err != nil {
		e := &serror.Event{
			Err:    fmt.Errorf("failed to get source: %w", err),
			Reason: "SourceUnavailable",
		}
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, "SourceUnavailable", e.Err.Error())

		// Return Kubernetes client errors, but ignore others which can only be
		// solved by a change in generation
		if apierrs.ReasonForError(err) == metav1.StatusReasonUnknown {
			return sreconcile.ResultEmpty, &serror.Stalling{
				Err:    fmt.Errorf("failed to get source: %w", err),
				Reason: "UnsupportedSourceKind",
			}
		}
		return sreconcile.ResultEmpty, e
	}

	// Assert source has an artifact
	if s.GetArtifact() == nil || !r.Storage.ArtifactExist(*s.GetArtifact()) {
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, "NoSourceArtifact",
			"no artifact available for %s source '%s'", obj.Spec.SourceRef.Kind, obj.Spec.SourceRef.Name)
		r.eventLogf(ctx, obj, corev1.EventTypeWarning, "NoSourceArtifact",
			"no artifact available for %s source '%s'", obj.Spec.SourceRef.Kind, obj.Spec.SourceRef.Name)
		return sreconcile.ResultRequeue, nil
	}

	// Record current artifact revision as last observed
	obj.Status.ObservedSourceArtifactRevision = s.GetArtifact().Revision

	// Defer observation of build result
	defer func() {
		// Record both success and error observations on the object
		observeChartBuild(obj, build, retErr)

		// If we actually build a chart, take a historical note of any dependencies we resolved.
		// The reason this is a done conditionally, is because if we have a cached one in storage,
		// we can not recover this information (and put it in a condition). Which would result in
		// a sudden (partial) disappearance of observed state.
		// TODO(hidde): include specific name/version information?
		if depNum := build.ResolvedDependencies; build.Complete() && depNum > 0 {
			r.Eventf(obj, events.EventTypeTrace, "ResolvedDependencies", "resolved %d chart dependencies", depNum)
		}

		// Handle any build error
		if retErr != nil {
			if buildErr := new(chart.BuildError); errors.As(retErr, &buildErr) {
				retErr = &serror.Event{
					Err:    buildErr,
					Reason: buildErr.Reason.Reason,
				}
				if chart.IsPersistentBuildErrorReason(buildErr.Reason) {
					retErr = &serror.Stalling{
						Err:    buildErr,
						Reason: buildErr.Reason.Reason,
					}
				}
			}
		}
	}()

	// Perform the build for the chart source type
	switch typedSource := s.(type) {
	case *sourcev1.HelmRepository:
		return r.buildFromHelmRepository(ctx, obj, typedSource, build)
	case *sourcev1.GitRepository, *sourcev1.Bucket:
		return r.buildFromTarballArtifact(ctx, obj, *typedSource.GetArtifact(), build)
	default:
		// Ending up here should generally not be possible
		// as getSource already validates
		return sreconcile.ResultEmpty, nil
	}
}

func (r *HelmChartReconciler) buildFromHelmRepository(ctx context.Context, obj *sourcev1.HelmChart,
	repo *sourcev1.HelmRepository, b *chart.Build) (sreconcile.Result, error) {

	// Construct the Getter options from the HelmRepository data
	clientOpts := []helmgetter.Option{
		helmgetter.WithURL(repo.Spec.URL),
		helmgetter.WithTimeout(repo.Spec.Timeout.Duration),
		helmgetter.WithPassCredentialsAll(repo.Spec.PassCredentials),
	}
	if secret, err := r.getHelmRepositorySecret(ctx, repo); secret != nil || err != nil {
		if err != nil {
			e := &serror.Event{
				Err:    fmt.Errorf("failed to get secret '%s': %w", repo.Spec.SecretRef.Name, err),
				Reason: sourcev1.AuthenticationFailedReason,
			}
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, e.Err.Error())
			// Return error as the world as observed may change
			return sreconcile.ResultEmpty, e
		}

		// Create temporary working directory for credentials
		authDir, err := util.TempDirForObj("", obj)
		if err != nil {
			e := &serror.Event{
				Err:    fmt.Errorf("failed to create temporary working directory: %w", err),
				Reason: sourcev1.StorageOperationFailedReason,
			}
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.StorageOperationFailedReason, e.Err.Error())
			return sreconcile.ResultEmpty, e
		}
		defer os.RemoveAll(authDir)

		// Build client options from secret
		opts, err := getter.ClientOptionsFromSecret(authDir, *secret)
		if err != nil {
			e := &serror.Event{
				Err:    fmt.Errorf("failed to configure Helm client with secret data: %w", err),
				Reason: sourcev1.AuthenticationFailedReason,
			}
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason, e.Err.Error())
			// Requeue as content of secret might change
			return sreconcile.ResultEmpty, e
		}
		clientOpts = append(clientOpts, opts...)
	}

	// Initialize the chart repository
	chartRepo, err := repository.NewChartRepository(repo.Spec.URL, r.Storage.LocalPath(*repo.GetArtifact()), r.Getters, clientOpts)
	if err != nil {
		// Any error requires a change in generation,
		// which we should be informed about by the watcher
		switch err.(type) {
		case *url.Error:
			e := &serror.Stalling{
				Err:    fmt.Errorf("invalid Helm repository URL: %w", err),
				Reason: sourcev1.URLInvalidReason,
			}
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.URLInvalidReason, e.Err.Error())
			return sreconcile.ResultEmpty, e
		default:
			e := &serror.Stalling{
				Err:    fmt.Errorf("failed to construct Helm client: %w", err),
				Reason: meta.FailedReason,
			}
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, meta.FailedReason, e.Err.Error())
			return sreconcile.ResultEmpty, e
		}
	}

	// Construct the chart builder with scoped configuration
	cb := chart.NewRemoteBuilder(chartRepo)
	opts := chart.BuildOptions{
		ValuesFiles: obj.GetValuesFiles(),
		Force:       obj.Generation != obj.Status.ObservedGeneration,
	}
	if artifact := obj.GetArtifact(); artifact != nil {
		opts.CachedChart = r.Storage.LocalPath(*artifact)
	}

	// Set the VersionMetadata to the object's Generation if ValuesFiles is defined
	// This ensures changes can be noticed by the Artifact consumer
	if len(opts.GetValuesFiles()) > 0 {
		opts.VersionMetadata = strconv.FormatInt(obj.Generation, 10)
	}

	// Build the chart
	ref := chart.RemoteReference{Name: obj.Spec.Chart, Version: obj.Spec.Version}
	build, err := cb.Build(ctx, ref, util.TempPathForObj("", ".tgz", obj), opts)
	if err != nil {
		return sreconcile.ResultEmpty, err
	}

	*b = *build
	return sreconcile.ResultSuccess, nil
}

func (r *HelmChartReconciler) buildFromTarballArtifact(ctx context.Context, obj *sourcev1.HelmChart, source sourcev1.Artifact, b *chart.Build) (sreconcile.Result, error) {
	// Create temporary working directory
	tmpDir, err := util.TempDirForObj("", obj)
	if err != nil {
		e := &serror.Event{
			Err:    fmt.Errorf("failed to create temporary working directory: %w", err),
			Reason: sourcev1.StorageOperationFailedReason,
		}
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.StorageOperationFailedReason, e.Err.Error())
		return sreconcile.ResultEmpty, e
	}
	defer os.RemoveAll(tmpDir)

	// Create directory to untar source into
	sourceDir := filepath.Join(tmpDir, "source")
	if err := os.Mkdir(sourceDir, 0700); err != nil {
		e := &serror.Event{
			Err:    fmt.Errorf("failed to create directory to untar source into: %w", err),
			Reason: sourcev1.StorageOperationFailedReason,
		}
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.StorageOperationFailedReason, e.Err.Error())
		return sreconcile.ResultEmpty, e
	}

	// Open the tarball artifact file and untar files into working directory
	f, err := os.Open(r.Storage.LocalPath(source))
	if err != nil {
		e := &serror.Event{
			Err:    fmt.Errorf("failed to open source artifact: %w", err),
			Reason: sourcev1.StorageOperationFailedReason,
		}
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.StorageOperationFailedReason, e.Err.Error())
		return sreconcile.ResultEmpty, e
	}
	if _, err = untar.Untar(f, sourceDir); err != nil {
		_ = f.Close()
		return sreconcile.ResultEmpty, &serror.Event{
			Err:    fmt.Errorf("artifact untar error: %w", err),
			Reason: meta.FailedReason,
		}
	}
	if err = f.Close(); err != nil {
		return sreconcile.ResultEmpty, &serror.Event{
			Err:    fmt.Errorf("artifact close error: %w", err),
			Reason: meta.FailedReason,
		}
	}

	// Calculate (secure) absolute chart path
	chartPath, err := securejoin.SecureJoin(sourceDir, obj.Spec.Chart)
	if err != nil {
		e := &serror.Stalling{
			Err:    fmt.Errorf("path calculation for chart '%s' failed: %w", obj.Spec.Chart, err),
			Reason: "IllegalPath",
		}
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, "IllegalPath", e.Err.Error())
		// We are unable to recover from this change without a change in generation
		return sreconcile.ResultEmpty, e
	}

	// Setup dependency manager
	authDir := filepath.Join(tmpDir, "creds")
	if err = os.Mkdir(authDir, 0700); err != nil {
		return sreconcile.ResultEmpty, &serror.Event{
			Err:    fmt.Errorf("failed to create temporary directory for dependency credentials: %w", err),
			Reason: meta.FailedReason,
		}
	}
	dm := chart.NewDependencyManager(
		chart.WithRepositoryCallback(r.namespacedChartRepositoryCallback(ctx, authDir, obj.GetNamespace())),
	)
	defer dm.Clear()

	// Configure builder options, including any previously cached chart
	opts := chart.BuildOptions{
		ValuesFiles: obj.GetValuesFiles(),
		Force:       obj.Generation != obj.Status.ObservedGeneration,
	}
	if artifact := obj.Status.Artifact; artifact != nil {
		opts.CachedChart = r.Storage.LocalPath(*artifact)
	}

	// Configure revision metadata for chart build if we should react to revision changes
	if obj.Spec.ReconcileStrategy == sourcev1.ReconcileStrategyRevision {
		rev := source.Revision
		if obj.Spec.SourceRef.Kind == sourcev1.GitRepositoryKind {
			// Split the reference by the `/` delimiter which may be present,
			// and take the last entry which contains the SHA.
			split := strings.Split(source.Revision, "/")
			rev = split[len(split)-1]
		}
		if kind := obj.Spec.SourceRef.Kind; kind == sourcev1.GitRepositoryKind || kind == sourcev1.BucketKind {
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
		opts.VersionMetadata += strconv.FormatInt(obj.Generation, 10)
	}

	// Build chart
	cb := chart.NewLocalBuilder(dm)
	build, err := cb.Build(ctx, chart.LocalReference{
		WorkDir: sourceDir,
		Path:    chartPath,
	}, util.TempPathForObj("", ".tgz", obj), opts)
	if err != nil {
		return sreconcile.ResultEmpty, err
	}

	*b = *build
	return sreconcile.ResultSuccess, nil
}

// reconcileArtifact reconciles the given chart.Build to an v1beta1.Artifact in the Storage, and records it
// on the object.
func (r *HelmChartReconciler) reconcileArtifact(ctx context.Context, obj *sourcev1.HelmChart, b *chart.Build) (sreconcile.Result, error) {
	// Without a complete chart build, there is little to reconcile
	if !b.Complete() {
		return sreconcile.ResultRequeue, nil
	}

	// Always restore the conditions in case they got overwritten by transient errors
	defer func() {
		if obj.Status.ObservedChartName == b.Name && obj.GetArtifact().HasRevision(b.Version) {
			conditions.Delete(obj, sourcev1.ArtifactOutdatedCondition)
			conditions.MarkTrue(obj, meta.ReadyCondition, reasonForBuild(b), b.Summary())
		}
	}()

	// Create artifact from build data
	artifact := r.Storage.NewArtifactFor(obj.Kind, obj.GetObjectMeta(), b.Version, fmt.Sprintf("%s-%s.tgz", b.Name, b.Version))

	// Return early if the build path equals the current artifact path
	if curArtifact := obj.GetArtifact(); curArtifact != nil && r.Storage.LocalPath(*curArtifact) == b.Path {
		ctrl.LoggerFrom(ctx).Info("artifact up-to-date", "revision", artifact.Revision)
		return sreconcile.ResultSuccess, nil
	}

	// Garbage collect chart build once persisted to storage
	defer os.Remove(b.Path)

	// Ensure artifact directory exists and acquire lock
	if err := r.Storage.MkdirAll(artifact); err != nil {
		return sreconcile.ResultEmpty, &serror.Event{
			Err:    fmt.Errorf("failed to create artifact directory: %w", err),
			Reason: sourcev1.StorageOperationFailedReason,
		}
	}
	unlock, err := r.Storage.Lock(artifact)
	if err != nil {
		return sreconcile.ResultEmpty, &serror.Event{
			Err:    fmt.Errorf("failed to acquire lock for artifact: %w", err),
			Reason: sourcev1.StorageOperationFailedReason,
		}
	}
	defer unlock()

	// Copy the packaged chart to the artifact path
	if err = r.Storage.CopyFromPath(&artifact, b.Path); err != nil {
		return sreconcile.ResultEmpty, &serror.Event{
			Err:    fmt.Errorf("unable to copy Helm chart to storage: %w", err),
			Reason: sourcev1.StorageOperationFailedReason,
		}
	}

	// Record it on the object
	obj.Status.Artifact = artifact.DeepCopy()
	obj.Status.ObservedChartName = b.Name

	// Publish an event
	r.AnnotatedEventf(obj, map[string]string{
		"revision": artifact.Revision,
		"checksum": artifact.Checksum,
	}, corev1.EventTypeNormal, reasonForBuild(b), b.Summary())

	// Update symlink on a "best effort" basis
	symURL, err := r.Storage.Symlink(artifact, "latest.tar.gz")
	if err != nil {
		r.eventLogf(ctx, obj, corev1.EventTypeWarning, sourcev1.StorageOperationFailedReason,
			"failed to update status URL symlink: %s", err)
	}
	if symURL != "" {
		obj.Status.URL = symURL
	}
	return sreconcile.ResultSuccess, nil
}

// getSource returns the v1beta1.Source for the given object, or an error describing why the source could not be
// returned.
func (r *HelmChartReconciler) getSource(ctx context.Context, obj *sourcev1.HelmChart) (sourcev1.Source, error) {
	namespacedName := types.NamespacedName{
		Namespace: obj.GetNamespace(),
		Name:      obj.Spec.SourceRef.Name,
	}
	var s sourcev1.Source
	switch obj.Spec.SourceRef.Kind {
	case sourcev1.HelmRepositoryKind:
		var repo sourcev1.HelmRepository
		if err := r.Client.Get(ctx, namespacedName, &repo); err != nil {
			return nil, err
		}
		s = &repo
	case sourcev1.GitRepositoryKind:
		var repo sourcev1.GitRepository
		if err := r.Client.Get(ctx, namespacedName, &repo); err != nil {
			return nil, err
		}
		s = &repo
	case sourcev1.BucketKind:
		var bucket sourcev1.Bucket
		if err := r.Client.Get(ctx, namespacedName, &bucket); err != nil {
			return nil, err
		}
		s = &bucket
	default:
		return nil, fmt.Errorf("unsupported source kind '%s', must be one of: %v", obj.Spec.SourceRef.Kind, []string{
			sourcev1.HelmRepositoryKind, sourcev1.GitRepositoryKind, sourcev1.BucketKind})
	}
	return s, nil
}

// reconcileDelete handles the delete of an object. It first garbage collects all artifacts for the object from the
// artifact storage, if successful, the finalizer is removed from the object.
func (r *HelmChartReconciler) reconcileDelete(ctx context.Context, obj *sourcev1.HelmChart) (sreconcile.Result, error) {
	// Garbage collect the resource's artifacts
	if err := r.garbageCollect(ctx, obj); err != nil {
		// Return the error so we retry the failed garbage collection
		return sreconcile.ResultEmpty, err
	}

	// Remove our finalizer from the list
	controllerutil.RemoveFinalizer(obj, sourcev1.SourceFinalizer)

	// Stop reconciliation as the object is being deleted
	return sreconcile.ResultEmpty, nil
}

// garbageCollect performs a garbage collection for the given v1beta1.HelmChart. It removes all but the current
// artifact, unless the deletion timestamp is set. Which will result in the removal of all artifacts for the
// resource.
func (r *HelmChartReconciler) garbageCollect(ctx context.Context, obj *sourcev1.HelmChart) error {
	if !obj.DeletionTimestamp.IsZero() {
		if deleted, err := r.Storage.RemoveAll(r.Storage.NewArtifactFor(obj.Kind, obj.GetObjectMeta(), "", "*")); err != nil {
			return &serror.Event{
				Err:    fmt.Errorf("garbage collection for deleted resource failed: %w", err),
				Reason: "GarbageCollectionFailed",
			}
		} else if deleted != "" {
			r.eventLogf(ctx, obj, events.EventTypeTrace, "GarbageCollectionSucceeded",
				"garbage collected artifacts for deleted resource")
		}
		obj.Status.Artifact = nil
		return nil
	}
	if obj.GetArtifact() != nil {
		if deleted, err := r.Storage.RemoveAllButCurrent(*obj.GetArtifact()); err != nil {
			return &serror.Event{
				Err:    fmt.Errorf("garbage collection of old artifacts failed: %w", err),
				Reason: "GarbageCollectionFailed",
			}
		} else if len(deleted) > 0 {
			r.eventLogf(ctx, obj, events.EventTypeTrace, "GarbageCollectionSucceeded",
				"garbage collected old artifacts")
		}
	}
	return nil
}

// namespacedChartRepositoryCallback returns a chart.GetChartRepositoryCallback scoped to the given namespace.
// Credentials for retrieved v1beta1.HelmRepository objects are stored in the given directory.
// The returned callback returns a repository.ChartRepository configured with the retrieved v1beta1.HelmRepository,
// or a shim with defaults if no object could be found.
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
		if secret, err := r.getHelmRepositorySecret(ctx, repo); secret != nil || err != nil {
			if err != nil {
				return nil, err
			}
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

func (r *HelmChartReconciler) resolveDependencyRepository(ctx context.Context, url string, namespace string) (*sourcev1.HelmRepository, error) {
	listOpts := []client.ListOption{
		client.InNamespace(namespace),
		client.MatchingFields{sourcev1.HelmRepositoryURLIndexKey: url},
		client.Limit(1),
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
	if repository.Spec.SecretRef == nil {
		return nil, nil
	}
	name := types.NamespacedName{
		Namespace: repository.GetNamespace(),
		Name:      repository.Spec.SecretRef.Name,
	}
	var secret corev1.Secret
	err := r.Client.Get(ctx, name, &secret)
	if err != nil {
		return nil, err
	}
	return &secret, nil
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

	var reqs []reconcile.Request
	for _, i := range list.Items {
		if i.Status.ObservedSourceArtifactRevision != repo.GetArtifact().Revision {
			reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&i)})
		}
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

	var reqs []reconcile.Request
	for _, i := range list.Items {
		if i.Status.ObservedSourceArtifactRevision != repo.GetArtifact().Revision {
			reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&i)})
		}
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

	var reqs []reconcile.Request
	for _, i := range list.Items {
		if i.Status.ObservedSourceArtifactRevision != bucket.GetArtifact().Revision {
			reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&i)})
		}
	}
	return reqs
}

// eventLogf records event and logs at the same time. This log is different from
// the debug log in the event recorder in the sense that this is a simple log,
// the event recorder debug log contains complete details about the event.
func (r *HelmChartReconciler) eventLogf(ctx context.Context, obj runtime.Object, eventType string, reason string, messageFmt string, args ...interface{}) {
	msg := fmt.Sprintf(messageFmt, args...)
	// Log and emit event.
	if eventType == corev1.EventTypeWarning {
		ctrl.LoggerFrom(ctx).Error(errors.New(reason), msg)
	} else {
		ctrl.LoggerFrom(ctx).Info(msg)
	}
	r.Eventf(obj, eventType, reason, msg)
}

// observeChartBuild records the observation on the given given build and error on the object.
func observeChartBuild(obj *sourcev1.HelmChart, build *chart.Build, err error) {
	if build.HasMetadata() {
		if build.Name != obj.Status.ObservedChartName || !obj.GetArtifact().HasRevision(build.Version) {
			conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "NewChart", build.Summary())
		}
	}

	if build.Complete() {
		conditions.Delete(obj, sourcev1.FetchFailedCondition)
		conditions.Delete(obj, sourcev1.BuildFailedCondition)
	}

	if err != nil {
		var buildErr *chart.BuildError
		if ok := errors.As(err, &buildErr); !ok {
			buildErr = &chart.BuildError{
				Reason: chart.ErrUnknown,
				Err:    err,
			}
		}

		switch buildErr.Reason {
		case chart.ErrChartMetadataPatch, chart.ErrValuesFilesMerge, chart.ErrDependencyBuild, chart.ErrChartPackage:
			conditions.Delete(obj, sourcev1.FetchFailedCondition)
			conditions.MarkTrue(obj, sourcev1.BuildFailedCondition, buildErr.Reason.Reason, buildErr.Error())
		default:
			conditions.Delete(obj, sourcev1.BuildFailedCondition)
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, buildErr.Reason.Reason, buildErr.Error())
		}
		return
	}
}

func reasonForBuild(build *chart.Build) string {
	if !build.Complete() {
		return ""
	}
	if build.Packaged {
		return sourcev1.ChartPackageSucceededReason
	}
	return sourcev1.ChartPullSucceededReason
}
