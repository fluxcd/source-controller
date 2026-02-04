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

package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/docker/go-units"
	"github.com/opencontainers/go-digest"
	helmgetter "helm.sh/helm/v3/pkg/getter"
	helmreg "helm.sh/helm/v3/pkg/registry"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kuberecorder "k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	eventv1 "github.com/fluxcd/pkg/apis/event/v1beta1"
	"github.com/fluxcd/pkg/apis/meta"
	intdigest "github.com/fluxcd/pkg/artifact/digest"
	"github.com/fluxcd/pkg/artifact/storage"
	"github.com/fluxcd/pkg/runtime/conditions"
	helper "github.com/fluxcd/pkg/runtime/controller"
	"github.com/fluxcd/pkg/runtime/jitter"
	"github.com/fluxcd/pkg/runtime/patch"
	"github.com/fluxcd/pkg/runtime/predicates"
	rreconcile "github.com/fluxcd/pkg/runtime/reconcile"

	sourcev1 "github.com/werf/nelm-source-controller/api/v1"
	"github.com/werf/nelm-source-controller/internal/cache"
	serror "github.com/werf/nelm-source-controller/internal/error"
	"github.com/werf/nelm-source-controller/internal/helm/getter"
	"github.com/werf/nelm-source-controller/internal/helm/repository"
	intpredicates "github.com/werf/nelm-source-controller/internal/predicates"
	sreconcile "github.com/werf/nelm-source-controller/internal/reconcile"
	"github.com/werf/nelm-source-controller/internal/reconcile/summarize"
)

// helmRepositoryReadyCondition contains the information required to summarize a
// v1.HelmRepository Ready Condition.
var helmRepositoryReadyCondition = summarize.Conditions{
	Target: meta.ReadyCondition,
	Owned: []string{
		sourcev1.StorageOperationFailedCondition,
		sourcev1.FetchFailedCondition,
		sourcev1.ArtifactOutdatedCondition,
		sourcev1.ArtifactInStorageCondition,
		meta.ReadyCondition,
		meta.ReconcilingCondition,
		meta.StalledCondition,
	},
	Summarize: []string{
		sourcev1.StorageOperationFailedCondition,
		sourcev1.FetchFailedCondition,
		sourcev1.ArtifactOutdatedCondition,
		sourcev1.ArtifactInStorageCondition,
		meta.StalledCondition,
		meta.ReconcilingCondition,
	},
	NegativePolarity: []string{
		sourcev1.StorageOperationFailedCondition,
		sourcev1.FetchFailedCondition,
		sourcev1.ArtifactOutdatedCondition,
		meta.StalledCondition,
		meta.ReconcilingCondition,
	},
}

// helmRepositoryFailConditions contains the conditions that represent a
// failure.
var helmRepositoryFailConditions = []string{
	sourcev1.FetchFailedCondition,
	sourcev1.StorageOperationFailedCondition,
}

// +kubebuilder:rbac:groups=source.werf.io,resources=helmrepositories,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=source.werf.io,resources=helmrepositories/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=source.werf.io,resources=helmrepositories/finalizers,verbs=get;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// HelmRepositoryReconciler reconciles a v1.HelmRepository object.
type HelmRepositoryReconciler struct {
	client.Client
	kuberecorder.EventRecorder
	helper.Metrics

	Getters        helmgetter.Providers
	Storage        *storage.Storage
	ControllerName string

	Cache *cache.Cache
	TTL   time.Duration
	*cache.CacheRecorder

	patchOptions []patch.Option
}

type HelmRepositoryReconcilerOptions struct {
	RateLimiter workqueue.TypedRateLimiter[reconcile.Request]
}

// helmRepositoryReconcileFunc is the function type for all the
// v1.HelmRepository (sub)reconcile functions. The type implementations
// are grouped and executed serially to perform the complete reconcile of the
// object.
type helmRepositoryReconcileFunc func(ctx context.Context, sp *patch.SerialPatcher, obj *sourcev1.HelmRepository, artifact *meta.Artifact, repo *repository.ChartRepository) (sreconcile.Result, error)

func (r *HelmRepositoryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return r.SetupWithManagerAndOptions(mgr, HelmRepositoryReconcilerOptions{})
}

func (r *HelmRepositoryReconciler) SetupWithManagerAndOptions(mgr ctrl.Manager, opts HelmRepositoryReconcilerOptions) error {
	r.patchOptions = getPatchOptions(helmRepositoryReadyCondition.Owned, r.ControllerName)

	return ctrl.NewControllerManagedBy(mgr).
		For(&sourcev1.HelmRepository{}).
		WithEventFilter(
			predicate.And(
				intpredicates.HelmRepositoryOCIMigrationPredicate{},
				predicate.Or(predicate.GenerationChangedPredicate{}, predicates.ReconcileRequestedPredicate{}),
			),
		).
		WithOptions(controller.Options{
			RateLimiter: opts.RateLimiter,
		}).
		Complete(r)
}

func (r *HelmRepositoryReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, retErr error) {
	start := time.Now()
	log := ctrl.LoggerFrom(ctx)

	// Fetch the HelmRepository
	obj := &sourcev1.HelmRepository{}
	if err := r.Get(ctx, req.NamespacedName, obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Initialize the patch helper with the current version of the object.
	serialPatcher := patch.NewSerialPatcher(obj, r.Client)

	// If it's of type OCI, migrate the object to static.
	if obj.Spec.Type == sourcev1.HelmRepositoryTypeOCI {
		return r.migrationToStatic(ctx, serialPatcher, obj)
	}

	// recResult stores the abstracted reconcile result.
	var recResult sreconcile.Result

	// Always attempt to patch the object after each reconciliation.
	// NOTE: The final runtime result and error are set in this block.
	defer func() {
		summarizeHelper := summarize.NewHelper(r.EventRecorder, serialPatcher)
		summarizeOpts := []summarize.Option{
			summarize.WithConditions(helmRepositoryReadyCondition),
			summarize.WithReconcileResult(recResult),
			summarize.WithReconcileError(retErr),
			summarize.WithIgnoreNotFound(),
			summarize.WithProcessors(
				summarize.ErrorActionHandler,
				summarize.RecordReconcileReq,
			),
			summarize.WithResultBuilder(sreconcile.AlwaysRequeueResultBuilder{
				RequeueAfter: jitter.JitteredIntervalDuration(obj.GetRequeueAfter()),
			}),
			summarize.WithPatchFieldOwner(r.ControllerName),
		}
		result, retErr = summarizeHelper.SummarizeAndPatch(ctx, obj, summarizeOpts...)

		// Always record duration metrics.
		r.Metrics.RecordDuration(ctx, obj, start)
	}()

	// Examine if the object is under deletion.
	if !obj.ObjectMeta.DeletionTimestamp.IsZero() {
		recResult, retErr = r.reconcileDelete(ctx, obj)
		return
	}

	// Add finalizer first if not exist to avoid the race condition
	// between init and delete.
	// Note: Finalizers in general can only be added when the deletionTimestamp
	// is not set.
	if !controllerutil.ContainsFinalizer(obj, sourcev1.SourceFinalizer) {
		controllerutil.AddFinalizer(obj, sourcev1.SourceFinalizer)
		recResult = sreconcile.ResultRequeue
		return
	}

	// Return if the object is suspended.
	if obj.Spec.Suspend {
		log.Info("reconciliation is suspended for this object")
		recResult, retErr = sreconcile.ResultEmpty, nil
		return
	}

	// Reconcile actual object
	reconcilers := []helmRepositoryReconcileFunc{
		r.reconcileStorage,
		r.reconcileSource,
		r.reconcileArtifact,
	}
	recResult, retErr = r.reconcile(ctx, serialPatcher, obj, reconcilers)
	return
}

// reconcile iterates through the helmRepositoryReconcileFunc tasks for the
// object. It returns early on the first call that returns
// reconcile.ResultRequeue, or produces an error.
func (r *HelmRepositoryReconciler) reconcile(ctx context.Context, sp *patch.SerialPatcher,
	obj *sourcev1.HelmRepository, reconcilers []helmRepositoryReconcileFunc) (sreconcile.Result, error) {
	oldObj := obj.DeepCopy()

	rreconcile.ProgressiveStatus(false, obj, meta.ProgressingReason, "reconciliation in progress")

	var reconcileAtVal string
	if v, ok := meta.ReconcileAnnotationValue(obj.GetAnnotations()); ok {
		reconcileAtVal = v
	}

	// Persist reconciling if generation differs or reconciliation is requested.
	switch {
	case obj.Generation != obj.Status.ObservedGeneration:
		rreconcile.ProgressiveStatus(false, obj, meta.ProgressingReason,
			"processing object: new generation %d -> %d", obj.Status.ObservedGeneration, obj.Generation)
		if err := sp.Patch(ctx, obj, r.patchOptions...); err != nil {
			return sreconcile.ResultEmpty, serror.NewGeneric(err, sourcev1.PatchOperationFailedReason)
		}
	case reconcileAtVal != obj.Status.GetLastHandledReconcileRequest():
		if err := sp.Patch(ctx, obj, r.patchOptions...); err != nil {
			return sreconcile.ResultEmpty, serror.NewGeneric(err, sourcev1.PatchOperationFailedReason)
		}
	}

	var chartRepo repository.ChartRepository
	var artifact meta.Artifact

	// Run the sub-reconcilers and build the result of reconciliation.
	var res sreconcile.Result
	var resErr error
	for _, rec := range reconcilers {
		recResult, err := rec(ctx, sp, obj, &artifact, &chartRepo)
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
		// Prioritize requeue request in the result for successful results.
		res = sreconcile.LowestRequeuingResult(res, recResult)
	}

	r.notify(ctx, oldObj, obj, &chartRepo, res, resErr)

	return res, resErr
}

// notify emits notification related to the reconciliation.
func (r *HelmRepositoryReconciler) notify(ctx context.Context, oldObj, newObj *sourcev1.HelmRepository, chartRepo *repository.ChartRepository, res sreconcile.Result, resErr error) {
	// Notify successful reconciliation for new artifact and recovery from any
	// failure.
	if resErr == nil && res == sreconcile.ResultSuccess && newObj.Status.Artifact != nil {
		annotations := map[string]string{
			fmt.Sprintf("%s/%s", sourcev1.GroupVersion.Group, eventv1.MetaRevisionKey): newObj.Status.Artifact.Revision,
			fmt.Sprintf("%s/%s", sourcev1.GroupVersion.Group, eventv1.MetaDigestKey):   newObj.Status.Artifact.Digest,
		}

		humanReadableSize := "unknown size"
		if size := newObj.Status.Artifact.Size; size != nil {
			humanReadableSize = fmt.Sprintf("size %s", units.HumanSize(float64(*size)))
		}

		message := fmt.Sprintf("stored fetched index of %s from '%s'", humanReadableSize, chartRepo.URL)

		// Notify on new artifact and failure recovery.
		if !oldObj.GetArtifact().HasDigest(newObj.GetArtifact().Digest) {
			r.AnnotatedEventf(newObj, annotations, corev1.EventTypeNormal,
				"NewArtifact", message)
			ctrl.LoggerFrom(ctx).Info(message)
		} else {
			if sreconcile.FailureRecovery(oldObj, newObj, helmRepositoryFailConditions) {
				r.AnnotatedEventf(newObj, annotations, corev1.EventTypeNormal,
					meta.SucceededReason, message)
				ctrl.LoggerFrom(ctx).Info(message)
			}
		}
	}
}

// reconcileStorage ensures the current state of the storage matches the
// desired and previously observed state.
//
// The garbage collection is executed based on the flag configured settings and
// may remove files that are beyond their TTL or the maximum number of files
// to survive a collection cycle.
// If the Artifact in the Status of the object disappeared from the Storage,
// it is removed from the object.
// If the object does not have an Artifact in its Status, a Reconciling
// condition is added.
// The hostname of any URL in the Status of the object are updated, to ensure
// they match the Storage server hostname of current runtime.
func (r *HelmRepositoryReconciler) reconcileStorage(ctx context.Context, sp *patch.SerialPatcher,
	obj *sourcev1.HelmRepository, _ *meta.Artifact, _ *repository.ChartRepository) (sreconcile.Result, error) {
	// Garbage collect previous advertised artifact(s) from storage
	_ = r.garbageCollect(ctx, obj)

	var artifactMissing bool
	if artifact := obj.GetArtifact(); artifact != nil {
		// Determine if the advertised artifact is still in storage
		if !r.Storage.ArtifactExist(*artifact) {
			artifactMissing = true
		}

		// If the artifact is in storage, verify if the advertised digest still
		// matches the actual artifact
		if !artifactMissing {
			if err := r.Storage.VerifyArtifact(*artifact); err != nil {
				r.Eventf(obj, corev1.EventTypeWarning, "ArtifactVerificationFailed", "failed to verify integrity of artifact: %s", err.Error())

				if err = r.Storage.Remove(*artifact); err != nil {
					return sreconcile.ResultEmpty, fmt.Errorf("failed to remove artifact after digest mismatch: %w", err)
				}

				artifactMissing = true
			}
		}

		// If the artifact is missing, remove it from the object
		if artifactMissing {
			obj.Status.Artifact = nil
			obj.Status.URL = ""
		}
	}

	// Record that we do not have an artifact
	if obj.GetArtifact() == nil {
		msg := "building artifact"
		if artifactMissing {
			msg += ": disappeared from storage"
		}
		rreconcile.ProgressiveStatus(true, obj, meta.ProgressingReason, "%s", msg)
		conditions.Delete(obj, sourcev1.ArtifactInStorageCondition)
		if err := sp.Patch(ctx, obj, r.patchOptions...); err != nil {
			return sreconcile.ResultEmpty, serror.NewGeneric(err, sourcev1.PatchOperationFailedReason)
		}
		return sreconcile.ResultSuccess, nil
	}

	// Always update URLs to ensure hostname is up-to-date
	// TODO(hidde): we may want to send out an event only if we notice the URL has changed
	r.Storage.SetArtifactURL(obj.GetArtifact())
	obj.Status.URL = r.Storage.SetHostname(obj.Status.URL)

	return sreconcile.ResultSuccess, nil
}

// reconcileSource attempts to fetch the Helm repository index using the
// specified configuration on the v1.HelmRepository object.
//
// When the fetch fails, it records v1.FetchFailedCondition=True and
// returns early.
// If successful and the index is valid, any previous
// v1.FetchFailedCondition is removed, and the repository.ChartRepository
// pointer is set to the newly fetched index.
func (r *HelmRepositoryReconciler) reconcileSource(ctx context.Context, sp *patch.SerialPatcher,
	obj *sourcev1.HelmRepository, artifact *meta.Artifact, chartRepo *repository.ChartRepository) (sreconcile.Result, error) {
	// Ensure it's not an OCI URL. API validation ensures that only
	// http/https/oci scheme are allowed.
	if strings.HasPrefix(obj.Spec.URL, helmreg.OCIScheme) {
		err := fmt.Errorf("'oci' URL scheme cannot be used with 'default' HelmRepository type")
		e := serror.NewStalling(
			fmt.Errorf("invalid Helm repository URL: %w", err),
			sourcev1.URLInvalidReason,
		)
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
		return sreconcile.ResultEmpty, e
	}

	normalizedURL, err := repository.NormalizeURL(obj.Spec.URL)
	if err != nil {
		e := serror.NewStalling(
			fmt.Errorf("invalid Helm repository URL: %w", err),
			sourcev1.URLInvalidReason,
		)
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
		return sreconcile.ResultEmpty, e
	}

	clientOpts, _, err := getter.GetClientOpts(ctx, r.Client, obj, normalizedURL)
	if err != nil {
		if errors.Is(err, getter.ErrDeprecatedTLSConfig) {
			ctrl.LoggerFrom(ctx).
				Info("warning: specifying TLS authentication data via `.spec.secretRef` is deprecated, please use `.spec.certSecretRef` instead")
		} else {
			e := serror.NewGeneric(
				err,
				sourcev1.AuthenticationFailedReason,
			)
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
			return sreconcile.ResultEmpty, e
		}
	}

	// Construct Helm chart repository with options and download index
	newChartRepo, err := repository.NewChartRepository(obj.Spec.URL, "", r.Getters, clientOpts.TlsConfig, clientOpts.GetterOpts...)
	if err != nil {
		switch err.(type) {
		case *url.Error:
			e := serror.NewStalling(
				fmt.Errorf("invalid Helm repository URL: %w", err),
				sourcev1.URLInvalidReason,
			)
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
			return sreconcile.ResultEmpty, e
		default:
			e := serror.NewStalling(
				fmt.Errorf("failed to construct Helm client: %w", err),
				meta.FailedReason,
			)
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
			return sreconcile.ResultEmpty, e
		}
	}

	// Fetch the repository index from remote.
	if err := newChartRepo.CacheIndex(); err != nil {
		e := serror.NewGeneric(
			fmt.Errorf("failed to fetch Helm repository index: %w", err),
			meta.FailedReason,
		)
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
		// Coin flip on transient or persistent error, return error and hope for the best
		return sreconcile.ResultEmpty, e
	}
	*chartRepo = *newChartRepo

	// Early comparison to current Artifact.
	if curArtifact := obj.GetArtifact(); curArtifact != nil {
		curRev := digest.Digest(curArtifact.Revision)
		if curRev.Validate() == nil {
			// Short-circuit based on the fetched index being an exact match to the
			// stored Artifact.
			if newRev := chartRepo.Digest(curRev.Algorithm()); newRev.Validate() == nil && (newRev == curRev) {
				*artifact = *curArtifact
				conditions.Delete(obj, sourcev1.FetchFailedCondition)
				return sreconcile.ResultSuccess, nil
			}
		}
	}

	// Load the cached repository index to ensure it passes validation.
	if err := chartRepo.LoadFromPath(); err != nil {
		e := serror.NewGeneric(
			fmt.Errorf("failed to load Helm repository from index YAML: %w", err),
			sourcev1.IndexationFailedReason,
		)
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
		return sreconcile.ResultEmpty, e
	}
	// Delete any stale failure observation
	conditions.Delete(obj, sourcev1.FetchFailedCondition)

	// Calculate revision.
	revision := chartRepo.Digest(intdigest.Canonical)
	if revision.Validate() != nil {
		e := serror.NewGeneric(
			fmt.Errorf("failed to calculate revision: %w", err),
			sourcev1.IndexationFailedReason,
		)
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, "%s", e)
		return sreconcile.ResultEmpty, e
	}

	// Mark observations about the revision on the object.
	message := fmt.Sprintf("new index revision '%s'", revision)
	if obj.GetArtifact() != nil {
		conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "NewRevision", "%s", message)
	}
	rreconcile.ProgressiveStatus(true, obj, meta.ProgressingReason, "building artifact: %s", message)
	if err := sp.Patch(ctx, obj, r.patchOptions...); err != nil {
		return sreconcile.ResultEmpty, serror.NewGeneric(err, sourcev1.PatchOperationFailedReason)
	}

	// Create potential new artifact.
	*artifact = r.Storage.NewArtifactFor(obj.Kind,
		obj.ObjectMeta.GetObjectMeta(),
		revision.String(),
		fmt.Sprintf("index-%s.yaml", revision.Encoded()),
	)

	return sreconcile.ResultSuccess, nil
}

// reconcileArtifact archives a new Artifact to the Storage, if the current
// (Status) data on the object does not match the given.
//
// The inspection of the given data to the object is differed, ensuring any
// stale observations like v1.ArtifactOutdatedCondition are removed.
// If the given Artifact does not differ from the object's current, it returns
// early.
// On a successful archive, the Artifact in the Status of the object is set,
// and the symlink in the Storage is updated to its path.
func (r *HelmRepositoryReconciler) reconcileArtifact(ctx context.Context, sp *patch.SerialPatcher, obj *sourcev1.HelmRepository, artifact *meta.Artifact, chartRepo *repository.ChartRepository) (sreconcile.Result, error) {
	// Set the ArtifactInStorageCondition if there's no drift.
	defer func() {
		if obj.GetArtifact().HasRevision(artifact.Revision) {
			conditions.Delete(obj, sourcev1.ArtifactOutdatedCondition)
			conditions.MarkTrue(obj, sourcev1.ArtifactInStorageCondition, meta.SucceededReason,
				"stored artifact: revision '%s'", artifact.Revision)
		}
		if err := chartRepo.Clear(); err != nil {
			ctrl.LoggerFrom(ctx).Error(err, "failed to remove temporary cached index file")
		}
	}()

	if obj.GetArtifact().HasRevision(artifact.Revision) && obj.GetArtifact().HasDigest(artifact.Digest) {
		// Extend TTL of the Index in the cache (if present).
		if r.Cache != nil {
			r.Cache.SetExpiration(artifact.Path, r.TTL)
		}

		r.eventLogf(ctx, obj, eventv1.EventTypeTrace, sourcev1.ArtifactUpToDateReason, "artifact up-to-date with remote revision: '%s'", artifact.Revision)
		return sreconcile.ResultSuccess, nil
	}

	// Create artifact dir
	if err := r.Storage.MkdirAll(*artifact); err != nil {
		e := serror.NewGeneric(
			fmt.Errorf("failed to create artifact directory: %w", err),
			sourcev1.DirCreationFailedReason,
		)
		conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, e.Reason, "%s", e)
		return sreconcile.ResultEmpty, e
	}

	// Acquire lock.
	unlock, err := r.Storage.Lock(*artifact)
	if err != nil {
		return sreconcile.ResultEmpty, serror.NewGeneric(
			fmt.Errorf("failed to acquire lock for artifact: %w", err),
			meta.FailedReason,
		)
	}
	defer unlock()

	// Save artifact to storage in JSON format.
	b, err := chartRepo.ToJSON()
	if err != nil {
		e := serror.NewGeneric(
			fmt.Errorf("unable to get JSON index from chart repo: %w", err),
			sourcev1.ArchiveOperationFailedReason,
		)
		conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, e.Reason, "%s", e)
		return sreconcile.ResultEmpty, e
	}
	if err = r.Storage.Copy(artifact, bytes.NewBuffer(b)); err != nil {
		e := serror.NewGeneric(
			fmt.Errorf("unable to save artifact to storage: %w", err),
			sourcev1.ArchiveOperationFailedReason,
		)
		conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, e.Reason, "%s", e)
		return sreconcile.ResultEmpty, e
	}

	// Record it on the object.
	obj.Status.Artifact = artifact.DeepCopy()

	// Cache the index if it was successfully retrieved.
	if r.Cache != nil && chartRepo.Index != nil {
		// The cache keys have to be safe in multi-tenancy environments, as
		// otherwise it could be used as a vector to bypass the repository's
		// authentication. Using the Artifact.Path is safe as the path is in
		// the format of: /<repository-name>/<chart-name>/<filename>.
		if err := r.Cache.Set(artifact.Path, chartRepo.Index, r.TTL); err != nil {
			r.eventLogf(ctx, obj, eventv1.EventTypeTrace, sourcev1.CacheOperationFailedReason, "failed to cache index: %s", err)
		}
	}

	// Update index symlink.
	indexURL, err := r.Storage.Symlink(*artifact, "index.yaml")
	if err != nil {
		r.eventLogf(ctx, obj, eventv1.EventTypeTrace, sourcev1.SymlinkUpdateFailedReason,
			"failed to update status URL symlink: %s", err)
	}
	if indexURL != "" {
		obj.Status.URL = indexURL
	}
	conditions.Delete(obj, sourcev1.StorageOperationFailedCondition)
	return sreconcile.ResultSuccess, nil
}

// reconcileDelete handles the deletion of the object.
// It first garbage collects all Artifacts for the object from the Storage.
// Removing the finalizer from the object if successful.
func (r *HelmRepositoryReconciler) reconcileDelete(ctx context.Context, obj *sourcev1.HelmRepository) (sreconcile.Result, error) {
	// Garbage collect the resource's artifacts
	if err := r.garbageCollect(ctx, obj); err != nil {
		// Return the error so we retry the failed garbage collection
		return sreconcile.ResultEmpty, err
	}

	// Remove our finalizer from the list if we are deleting the object
	if !obj.DeletionTimestamp.IsZero() {
		controllerutil.RemoveFinalizer(obj, sourcev1.SourceFinalizer)
	}

	// Delete cache metrics.
	if r.CacheRecorder != nil && r.Metrics.IsDelete(obj) {
		r.DeleteCacheEvent(cache.CacheEventTypeHit, obj.Name, obj.Namespace)
		r.DeleteCacheEvent(cache.CacheEventTypeMiss, obj.Name, obj.Namespace)
	}

	// Stop reconciliation as the object is being deleted
	return sreconcile.ResultEmpty, nil
}

// garbageCollect performs a garbage collection for the given object.
//
// It removes all but the current Artifact from the Storage, unless:
// - the deletion timestamp on the object is set
// - the obj.Spec.Type has changed and artifacts are not supported by the new type
// Which will result in the removal of all Artifacts for the objects.
func (r *HelmRepositoryReconciler) garbageCollect(ctx context.Context, obj *sourcev1.HelmRepository) error {
	if !obj.DeletionTimestamp.IsZero() || (obj.Spec.Type != "" && obj.Spec.Type != sourcev1.HelmRepositoryTypeDefault) {
		if deleted, err := r.Storage.RemoveAll(r.Storage.NewArtifactFor(obj.Kind, obj.GetObjectMeta(), "", "*")); err != nil {
			return serror.NewGeneric(
				fmt.Errorf("garbage collection for deleted resource failed: %w", err),
				"GarbageCollectionFailed",
			)
		} else if deleted != "" {
			r.eventLogf(ctx, obj, eventv1.EventTypeTrace, "GarbageCollectionSucceeded",
				"garbage collected artifacts for deleted resource")
		}
		// Clean status sub-resource
		obj.Status.Artifact = nil
		obj.Status.URL = ""
		// Remove any stale conditions.
		obj.Status.Conditions = nil
		return nil
	}
	if obj.GetArtifact() != nil {
		delFiles, err := r.Storage.GarbageCollect(ctx, *obj.GetArtifact(), time.Second*5)
		if err != nil {
			return serror.NewGeneric(
				fmt.Errorf("garbage collection of artifacts failed: %w", err),
				"GarbageCollectionFailed",
			)
		}
		if len(delFiles) > 0 {
			r.eventLogf(ctx, obj, eventv1.EventTypeTrace, "GarbageCollectionSucceeded",
				"garbage collected %d artifacts", len(delFiles))
			return nil
		}
	}
	return nil
}

// eventLogf records events, and logs at the same time.
//
// This log is different from the debug log in the EventRecorder, in the sense
// that this is a simple log. While the debug log contains complete details
// about the event.
func (r *HelmRepositoryReconciler) eventLogf(ctx context.Context, obj runtime.Object, eventType string, reason string, messageFmt string, args ...interface{}) {
	msg := fmt.Sprintf(messageFmt, args...)
	// Log and emit event.
	if eventType == corev1.EventTypeWarning {
		ctrl.LoggerFrom(ctx).Error(errors.New(reason), msg)
	} else {
		ctrl.LoggerFrom(ctx).Info(msg)
	}
	r.Eventf(obj, eventType, reason, msg)
}

// migrateToStatic is HelmRepository OCI migration to static object.
func (r *HelmRepositoryReconciler) migrationToStatic(ctx context.Context, sp *patch.SerialPatcher, obj *sourcev1.HelmRepository) (result ctrl.Result, err error) {
	// Skip migration if suspended and not being deleted.
	if obj.Spec.Suspend && obj.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	if !intpredicates.HelmRepositoryOCIRequireMigration(obj) {
		// Already migrated, nothing to do.
		return ctrl.Result{}, nil
	}

	// Delete any artifact.
	_, err = r.reconcileDelete(ctx, obj)
	if err != nil {
		return ctrl.Result{}, err
	}
	// Delete finalizer and reset the status.
	controllerutil.RemoveFinalizer(obj, sourcev1.SourceFinalizer)
	obj.Status = sourcev1.HelmRepositoryStatus{}

	if err := sp.Patch(ctx, obj); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}
