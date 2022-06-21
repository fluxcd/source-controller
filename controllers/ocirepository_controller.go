/*
Copyright 2022 The Flux authors

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
	"os"
	"time"

	"github.com/google/go-containerregistry/pkg/crane"
	gcrv1 "github.com/google/go-containerregistry/pkg/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/uuid"
	kuberecorder "k8s.io/client-go/tools/record"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/ratelimiter"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/conditions"
	helper "github.com/fluxcd/pkg/runtime/controller"
	"github.com/fluxcd/pkg/runtime/events"
	"github.com/fluxcd/pkg/runtime/patch"
	"github.com/fluxcd/pkg/runtime/predicates"
	"github.com/fluxcd/pkg/untar"
	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
	serror "github.com/fluxcd/source-controller/internal/error"
	sreconcile "github.com/fluxcd/source-controller/internal/reconcile"
	"github.com/fluxcd/source-controller/internal/reconcile/summarize"
)

// ociRepositoryReadyCondition contains the information required to summarize a
// v1beta2.OCIRepository Ready Condition.
var ociRepositoryReadyCondition = summarize.Conditions{
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

// ociRepositoryFailConditions contains the conditions that represent a failure.
var ociRepositoryFailConditions = []string{
	sourcev1.FetchFailedCondition,
	sourcev1.StorageOperationFailedCondition,
}

// ociRepositoryReconcileFunc is the function type for all the v1beta2.OCIRepository
// (sub)reconcile functions. The type implementations are grouped and
// executed serially to perform the complete reconcile of the object.
type ociRepositoryReconcileFunc func(ctx context.Context, obj *sourcev1.OCIRepository, digest *gcrv1.Hash, dir string) (sreconcile.Result, error)

// OCIRepositoryReconciler reconciles a v1beta2.OCIRepository object
type OCIRepositoryReconciler struct {
	client.Client
	helper.Metrics
	kuberecorder.EventRecorder

	Storage           *Storage
	ControllerName    string
	requeueDependency time.Duration
}

type OCIRepositoryReconcilerOptions struct {
	MaxConcurrentReconciles   int
	DependencyRequeueInterval time.Duration
	RateLimiter               ratelimiter.RateLimiter
}

// SetupWithManager sets up the controller with the Manager.
func (r *OCIRepositoryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return r.SetupWithManagerAndOptions(mgr, OCIRepositoryReconcilerOptions{})
}

func (r *OCIRepositoryReconciler) SetupWithManagerAndOptions(mgr ctrl.Manager, opts OCIRepositoryReconcilerOptions) error {
	r.requeueDependency = opts.DependencyRequeueInterval

	return ctrl.NewControllerManagedBy(mgr).
		For(&sourcev1.OCIRepository{}, builder.WithPredicates(
			predicate.Or(predicate.GenerationChangedPredicate{}, predicates.ReconcileRequestedPredicate{}),
		)).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: opts.MaxConcurrentReconciles,
			RateLimiter:             opts.RateLimiter,
		}).
		Complete(r)
}

// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=ocirepositories,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=ocirepositories/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=ocirepositories/finalizers,verbs=get;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

func (r *OCIRepositoryReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, retErr error) {
	start := time.Now()
	log := ctrl.LoggerFrom(ctx).
		// Sets a reconcile ID to correlate logs from all suboperations.
		WithValues("reconcileID", uuid.NewUUID())

	// logger will be associated to the new context that is
	// returned from ctrl.LoggerInto.
	ctx = ctrl.LoggerInto(ctx, log)

	// Fetch the OCIRepository
	obj := &sourcev1.OCIRepository{}
	if err := r.Get(ctx, req.NamespacedName, obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Record suspended status metric
	r.RecordSuspend(ctx, obj, obj.Spec.Suspend)

	// Return early if the object is suspended
	if obj.Spec.Suspend {
		log.Info("reconciliation is suspended for this object")
		return ctrl.Result{}, nil
	}

	// Initialize the patch helper with the current version of the object.
	patchHelper, err := patch.NewHelper(obj, r.Client)
	if err != nil {
		return ctrl.Result{}, err
	}

	// recResult stores the abstracted reconcile result.
	var recResult sreconcile.Result

	// Always attempt to patch the object and status after each reconciliation
	// NOTE: The final runtime result and error are set in this block.
	defer func() {
		summarizeHelper := summarize.NewHelper(r.EventRecorder, patchHelper)
		summarizeOpts := []summarize.Option{
			summarize.WithConditions(ociRepositoryReadyCondition),
			summarize.WithReconcileResult(recResult),
			summarize.WithReconcileError(retErr),
			summarize.WithIgnoreNotFound(),
			summarize.WithProcessors(
				summarize.RecordContextualError,
				summarize.RecordReconcileReq,
			),
			summarize.WithResultBuilder(sreconcile.AlwaysRequeueResultBuilder{RequeueAfter: obj.GetRequeueAfter()}),
			summarize.WithPatchFieldOwner(r.ControllerName),
		}
		result, retErr = summarizeHelper.SummarizeAndPatch(ctx, obj, summarizeOpts...)

		// Always record readiness and duration metrics
		r.Metrics.RecordReadiness(ctx, obj)
		r.Metrics.RecordDuration(ctx, obj, start)
	}()

	// Add finalizer first if not exist to avoid the race condition between init and delete
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
	reconcilers := []ociRepositoryReconcileFunc{
		r.reconcileStorage,
		r.reconcileSource,
		r.reconcileArtifact,
	}
	recResult, retErr = r.reconcile(ctx, obj, reconcilers)
	return
}

// reconcile iterates through the ociRepositoryReconcileFunc tasks for the
// object. It returns early on the first call that returns
// reconcile.ResultRequeue, or produces an error.
func (r *OCIRepositoryReconciler) reconcile(ctx context.Context, obj *sourcev1.OCIRepository, reconcilers []ociRepositoryReconcileFunc) (sreconcile.Result, error) {
	oldObj := obj.DeepCopy()

	// Mark as reconciling if generation differs.
	if obj.Generation != obj.Status.ObservedGeneration {
		conditions.MarkReconciling(obj, "NewGeneration", "reconciling new object generation (%d)", obj.Generation)
	}

	// Create temp working dir
	tmpDir, err := os.MkdirTemp("", fmt.Sprintf("%s-%s-%s-", obj.Kind, obj.Namespace, obj.Name))
	if err != nil {
		e := &serror.Event{
			Err:    fmt.Errorf("failed to create temporary working directory: %w", err),
			Reason: sourcev1.DirCreationFailedReason,
		}
		conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, e.Reason, e.Err.Error())
		return sreconcile.ResultEmpty, e
	}
	defer func() {
		if err = os.RemoveAll(tmpDir); err != nil {
			ctrl.LoggerFrom(ctx).Error(err, "failed to remove temporary working directory")
		}
	}()
	conditions.Delete(obj, sourcev1.StorageOperationFailedCondition)

	hs := gcrv1.Hash{}
	var (
		res    sreconcile.Result
		resErr error
		digest = hs.DeepCopy()
	)

	// Run the sub-reconcilers and build the result of reconciliation.
	for _, rec := range reconcilers {
		recResult, err := rec(ctx, obj, digest, tmpDir)
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

	r.notify(ctx, oldObj, obj, digest, res, resErr)

	return res, resErr
}

// notify emits notification related to the reconciliation.
func (r *OCIRepositoryReconciler) notify(ctx context.Context, oldObj, newObj *sourcev1.OCIRepository, digest *gcrv1.Hash, res sreconcile.Result, resErr error) {
	// Notify successful reconciliation for new artifact and recovery from any
	// failure.
	if resErr == nil && res == sreconcile.ResultSuccess && newObj.Status.Artifact != nil {
		annotations := map[string]string{
			sourcev1.GroupVersion.Group + "/revision": newObj.Status.Artifact.Revision,
			sourcev1.GroupVersion.Group + "/checksum": newObj.Status.Artifact.Checksum,
		}

		var oldChecksum string
		if oldObj.GetArtifact() != nil {
			oldChecksum = oldObj.GetArtifact().Checksum
		}

		message := fmt.Sprintf("stored artifact with digest '%s' from '%s'", digest.String(), newObj.Spec.URL)

		// Notify on new artifact and failure recovery.
		if oldChecksum != newObj.GetArtifact().Checksum {
			r.AnnotatedEventf(newObj, annotations, corev1.EventTypeNormal,
				"NewArtifact", message)
			ctrl.LoggerFrom(ctx).Info(message)
		} else {
			if sreconcile.FailureRecovery(oldObj, newObj, ociRepositoryFailConditions) {
				r.AnnotatedEventf(newObj, annotations, corev1.EventTypeNormal,
					meta.SucceededReason, message)
				ctrl.LoggerFrom(ctx).Info(message)
			}
		}
	}
}

// reconcileSource fetches the upstream OCI artifact content.
// If this fails, it records v1beta2.FetchFailedCondition=True on the object and returns early.
func (r *OCIRepositoryReconciler) reconcileSource(ctx context.Context, obj *sourcev1.OCIRepository, digest *gcrv1.Hash, dir string) (sreconcile.Result, error) {
	ctxTimeout, cancel := context.WithTimeout(ctx, obj.Spec.Timeout.Duration)
	defer cancel()

	url := obj.Spec.URL
	if obj.Spec.Reference != nil {
		if obj.Spec.Reference.Tag != "" {
			url = fmt.Sprintf("%s:%s", obj.Spec.URL, obj.Spec.Reference.Tag)
		}
		if obj.Spec.Reference.Digest != "" {
			url = fmt.Sprintf("%s@%s", obj.Spec.URL, obj.Spec.Reference.Digest)
		}
	}

	// Pull OCI artifact
	img, err := crane.Pull(url, r.craneOptions(ctxTimeout)...)
	if err != nil {
		e := &serror.Event{Err: err, Reason: sourcev1.OCIOperationFailedReason}
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, e.Error())
		return sreconcile.ResultEmpty, e
	}

	// Fetch digest
	imgDigest, err := img.Digest()
	if err != nil {
		e := &serror.Event{Err: err, Reason: sourcev1.OCIOperationFailedReason}
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, e.Error())
		return sreconcile.ResultEmpty, e
	}

	// Set revision from digest hex
	imgDigest.DeepCopyInto(digest)
	revision := imgDigest.Hex

	// Mark observations about the revision on the object
	defer func() {
		if !obj.GetArtifact().HasRevision(revision) {
			message := fmt.Sprintf("new upstream revision '%s'", revision)
			conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "NewRevision", message)
			conditions.MarkReconciling(obj, "NewRevision", message)
		}
	}()

	// Extract the content of the first artifact layer
	if !obj.GetArtifact().HasRevision(revision) {
		layers, err := img.Layers()
		if err != nil {
			e := &serror.Event{Err: err, Reason: sourcev1.OCIOperationFailedReason}
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, e.Error())
			return sreconcile.ResultEmpty, e
		}

		if len(layers) < 1 {
			err = fmt.Errorf("no layers found in artifact")
			e := &serror.Event{Err: err, Reason: sourcev1.OCIOperationFailedReason}
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, e.Error())
			return sreconcile.ResultEmpty, e
		}

		blob, err := layers[0].Compressed()
		if err != nil {
			e := &serror.Event{Err: err, Reason: sourcev1.OCIOperationFailedReason}
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, e.Error())
			return sreconcile.ResultEmpty, e
		}

		if _, err = untar.Untar(blob, dir); err != nil {
			e := &serror.Event{Err: err, Reason: sourcev1.OCIOperationFailedReason}
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, e.Error())
			return sreconcile.ResultEmpty, e
		}
	}

	conditions.Delete(obj, sourcev1.FetchFailedCondition)
	return sreconcile.ResultSuccess, nil
}

// reconcileStorage ensures the current state of the storage matches the
// desired and previously observed state.
//
// All Artifacts for the object except for the current one in the Status are
// garbage collected from the Storage.
// If the Artifact in the Status of the object disappeared from the Storage,
// it is removed from the object.
// If the object does not have an Artifact in its Status, a Reconciling
// condition is added.
// The hostname of any URL in the Status of the object are updated, to ensure
// they match the Storage server hostname of current runtime.
func (r *OCIRepositoryReconciler) reconcileStorage(ctx context.Context, obj *sourcev1.OCIRepository, _ *gcrv1.Hash, _ string) (sreconcile.Result, error) {
	// Garbage collect previous advertised artifact(s) from storage
	_ = r.garbageCollect(ctx, obj)

	// Determine if the advertised artifact is still in storage
	if artifact := obj.GetArtifact(); artifact != nil && !r.Storage.ArtifactExist(*artifact) {
		obj.Status.Artifact = nil
		obj.Status.URL = ""
		// Remove the condition as the artifact doesn't exist.
		conditions.Delete(obj, sourcev1.ArtifactInStorageCondition)
	}

	// Record that we do not have an artifact
	if obj.GetArtifact() == nil {
		conditions.MarkReconciling(obj, "NoArtifact", "no artifact for resource in storage")
		conditions.Delete(obj, sourcev1.ArtifactInStorageCondition)
		return sreconcile.ResultSuccess, nil
	}

	// Always update URLs to ensure hostname is up-to-date
	r.Storage.SetArtifactURL(obj.GetArtifact())
	obj.Status.URL = r.Storage.SetHostname(obj.Status.URL)

	return sreconcile.ResultSuccess, nil
}

// reconcileArtifact archives a new Artifact to the Storage, if the current
// (Status) data on the object does not match the given.
//
// The inspection of the given data to the object is differed, ensuring any
// stale observations like v1beta2.ArtifactOutdatedCondition are removed.
// If the given Artifact does not differ from the object's current, it returns
// early.
// On a successful archive, the Artifact in the Status of the object is set,
// and the symlink in the Storage is updated to its path.
func (r *OCIRepositoryReconciler) reconcileArtifact(ctx context.Context, obj *sourcev1.OCIRepository, digest *gcrv1.Hash, dir string) (sreconcile.Result, error) {
	// Calculate revision
	revision := digest.Hex

	// Create artifact
	artifact := r.Storage.NewArtifactFor(obj.Kind, obj, revision, fmt.Sprintf("%s.tar.gz", revision))

	// Set the ArtifactInStorageCondition if there's no drift.
	defer func() {
		if obj.GetArtifact().HasRevision(artifact.Revision) {
			conditions.Delete(obj, sourcev1.ArtifactOutdatedCondition)
			conditions.MarkTrue(obj, sourcev1.ArtifactInStorageCondition, meta.SucceededReason,
				"stored artifact for revision '%s'", artifact.Revision)
		}
	}()

	// The artifact is up-to-date
	if obj.GetArtifact().HasRevision(artifact.Revision) {
		r.eventLogf(ctx, obj, events.EventTypeTrace, sourcev1.ArtifactUpToDateReason, "artifact up-to-date with remote revision: '%s'", artifact.Revision)
		return sreconcile.ResultSuccess, nil
	}

	// Ensure target path exists and is a directory
	if f, err := os.Stat(dir); err != nil {
		e := &serror.Event{
			Err:    fmt.Errorf("failed to stat source path: %w", err),
			Reason: sourcev1.StatOperationFailedReason,
		}
		conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, e.Reason, e.Err.Error())
		return sreconcile.ResultEmpty, e
	} else if !f.IsDir() {
		e := &serror.Event{
			Err:    fmt.Errorf("source path '%s' is not a directory", dir),
			Reason: sourcev1.InvalidPathReason,
		}
		conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, e.Reason, e.Err.Error())
		return sreconcile.ResultEmpty, e
	}

	// Ensure artifact directory exists and acquire lock
	if err := r.Storage.MkdirAll(artifact); err != nil {
		e := &serror.Event{
			Err:    fmt.Errorf("failed to create artifact directory: %w", err),
			Reason: sourcev1.DirCreationFailedReason,
		}
		conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, e.Reason, e.Err.Error())
		return sreconcile.ResultEmpty, e
	}
	unlock, err := r.Storage.Lock(artifact)
	if err != nil {
		return sreconcile.ResultEmpty, &serror.Event{
			Err:    fmt.Errorf("failed to acquire lock for artifact: %w", err),
			Reason: meta.FailedReason,
		}
	}
	defer unlock()

	// Archive directory to storage
	if err := r.Storage.Archive(&artifact, dir, nil); err != nil {
		e := &serror.Event{
			Err:    fmt.Errorf("unable to archive artifact to storage: %s", err),
			Reason: sourcev1.ArchiveOperationFailedReason,
		}
		conditions.MarkTrue(obj, sourcev1.StorageOperationFailedCondition, e.Reason, e.Err.Error())
		return sreconcile.ResultEmpty, e
	}

	// Record it on the object
	obj.Status.Artifact = artifact.DeepCopy()

	// Update symlink on a "best effort" basis
	url, err := r.Storage.Symlink(artifact, "latest.tar.gz")
	if err != nil {
		r.eventLogf(ctx, obj, events.EventTypeTrace, sourcev1.SymlinkUpdateFailedReason,
			"failed to update status URL symlink: %s", err)
	}
	if url != "" {
		obj.Status.URL = url
	}
	conditions.Delete(obj, sourcev1.StorageOperationFailedCondition)
	return sreconcile.ResultSuccess, nil
}

// reconcileDelete handles the deletion of the object.
// It first garbage collects all Artifacts for the object from the Storage.
// Removing the finalizer from the object if successful.
func (r *OCIRepositoryReconciler) reconcileDelete(ctx context.Context, obj *sourcev1.OCIRepository) (sreconcile.Result, error) {
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

// garbageCollect performs a garbage collection for the given object.
//
// It removes all but the current Artifact from the Storage, unless the
// deletion timestamp on the object is set. Which will result in the
// removal of all Artifacts for the objects.
func (r *OCIRepositoryReconciler) garbageCollect(ctx context.Context, obj *sourcev1.OCIRepository) error {
	if !obj.DeletionTimestamp.IsZero() {
		if deleted, err := r.Storage.RemoveAll(r.Storage.NewArtifactFor(obj.Kind, obj.GetObjectMeta(), "", "*")); err != nil {
			return serror.NewGeneric(
				fmt.Errorf("garbage collection for deleted resource failed: %w", err),
				"GarbageCollectionFailed",
			)
		} else if deleted != "" {
			r.eventLogf(ctx, obj, events.EventTypeTrace, "GarbageCollectionSucceeded",
				"garbage collected artifacts for deleted resource")
		}
		obj.Status.Artifact = nil
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
			r.eventLogf(ctx, obj, events.EventTypeTrace, "GarbageCollectionSucceeded",
				fmt.Sprintf("garbage collected %d artifacts", len(delFiles)))
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
func (r *OCIRepositoryReconciler) eventLogf(ctx context.Context, obj runtime.Object, eventType string, reason string, messageFmt string, args ...interface{}) {
	msg := fmt.Sprintf(messageFmt, args...)
	// Log and emit event.
	if eventType == corev1.EventTypeWarning {
		ctrl.LoggerFrom(ctx).Error(errors.New(reason), msg)
	} else {
		ctrl.LoggerFrom(ctx).Info(msg)
	}
	r.Eventf(obj, eventType, reason, msg)
}

func (r *OCIRepositoryReconciler) craneOptions(ctx context.Context) []crane.Option {
	return []crane.Option{
		crane.WithContext(ctx),
		crane.WithUserAgent("flux/v2"),
		crane.WithPlatform(&gcrv1.Platform{
			Architecture: "flux",
			OS:           "flux",
			OSVersion:    "v2",
		}),
	}
}
