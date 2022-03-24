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
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fluxcd/source-controller/pkg/azure"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kuberecorder "k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/conditions"
	helper "github.com/fluxcd/pkg/runtime/controller"
	"github.com/fluxcd/pkg/runtime/events"
	"github.com/fluxcd/pkg/runtime/patch"
	"github.com/fluxcd/pkg/runtime/predicates"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
	serror "github.com/fluxcd/source-controller/internal/error"
	sreconcile "github.com/fluxcd/source-controller/internal/reconcile"
	"github.com/fluxcd/source-controller/internal/reconcile/summarize"
	"github.com/fluxcd/source-controller/pkg/gcp"
	"github.com/fluxcd/source-controller/pkg/minio"
	"github.com/fluxcd/source-controller/pkg/sourceignore"
)

// maxConcurrentBucketFetches is the upper bound on the goroutines used to
// fetch bucket objects. It's important to have a bound, to avoid
// using arbitrary amounts of memory; the actual number is chosen
// according to the queueing rule of thumb with some conservative
// parameters:
// s > Nr / T
// N (number of requestors, i.e., objects to fetch) = 10000
// r (service time -- fetch duration) = 0.01s (~ a megabyte file over 1Gb/s)
// T (total time available) = 1s
// -> s > 100
const maxConcurrentBucketFetches = 100

// bucketReadyCondition contains the information required to summarize a
// v1beta2.Bucket Ready Condition.
var bucketReadyCondition = summarize.Conditions{
	Target: meta.ReadyCondition,
	Owned: []string{
		sourcev1.FetchFailedCondition,
		sourcev1.StorageOperationFailedCondition,
		sourcev1.ArtifactOutdatedCondition,
		meta.ReadyCondition,
		meta.ReconcilingCondition,
		meta.StalledCondition,
	},
	Summarize: []string{
		sourcev1.FetchFailedCondition,
		sourcev1.StorageOperationFailedCondition,
		sourcev1.ArtifactOutdatedCondition,
		meta.StalledCondition,
		meta.ReconcilingCondition,
	},
	NegativePolarity: []string{
		sourcev1.FetchFailedCondition,
		sourcev1.StorageOperationFailedCondition,
		sourcev1.ArtifactOutdatedCondition,
		meta.StalledCondition,
		meta.ReconcilingCondition,
	},
}

// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=buckets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=buckets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=buckets/finalizers,verbs=get;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// BucketReconciler reconciles a v1beta2.Bucket object.
type BucketReconciler struct {
	client.Client
	kuberecorder.EventRecorder
	helper.Metrics

	Storage        *Storage
	ControllerName string
}

type BucketReconcilerOptions struct {
	MaxConcurrentReconciles int
}

// BucketProvider is an interface for fetching objects from a storage provider
// bucket.
type BucketProvider interface {
	// BucketExists returns if an object storage bucket with the provided name
	// exists, or returns a (client) error.
	BucketExists(ctx context.Context, bucketName string) (bool, error)
	// FGetObject gets the object from the provided object storage bucket, and
	// writes it to targetPath.
	// It returns the etag of the successfully fetched file, or any error.
	FGetObject(ctx context.Context, bucketName, objectKey, targetPath string) (etag string, err error)
	// VisitObjects iterates over the items in the provided object storage
	// bucket, calling visit for every item.
	// If the underlying client or the visit callback returns an error,
	// it returns early.
	VisitObjects(ctx context.Context, bucketName string, visit func(key, etag string) error) error
	// ObjectIsNotFound returns true if the given error indicates an object
	// could not be found.
	ObjectIsNotFound(error) bool
	// Close closes the provider's client, if supported.
	Close(context.Context)
}

// bucketReconcileFunc is the function type for all the v1beta2.Bucket
// (sub)reconcile functions. The type implementations are grouped and
// executed serially to perform the complete reconcile of the object.
type bucketReconcileFunc func(ctx context.Context, obj *sourcev1.Bucket, index *etagIndex, dir string) (sreconcile.Result, error)

// etagIndex is an index of storage object keys and their Etag values.
type etagIndex struct {
	sync.RWMutex
	index map[string]string
}

// newEtagIndex returns a new etagIndex with an empty initialized index.
func newEtagIndex() *etagIndex {
	return &etagIndex{
		index: make(map[string]string),
	}
}

func (i *etagIndex) Add(key, etag string) {
	i.Lock()
	defer i.Unlock()
	i.index[key] = etag
}

func (i *etagIndex) Delete(key string) {
	i.Lock()
	defer i.Unlock()
	delete(i.index, key)
}

func (i *etagIndex) Get(key string) string {
	i.RLock()
	defer i.RUnlock()
	return i.index[key]
}

func (i *etagIndex) Has(key string) bool {
	i.RLock()
	defer i.RUnlock()
	_, ok := i.index[key]
	return ok
}

func (i *etagIndex) Index() map[string]string {
	i.RLock()
	defer i.RUnlock()
	index := make(map[string]string)
	for k, v := range i.index {
		index[k] = v
	}
	return index
}

func (i *etagIndex) Len() int {
	i.RLock()
	defer i.RUnlock()
	return len(i.index)
}

// Revision calculates the SHA256 checksum of the index.
// The keys are stable sorted, and the SHA256 sum is then calculated for the
// string representation of the key/value pairs, each pair written on a newline
// with a space between them. The sum result is returned as a string.
func (i *etagIndex) Revision() (string, error) {
	i.RLock()
	defer i.RUnlock()
	keyIndex := make([]string, 0, len(i.index))
	for k := range i.index {
		keyIndex = append(keyIndex, k)
	}

	sort.Strings(keyIndex)
	sum := sha256.New()
	for _, k := range keyIndex {
		if _, err := sum.Write([]byte(fmt.Sprintf("%s %s\n", k, i.index[k]))); err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("%x", sum.Sum(nil)), nil
}

func (r *BucketReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return r.SetupWithManagerAndOptions(mgr, BucketReconcilerOptions{})
}

func (r *BucketReconciler) SetupWithManagerAndOptions(mgr ctrl.Manager, opts BucketReconcilerOptions) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sourcev1.Bucket{}).
		WithEventFilter(predicate.Or(predicate.GenerationChangedPredicate{}, predicates.ReconcileRequestedPredicate{})).
		WithOptions(controller.Options{MaxConcurrentReconciles: opts.MaxConcurrentReconciles}).
		Complete(r)
}

func (r *BucketReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, retErr error) {
	start := time.Now()
	log := ctrl.LoggerFrom(ctx)

	// Fetch the Bucket
	obj := &sourcev1.Bucket{}
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
			summarize.WithConditions(bucketReadyCondition),
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
	reconcilers := []bucketReconcileFunc{
		r.reconcileStorage,
		r.reconcileSource,
		r.reconcileArtifact,
	}
	recResult, retErr = r.reconcile(ctx, obj, reconcilers)
	return
}

// reconcile iterates through the gitRepositoryReconcileFunc tasks for the
// object. It returns early on the first call that returns
// reconcile.ResultRequeue, or produces an error.
func (r *BucketReconciler) reconcile(ctx context.Context, obj *sourcev1.Bucket, reconcilers []bucketReconcileFunc) (sreconcile.Result, error) {
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

	// Run the sub-reconcilers and build the result of reconciliation.
	var (
		res    sreconcile.Result
		resErr error
		index  = newEtagIndex()
	)

	for _, rec := range reconcilers {
		recResult, err := rec(ctx, obj, index, tmpDir)
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
func (r *BucketReconciler) reconcileStorage(ctx context.Context, obj *sourcev1.Bucket, _ *etagIndex, _ string) (sreconcile.Result, error) {
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

// reconcileSource fetches the upstream bucket contents with the client for the
// given object's Provider, and returns the result.
// When a SecretRef is defined, it attempts to fetch the Secret before calling
// the provider. If this fails, it records v1beta2.FetchFailedCondition=True on
// the object and returns early.
func (r *BucketReconciler) reconcileSource(ctx context.Context, obj *sourcev1.Bucket, index *etagIndex, dir string) (sreconcile.Result, error) {
	secret, err := r.getBucketSecret(ctx, obj)
	if err != nil {
		e := &serror.Event{Err: err, Reason: sourcev1.AuthenticationFailedReason}
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, e.Error())
		// Return error as the world as observed may change
		return sreconcile.ResultEmpty, e
	}

	// Construct provider client
	var provider BucketProvider
	switch obj.Spec.Provider {
	case sourcev1.GoogleBucketProvider:
		if err = gcp.ValidateSecret(secret); err != nil {
			e := &serror.Event{Err: err, Reason: sourcev1.AuthenticationFailedReason}
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, e.Error())
			return sreconcile.ResultEmpty, e
		}
		if provider, err = gcp.NewClient(ctx, secret); err != nil {
			e := &serror.Event{Err: err, Reason: "ClientError"}
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, e.Error())
			return sreconcile.ResultEmpty, e
		}
	case sourcev1.AzureBucketProvider:
		if err = azure.ValidateSecret(secret); err != nil {
			e := &serror.Event{Err: err, Reason: sourcev1.AuthenticationFailedReason}
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, e.Error())
			return sreconcile.ResultEmpty, e
		}
		if provider, err = azure.NewClient(obj, secret); err != nil {
			e := &serror.Event{Err: err, Reason: "ClientError"}
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, e.Error())
			return sreconcile.ResultEmpty, e
		}
	default:
		if err = minio.ValidateSecret(secret); err != nil {
			e := &serror.Event{Err: err, Reason: sourcev1.AuthenticationFailedReason}
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, e.Error())
			return sreconcile.ResultEmpty, e
		}
		if provider, err = minio.NewClient(obj, secret); err != nil {
			e := &serror.Event{Err: err, Reason: "ClientError"}
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, e.Error())
			return sreconcile.ResultEmpty, e
		}
	}

	// Fetch etag index
	if err = fetchEtagIndex(ctx, provider, obj, index, dir); err != nil {
		e := &serror.Event{Err: err, Reason: sourcev1.BucketOperationFailedReason}
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, e.Error())
		return sreconcile.ResultEmpty, e
	}

	// Calculate revision
	revision, err := index.Revision()
	if err != nil {
		return sreconcile.ResultEmpty, &serror.Event{
			Err:    fmt.Errorf("failed to calculate revision: %w", err),
			Reason: meta.FailedReason,
		}
	}

	// Mark observations about the revision on the object
	defer func() {
		// As fetchIndexFiles can make last-minute modifications to the etag
		// index, we need to re-calculate the revision at the end
		revision, err := index.Revision()
		if err != nil {
			ctrl.LoggerFrom(ctx).Error(err, "failed to calculate revision after fetching etag index")
			return
		}

		if !obj.GetArtifact().HasRevision(revision) {
			message := fmt.Sprintf("new upstream revision '%s'", revision)
			conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "NewRevision", message)
			conditions.MarkReconciling(obj, "NewRevision", message)
		}
	}()

	if !obj.GetArtifact().HasRevision(revision) {
		if err = fetchIndexFiles(ctx, provider, obj, index, dir); err != nil {
			e := &serror.Event{Err: err, Reason: sourcev1.BucketOperationFailedReason}
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, e.Reason, e.Error())
			return sreconcile.ResultEmpty, e
		}
	}

	conditions.Delete(obj, sourcev1.FetchFailedCondition)
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
func (r *BucketReconciler) reconcileArtifact(ctx context.Context, obj *sourcev1.Bucket, index *etagIndex, dir string) (sreconcile.Result, error) {
	// Calculate revision
	revision, err := index.Revision()
	if err != nil {
		return sreconcile.ResultEmpty, &serror.Event{
			Err:    fmt.Errorf("failed to calculate revision of new artifact: %w", err),
			Reason: meta.FailedReason,
		}
	}

	// Create artifact
	artifact := r.Storage.NewArtifactFor(obj.Kind, obj, revision, fmt.Sprintf("%s.tar.gz", revision))

	// Always restore the Ready condition in case it got removed due to a transient error
	defer func() {
		if obj.GetArtifact().HasRevision(artifact.Revision) {
			conditions.Delete(obj, sourcev1.ArtifactOutdatedCondition)
			conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason,
				"stored artifact for revision '%s'", artifact.Revision)
		}
	}()

	// The artifact is up-to-date
	if obj.GetArtifact().HasRevision(artifact.Revision) {
		ctrl.LoggerFrom(ctx).Info("artifact up-to-date", "revision", artifact.Revision)
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
	r.annotatedEventLogf(ctx, obj, map[string]string{
		sourcev1.GroupVersion.Group + "/revision": artifact.Revision,
		sourcev1.GroupVersion.Group + "/checksum": artifact.Checksum,
	}, corev1.EventTypeNormal, "NewArtifact", "fetched %d files from '%s'", index.Len(), obj.Spec.BucketName)

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
func (r *BucketReconciler) reconcileDelete(ctx context.Context, obj *sourcev1.Bucket) (sreconcile.Result, error) {
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
func (r *BucketReconciler) garbageCollect(ctx context.Context, obj *sourcev1.Bucket) error {
	if !obj.DeletionTimestamp.IsZero() {
		if deleted, err := r.Storage.RemoveAll(r.Storage.NewArtifactFor(obj.Kind, obj.GetObjectMeta(), "", "*")); err != nil {
			return &serror.Event{
				Err:    fmt.Errorf("garbage collection for deleted resource failed: %s", err),
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
				Err:    fmt.Errorf("garbage collection of old artifacts failed: %s", err),
				Reason: "GarbageCollectionFailed",
			}
		} else if len(deleted) > 0 {
			r.eventLogf(ctx, obj, events.EventTypeTrace, "GarbageCollectionSucceeded",
				"garbage collected old artifacts")
		}
	}
	return nil
}

// getBucketSecret attempts to fetch the Secret reference if specified on the
// obj. It returns any client error.
func (r *BucketReconciler) getBucketSecret(ctx context.Context, obj *sourcev1.Bucket) (*corev1.Secret, error) {
	if obj.Spec.SecretRef == nil {
		return nil, nil
	}
	secretName := types.NamespacedName{
		Namespace: obj.GetNamespace(),
		Name:      obj.Spec.SecretRef.Name,
	}
	secret := &corev1.Secret{}
	if err := r.Get(ctx, secretName, secret); err != nil {
		return nil, fmt.Errorf("failed to get secret '%s': %w", secretName.String(), err)
	}
	return secret, nil
}

// eventLogf records events, and logs at the same time.
//
// This log is different from the debug log in the EventRecorder, in the sense
// that this is a simple log. While the debug log contains complete details
// about the event.
func (r *BucketReconciler) eventLogf(ctx context.Context, obj runtime.Object, eventType string, reason string, messageFmt string, args ...interface{}) {
	r.annotatedEventLogf(ctx, obj, nil, eventType, reason, messageFmt, args...)
}

// annotatedEventLogf records annotated events, and logs at the same time.
//
// This log is different from the debug log in the EventRecorder, in the sense
// that this is a simple log. While the debug log contains complete details
// about the event.
func (r *BucketReconciler) annotatedEventLogf(ctx context.Context,
	obj runtime.Object, annotations map[string]string, eventType string, reason string, messageFmt string, args ...interface{}) {
	msg := fmt.Sprintf(messageFmt, args...)
	// Log and emit event.
	if eventType == corev1.EventTypeWarning {
		ctrl.LoggerFrom(ctx).Error(errors.New(reason), msg)
	} else {
		ctrl.LoggerFrom(ctx).Info(msg)
	}
	r.AnnotatedEventf(obj, annotations, eventType, reason, msg)
}

// fetchEtagIndex fetches the current etagIndex for the in the obj specified
// bucket using the given provider, while filtering them using .sourceignore
// rules. After fetching an object, the etag value in the index is updated to
// the current value to ensure accuracy.
func fetchEtagIndex(ctx context.Context, provider BucketProvider, obj *sourcev1.Bucket, index *etagIndex, tempDir string) error {
	ctxTimeout, cancel := context.WithTimeout(ctx, obj.Spec.Timeout.Duration)
	defer cancel()

	// Confirm bucket exists
	exists, err := provider.BucketExists(ctxTimeout, obj.Spec.BucketName)
	if err != nil {
		return fmt.Errorf("failed to confirm existence of '%s' bucket: %w", obj.Spec.BucketName, err)
	}
	if !exists {
		err = fmt.Errorf("bucket '%s' not found", obj.Spec.BucketName)
		return err
	}

	// Look for file with ignore rules first
	path := filepath.Join(tempDir, sourceignore.IgnoreFile)
	if _, err := provider.FGetObject(ctxTimeout, obj.Spec.BucketName, sourceignore.IgnoreFile, path); err != nil {
		if !provider.ObjectIsNotFound(err) {
			return err
		}
	}
	ps, err := sourceignore.ReadIgnoreFile(path, nil)
	if err != nil {
		return err
	}
	// In-spec patterns take precedence
	if obj.Spec.Ignore != nil {
		ps = append(ps, sourceignore.ReadPatterns(strings.NewReader(*obj.Spec.Ignore), nil)...)
	}
	matcher := sourceignore.NewMatcher(ps)

	// Build up index
	err = provider.VisitObjects(ctxTimeout, obj.Spec.BucketName, func(key, etag string) error {
		if strings.HasSuffix(key, "/") || key == sourceignore.IgnoreFile {
			return nil
		}

		if matcher.Match(strings.Split(key, "/"), false) {
			return nil
		}

		index.Add(key, etag)
		return nil
	})
	if err != nil {
		return fmt.Errorf("indexation of objects from bucket '%s' failed: %w", obj.Spec.BucketName, err)
	}
	return nil
}

// fetchIndexFiles fetches the object files for the keys from the given etagIndex
// using the given provider, and stores them into tempDir. It downloads in
// parallel, but limited to the maxConcurrentBucketFetches.
// Given an index is provided, the bucket is assumed to exist.
func fetchIndexFiles(ctx context.Context, provider BucketProvider, obj *sourcev1.Bucket, index *etagIndex, tempDir string) error {
	ctxTimeout, cancel := context.WithTimeout(ctx, obj.Spec.Timeout.Duration)
	defer cancel()

	// Download in parallel, but bound the concurrency. According to
	// AWS and GCP docs, rate limits are either soft or don't exist:
	//  - https://cloud.google.com/storage/quotas
	//  - https://docs.aws.amazon.com/general/latest/gr/s3.html
	// .. so, the limiting factor is this process keeping a small footprint.
	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		sem := semaphore.NewWeighted(maxConcurrentBucketFetches)
		for key, etag := range index.Index() {
			k := key
			t := etag
			if err := sem.Acquire(groupCtx, 1); err != nil {
				return err
			}
			group.Go(func() error {
				defer sem.Release(1)
				localPath := filepath.Join(tempDir, k)
				etag, err := provider.FGetObject(ctxTimeout, obj.Spec.BucketName, k, localPath)
				if err != nil {
					if provider.ObjectIsNotFound(err) {
						ctrl.LoggerFrom(ctx).Info(fmt.Sprintf("indexed object '%s' disappeared from '%s' bucket", k, obj.Spec.BucketName))
						index.Delete(k)
						return nil
					}
					return fmt.Errorf("failed to get '%s' object: %w", k, err)
				}
				if t != etag {
					index.Add(k, etag)
				}
				return nil
			})
		}
		return nil
	})
	if err := group.Wait(); err != nil {
		return fmt.Errorf("fetch from bucket '%s' failed: %w", obj.Spec.BucketName, err)
	}

	return nil
}
