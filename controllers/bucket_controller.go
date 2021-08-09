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
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	gcpstorage "cloud.google.com/go/storage"
	"github.com/fluxcd/source-controller/pkg/gcp"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/s3utils"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
	"google.golang.org/api/option"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
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

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	"github.com/fluxcd/source-controller/pkg/sourceignore"
)

// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=buckets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=buckets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=buckets/finalizers,verbs=get;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// BucketReconciler reconciles a Bucket object
type BucketReconciler struct {
	client.Client
	helper.Events
	helper.Metrics

	Storage *Storage
}

type BucketReconcilerOptions struct {
	MaxConcurrentReconciles int
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
		log.Info("Reconciliation is suspended for this object")
		return ctrl.Result{}, nil
	}

	// Initialize the patch helper
	patchHelper, err := patch.NewHelper(obj, r.Client)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Always attempt to patch the object and status after each reconciliation
	defer func() {
		// Record the value of the reconciliation request, if any
		if v, ok := meta.ReconcileAnnotationValue(obj.GetAnnotations()); ok {
			obj.Status.SetLastHandledReconcileRequest(v)
		}

		// Summarize the Ready condition based on abnormalities that may have been observed
		conditions.SetSummary(obj,
			meta.ReadyCondition,
			conditions.WithConditions(
				sourcev1.ArtifactOutdatedCondition,
				sourcev1.FetchFailedCondition,
				sourcev1.ArtifactUnavailableCondition,
			),
			conditions.WithNegativePolarityConditions(
				sourcev1.ArtifactOutdatedCondition,
				sourcev1.FetchFailedCondition,
				sourcev1.ArtifactUnavailableCondition,
			),
		)

		// Patch the object, ignoring conflicts on the conditions owned by this controller
		patchOpts := []patch.Option{
			patch.WithOwnedConditions{
				Conditions: []string{
					sourcev1.ArtifactOutdatedCondition,
					sourcev1.FetchFailedCondition,
					sourcev1.ArtifactUnavailableCondition,
					meta.ReadyCondition,
					meta.ReconcilingCondition,
					meta.StalledCondition,
				},
			},
		}

		// Determine if the resource is still being reconciled, or if it has stalled, and record this observation
		if retErr == nil && (result.IsZero() || !result.Requeue) {
			// We are no longer reconciling
			conditions.Delete(obj, meta.ReconcilingCondition)

			// We have now observed this generation
			patchOpts = append(patchOpts, patch.WithStatusObservedGeneration{})

			readyCondition := conditions.Get(obj, meta.ReadyCondition)
			switch readyCondition.Status {
			case metav1.ConditionFalse:
				// As we are no longer reconciling and the end-state is not ready, the reconciliation has stalled
				conditions.MarkStalled(obj, readyCondition.Reason, readyCondition.Message)
			case metav1.ConditionTrue:
				// As we are no longer reconciling and the end-state is ready, the reconciliation is no longer stalled
				conditions.Delete(obj, meta.StalledCondition)
			}
		}

		// Finally, patch the resource
		if err := patchHelper.Patch(ctx, obj, patchOpts...); err != nil {
			retErr = kerrors.NewAggregate([]error{retErr, err})
		}

		// Always record readiness and duration metrics
		r.Metrics.RecordReadiness(ctx, obj)
		r.Metrics.RecordDuration(ctx, obj, start)
	}()

	// Add finalizer first if not exist to avoid the race condition between init and delete
	if !controllerutil.ContainsFinalizer(obj, sourcev1.SourceFinalizer) {
		controllerutil.AddFinalizer(obj, sourcev1.SourceFinalizer)
		return ctrl.Result{Requeue: true}, nil
	}

	// Examine if the object is under deletion
	if !obj.ObjectMeta.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, obj)
	}

	// Reconcile actual object
	return r.reconcile(ctx, obj)
}

// reconcile steps through the actual reconciliation tasks for the object, it returns early on the first step that
// produces an error.
func (r *BucketReconciler) reconcile(ctx context.Context, obj *sourcev1.Bucket) (ctrl.Result, error) {
	// Mark the resource as under reconciliation
	conditions.MarkReconciling(obj, meta.ProgressingReason, "")

	// Reconcile the storage data
	if result, err := r.reconcileStorage(ctx, obj); err != nil || result.IsZero() {
		return result, err
	}

	// Create temp working dir
	tmpDir, err := os.MkdirTemp("", fmt.Sprintf("%s-%s-%s-", obj.Kind, obj.Namespace, obj.Name))
	if err != nil {
		r.Eventf(ctx, obj, events.EventSeverityError, sourcev1.StorageOperationFailedReason, "Failed to create temporary directory: %s", err)
		return ctrl.Result{}, err
	}
	defer os.RemoveAll(tmpDir)

	// Reconcile the source from upstream
	var artifact sourcev1.Artifact
	if result, err := r.reconcileSource(ctx, obj, &artifact, tmpDir); err != nil || result.IsZero() {
		return ctrl.Result{RequeueAfter: obj.GetRequeueAfter()}, err
	}

	// Reconcile the artifact to storage
	if result, err := r.reconcileArtifact(ctx, obj, artifact, tmpDir); err != nil || result.IsZero() {
		return result, err
	}

	return ctrl.Result{RequeueAfter: obj.GetRequeueAfter()}, nil
}

// reconcileStorage ensures the current state of the storage matches the desired and previously observed state.
//
// All artifacts for the resource except for the current one are garbage collected from the storage.
// If the artifact in the Status object of the resource disappeared from storage, it is removed from the object.
// If the object does not have an artifact in its Status object, a v1beta1.ArtifactUnavailableCondition is set.
// If the hostname of the URLs on the object do not match the current storage server hostname, they are updated.
//
// The caller should assume a failure if an error is returned, or the Result is zero.
func (r *BucketReconciler) reconcileStorage(ctx context.Context, obj *sourcev1.Bucket) (ctrl.Result, error) {
	// Garbage collect previous advertised artifact(s) from storage
	_ = r.garbageCollect(ctx, obj)

	// Determine if the advertised artifact is still in storage
	if artifact := obj.GetArtifact(); artifact != nil && !r.Storage.ArtifactExist(*artifact) {
		obj.Status.Artifact = nil
		obj.Status.URL = ""
	}

	// Record that we do not have an artifact
	if obj.GetArtifact() == nil {
		conditions.MarkTrue(obj, sourcev1.ArtifactUnavailableCondition, "NoArtifact", "No artifact for resource in storage")
		return ctrl.Result{Requeue: true}, nil
	}
	conditions.Delete(obj, sourcev1.ArtifactUnavailableCondition)

	// Always update URLs to ensure hostname is up-to-date
	// TODO(hidde): we may want to send out an event only if we notice the URL has changed
	r.Storage.SetArtifactURL(obj.GetArtifact())
	obj.Status.URL = r.Storage.SetHostname(obj.Status.URL)

	return ctrl.Result{RequeueAfter: obj.GetRequeueAfter()}, nil
}

// reconcileSource reconciles the upstream bucket with the client for the given object's Provider, and returns the
// result.
// If a SecretRef is defined, it attempts to fetch the Secret before calling the provider. If the fetch of the Secret
// fails, it records v1beta1.FetchFailedCondition=True and returns early.
//
// The caller should assume a failure if an error is returned, or the Result is zero.
func (r *BucketReconciler) reconcileSource(ctx context.Context, obj *sourcev1.Bucket, artifact *sourcev1.Artifact, dir string) (ctrl.Result, error) {
	var secret corev1.Secret
	if obj.Spec.SecretRef != nil {
		secretName := types.NamespacedName{
			Namespace: obj.GetNamespace(),
			Name:      obj.Spec.SecretRef.Name,
		}
		if err := r.Get(ctx, secretName, &secret); err != nil {
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.AuthenticationFailedReason,
				"Failed to get secret '%s': %s", secretName.String(), err.Error())
			r.Eventf(ctx, obj, events.EventSeverityError, sourcev1.AuthenticationFailedReason,
				"Failed to get secret '%s': %s", secretName.String(), err.Error())
			// Return error as the world as observed may change
			return ctrl.Result{}, err
		}
	}

	switch obj.Spec.Provider {
	case sourcev1.GoogleBucketProvider:
		return r.reconcileGCPSource(ctx, obj, artifact, &secret, dir)
	default:
		return r.reconcileMinioSource(ctx, obj, artifact, &secret, dir)
	}
}

// reconcileMinioSource ensures the upstream Minio client compatible bucket can be reached and downloaded from using the
// declared configuration, and observes its state.
//
// The bucket contents are downloaded to the given dir using the defined configuration, while taking ignore rules into
// account. In case of an error during the download process (including transient errors), it records
// v1beta1.FetchFailedCondition=True and returns early.
// On a successful download, it removes v1beta1.FetchFailedCondition, and compares the current revision of HEAD to
// the artifact on the object, and records v1beta1.ArtifactOutdatedCondition if they differ.
// If the download was successful, the given artifact pointer is set to a new artifact with the available metadata.
//
// The caller should assume a failure if an error is returned, or the Result is zero.
func (r *BucketReconciler) reconcileMinioSource(ctx context.Context, obj *sourcev1.Bucket, artifact *sourcev1.Artifact,
	secret *corev1.Secret, dir string) (ctrl.Result, error) {
	// Build the client with the configuration from the object and secret
	s3Client, err := r.buildMinioClient(obj, secret)
	if err != nil {
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.BucketOperationFailedReason,
			"Failed to construct S3 client: %s", err.Error())
		r.Eventf(ctx, obj, events.EventSeverityError, sourcev1.BucketOperationFailedReason,
			"Failed to construct S3 client: %s", err.Error())
		// Return error as the contents of the secret may change
		return ctrl.Result{}, err
	}

	// Confirm bucket exists
	ctxTimeout, cancel := context.WithTimeout(ctx, obj.Spec.Timeout.Duration)
	defer cancel()
	exists, err := s3Client.BucketExists(ctxTimeout, obj.Spec.BucketName)
	if err != nil {
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.BucketOperationFailedReason,
			"Failed to verify existence of bucket '%s': %s", obj.Spec.BucketName, err.Error())
		return ctrl.Result{}, err
	}
	if !exists {
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.BucketOperationFailedReason,
			"Bucket '%s' does not exist", obj.Spec.BucketName)
		r.Eventf(ctx, obj, events.EventSeverityError, sourcev1.BucketOperationFailedReason,
			"Bucket '%s' does not exist", obj.Spec.BucketName)
		return ctrl.Result{}, fmt.Errorf("bucket '%s' does not exist", obj.Spec.BucketName)
	}

	// Look for file with ignore rules first
	path := filepath.Join(dir, sourceignore.IgnoreFile)
	if err := s3Client.FGetObject(ctxTimeout, obj.Spec.BucketName, sourceignore.IgnoreFile, path, minio.GetObjectOptions{}); err != nil {
		if resp, ok := err.(minio.ErrorResponse); ok && resp.Code != "NoSuchKey" {
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.BucketOperationFailedReason,
				"Failed to get '%s' file: %s", sourceignore.IgnoreFile, err.Error())
			r.Eventf(ctx, obj, events.EventSeverityError, sourcev1.BucketOperationFailedReason,
				"Failed to get '%s' file: %s", sourceignore.IgnoreFile, err.Error())
			return ctrl.Result{}, err
		}
	}
	ps, err := sourceignore.ReadIgnoreFile(path, nil)
	if err != nil {
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.BucketOperationFailedReason,
			"Failed to read '%s' file: %s", sourceignore.IgnoreFile, err.Error())
		r.Eventf(ctx, obj, events.EventSeverityError, sourcev1.BucketOperationFailedReason,
			"Failed to read '%s' file: %s", sourceignore.IgnoreFile, err.Error())
		return ctrl.Result{}, err
	}
	// In-spec patterns take precedence
	if obj.Spec.Ignore != nil {
		ps = append(ps, sourceignore.ReadPatterns(strings.NewReader(*obj.Spec.Ignore), nil)...)
	}
	matcher := sourceignore.NewMatcher(ps)

	// Build up an index of object keys and their etags
	// As the keys define the paths and the etags represent a change in file contents, this should be sufficient to
	// detect both structural and file changes
	var index = make(etagIndex)
	for object := range s3Client.ListObjects(ctxTimeout, obj.Spec.BucketName, minio.ListObjectsOptions{
		Recursive: true,
		UseV1:     s3utils.IsGoogleEndpoint(*s3Client.EndpointURL()),
	}) {
		if err = object.Err; err != nil {
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.BucketOperationFailedReason,
				"Failed to list objects from bucket '%s': %s", obj.Spec.BucketName, err.Error())
			r.Eventf(ctx, obj, events.EventSeverityError, sourcev1.BucketOperationFailedReason,
				"Failed to list objects from bucket '%s': %s", obj.Spec.BucketName, err.Error())
			return ctrl.Result{}, err
		}

		// Ignore directories and the .sourceignore file
		if strings.HasSuffix(object.Key, "/") || object.Key == sourceignore.IgnoreFile {
			continue
		}
		// Ignore matches
		if matcher.Match(strings.Split(object.Key, "/"), false) {
			continue
		}

		index[object.Key] = object.ETag
	}

	// Calculate revision checksum from the collected index values
	revision, err := index.Revision()
	if err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "failed to calculate revision")
		return ctrl.Result{}, err
	}

	if !obj.GetArtifact().HasRevision(revision) {
		// Mark observations about the revision on the object
		conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "NewRevision",
			"New upstream revision '%s'", revision)

		// Download the files in parallel, but with a limited number of workers
		group, groupCtx := errgroup.WithContext(ctx)
		group.Go(func() error {
			const workers = 4
			sem := semaphore.NewWeighted(workers)
			for key := range index {
				k := key
				if err := sem.Acquire(groupCtx, 1); err != nil {
					return err
				}
				group.Go(func() error {
					defer sem.Release(1)
					localPath := filepath.Join(dir, k)
					if err := s3Client.FGetObject(ctxTimeout, obj.Spec.BucketName, k, localPath, minio.GetObjectOptions{}); err != nil {
						return fmt.Errorf("failed to get '%s' file: %w", k, err)
					}
					return nil
				})
			}
			return nil
		})
		if err = group.Wait(); err != nil {
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.BucketOperationFailedReason,
				"Download from bucket '%s' failed: %s", obj.Spec.BucketName, err)
			r.Eventf(ctx, obj, events.EventSeverityError, sourcev1.BucketOperationFailedReason,
				"Download from bucket '%s' failed: %s", obj.Spec.BucketName, err)
			return ctrl.Result{}, err
		}
		r.Eventf(ctx, obj, events.EventSeverityInfo, sourcev1.BucketOperationSucceedReason,
			"Downloaded %d files from bucket '%s' revision '%s'", len(index), obj.Spec.BucketName, revision)
	}
	conditions.Delete(obj, sourcev1.FetchFailedCondition)

	// Create potential new artifact
	*artifact = r.Storage.NewArtifactFor(obj.Kind, obj, revision, fmt.Sprintf("%s.tar.gz", revision))
	return ctrl.Result{RequeueAfter: obj.GetRequeueAfter()}, nil
}

// reconcileGCPSource ensures the upstream Google Cloud Storage bucket can be reached and downloaded from using the
// declared configuration, and observes its state.
//
// The bucket contents are downloaded to the given dir using the defined configuration, while taking ignore rules into
// account. In case of an error during the download process (including transient errors), it records
// v1beta1.DownloadFailedCondition=True and returns early.
// On a successful download, it removes v1beta1.DownloadFailedCondition, and compares the current revision of HEAD to
// the artifact on the object, and records v1beta1.ArtifactOutdatedCondition if they differ.
// If the download was successful, the given artifact pointer is set to a new artifact with the available metadata.
//
// The caller should assume a failure if an error is returned, or the Result is zero.
func (r *BucketReconciler) reconcileGCPSource(ctx context.Context, obj *sourcev1.Bucket, artifact *sourcev1.Artifact,
	secret *corev1.Secret, dir string) (ctrl.Result, error) {
	gcpClient, err := r.buildGCPClient(ctx, secret)
	if err != nil {
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.BucketOperationFailedReason,
			"Failed to construct GCP client: %s", err.Error())
		r.Eventf(ctx, obj, events.EventSeverityError, sourcev1.BucketOperationFailedReason,
			"Failed to construct GCP client: %s", err.Error())
		// Return error as the contents of the secret may change
		return ctrl.Result{}, err
	}
	defer gcpClient.Close(ctrl.LoggerFrom(ctx))

	// Confirm bucket exists
	ctxTimeout, cancel := context.WithTimeout(ctx, obj.Spec.Timeout.Duration)
	defer cancel()
	exists, err := gcpClient.BucketExists(ctxTimeout, obj.Spec.BucketName)
	if err != nil {
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.BucketOperationFailedReason,
			"Failed to verify existence of bucket '%s': %s", obj.Spec.BucketName, err.Error())
		return ctrl.Result{}, err
	}
	if !exists {
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.BucketOperationFailedReason,
			"Bucket '%s' does not exist", obj.Spec.BucketName)
		r.Eventf(ctx, obj, events.EventSeverityError, sourcev1.BucketOperationFailedReason,
			"Bucket '%s' does not exist", obj.Spec.BucketName)
		return ctrl.Result{}, fmt.Errorf("bucket '%s' does not exist", obj.Spec.BucketName)
	}

	// Look for file with ignore rules first
	path := filepath.Join(dir, sourceignore.IgnoreFile)
	if err := gcpClient.FGetObject(ctxTimeout, obj.Spec.BucketName, sourceignore.IgnoreFile, path); err != nil {
		if err != gcpstorage.ErrObjectNotExist {
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.BucketOperationFailedReason,
				"Failed to get '%s' file: %s", sourceignore.IgnoreFile, err.Error())
			r.Eventf(ctx, obj, events.EventSeverityError, sourcev1.BucketOperationFailedReason,
				"Failed to get '%s' file: %s", sourceignore.IgnoreFile, err.Error())
			return ctrl.Result{}, err
		}
	}
	ps, err := sourceignore.ReadIgnoreFile(path, nil)
	if err != nil {
		conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.BucketOperationFailedReason,
			"Failed to read '%s' file: %s", sourceignore.IgnoreFile, err.Error())
		r.Eventf(ctx, obj, events.EventSeverityError, sourcev1.BucketOperationFailedReason,
			"Failed to read '%s' file: %s", sourceignore.IgnoreFile, err.Error())
		return ctrl.Result{}, err
	}
	// In-spec patterns take precedence
	if obj.Spec.Ignore != nil {
		ps = append(ps, sourceignore.ReadPatterns(strings.NewReader(*obj.Spec.Ignore), nil)...)
	}
	matcher := sourceignore.NewMatcher(ps)

	// Build up an index of object keys and their etags
	// As the keys define the paths and the etags represent a change in file contents, this should be sufficient to
	// detect both structural and file changes
	var index = make(etagIndex)
	objects := gcpClient.ListObjects(ctxTimeout, obj.Spec.BucketName, nil)
	for {
		object, err := objects.Next()
		if err != nil {
			if err == gcp.IteratorDone {
				break
			}
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.BucketOperationFailedReason,
				"Failed to list objects from bucket '%s': %s", obj.Spec.BucketName, err.Error())
			r.Eventf(ctx, obj, events.EventSeverityError, sourcev1.BucketOperationFailedReason,
				"Failed to list objects from bucket '%s': %s", obj.Spec.BucketName, err.Error())
			return ctrl.Result{}, err
		}

		if strings.HasSuffix(object.Name, "/") || object.Name == sourceignore.IgnoreFile {
			continue
		}

		if matcher.Match(strings.Split(object.Name, "/"), false) {
			continue
		}

		index[object.Name] = object.Etag
	}

	// Calculate revision checksum from the collected index values
	revision, err := index.Revision()
	if err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "failed to calculate revision")
		return ctrl.Result{}, err
	}

	if !obj.GetArtifact().HasRevision(revision) {
		// Mark observations about the revision on the object
		conditions.MarkTrue(obj, sourcev1.ArtifactOutdatedCondition, "NewRevision",
			"New upstream revision '%s'", revision)

		// Download the files in parallel, but with a limited number of workers
		group, groupCtx := errgroup.WithContext(ctx)
		group.Go(func() error {
			const workers = 4
			sem := semaphore.NewWeighted(workers)
			for key := range index {
				k := key
				if err := sem.Acquire(groupCtx, 1); err != nil {
					return err
				}
				group.Go(func() error {
					defer sem.Release(1)
					localPath := filepath.Join(dir, k)
					if err := gcpClient.FGetObject(ctxTimeout, obj.Spec.BucketName, k, localPath); err != nil {
						return fmt.Errorf("failed to get '%s' file: %w", k, err)
					}
					return nil
				})
			}
			return nil
		})
		if err = group.Wait(); err != nil {
			conditions.MarkTrue(obj, sourcev1.FetchFailedCondition, sourcev1.BucketOperationFailedReason,
				"Download from bucket '%s' failed: %s", obj.Spec.BucketName, err)
			r.Eventf(ctx, obj, events.EventSeverityError, sourcev1.BucketOperationFailedReason,
				"Download from bucket '%s' failed: %s", obj.Spec.BucketName, err)
			return ctrl.Result{}, err
		}
		r.Eventf(ctx, obj, events.EventSeverityInfo, sourcev1.BucketOperationSucceedReason,
			"Downloaded %d files from bucket '%s' revision '%s'", len(index), obj.Spec.BucketName, revision)
	}
	conditions.Delete(obj, sourcev1.FetchFailedCondition)

	// Create potential new artifact
	*artifact = r.Storage.NewArtifactFor(obj.Kind, obj, revision, fmt.Sprintf("%s.tar.gz", revision))
	return ctrl.Result{RequeueAfter: obj.GetRequeueAfter()}, nil
}

// reconcileArtifact archives a new artifact to the storage, if the current observation on the object does not match the
// given data.
//
// The inspection of the given data to the object is differed, ensuring any stale observations as
// v1beta1.ArtifactUnavailableCondition and v1beta1.ArtifactOutdatedCondition are always deleted.
// If the given artifact does not differ from the object's current, it returns early.
// On a successful archive, the artifact in the status of the given object is set, and the symlink in the storage is
// updated to its path.
//
// The caller should assume a failure if an error is returned, or the Result is zero.
func (r *BucketReconciler) reconcileArtifact(ctx context.Context, obj *sourcev1.Bucket, artifact sourcev1.Artifact, dir string) (ctrl.Result, error) {
	// Always restore the Ready condition in case it got removed due to a transient error
	defer func() {
		if obj.GetArtifact() != nil {
			conditions.Delete(obj, sourcev1.ArtifactUnavailableCondition)
		}
		if obj.GetArtifact().HasRevision(artifact.Revision) {
			conditions.Delete(obj, sourcev1.ArtifactOutdatedCondition)
			conditions.MarkTrue(obj, meta.ReadyCondition, meta.SucceededReason,
				"Stored artifact for revision '%s'", artifact.Revision)
		}
	}()

	// The artifact is up-to-date
	if obj.GetArtifact().HasRevision(artifact.Revision) {
		ctrl.LoggerFrom(ctx).Info(fmt.Sprintf("Already up to date, current revision '%s'", artifact.Revision))
		return ctrl.Result{RequeueAfter: obj.GetRequeueAfter()}, nil
	}

	// Ensure target path exists and is a directory
	if f, err := os.Stat(dir); err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "failed to stat source path")
		return ctrl.Result{}, err
	} else if !f.IsDir() {
		err := fmt.Errorf("source path '%s' is not a directory", dir)
		ctrl.LoggerFrom(ctx).Error(err, "invalid target path")
		return ctrl.Result{}, err
	}

	// Ensure artifact directory exists and acquire lock
	if err := r.Storage.MkdirAll(artifact); err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "failed to create artifact directory")
		return ctrl.Result{}, err
	}
	unlock, err := r.Storage.Lock(artifact)
	if err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "failed to acquire lock for artifact")
		return ctrl.Result{}, err
	}
	defer unlock()

	// Archive directory to storage
	if err := r.Storage.Archive(&artifact, dir, nil); err != nil {
		r.Eventf(ctx, obj, events.EventSeverityError, sourcev1.StorageOperationFailedReason,
			"Unable to archive artifact to storage: %s", err)
		return ctrl.Result{}, err
	}
	r.Events.EventWithMetaf(ctx, obj, map[string]string{
		"revision": artifact.Revision,
		"checksum": artifact.Checksum,
	}, events.EventSeverityInfo, "NewArtifact", "Stored artifact for revision '%s'", artifact.Revision)

	// Record it on the object
	obj.Status.Artifact = artifact.DeepCopy()

	// Update symlink on a "best effort" basis
	url, err := r.Storage.Symlink(artifact, "latest.tar.gz")
	if err != nil {
		r.Events.Eventf(ctx, obj, events.EventSeverityError, sourcev1.StorageOperationFailedReason,
			"Failed to update status URL symlink: %s", err)
	}
	if url != "" {
		obj.Status.URL = url
	}
	return ctrl.Result{RequeueAfter: obj.GetRequeueAfter()}, nil
}

// reconcileDelete handles the deletion of an object. It first garbage collects all artifacts for the object from the
// artifact storage, if successful, the finalizer is removed from the object.
func (r *BucketReconciler) reconcileDelete(ctx context.Context, obj *sourcev1.Bucket) (ctrl.Result, error) {
	// Garbage collect the resource's artifacts
	if err := r.garbageCollect(ctx, obj); err != nil {
		// Return the error so we retry the failed garbage collection
		return ctrl.Result{}, err
	}

	// Remove our finalizer from the list
	controllerutil.RemoveFinalizer(obj, sourcev1.SourceFinalizer)

	// Stop reconciliation as the object is being deleted
	return ctrl.Result{}, nil
}

// garbageCollect performs a garbage collection for the given v1beta1.Bucket. It removes all but the current
// artifact except for when the deletion timestamp is set, which will result in the removal of all artifacts for the
// resource.
func (r *BucketReconciler) garbageCollect(ctx context.Context, obj *sourcev1.Bucket) error {
	if !obj.DeletionTimestamp.IsZero() {
		if err := r.Storage.RemoveAll(r.Storage.NewArtifactFor(obj.Kind, obj.GetObjectMeta(), "", "*")); err != nil {
			r.Eventf(ctx, obj, events.EventSeverityError, "GarbageCollectionFailed",
				"Garbage collection for deleted resource failed: %s", err)
			return err
		}
		obj.Status.Artifact = nil
		// TODO(hidde): we should only push this event if we actually garbage collected something
		r.Eventf(ctx, obj, events.EventSeverityInfo, "GarbageCollectionSucceeded",
			"Garbage collected artifacts for deleted resource")
		return nil
	}
	if obj.GetArtifact() != nil {
		if err := r.Storage.RemoveAllButCurrent(*obj.GetArtifact()); err != nil {
			r.Eventf(ctx, obj, events.EventSeverityError, "GarbageCollectionFailed", "Garbage collection of old artifacts failed: %s", err)
			return err
		}
		// TODO(hidde): we should only push this event if we actually garbage collected something
		r.Eventf(ctx, obj, events.EventSeverityInfo, "GarbageCollectionSucceeded", "Garbage collected old artifacts")
	}
	return nil
}

// buildMinioClient constructs a minio.Client with the data from the given object and Secret.
// It returns an error if the Secret does not have the required fields, or if there is no credential handler
// configured.
func (r *BucketReconciler) buildMinioClient(obj *sourcev1.Bucket, secret *corev1.Secret) (*minio.Client, error) {
	opts := minio.Options{
		Region: obj.Spec.Region,
		Secure: !obj.Spec.Insecure,
	}
	if secret != nil {
		var accessKey, secretKey string
		if k, ok := secret.Data["accesskey"]; ok {
			accessKey = string(k)
		}
		if k, ok := secret.Data["secretkey"]; ok {
			secretKey = string(k)
		}
		if accessKey == "" || secretKey == "" {
			return nil, fmt.Errorf("invalid '%s' secret data: required fields 'accesskey' and 'secretkey'", secret.Name)
		}
		opts.Creds = credentials.NewStaticV4(accessKey, secretKey, "")
	} else if obj.Spec.Provider == sourcev1.AmazonBucketProvider {
		opts.Creds = credentials.NewIAM("")
	}
	return minio.New(obj.Spec.Endpoint, &opts)
}

// buildGCPClient constructs a gcp.GCPClient with the data from the given Secret.
// It returns an error if the Secret does not have the required field, or if the client construction fails.
func (r *BucketReconciler) buildGCPClient(ctx context.Context, secret *corev1.Secret) (*gcp.GCPClient, error) {
	var client *gcp.GCPClient
	var err error
	if secret != nil {
		if err := gcp.ValidateSecret(secret.Data, secret.Name); err != nil {
			return nil, err
		}
		client, err = gcp.NewClient(ctx, option.WithCredentialsJSON(secret.Data["serviceaccount"]))
		if err != nil {
			return nil, err
		}
	} else {
		client, err = gcp.NewClient(ctx)
		if err != nil {
			return nil, err
		}
	}
	return client, nil
}

// etagIndex is an index of bucket keys and their Etag values.
type etagIndex map[string]string

// Revision calculates the SHA256 checksum of the index.
// The keys are sorted to ensure a stable order, and the SHA256 sum is then calculated for the string representations of
// the key/value pairs, each pair written on a newline
// The sum result is returned as a string.
func (i etagIndex) Revision() (string, error) {
	keyIndex := make([]string, 0, len(i))
	for k := range i {
		keyIndex = append(keyIndex, k)
	}
	sort.Strings(keyIndex)
	sum := sha256.New()
	for _, k := range keyIndex {
		if _, err := sum.Write([]byte(fmt.Sprintf("%s  %s\n", k, i[k]))); err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("%x", sum.Sum(nil)), nil
}
