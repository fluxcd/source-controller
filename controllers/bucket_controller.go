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
	"crypto/sha1"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/s3utils"
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

	// Always attempt to patch the object and status after each
	// reconciliation
	defer func() {
		// Record the value of the reconciliation request, if any
		if v, ok := meta.ReconcileAnnotationValue(obj.GetAnnotations()); ok {
			obj.Status.SetLastHandledReconcileRequest(v)
		}

		// Summarize Ready condition
		conditions.SetSummary(obj,
			meta.ReadyCondition,
			conditions.WithConditions(
				sourcev1.ArtifactAvailableCondition,
				sourcev1.SourceAvailableCondition,
			),
		)

		// Patch the object, ignoring conflicts on the conditions owned by
		// this controller
		patchOpts := []patch.Option{
			patch.WithOwnedConditions{
				Conditions: []string{
					sourcev1.ArtifactAvailableCondition,
					sourcev1.SourceAvailableCondition,
					meta.ReadyCondition,
					meta.ReconcilingCondition,
					meta.ProgressingReason,
				},
			},
		}

		// Determine if the resource is still being reconciled, or if
		// it has stalled, and record this observation
		if retErr == nil && (result.IsZero() || !result.Requeue) {
			// We are no longer reconciling
			conditions.Delete(obj, meta.ReconcilingCondition)

			// We have now observed this generation
			patchOpts = append(patchOpts, patch.WithStatusObservedGeneration{})

			readyCondition := conditions.Get(obj, meta.ReadyCondition)
			switch readyCondition.Status {
			case metav1.ConditionFalse:
				// As we are no longer reconciling and the end-state
				// is not ready, the reconciliation has stalled
				conditions.MarkTrue(obj, meta.StalledCondition, readyCondition.Reason, readyCondition.Message)
			case metav1.ConditionTrue:
				// As we are no longer reconciling and the end-state
				// is ready, the reconciliation is no longer stalled
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

	// Add finalizer first if not exist to avoid the race condition
	// between init and delete
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

func (r *BucketReconciler) reconcile(ctx context.Context, obj *sourcev1.Bucket) (ctrl.Result, error) {
	// Mark the resource as under reconciliation
	conditions.MarkTrue(obj, meta.ReconcilingCondition, "Reconciling", "")
	logr.FromContext(ctx).Info("Starting reconciliation")

	// Reconcile the storage data
	if result, err := r.reconcileStorage(ctx, obj); err != nil {
		return result, err
	}

	// Create temp dir for the bucket objects
	tmpDir, err := ioutil.TempDir("", fmt.Sprintf("%s-%s-%s-", obj.Kind, obj.Namespace, obj.Name))
	if err != nil {
		conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.StorageOperationFailedReason, "Failed to create temporary directory: %s", err)
		return ctrl.Result{}, err
	}
	defer os.RemoveAll(tmpDir)

	// Reconcile the source from upstream
	var artifact sourcev1.Artifact
	if result, err := r.reconcileSource(ctx, obj, &artifact, tmpDir); err != nil || conditions.IsFalse(obj, sourcev1.SourceAvailableCondition) {
		return result, err
	}

	// Reconcile the artifact to storage
	if result, err := r.reconcileArtifact(ctx, obj, artifact, tmpDir); err != nil {
		return result, err
	}

	return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
}

// reconcileStorage reconciles the storage data for the given object
// by garbage collecting previous advertised artifact(s) from storage,
// observing if the artifact in the status still exists, and
// ensuring the URLs are up-to-date with the current hostname
// configuration.
func (r *BucketReconciler) reconcileStorage(ctx context.Context, obj *sourcev1.Bucket) (ctrl.Result, error) {
	// Garbage collect previous advertised artifact(s) from storage
	if err := r.garbageCollect(obj); err != nil {
		r.Events.Eventf(ctx, obj, events.EventSeverityError, "GarbageCollectionFailed", "Garbage collection failed: %s", err)
	}

	// Determine if the advertised artifact is still in storage
	if artifact := obj.GetArtifact(); artifact != nil && !r.Storage.ArtifactExist(*artifact) {
		obj.Status.Artifact = nil
		obj.Status.URL = ""
	}

	// Record that we do not have an artifact
	if obj.GetArtifact() == nil {
		conditions.MarkFalse(obj, sourcev1.ArtifactAvailableCondition, "NoArtifactFound", "No artifact for resource in storage")
		return ctrl.Result{Requeue: true}, nil
	}

	// Always update URLs to ensure hostname is up-to-date
	r.Storage.SetArtifactURL(obj.GetArtifact())
	obj.Status.URL = r.Storage.SetHostname(obj.Status.URL)

	return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
}

// reconcileSource reconciles the bucket from upstream to the given
// directory path while using the information on the object to determine
// authentication and exclude strategies.
// On a successful download of all bucket objects, the given pointer is
// set to a new artifact.
func (r *BucketReconciler) reconcileSource(ctx context.Context, obj *sourcev1.Bucket, artifact *sourcev1.Artifact, dir string) (ctrl.Result, error) {
	// Attempt to retrieve secret if one is configured
	var secret *corev1.Secret
	if obj.Spec.SecretRef != nil {
		secret = &corev1.Secret{}
		name := types.NamespacedName{
			Namespace: obj.GetNamespace(),
			Name:      obj.Spec.SecretRef.Name,
		}
		if err := r.Client.Get(ctx, name, secret); err != nil {
			conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.AuthenticationFailedReason, "Failed to get secret '%s': %s", name.String(), err.Error())
			r.Events.Event(ctx, obj, events.EventSeverityError, sourcev1.AuthenticationFailedReason, conditions.Get(obj, sourcev1.SourceAvailableCondition).Message)
			// Return transient errors but wait for next interval on not found
			return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, client.IgnoreNotFound(err)
		}
	}

	// Build the client with the configuration from the object and secret
	s3Client, err := r.buildClient(obj, secret)
	if err != nil {
		conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.BucketOperationFailedReason, "Failed to construct S3 client: %s", err.Error())
		// Recovering from this without a change to the secret or object
		// is impossible
		return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
	}
	ctxTimeout, cancel := context.WithTimeout(ctx, obj.Spec.Timeout.Duration)
	defer cancel()

	// Confirm bucket exists
	exists, err := s3Client.BucketExists(ctxTimeout, obj.Spec.BucketName)
	if err != nil {
		// Error may be transient
		conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.BucketOperationFailedReason, "Failed to verify existence of bucket %q: %s", obj.Spec.BucketName, err.Error())
		return ctrl.Result{}, err
	}
	if !exists {
		conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.BucketOperationFailedReason, "Bucket %q does not exist", obj.Spec.BucketName)
		return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
	}

	// Look for file with ignore rules first
	// NB: S3 has flat filepath keys making it impossible to look
	// for files in "subdirectories" without building up a tree first.
	path := filepath.Join(dir, sourceignore.IgnoreFile)
	if err := s3Client.FGetObject(ctxTimeout, obj.Spec.BucketName, sourceignore.IgnoreFile, path, minio.GetObjectOptions{}); err != nil {
		if resp, ok := err.(minio.ErrorResponse); ok && resp.Code != "NoSuchKey" {
			conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.BucketOperationFailedReason, "Failed to download '%s' file: %s", sourceignore.IgnoreFile, err.Error())
			return ctrl.Result{}, err
		}
	}
	ps, err := sourceignore.ReadIgnoreFile(path, nil)
	if err != nil {
		conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.BucketOperationFailedReason, "Failed to read '%s' file: %s", sourceignore.IgnoreFile, err.Error())
		return ctrl.Result{}, err
	}
	// In-spec patterns take precedence
	if obj.Spec.Ignore != nil {
		ps = append(ps, sourceignore.ReadPatterns(strings.NewReader(*obj.Spec.Ignore), nil)...)
	}
	matcher := sourceignore.NewMatcher(ps)

	// Download bucket objects while taking the ignore rules into account
	var objCount int64
	for object := range s3Client.ListObjects(ctxTimeout, obj.Spec.BucketName, minio.ListObjectsOptions{
		Recursive: true,
		UseV1:     s3utils.IsGoogleEndpoint(*s3Client.EndpointURL()),
	}) {
		if err = object.Err; err != nil {
			conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.BucketOperationFailedReason, "Failed to list objects from bucket %q: %s", obj.Spec.BucketName, err.Error())
			return ctrl.Result{}, err
		}

		if strings.HasSuffix(object.Key, "/") || object.Key == sourceignore.IgnoreFile {
			continue
		}

		if matcher.Match(strings.Split(object.Key, "/"), false) {
			continue
		}

		localPath := filepath.Join(dir, object.Key)
		if err = s3Client.FGetObject(ctx, obj.Spec.BucketName, object.Key, localPath, minio.GetObjectOptions{}); err != nil {
			conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.BucketOperationFailedReason, "Failed to download object %q from bucket %q: %s", object.Key, obj.Spec.BucketName, err.Error())
			return ctrl.Result{}, err
		}

		objCount++
	}

	// Compute the checksum of the downloaded file contents, which is used as the revision
	checksum, err := r.checksum(dir)
	if err != nil {
		conditions.MarkFalse(obj, sourcev1.SourceAvailableCondition, sourcev1.BucketOperationFailedReason, "Failed to compute checksum for downloaded objects: %s", err.Error())
		return ctrl.Result{}, err
	}

	// Create potential new artifact
	*artifact = r.Storage.NewArtifactFor(obj.Kind, obj, checksum, fmt.Sprintf("%s.tar.gz", checksum))
	conditions.MarkTrue(obj, sourcev1.SourceAvailableCondition, sourcev1.BucketOperationSucceedReason, "Downloaded %d objects from bucket %q", objCount, obj.Spec.BucketName)

	return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
}

// reconcileArtifact reconciles the downloaded files to the artifact
// storage by archiving the directory.
// On a successful archive, the artifact and includes in the status of
// the given object are set, and the symlink in the storage is updated
// to its path.
func (r *BucketReconciler) reconcileArtifact(ctx context.Context, obj *sourcev1.Bucket, artifact sourcev1.Artifact, dir string) (ctrl.Result, error) {
	// The artifact is up-to-date
	if obj.GetArtifact().HasRevision(artifact.Revision) {
		logr.FromContext(ctx).Info("Artifact is up-to-date")
		conditions.MarkTrue(obj, sourcev1.ArtifactAvailableCondition, meta.SucceededReason, "Compressed source to artifact with revision '%s'", artifact.Revision)
		return ctrl.Result{RequeueAfter: obj.GetInterval().Duration}, nil
	}

	// Ensure target path exists and is a directory
	if f, err := os.Stat(dir); err != nil {
		conditions.MarkFalse(obj, sourcev1.ArtifactAvailableCondition, sourcev1.StorageOperationFailedReason, "Failed to stat source path: %s", err.Error())
		return ctrl.Result{}, err
	} else if !f.IsDir() {
		err = fmt.Errorf("source path %q is not a directory", dir)
		conditions.MarkFalse(obj, sourcev1.ArtifactAvailableCondition, sourcev1.StorageOperationFailedReason, "Failed to reconcile artifact: %s", err.Error())
		return ctrl.Result{}, err
	}

	// Ensure artifact directory exists and acquire lock
	if err := r.Storage.MkdirAll(artifact); err != nil {
		conditions.MarkFalse(obj, sourcev1.ArtifactAvailableCondition, sourcev1.StorageOperationFailedReason, "Failed to create directory: %s", err)
		return ctrl.Result{}, err
	}
	unlock, err := r.Storage.Lock(artifact)
	if err != nil {
		conditions.MarkFalse(obj, sourcev1.ArtifactAvailableCondition, sourcev1.StorageOperationFailedReason, "Failed to acquire lock: %s", err)
		return ctrl.Result{}, err
	}
	defer unlock()

	// Archive directory to storage
	if err = r.Storage.Archive(&artifact, dir, nil); err != nil {
		conditions.MarkFalse(obj, sourcev1.ArtifactAvailableCondition, sourcev1.StorageOperationFailedReason, "Unable to archive artifact to storage: %s", err)
		return ctrl.Result{}, err
	}

	// Record it on the object
	obj.Status.Artifact = artifact.DeepCopy()
	conditions.MarkTrue(obj, sourcev1.ArtifactAvailableCondition, meta.SucceededReason, "Compressed source to artifact with revision '%s'", artifact.Revision)
	r.Events.EventWithMetaf(ctx, obj, map[string]string{
		"revision": obj.GetArtifact().Revision,
	}, events.EventSeverityInfo, meta.SucceededReason, conditions.Get(obj, sourcev1.ArtifactAvailableCondition).Message)

	// Update symlink on a "best effort" basis
	url, err := r.Storage.Symlink(artifact, "latest.tar.gz")
	if err != nil {
		r.Events.Eventf(ctx, obj, events.EventSeverityError, sourcev1.StorageOperationFailedReason, "Failed to update status URL symlink: %s", err)
	}
	if url != "" {
		obj.Status.URL = url
	}

	return ctrl.Result{RequeueAfter: obj.Spec.Interval.Duration}, nil
}

// reconcileDelete reconciles the delete of an object by garbage
// collecting all artifacts for the object in the artifact storage,
// if successful, the finalizer is removed from the object.
func (r *BucketReconciler) reconcileDelete(ctx context.Context, obj *sourcev1.Bucket) (ctrl.Result, error) {
	// Garbage collect the resource's artifacts
	if err := r.garbageCollect(obj); err != nil {
		r.Events.Eventf(ctx, obj, events.EventSeverityError, "GarbageCollectionFailed", "Garbage collection for deleted resource failed: %s", err)
		// Return the error so we retry the failed garbage collection
		return ctrl.Result{}, err
	}

	// Remove our finalizer from the list
	controllerutil.RemoveFinalizer(obj, sourcev1.SourceFinalizer)

	// Stop reconciliation as the object is being deleted
	return ctrl.Result{}, nil
}

// buildClient constructs a minio.Client with the data from the given
// Bucket and Secret. It returns an error if the given Secret does not
// have the required fields, or if there is no credential handler
// configured.
func (r *BucketReconciler) buildClient(obj *sourcev1.Bucket, secret *corev1.Secret) (*minio.Client, error) {
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
			return nil, fmt.Errorf("invalid %q secret data: required fields 'accesskey' and 'secretkey'", secret.Name)
		}
		opts.Creds = credentials.NewStaticV4(accessKey, secretKey, "")
	} else if obj.Spec.Provider == sourcev1.AmazonBucketProvider {
		opts.Creds = credentials.NewIAM("")
	}

	return minio.New(obj.Spec.Endpoint, &opts)
}

// checksum computes the SHA1 checksum of all files in the given root
// directory path.
func (r *BucketReconciler) checksum(root string) (string, error) {
	checksum := sha1.New()
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		if _, err = io.Copy(checksum, f); err != nil {
			f.Close()
			return err
		}
		return f.Close()
	}); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", checksum.Sum(nil)), nil
}

// garbageCollect performs a garbage collection for the given
// v1beta1.Bucket. It removes all but the current artifact
// except for when the deletion timestamp is set, which will result
// in the removal of all artifacts for the resource.
func (r *BucketReconciler) garbageCollect(obj *sourcev1.Bucket) error {
	if !obj.DeletionTimestamp.IsZero() {
		if err := r.Storage.RemoveAll(r.Storage.NewArtifactFor(obj.Kind, obj.GetObjectMeta(), "", "*")); err != nil {
			return err
		}
		obj.Status.Artifact = nil
		return nil
	}
	if obj.GetArtifact() != nil {
		return r.Storage.RemoveAllButCurrent(*obj.GetArtifact())
	}
	return nil
}
