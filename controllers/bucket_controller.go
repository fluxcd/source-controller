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
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kuberecorder "k8s.io/client-go/tools/record"
	"k8s.io/client-go/tools/reference"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/events"
	"github.com/fluxcd/pkg/runtime/metrics"
	"github.com/fluxcd/pkg/runtime/predicates"
	"github.com/fluxcd/source-controller/pkg/gcp"
	"github.com/fluxcd/source-controller/pkg/minio"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	"github.com/fluxcd/source-controller/pkg/sourceignore"
	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
)

// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=buckets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=buckets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=buckets/finalizers,verbs=get;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// BucketReconciler reconciles a Bucket object
type BucketReconciler struct {
	client.Client
	Scheme                *runtime.Scheme
	Storage               *Storage
	EventRecorder         kuberecorder.EventRecorder
	ExternalEventRecorder *events.Recorder
	MetricsRecorder       *metrics.Recorder
}

type BucketReconcilerOptions struct {
	MaxConcurrentReconciles int
}

type BucketProvider interface {
	BucketExists(context.Context, string) (bool, error)
	ObjectExists(context.Context, string, string) (bool, error)
	FGetObject(context.Context, string, string, string) error
	ListObjects(context.Context, gitignore.Matcher, string, string) error
	ObjectIsNotFound(error) bool
	Close(context.Context)
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

func (r *BucketReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	start := time.Now()
	log := ctrl.LoggerFrom(ctx)

	var bucket sourcev1.Bucket
	if err := r.Get(ctx, req.NamespacedName, &bucket); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Record suspended status metric
	defer r.recordSuspension(ctx, bucket)

	// Add our finalizer if it does not exist
	if !controllerutil.ContainsFinalizer(&bucket, sourcev1.SourceFinalizer) {
		controllerutil.AddFinalizer(&bucket, sourcev1.SourceFinalizer)
		if err := r.Update(ctx, &bucket); err != nil {
			log.Error(err, "unable to register finalizer")
			return ctrl.Result{}, err
		}
	}

	// Examine if the object is under deletion
	if !bucket.ObjectMeta.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, bucket)
	}

	// Return early if the object is suspended.
	if bucket.Spec.Suspend {
		log.Info("Reconciliation is suspended for this object")
		return ctrl.Result{}, nil
	}

	// record reconciliation duration
	if r.MetricsRecorder != nil {
		objRef, err := reference.GetReference(r.Scheme, &bucket)
		if err != nil {
			return ctrl.Result{}, err
		}
		defer r.MetricsRecorder.RecordDuration(*objRef, start)
	}

	// set initial status
	if resetBucket, ok := r.resetStatus(bucket); ok {
		bucket = resetBucket
		if err := r.updateStatus(ctx, req, bucket.Status); err != nil {
			log.Error(err, "unable to update status")
			return ctrl.Result{Requeue: true}, err
		}
		r.recordReadiness(ctx, bucket)
	}

	// record the value of the reconciliation request, if any
	// TODO(hidde): would be better to defer this in combination with
	//   always patching the status sub-resource after a reconciliation.
	if v, ok := meta.ReconcileAnnotationValue(bucket.GetAnnotations()); ok {
		bucket.Status.SetLastHandledReconcileRequest(v)
	}

	// purge old artifacts from storage
	if err := r.gc(bucket); err != nil {
		log.Error(err, "unable to purge old artifacts")
	}

	// reconcile bucket by downloading its content
	reconciledBucket, reconcileErr := r.reconcile(ctx, *bucket.DeepCopy())

	// update status with the reconciliation result
	if err := r.updateStatus(ctx, req, reconciledBucket.Status); err != nil {
		log.Error(err, "unable to update status")
		return ctrl.Result{Requeue: true}, err
	}

	// if reconciliation failed, record the failure and requeue immediately
	if reconcileErr != nil {
		r.event(ctx, reconciledBucket, events.EventSeverityError, reconcileErr.Error())
		r.recordReadiness(ctx, reconciledBucket)
		return ctrl.Result{Requeue: true}, reconcileErr
	}

	// emit revision change event
	if bucket.Status.Artifact == nil || reconciledBucket.Status.Artifact.Revision != bucket.Status.Artifact.Revision {
		r.event(ctx, reconciledBucket, events.EventSeverityInfo, sourcev1.BucketReadyMessage(reconciledBucket))
	}
	r.recordReadiness(ctx, reconciledBucket)

	log.Info(fmt.Sprintf("Reconciliation finished in %s, next run in %s",
		time.Now().Sub(start).String(),
		bucket.GetInterval().Duration.String(),
	))

	return ctrl.Result{RequeueAfter: bucket.GetInterval().Duration}, nil
}

func (r *BucketReconciler) getBucketSecret(ctx context.Context, bucket sourcev1.Bucket) (corev1.Secret, error) {
	var secret corev1.Secret
	secretName := types.NamespacedName{
		Namespace: bucket.GetNamespace(),
		Name:      bucket.Spec.SecretRef.Name,
	}
	if err := r.Get(ctx, secretName, &secret); err != nil {
		return secret, err
	}
	return secret, nil
}

func (r *BucketReconciler) reconcile(ctx context.Context, bucket sourcev1.Bucket) (sourcev1.Bucket, error) {
	tempDir, err := os.MkdirTemp("", bucket.Name)
	if err != nil {
		err = fmt.Errorf("tmp dir error: %w", err)
		return sourcev1.BucketNotReady(bucket, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	defer os.RemoveAll(tempDir)
	var secret corev1.Secret

	if bucket.Spec.SecretRef != nil {
		secret, err = r.getBucketSecret(ctx, bucket)
		if err != nil {
			return sourcev1.BucketNotReady(bucket, sourcev1.AuthenticationFailedReason, err.Error()), fmt.Errorf("credentials secret error: %w", err)
		}
	}

	if bucketResponse, err := fetchBucketContents(ctx, bucket, secret, tempDir); err != nil {
		return bucketResponse, err
	}

	revision, err := r.checksum(tempDir)
	if err != nil {
		return sourcev1.BucketNotReady(bucket, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// return early on unchanged revision
	artifact := r.Storage.NewArtifactFor(bucket.Kind, bucket.GetObjectMeta(), revision, fmt.Sprintf("%s.tar.gz", revision))
	if apimeta.IsStatusConditionTrue(bucket.Status.Conditions, meta.ReadyCondition) && bucket.GetArtifact().HasRevision(artifact.Revision) {
		if artifact.URL != bucket.GetArtifact().URL {
			r.Storage.SetArtifactURL(bucket.GetArtifact())
			bucket.Status.URL = r.Storage.SetHostname(bucket.Status.URL)
		}
		return bucket, nil
	}

	// create artifact dir
	err = r.Storage.MkdirAll(artifact)
	if err != nil {
		err = fmt.Errorf("mkdir dir error: %w", err)
		return sourcev1.BucketNotReady(bucket, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// acquire lock
	unlock, err := r.Storage.Lock(artifact)
	if err != nil {
		err = fmt.Errorf("unable to acquire lock: %w", err)
		return sourcev1.BucketNotReady(bucket, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	defer unlock()

	// archive artifact and check integrity
	if err := r.Storage.Archive(&artifact, tempDir, nil); err != nil {
		err = fmt.Errorf("storage archive error: %w", err)
		return sourcev1.BucketNotReady(bucket, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// update latest symlink
	url, err := r.Storage.Symlink(artifact, "latest.tar.gz")
	if err != nil {
		err = fmt.Errorf("storage symlink error: %w", err)
		return sourcev1.BucketNotReady(bucket, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	message := fmt.Sprintf("Fetched revision: %s", artifact.Revision)
	return sourcev1.BucketReady(bucket, artifact, url, sourcev1.BucketOperationSucceedReason, message), nil
}

// fetchBucketContents selects a bucket provider that implement the bucket provider interface based on
// on the specified provider in the bucket spec.
func fetchBucketContents(ctx context.Context, bucket sourcev1.Bucket, secret corev1.Secret, tempDir string) (sourcev1.Bucket, error) {
	switch bucket.Spec.Provider {
	case sourcev1.GoogleBucketProvider:
		gcpClient, err := gcp.NewClient(ctx, secret, bucket)
		if err != nil {
			err = fmt.Errorf("auth error: %w", err)
			return sourcev1.Bucket{}, err
		}
		defer gcpClient.Close(ctx)
		if bucketResponse, err := fetchFiles(ctx, gcpClient, bucket, tempDir); err != nil {
			return bucketResponse, err
		}
	default:
		minioClient, err := minio.NewClient(ctx, secret, bucket)
		if err != nil {
			err = fmt.Errorf("auth error: %w", err)
			return sourcev1.Bucket{}, err
		}
		if bucketResponse, err := fetchFiles(ctx, minioClient, bucket, tempDir); err != nil {
			return bucketResponse, err
		}
	}
	return sourcev1.Bucket{}, nil
}

func fetchFiles(ctx context.Context, client BucketProvider, bucket sourcev1.Bucket, tempDir string) (sourcev1.Bucket, error) {
	ctxTimeout, cancel := context.WithTimeout(ctx, bucket.Spec.Timeout.Duration)
	defer cancel()
	exists, err := client.BucketExists(ctxTimeout, bucket.Spec.BucketName)
	if err != nil {
		return sourcev1.BucketNotReady(bucket, sourcev1.BucketOperationFailedReason, err.Error()), err
	}
	if !exists {
		err = fmt.Errorf("bucket '%s' not found", bucket.Spec.BucketName)
		return sourcev1.BucketNotReady(bucket, sourcev1.BucketOperationFailedReason, err.Error()), err
	}

	// Look for file with ignore rules first.
	path := filepath.Join(tempDir, sourceignore.IgnoreFile)
	if err := client.FGetObject(ctxTimeout, bucket.Spec.BucketName, sourceignore.IgnoreFile, path); err != nil {
		if client.ObjectIsNotFound(err) && sourceignore.IgnoreFile != ".sourceignore" {
			return sourcev1.BucketNotReady(bucket, sourcev1.BucketOperationFailedReason, err.Error()), err
		}
	}
	ps, err := sourceignore.ReadIgnoreFile(path, nil)
	if err != nil {
		return sourcev1.BucketNotReady(bucket, sourcev1.BucketOperationFailedReason, err.Error()), err
	}
	// In-spec patterns take precedence
	if bucket.Spec.Ignore != nil {
		ps = append(ps, sourceignore.ReadPatterns(strings.NewReader(*bucket.Spec.Ignore), nil)...)
	}
	matcher := sourceignore.NewMatcher(ps)
	err = client.ListObjects(ctxTimeout, matcher, bucket.Spec.BucketName, tempDir)
	if err != nil {
		err = fmt.Errorf("listing objects from bucket '%s' failed: %w", bucket.Spec.BucketName, err)
		return sourcev1.BucketNotReady(bucket, sourcev1.BucketOperationFailedReason, err.Error()), err
	}
	return sourcev1.Bucket{}, nil
}

func (r *BucketReconciler) reconcileDelete(ctx context.Context, bucket sourcev1.Bucket) (ctrl.Result, error) {
	if err := r.gc(bucket); err != nil {
		r.event(ctx, bucket, events.EventSeverityError,
			fmt.Sprintf("garbage collection for deleted resource failed: %s", err.Error()))
		// Return the error so we retry the failed garbage collection
		return ctrl.Result{}, err
	}

	// Record deleted status
	r.recordReadiness(ctx, bucket)

	// Remove our finalizer from the list and update it
	controllerutil.RemoveFinalizer(&bucket, sourcev1.SourceFinalizer)
	if err := r.Update(ctx, &bucket); err != nil {
		return ctrl.Result{}, err
	}

	// Stop reconciliation as the object is being deleted
	return ctrl.Result{}, nil
}

// checksum calculates the SHA1 checksum of the given root directory.
// It traverses the given root directory and calculates the checksum for any found file, and returns the SHA1 sum of the
// list with relative file paths and their checksums.
func (r *BucketReconciler) checksum(root string) (string, error) {
	sum := sha1.New()
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		sum.Write([]byte(fmt.Sprintf("%x  %s\n", sha1.Sum(data), relPath)))
		return nil
	}); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sum.Sum(nil)), nil
}

// resetStatus returns a modified v1beta1.Bucket and a boolean indicating
// if the status field has been reset.
func (r *BucketReconciler) resetStatus(bucket sourcev1.Bucket) (sourcev1.Bucket, bool) {
	// We do not have an artifact, or it does no longer exist
	if bucket.GetArtifact() == nil || !r.Storage.ArtifactExist(*bucket.GetArtifact()) {
		bucket = sourcev1.BucketProgressing(bucket)
		bucket.Status.Artifact = nil
		return bucket, true
	}
	if bucket.Generation != bucket.Status.ObservedGeneration {
		return sourcev1.BucketProgressing(bucket), true
	}
	return bucket, false
}

// gc performs a garbage collection for the given v1beta1.Bucket.
// It removes all but the current artifact except for when the
// deletion timestamp is set, which will result in the removal of
// all artifacts for the resource.
func (r *BucketReconciler) gc(bucket sourcev1.Bucket) error {
	if !bucket.DeletionTimestamp.IsZero() {
		return r.Storage.RemoveAll(r.Storage.NewArtifactFor(bucket.Kind, bucket.GetObjectMeta(), "", "*"))
	}
	if bucket.GetArtifact() != nil {
		return r.Storage.RemoveAllButCurrent(*bucket.GetArtifact())
	}
	return nil
}

// event emits a Kubernetes event and forwards the event to notification controller if configured
func (r *BucketReconciler) event(ctx context.Context, bucket sourcev1.Bucket, severity, msg string) {
	log := logr.FromContext(ctx)
	if r.EventRecorder != nil {
		r.EventRecorder.Eventf(&bucket, "Normal", severity, msg)
	}
	if r.ExternalEventRecorder != nil {
		objRef, err := reference.GetReference(r.Scheme, &bucket)
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

func (r *BucketReconciler) recordReadiness(ctx context.Context, bucket sourcev1.Bucket) {
	log := logr.FromContext(ctx)
	if r.MetricsRecorder == nil {
		return
	}
	objRef, err := reference.GetReference(r.Scheme, &bucket)
	if err != nil {
		log.Error(err, "unable to record readiness metric")
		return
	}
	if rc := apimeta.FindStatusCondition(bucket.Status.Conditions, meta.ReadyCondition); rc != nil {
		r.MetricsRecorder.RecordCondition(*objRef, *rc, !bucket.DeletionTimestamp.IsZero())
	} else {
		r.MetricsRecorder.RecordCondition(*objRef, metav1.Condition{
			Type:   meta.ReadyCondition,
			Status: metav1.ConditionUnknown,
		}, !bucket.DeletionTimestamp.IsZero())
	}
}

func (r *BucketReconciler) recordSuspension(ctx context.Context, bucket sourcev1.Bucket) {
	if r.MetricsRecorder == nil {
		return
	}
	log := logr.FromContext(ctx)

	objRef, err := reference.GetReference(r.Scheme, &bucket)
	if err != nil {
		log.Error(err, "unable to record suspended metric")
		return
	}

	if !bucket.DeletionTimestamp.IsZero() {
		r.MetricsRecorder.RecordSuspend(*objRef, false)
	} else {
		r.MetricsRecorder.RecordSuspend(*objRef, bucket.Spec.Suspend)
	}
}

func (r *BucketReconciler) updateStatus(ctx context.Context, req ctrl.Request, newStatus sourcev1.BucketStatus) error {
	var bucket sourcev1.Bucket
	if err := r.Get(ctx, req.NamespacedName, &bucket); err != nil {
		return err
	}

	patch := client.MergeFrom(bucket.DeepCopy())
	bucket.Status = newStatus

	return r.Status().Patch(ctx, &bucket, patch)
}
