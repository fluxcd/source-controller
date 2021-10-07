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
	"archive/tar"
	"context"
	"fmt"
	"github.com/Masterminds/semver/v3"
	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/events"
	"github.com/fluxcd/pkg/runtime/metrics"
	"github.com/fluxcd/pkg/runtime/predicates"
	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	"github.com/fluxcd/source-controller/pkg/sourceignore"
	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
	"github.com/go-logr/logr"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/k8schain"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	kuberecorder "k8s.io/client-go/tools/record"
	"k8s.io/client-go/tools/reference"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sort"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=ocirepositories,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=ocirepositories/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=ocirepositories/finalizers,verbs=get;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch

// OCIRepositoryReconciler reconciles a OCIRepository object
type OCIRepositoryReconciler struct {
	client.Client
	requeueDependency     time.Duration
	Scheme                *runtime.Scheme
	Storage               *Storage
	EventRecorder         kuberecorder.EventRecorder
	ExternalEventRecorder *events.Recorder
	MetricsRecorder       *metrics.Recorder
}

type OCIRepositoryReconcilerOptions struct {
	MaxConcurrentReconciles   int
	DependencyRequeueInterval time.Duration
}

func (r *OCIRepositoryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return r.SetupWithManagerAndOptions(mgr, OCIRepositoryReconcilerOptions{})
}

func (r *OCIRepositoryReconciler) SetupWithManagerAndOptions(mgr ctrl.Manager, opts OCIRepositoryReconcilerOptions) error {
	r.requeueDependency = opts.DependencyRequeueInterval

	return ctrl.NewControllerManagedBy(mgr).
		For(&sourcev1.OCIRepository{}, builder.WithPredicates(
			predicate.Or(predicate.GenerationChangedPredicate{}, predicates.ReconcileRequestedPredicate{}),
		)).
		WithOptions(controller.Options{MaxConcurrentReconciles: opts.MaxConcurrentReconciles}).
		Complete(r)
}

func (r *OCIRepositoryReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	start := time.Now()
	log := logr.FromContext(ctx)

	var repository sourcev1.OCIRepository
	if err := r.Get(ctx, req.NamespacedName, &repository); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Record suspended status metric
	defer r.recordSuspension(ctx, repository)

	// Add our finalizer if it does not exist
	if !controllerutil.ContainsFinalizer(&repository, sourcev1.SourceFinalizer) {
		controllerutil.AddFinalizer(&repository, sourcev1.SourceFinalizer)
		if err := r.Update(ctx, &repository); err != nil {
			log.Error(err, "unable to register finalizer")
			return ctrl.Result{}, err
		}
	}

	// Examine if the object is under deletion
	if !repository.ObjectMeta.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, repository)
	}

	// Return early if the object is suspended.
	if repository.Spec.Suspend {
		log.Info("Reconciliation is suspended for this object")
		return ctrl.Result{}, nil
	}

	// record reconciliation duration
	if r.MetricsRecorder != nil {
		objRef, err := reference.GetReference(r.Scheme, &repository)
		if err != nil {
			return ctrl.Result{}, err
		}
		defer r.MetricsRecorder.RecordDuration(*objRef, start)
	}

	// set initial status
	if resetRepository, ok := r.resetStatus(repository); ok {
		repository = resetRepository
		if err := r.updateStatus(ctx, req, repository.Status); err != nil {
			log.Error(err, "unable to update status")
			return ctrl.Result{Requeue: true}, err
		}
		r.recordReadiness(ctx, repository)
	}

	// record the value of the reconciliation request, if any
	// TODO(hidde): would be better to defer this in combination with
	//   always patching the status sub-resource after a reconciliation.
	if v, ok := meta.ReconcileAnnotationValue(repository.GetAnnotations()); ok {
		repository.Status.SetLastHandledReconcileRequest(v)
	}

	// purge old artifacts from storage
	if err := r.gc(repository); err != nil {
		log.Error(err, "unable to purge old artifacts")
	}

	// reconcile repository by pulling the latest repository
	reconciledRepository, reconcileErr := r.reconcile(ctx, *repository.DeepCopy())

	// update status with the reconciliation result
	if err := r.updateStatus(ctx, req, reconciledRepository.Status); err != nil {
		log.Error(err, "unable to update status")
		return ctrl.Result{Requeue: true}, err
	}

	// if reconciliation failed, record the failure and requeue immediately
	if reconcileErr != nil {
		r.event(ctx, reconciledRepository, events.EventSeverityError, reconcileErr.Error())
		r.recordReadiness(ctx, reconciledRepository)
		return ctrl.Result{Requeue: true}, reconcileErr
	}

	// emit revision change event
	if repository.Status.Artifact == nil || reconciledRepository.Status.Artifact.Revision != repository.Status.Artifact.Revision {
		r.event(ctx, reconciledRepository, events.EventSeverityInfo, sourcev1.OCIRepositoryReadyMessage(reconciledRepository))
	}
	r.recordReadiness(ctx, reconciledRepository)

	log.Info(fmt.Sprintf("Reconciliation finished in %s, next run in %s",
		time.Now().Sub(start).String(),
		repository.GetInterval().Duration.String(),
	))

	return ctrl.Result{RequeueAfter: repository.GetInterval().Duration}, nil
}

// event emits a Kubernetes event and forwards the event to notification controller if configured
func (r *OCIRepositoryReconciler) event(ctx context.Context, repository sourcev1.OCIRepository, severity, msg string) {
	log := logr.FromContext(ctx)

	if r.EventRecorder != nil {
		r.EventRecorder.Eventf(&repository, "Normal", severity, msg)
	}
	if r.ExternalEventRecorder != nil {
		objRef, err := reference.GetReference(r.Scheme, &repository)
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

// gc performs a garbage collection for the given v1beta1.OCIRepository.
// It removes all but the current artifact except for when the
// deletion timestamp is set, which will result in the removal of
// all artifacts for the resource.
func (r *OCIRepositoryReconciler) gc(repository sourcev1.OCIRepository) error {
	if !repository.DeletionTimestamp.IsZero() {
		return r.Storage.RemoveAll(r.Storage.NewArtifactFor(repository.Kind, repository.GetObjectMeta(), "", "*"))
	}
	if repository.GetArtifact() != nil {
		return r.Storage.RemoveAllButCurrent(*repository.GetArtifact())
	}
	return nil
}

// keychain generates the credential keychain based on the resource
// configuration. If no auth is specified a default keychain with
// anonymous access is returned
func (r *OCIRepositoryReconciler) keychain(ctx context.Context, repository sourcev1.OCIRepository) (authn.Keychain, error) {
	auth := repository.Spec.Authentication
	if auth == nil {
		return authn.DefaultKeychain, nil
	}

	pullSecretNames := sets.NewString()
	if auth.SecretRef != nil {
		pullSecretNames.Insert(auth.SecretRef.Name)
	}

	// lookup service account
	serviceAccountName := auth.ServiceAccountName
	if serviceAccountName == "" {
		serviceAccountName = "default"
	}
	serviceAccount := corev1.ServiceAccount{}
	err := r.Get(ctx, types.NamespacedName{Namespace: repository.Namespace, Name: serviceAccountName}, &serviceAccount)
	if err != nil {
		return nil, err
	}
	for _, ips := range serviceAccount.ImagePullSecrets {
		pullSecretNames.Insert(ips.Name)
	}

	// lookup image pull secrets
	imagePullSecrets := make([]corev1.Secret, len(pullSecretNames))
	for i, imagePullSecretName := range pullSecretNames.List() {
		imagePullSecret := corev1.Secret{}
		err := r.Get(ctx, types.NamespacedName{Namespace: repository.Namespace, Name: imagePullSecretName}, &imagePullSecret)
		if err != nil {
			return nil, err
		}
		imagePullSecrets[i] = imagePullSecret
	}

	return k8schain.NewFromPullSecrets(ctx, imagePullSecrets)
}

func (r *OCIRepositoryReconciler) reconcile(ctx context.Context, repository sourcev1.OCIRepository) (sourcev1.OCIRepository, error) {
	ociCtx, cancel := context.WithTimeout(ctx, repository.Spec.Timeout.Duration)
	defer cancel()

	keychain, err := r.keychain(ociCtx, repository)
	if err != nil {
		return sourcev1.OCIRepositoryNotReady(repository, sourcev1.AuthenticationFailedReason, err.Error()), err
	}

	ref, err := r.reference(ociCtx, keychain, repository)
	if err != nil {
		return sourcev1.OCIRepositoryNotReady(repository, sourcev1.OCIRepositoryOperationFailedReason, err.Error()), err
	}

	image, err := remote.Image(ref, remote.WithAuthFromKeychain(keychain))
	if err != nil {
		return sourcev1.OCIRepositoryNotReady(repository, sourcev1.OCIRepositoryOperationFailedReason, err.Error()), err
	}

	digest, err := image.Digest()
	if err != nil {
		return sourcev1.OCIRepositoryNotReady(repository, sourcev1.OCIRepositoryOperationFailedReason, err.Error()), err
	}

	revision := fmt.Sprintf("%s@%s", ref.Context().Name(), digest)
	artifact := r.Storage.NewArtifactFor(repository.Kind, repository.GetObjectMeta(), revision, fmt.Sprintf("%s.tar.gz", digest))

	// return early on unchanged digest
	if apimeta.IsStatusConditionTrue(repository.Status.Conditions, meta.ReadyCondition) && repository.GetArtifact().HasRevision(artifact.Revision) {
		if artifact.URL != repository.GetArtifact().URL {
			r.Storage.SetArtifactURL(repository.GetArtifact())
			repository.Status.URL = r.Storage.SetHostname(repository.Status.URL)
		}
		return repository, nil
	}

	// create artifact dir
	err = r.Storage.MkdirAll(artifact)
	if err != nil {
		err = fmt.Errorf("mkdir dir error: %w", err)
		return sourcev1.OCIRepositoryNotReady(repository, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// acquire lock
	unlock, err := r.Storage.Lock(artifact)
	if err != nil {
		err = fmt.Errorf("unable to acquire lock: %w", err)
		return sourcev1.OCIRepositoryNotReady(repository, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	defer unlock()

	// archive artifact and check integrity
	var ignoreDomain []string
	var ps []gitignore.Pattern
	if repository.Spec.Ignore != nil {
		ps = append(ps, sourceignore.ReadPatterns(strings.NewReader(*repository.Spec.Ignore), ignoreDomain)...)
	}

	in := mutate.Extract(image)
	if err := r.Storage.ArchiveTar(&artifact, tar.NewReader(in), SourceIgnoreFilter(ps, ignoreDomain)); err != nil {
		in.Close()
		err = fmt.Errorf("storage archive error: %w", err)
		return sourcev1.OCIRepositoryNotReady(repository, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	in.Close()

	// update latest symlink
	url, err := r.Storage.Symlink(artifact, "latest.tar.gz")
	if err != nil {
		err = fmt.Errorf("storage symlink error: %w", err)
		return sourcev1.OCIRepositoryNotReady(repository, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	message := fmt.Sprintf("Fetched revision: %s", artifact.Revision)
	return sourcev1.OCIRepositoryReady(repository, artifact, url, sourcev1.OCIRepositoryOperationSucceedReason, message), nil
}

func (r *OCIRepositoryReconciler) reconcileDelete(ctx context.Context, repository sourcev1.OCIRepository) (ctrl.Result, error) {
	if err := r.gc(repository); err != nil {
		r.event(ctx, repository, events.EventSeverityError,
			fmt.Sprintf("garbage collection for deleted resource failed: %s", err.Error()))
		// Return the error so we retry the failed garbage collection
		return ctrl.Result{}, err
	}

	// Record deleted status
	r.recordReadiness(ctx, repository)

	// Remove our finalizer from the list and update it
	controllerutil.RemoveFinalizer(&repository, sourcev1.SourceFinalizer)
	if err := r.Update(ctx, &repository); err != nil {
		return ctrl.Result{}, err
	}

	// Stop reconciliation as the object is being deleted
	return ctrl.Result{}, nil
}

func (r *OCIRepositoryReconciler) recordReadiness(ctx context.Context, repository sourcev1.OCIRepository) {
	log := logr.FromContext(ctx)
	if r.MetricsRecorder == nil {
		return
	}
	objRef, err := reference.GetReference(r.Scheme, &repository)
	if err != nil {
		log.Error(err, "unable to record readiness metric")
		return
	}
	if rc := apimeta.FindStatusCondition(repository.Status.Conditions, meta.ReadyCondition); rc != nil {
		r.MetricsRecorder.RecordCondition(*objRef, *rc, !repository.DeletionTimestamp.IsZero())
	} else {
		r.MetricsRecorder.RecordCondition(*objRef, metav1.Condition{
			Type:   meta.ReadyCondition,
			Status: metav1.ConditionUnknown,
		}, !repository.DeletionTimestamp.IsZero())
	}
}

func (r *OCIRepositoryReconciler) recordSuspension(ctx context.Context, repository sourcev1.OCIRepository) {
	if r.MetricsRecorder == nil {
		return
	}
	log := logr.FromContext(ctx)

	objRef, err := reference.GetReference(r.Scheme, &repository)
	if err != nil {
		log.Error(err, "unable to record suspended metric")
		return
	}

	if !repository.DeletionTimestamp.IsZero() {
		r.MetricsRecorder.RecordSuspend(*objRef, false)
	} else {
		r.MetricsRecorder.RecordSuspend(*objRef, repository.Spec.Suspend)
	}
}

// resetStatus returns a modified v1beta1.OCIRepository and a boolean indicating
// if the status field has been reset.
func (r *OCIRepositoryReconciler) resetStatus(repository sourcev1.OCIRepository) (sourcev1.OCIRepository, bool) {
	// We do not have an artifact, or it does no longer exist
	if repository.GetArtifact() == nil || !r.Storage.ArtifactExist(*repository.GetArtifact()) {
		repository = sourcev1.OCIRepositoryProgressing(repository)
		repository.Status.Artifact = nil
		return repository, true
	}
	if repository.Generation != repository.Status.ObservedGeneration {
		return sourcev1.OCIRepositoryProgressing(repository), true
	}
	return repository, false
}

func (r *OCIRepositoryReconciler) reference(ctx context.Context, keychain authn.Keychain, repository sourcev1.OCIRepository) (name.Reference, error) {
	url := repository.Spec.URL

	ref := repository.Spec.Reference
	if ref == nil {
		return name.ParseReference(fmt.Sprintf("%s:latest", url))
	}

	if ref.Digest != "" {
		return name.ParseReference(fmt.Sprintf("%s@%s", url, ref.Digest))
	}

	if ref.SemVer != "" {
		repo, err := name.NewRepository(url)
		if err != nil {
			return nil, err
		}

		tags, err := remote.List(repo, remote.WithAuthFromKeychain(keychain), remote.WithContext(ctx))
		if err != nil {
			return nil, err
		}

		c, err := semver.NewConstraint(ref.SemVer)
		if err != nil {
			return nil, err
		}

		var candidates []*semver.Version
		for _, t := range tags {
				v, err := semver.NewVersion(t)
				if err != nil {
					continue
				}

				if c != nil && !c.Check(v) {
					continue
				}

				candidates = append(candidates, v)
		}

		if len(candidates) == 0 {
			return nil, fmt.Errorf("no matching tags were found")
		}

		sort.Sort(sort.Reverse(semver.Collection(candidates)))
		return name.ParseReference(fmt.Sprintf("%s:%s", url, candidates[0]))
	}

	if ref.Tag != "" {
		return name.ParseReference(fmt.Sprintf("%s:%s", url, ref.Tag))
	}

	return name.ParseReference(fmt.Sprintf("%s:latest", url))
}

func (r *OCIRepositoryReconciler) updateStatus(ctx context.Context, req ctrl.Request, newStatus sourcev1.OCIRepositoryStatus) error {
	var repository sourcev1.OCIRepository
	if err := r.Get(ctx, req.NamespacedName, &repository); err != nil {
		return err
	}

	patch := client.MergeFrom(repository.DeepCopy())
	repository.Status = newStatus

	return r.Status().Patch(ctx, &repository, patch)
}
