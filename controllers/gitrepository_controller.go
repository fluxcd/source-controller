/*
Copyright 2020 The Flux CD contributors.

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
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kuberecorder "k8s.io/client-go/tools/record"
	"k8s.io/client-go/tools/reference"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/fluxcd/pkg/runtime/events"
	"github.com/fluxcd/pkg/runtime/metrics"
	"github.com/fluxcd/pkg/runtime/predicates"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	"github.com/fluxcd/source-controller/pkg/git"
)

// GitRepositoryReconciler reconciles a GitRepository object
type GitRepositoryReconciler struct {
	client.Client
	Log                   logr.Logger
	Scheme                *runtime.Scheme
	Storage               *Storage
	EventRecorder         kuberecorder.EventRecorder
	ExternalEventRecorder *events.Recorder
	MetricsRecorder       *metrics.Recorder
}

// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=gitrepositories,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=gitrepositories/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

func (r *GitRepositoryReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	start := time.Now()

	var repository sourcev1.GitRepository
	if err := r.Get(ctx, req.NamespacedName, &repository); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log := r.Log.WithValues("controller", strings.ToLower(sourcev1.GitRepositoryKind), "request", req.NamespacedName)

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
		if err := r.Status().Update(ctx, &repository); err != nil {
			log.Error(err, "unable to update status")
			return ctrl.Result{Requeue: true}, err
		}
		r.recordReadiness(repository, false)
	}

	// purge old artifacts from storage
	if err := r.gc(repository, false); err != nil {
		log.Error(err, "unable to purge old artifacts")
	}

	// reconcile repository by pulling the latest Git commit
	reconciledRepository, reconcileErr := r.reconcile(ctx, *repository.DeepCopy())

	// update status with the reconciliation result
	if err := r.Status().Update(ctx, &reconciledRepository); err != nil {
		log.Error(err, "unable to update status")
		return ctrl.Result{Requeue: true}, err
	}

	// if reconciliation failed, record the failure and requeue immediately
	if reconcileErr != nil {
		r.event(reconciledRepository, events.EventSeverityError, reconcileErr.Error())
		r.recordReadiness(reconciledRepository, false)
		return ctrl.Result{Requeue: true}, reconcileErr
	}

	// emit revision change event
	if repository.Status.Artifact == nil || reconciledRepository.Status.Artifact.Revision != repository.Status.Artifact.Revision {
		r.event(reconciledRepository, events.EventSeverityInfo, sourcev1.GitRepositoryReadyMessage(reconciledRepository))
	}
	r.recordReadiness(reconciledRepository, false)

	log.Info(fmt.Sprintf("Reconciliation finished in %s, next run in %s",
		time.Now().Sub(start).String(),
		repository.GetInterval().Duration.String(),
	))

	return ctrl.Result{RequeueAfter: repository.GetInterval().Duration}, nil

}

type GitRepositoryReconcilerOptions struct {
	MaxConcurrentReconciles int
}

func (r *GitRepositoryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return r.SetupWithManagerAndOptions(mgr, GitRepositoryReconcilerOptions{})
}

func (r *GitRepositoryReconciler) SetupWithManagerAndOptions(mgr ctrl.Manager, opts GitRepositoryReconcilerOptions) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sourcev1.GitRepository{}).
		WithEventFilter(predicates.ChangePredicate{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: opts.MaxConcurrentReconciles}).
		Complete(r)
}

func (r *GitRepositoryReconciler) reconcile(ctx context.Context, repository sourcev1.GitRepository) (sourcev1.GitRepository, error) {
	// create tmp dir for the Git clone
	tmpGit, err := ioutil.TempDir("", repository.Name)
	if err != nil {
		err = fmt.Errorf("tmp dir error: %w", err)
		return sourcev1.GitRepositoryNotReady(repository, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	defer os.RemoveAll(tmpGit)

	// determine auth method
	var auth transport.AuthMethod
	authStrategy := git.AuthSecretStrategyForURL(repository.Spec.URL)
	if repository.Spec.SecretRef != nil && authStrategy != nil {
		name := types.NamespacedName{
			Namespace: repository.GetNamespace(),
			Name:      repository.Spec.SecretRef.Name,
		}

		var secret corev1.Secret
		err := r.Client.Get(ctx, name, &secret)
		if err != nil {
			err = fmt.Errorf("auth secret error: %w", err)
			return sourcev1.GitRepositoryNotReady(repository, sourcev1.AuthenticationFailedReason, err.Error()), err
		}

		auth, err = authStrategy.Method(secret)
		if err != nil {
			err = fmt.Errorf("auth error: %w", err)
			return sourcev1.GitRepositoryNotReady(repository, sourcev1.AuthenticationFailedReason, err.Error()), err
		}
	}

	checkoutStrategy := git.CheckoutStrategyForRef(repository.Spec.Reference)
	commit, revision, err := checkoutStrategy.Checkout(ctx, tmpGit, repository.Spec.URL, auth)
	if err != nil {
		return sourcev1.GitRepositoryNotReady(repository, sourcev1.GitOperationFailedReason, err.Error()), err
	}

	// return early on unchanged revision
	artifact := r.Storage.NewArtifactFor(repository.Kind, repository.GetObjectMeta(), revision, fmt.Sprintf("%s.tar.gz", commit.Hash.String()))
	if meta.HasReadyCondition(repository.Status.Conditions) && repository.GetArtifact().HasRevision(artifact.Revision) {
		if artifact.URL != repository.GetArtifact().URL {
			r.Storage.SetArtifactURL(repository.GetArtifact())
			repository.Status.URL = r.Storage.SetHostname(repository.Status.URL)
		}
		return repository, nil
	}

	// verify PGP signature
	if repository.Spec.Verification != nil {
		err := r.verify(ctx, types.NamespacedName{
			Namespace: repository.Namespace,
			Name:      repository.Spec.Verification.SecretRef.Name,
		}, commit)
		if err != nil {
			return sourcev1.GitRepositoryNotReady(repository, sourcev1.VerificationFailedReason, err.Error()), err
		}
	}

	// create artifact dir
	err = r.Storage.MkdirAll(artifact)
	if err != nil {
		err = fmt.Errorf("mkdir dir error: %w", err)
		return sourcev1.GitRepositoryNotReady(repository, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// acquire lock
	unlock, err := r.Storage.Lock(artifact)
	if err != nil {
		err = fmt.Errorf("unable to acquire lock: %w", err)
		return sourcev1.GitRepositoryNotReady(repository, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	defer unlock()

	// archive artifact and check integrity
	if err := r.Storage.Archive(&artifact, tmpGit, repository.Spec.Ignore); err != nil {
		err = fmt.Errorf("storage archive error: %w", err)
		return sourcev1.GitRepositoryNotReady(repository, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// update latest symlink
	url, err := r.Storage.Symlink(artifact, "latest.tar.gz")
	if err != nil {
		err = fmt.Errorf("storage symlink error: %w", err)
		return sourcev1.GitRepositoryNotReady(repository, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	message := fmt.Sprintf("Fetched revision: %s", artifact.Revision)
	return sourcev1.GitRepositoryReady(repository, artifact, url, sourcev1.GitOperationSucceedReason, message), nil
}

func (r *GitRepositoryReconciler) reconcileDelete(ctx context.Context, repository sourcev1.GitRepository) (ctrl.Result, error) {
	if err := r.gc(repository, true); err != nil {
		r.event(repository, events.EventSeverityError, fmt.Sprintf("garbage collection for deleted resource failed: %s", err.Error()))
		// Return the error so we retry the failed garbage collection
		return ctrl.Result{}, err
	}

	// Record deleted status
	r.recordReadiness(repository, true)

	// Remove our finalizer from the list and update it
	controllerutil.RemoveFinalizer(&repository, sourcev1.SourceFinalizer)
	if err := r.Update(ctx, &repository); err != nil {
		return ctrl.Result{}, err
	}

	// Stop reconciliation as the object is being deleted
	return ctrl.Result{}, nil
}

// verify returns an error if the PGP signature can't be verified
func (r *GitRepositoryReconciler) verify(ctx context.Context, publicKeySecret types.NamespacedName, commit *object.Commit) error {
	if commit.PGPSignature == "" {
		return fmt.Errorf("no PGP signature found for commit: %s", commit.Hash)
	}

	var secret corev1.Secret
	if err := r.Client.Get(ctx, publicKeySecret, &secret); err != nil {
		return fmt.Errorf("PGP public keys secret error: %w", err)
	}

	var verified bool
	for _, bytes := range secret.Data {
		if _, err := commit.Verify(string(bytes)); err == nil {
			verified = true
			break
		}
	}
	if !verified {
		return fmt.Errorf("PGP signature '%s' of '%s' can't be verified", commit.PGPSignature, commit.Author)
	}
	return nil
}

// resetStatus returns a modified v1beta1.GitRepository and a boolean indicating
// if the status field has been reset.
func (r *GitRepositoryReconciler) resetStatus(repository sourcev1.GitRepository) (sourcev1.GitRepository, bool) {
	// We do not have an artifact, or it does no longer exist
	if repository.GetArtifact() == nil || !r.Storage.ArtifactExist(*repository.GetArtifact()) {
		repository = sourcev1.GitRepositoryProgressing(repository)
		repository.Status.Artifact = nil
		return repository, true
	}
	if repository.Generation != repository.Status.ObservedGeneration {
		return sourcev1.GitRepositoryProgressing(repository), true
	}
	return repository, false
}

// gc performs a garbage collection on all but current artifacts of
// the given repository.
func (r *GitRepositoryReconciler) gc(repository sourcev1.GitRepository, all bool) error {
	if all {
		return r.Storage.RemoveAll(r.Storage.NewArtifactFor(repository.Kind, repository.GetObjectMeta(), "", ""))
	}
	if repository.GetArtifact() != nil {
		return r.Storage.RemoveAllButCurrent(*repository.GetArtifact())
	}
	return nil
}

// event emits a Kubernetes event and forwards the event to notification controller if configured
func (r *GitRepositoryReconciler) event(repository sourcev1.GitRepository, severity, msg string) {
	if r.EventRecorder != nil {
		r.EventRecorder.Eventf(&repository, "Normal", severity, msg)
	}
	if r.ExternalEventRecorder != nil {
		objRef, err := reference.GetReference(r.Scheme, &repository)
		if err != nil {
			r.Log.WithValues(
				"request",
				fmt.Sprintf("%s/%s", repository.GetNamespace(), repository.GetName()),
			).Error(err, "unable to send event")
			return
		}

		if err := r.ExternalEventRecorder.Eventf(*objRef, nil, severity, severity, msg); err != nil {
			r.Log.WithValues(
				"request",
				fmt.Sprintf("%s/%s", repository.GetNamespace(), repository.GetName()),
			).Error(err, "unable to send event")
			return
		}
	}
}

func (r *GitRepositoryReconciler) recordReadiness(repository sourcev1.GitRepository, deleted bool) {
	if r.MetricsRecorder == nil {
		return
	}

	objRef, err := reference.GetReference(r.Scheme, &repository)
	if err != nil {
		r.Log.WithValues(
			strings.ToLower(repository.Kind),
			fmt.Sprintf("%s/%s", repository.GetNamespace(), repository.GetName()),
		).Error(err, "unable to record readiness metric")
		return
	}
	if rc := meta.GetCondition(repository.Status.Conditions, meta.ReadyCondition); rc != nil {
		r.MetricsRecorder.RecordCondition(*objRef, *rc, deleted)
	} else {
		r.MetricsRecorder.RecordCondition(*objRef, meta.Condition{
			Type:   meta.ReadyCondition,
			Status: corev1.ConditionUnknown,
		}, deleted)
	}
}
