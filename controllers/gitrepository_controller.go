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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
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
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/events"
	"github.com/fluxcd/pkg/runtime/metrics"
	"github.com/fluxcd/pkg/runtime/predicates"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	"github.com/fluxcd/source-controller/pkg/git"
	"github.com/fluxcd/source-controller/pkg/git/strategy"
	"github.com/fluxcd/source-controller/pkg/sourceignore"
)

// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=gitrepositories,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=gitrepositories/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=gitrepositories/finalizers,verbs=get;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// GitRepositoryReconciler reconciles a GitRepository object
type GitRepositoryReconciler struct {
	client.Client
	requeueDependency     time.Duration
	Scheme                *runtime.Scheme
	Storage               *Storage
	EventRecorder         kuberecorder.EventRecorder
	ExternalEventRecorder *events.Recorder
	MetricsRecorder       *metrics.Recorder
}

type GitRepositoryReconcilerOptions struct {
	MaxConcurrentReconciles   int
	DependencyRequeueInterval time.Duration
}

func (r *GitRepositoryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return r.SetupWithManagerAndOptions(mgr, GitRepositoryReconcilerOptions{})
}

func (r *GitRepositoryReconciler) SetupWithManagerAndOptions(mgr ctrl.Manager, opts GitRepositoryReconcilerOptions) error {
	r.requeueDependency = opts.DependencyRequeueInterval

	return ctrl.NewControllerManagedBy(mgr).
		For(&sourcev1.GitRepository{}, builder.WithPredicates(
			predicate.Or(predicate.GenerationChangedPredicate{}, predicates.ReconcileRequestedPredicate{}),
		)).
		WithOptions(controller.Options{MaxConcurrentReconciles: opts.MaxConcurrentReconciles}).
		Complete(r)
}

func (r *GitRepositoryReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	start := time.Now()
	log := logr.FromContext(ctx)

	var repository sourcev1.GitRepository
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

	// check dependencies
	if len(repository.Spec.Include) > 0 {
		if err := r.checkDependencies(repository); err != nil {
			repository = sourcev1.GitRepositoryNotReady(repository, "DependencyNotReady", err.Error())
			if err := r.updateStatus(ctx, req, repository.Status); err != nil {
				log.Error(err, "unable to update status for dependency not ready")
				return ctrl.Result{Requeue: true}, err
			}
			// we can't rely on exponential backoff because it will prolong the execution too much,
			// instead we requeue on a fix interval.
			msg := fmt.Sprintf("Dependencies do not meet ready condition, retrying in %s", r.requeueDependency.String())
			log.Info(msg)
			r.event(ctx, repository, events.EventSeverityInfo, msg)
			r.recordReadiness(ctx, repository)
			return ctrl.Result{RequeueAfter: r.requeueDependency}, nil
		}
		log.Info("All dependencies area ready, proceeding with reconciliation")
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

	// reconcile repository by pulling the latest Git commit
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
		r.event(ctx, reconciledRepository, events.EventSeverityInfo, sourcev1.GitRepositoryReadyMessage(reconciledRepository))
	}
	r.recordReadiness(ctx, reconciledRepository)

	log.Info(fmt.Sprintf("Reconciliation finished in %s, next run in %s",
		time.Since(start).String(),
		repository.GetInterval().Duration.String(),
	))

	return ctrl.Result{RequeueAfter: repository.GetInterval().Duration}, nil
}

func (r *GitRepositoryReconciler) checkDependencies(repository sourcev1.GitRepository) error {
	for _, d := range repository.Spec.Include {
		dName := types.NamespacedName{Name: d.GitRepositoryRef.Name, Namespace: repository.Namespace}
		var gr sourcev1.GitRepository
		err := r.Get(context.Background(), dName, &gr)
		if err != nil {
			return fmt.Errorf("unable to get '%s' dependency: %w", dName, err)
		}

		if len(gr.Status.Conditions) == 0 || gr.Generation != gr.Status.ObservedGeneration {
			return fmt.Errorf("dependency '%s' is not ready", dName)
		}

		if !apimeta.IsStatusConditionTrue(gr.Status.Conditions, meta.ReadyCondition) {
			return fmt.Errorf("dependency '%s' is not ready", dName)
		}
	}

	return nil
}

func (r *GitRepositoryReconciler) reconcile(ctx context.Context, repository sourcev1.GitRepository) (sourcev1.GitRepository, error) {
	// create tmp dir for the Git clone
	tmpGit, err := os.MkdirTemp("", repository.Name)
	if err != nil {
		err = fmt.Errorf("tmp dir error: %w", err)
		return sourcev1.GitRepositoryNotReady(repository, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	defer os.RemoveAll(tmpGit)

	// Configure auth options using secret
	var authOpts *git.AuthOptions
	if repository.Spec.SecretRef != nil {
		name := types.NamespacedName{
			Namespace: repository.GetNamespace(),
			Name:      repository.Spec.SecretRef.Name,
		}

		secret := &corev1.Secret{}
		err = r.Client.Get(ctx, name, secret)
		if err != nil {
			err = fmt.Errorf("auth secret error: %w", err)
			return sourcev1.GitRepositoryNotReady(repository, sourcev1.AuthenticationFailedReason, err.Error()), err
		}

		authOpts, err = git.AuthOptionsFromSecret(repository.Spec.URL, secret)
		if err != nil {
			return sourcev1.GitRepositoryNotReady(repository, sourcev1.AuthenticationFailedReason, err.Error()), err
		}
	}
	checkoutOpts := git.CheckoutOptions{RecurseSubmodules: repository.Spec.RecurseSubmodules}
	if ref := repository.Spec.Reference; ref != nil {
		checkoutOpts.Branch = ref.Branch
		checkoutOpts.Commit = ref.Commit
		checkoutOpts.Tag = ref.Tag
		checkoutOpts.SemVer = ref.SemVer
	}
	checkoutStrategy, err := strategy.CheckoutStrategyForImplementation(ctx,
		git.Implementation(repository.Spec.GitImplementation), checkoutOpts)
	if err != nil {
		return sourcev1.GitRepositoryNotReady(repository, sourcev1.GitOperationFailedReason, err.Error()), err
	}

	gitCtx, cancel := context.WithTimeout(ctx, repository.Spec.Timeout.Duration)
	defer cancel()

	commit, err := checkoutStrategy.Checkout(gitCtx, tmpGit, repository.Spec.URL, authOpts)
	if err != nil {
		return sourcev1.GitRepositoryNotReady(repository, sourcev1.GitOperationFailedReason, err.Error()), err
	}
	artifact := r.Storage.NewArtifactFor(repository.Kind, repository.GetObjectMeta(), commit.String(), fmt.Sprintf("%s.tar.gz", commit.Hash.String()))

	// copy all included repository into the artifact
	includedArtifacts := []*sourcev1.Artifact{}
	for _, incl := range repository.Spec.Include {
		dName := types.NamespacedName{Name: incl.GitRepositoryRef.Name, Namespace: repository.Namespace}
		var gr sourcev1.GitRepository
		err := r.Get(context.Background(), dName, &gr)
		if err != nil {
			return sourcev1.GitRepositoryNotReady(repository, "DependencyNotReady", err.Error()), err
		}
		includedArtifacts = append(includedArtifacts, gr.GetArtifact())
	}

	// return early on unchanged revision and unchanged included repositories
	if apimeta.IsStatusConditionTrue(repository.Status.Conditions, meta.ReadyCondition) && repository.GetArtifact().HasRevision(artifact.Revision) && !hasArtifactUpdated(repository.Status.IncludedArtifacts, includedArtifacts) {
		if artifact.URL != repository.GetArtifact().URL {
			r.Storage.SetArtifactURL(repository.GetArtifact())
			repository.Status.URL = r.Storage.SetHostname(repository.Status.URL)
		}
		return repository, nil
	}

	// verify PGP signature
	if repository.Spec.Verification != nil {
		publicKeySecret := types.NamespacedName{
			Namespace: repository.Namespace,
			Name:      repository.Spec.Verification.SecretRef.Name,
		}
		secret := &corev1.Secret{}
		if err := r.Client.Get(ctx, publicKeySecret, secret); err != nil {
			err = fmt.Errorf("PGP public keys secret error: %w", err)
			return sourcev1.GitRepositoryNotReady(repository, sourcev1.VerificationFailedReason, err.Error()), err
		}

		var keyRings []string
		for _, v := range secret.Data {
			keyRings = append(keyRings, string(v))
		}
		if _, err = commit.Verify(keyRings...); err != nil {
			return sourcev1.GitRepositoryNotReady(repository, sourcev1.VerificationFailedReason, err.Error()), err
		}
	}

	// create artifact dir
	err = r.Storage.MkdirAll(artifact)
	if err != nil {
		err = fmt.Errorf("mkdir dir error: %w", err)
		return sourcev1.GitRepositoryNotReady(repository, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	for i, incl := range repository.Spec.Include {
		toPath, err := securejoin.SecureJoin(tmpGit, incl.GetToPath())
		if err != nil {
			return sourcev1.GitRepositoryNotReady(repository, "DependencyNotReady", err.Error()), err
		}
		err = r.Storage.CopyToPath(includedArtifacts[i], incl.GetFromPath(), toPath)
		if err != nil {
			return sourcev1.GitRepositoryNotReady(repository, "DependencyNotReady", err.Error()), err
		}
	}

	// acquire lock
	unlock, err := r.Storage.Lock(artifact)
	if err != nil {
		err = fmt.Errorf("unable to acquire lock: %w", err)
		return sourcev1.GitRepositoryNotReady(repository, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	defer unlock()

	// archive artifact and check integrity
	ignoreDomain := strings.Split(tmpGit, string(filepath.Separator))
	ps, err := sourceignore.LoadIgnorePatterns(tmpGit, ignoreDomain)
	if err != nil {
		err = fmt.Errorf(".sourceignore error: %w", err)
		return sourcev1.GitRepositoryNotReady(repository, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	if repository.Spec.Ignore != nil {
		ps = append(ps, sourceignore.ReadPatterns(strings.NewReader(*repository.Spec.Ignore), ignoreDomain)...)
	}
	if err := r.Storage.Archive(&artifact, tmpGit, SourceIgnoreFilter(ps, ignoreDomain)); err != nil {
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
	return sourcev1.GitRepositoryReady(repository, artifact, includedArtifacts, url, sourcev1.GitOperationSucceedReason, message), nil
}

func (r *GitRepositoryReconciler) reconcileDelete(ctx context.Context, repository sourcev1.GitRepository) (ctrl.Result, error) {
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

// gc performs a garbage collection for the given v1beta1.GitRepository.
// It removes all but the current artifact except for when the
// deletion timestamp is set, which will result in the removal of
// all artifacts for the resource.
func (r *GitRepositoryReconciler) gc(repository sourcev1.GitRepository) error {
	if !repository.DeletionTimestamp.IsZero() {
		return r.Storage.RemoveAll(r.Storage.NewArtifactFor(repository.Kind, repository.GetObjectMeta(), "", "*"))
	}
	if repository.GetArtifact() != nil {
		return r.Storage.RemoveAllButCurrent(*repository.GetArtifact())
	}
	return nil
}

// event emits a Kubernetes event and forwards the event to notification controller if configured
func (r *GitRepositoryReconciler) event(ctx context.Context, repository sourcev1.GitRepository, severity, msg string) {
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

func (r *GitRepositoryReconciler) recordReadiness(ctx context.Context, repository sourcev1.GitRepository) {
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

func (r *GitRepositoryReconciler) recordSuspension(ctx context.Context, gitrepository sourcev1.GitRepository) {
	if r.MetricsRecorder == nil {
		return
	}
	log := logr.FromContext(ctx)

	objRef, err := reference.GetReference(r.Scheme, &gitrepository)
	if err != nil {
		log.Error(err, "unable to record suspended metric")
		return
	}

	if !gitrepository.DeletionTimestamp.IsZero() {
		r.MetricsRecorder.RecordSuspend(*objRef, false)
	} else {
		r.MetricsRecorder.RecordSuspend(*objRef, gitrepository.Spec.Suspend)
	}
}

func (r *GitRepositoryReconciler) updateStatus(ctx context.Context, req ctrl.Request, newStatus sourcev1.GitRepositoryStatus) error {
	var repository sourcev1.GitRepository
	if err := r.Get(ctx, req.NamespacedName, &repository); err != nil {
		return err
	}

	patch := client.MergeFrom(repository.DeepCopy())
	repository.Status = newStatus

	return r.Status().Patch(ctx, &repository, patch)
}
