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

	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	sourcev1 "github.com/fluxcd/source-controller/api/v1alpha1"
	intgit "github.com/fluxcd/source-controller/internal/git"
)

// GitRepositoryReconciler reconciles a GitRepository object
type GitRepositoryReconciler struct {
	client.Client
	Log     logr.Logger
	Scheme  *runtime.Scheme
	Storage *Storage
}

// +kubebuilder:rbac:groups=source.fluxcd.io,resources=gitrepositories,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=source.fluxcd.io,resources=gitrepositories/status,verbs=get;update;patch

func (r *GitRepositoryReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()

	var repo sourcev1.GitRepository
	if err := r.Get(ctx, req.NamespacedName, &repo); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log := r.Log.WithValues(repo.Kind, req.NamespacedName)

	// set initial status
	if reset, status := r.shouldResetStatus(repo); reset {
		log.Info("Initializing Git repository")
		repo.Status = status
		if err := r.Status().Update(ctx, &repo); err != nil {
			log.Error(err, "unable to update GitRepository status")
			return ctrl.Result{Requeue: true}, err
		}
	} else {
		repo = sourcev1.GitRepositoryProgressing(repo)
		if err := r.Status().Update(ctx, &repo); err != nil {
			log.Error(err, "unable to update GitRepository status")
			return ctrl.Result{Requeue: true}, err
		}
	}

	// try to remove old artifacts
	if err := r.gc(repo); err != nil {
		log.Error(err, "artifacts GC failed")
	}

	// try git sync
	syncedRepo, err := r.sync(ctx, *repo.DeepCopy())
	if err != nil {
		log.Error(err, "Git repository sync failed")
		if err := r.Status().Update(ctx, &syncedRepo); err != nil {
			log.Error(err, "unable to update GitRepository status")
		}
		return ctrl.Result{Requeue: true}, err
	}

	// update status
	if err := r.Status().Update(ctx, &syncedRepo); err != nil {
		log.Error(err, "unable to update GitRepository status")
		return ctrl.Result{Requeue: true}, err
	}

	log.Info("Git repository sync succeeded", "msg", sourcev1.GitRepositoryReadyMessage(syncedRepo))

	// requeue repository
	return ctrl.Result{RequeueAfter: repo.GetInterval().Duration}, nil
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
		WithEventFilter(SourceChangePredicate{}).
		WithEventFilter(GarbageCollectPredicate{Scheme: r.Scheme, Log: r.Log, Storage: r.Storage}).
		WithOptions(controller.Options{MaxConcurrentReconciles: opts.MaxConcurrentReconciles}).
		Complete(r)
}

func (r *GitRepositoryReconciler) sync(ctx context.Context, repository sourcev1.GitRepository) (sourcev1.GitRepository, error) {
	// create tmp dir for the Git clone
	tmpGit, err := ioutil.TempDir("", repository.Name)
	if err != nil {
		err = fmt.Errorf("tmp dir error: %w", err)
		return sourcev1.GitRepositoryNotReady(repository, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	defer os.RemoveAll(tmpGit)

	// determine auth method
	var auth transport.AuthMethod
	authStrategy := intgit.AuthSecretStrategyForURL(repository.Spec.URL)
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

	checkoutStrategy := intgit.CheckoutStrategyForRef(repository.Spec.Reference)
	commit, revision, err := checkoutStrategy.Checkout(ctx, tmpGit, repository.Spec.URL, auth)
	if err != nil {
		return sourcev1.GitRepositoryNotReady(repository, sourcev1.GitOperationFailedReason, err.Error()), err
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

	artifact := r.Storage.ArtifactFor(repository.Kind, repository.ObjectMeta.GetObjectMeta(),
		fmt.Sprintf("%s.tar.gz", commit.Hash.String()), revision)

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
	err = r.Storage.Archive(artifact, tmpGit)
	if err != nil {
		err = fmt.Errorf("storage archive error: %w", err)
		return sourcev1.GitRepositoryNotReady(repository, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// update latest symlink
	url, err := r.Storage.Symlink(artifact, "latest.tar.gz")
	if err != nil {
		err = fmt.Errorf("storage lock error: %w", err)
		return sourcev1.GitRepositoryNotReady(repository, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	message := fmt.Sprintf("Fetched revision: %s", artifact.Revision)
	return sourcev1.GitRepositoryReady(repository, artifact, url, sourcev1.GitOperationSucceedReason, message), nil
}

// shouldResetStatus returns a boolean indicating if the status of the
// given repository should be reset and a reset HelmChartStatus.
func (r *GitRepositoryReconciler) shouldResetStatus(repository sourcev1.GitRepository) (bool, sourcev1.GitRepositoryStatus) {
	resetStatus := false
	if repository.Status.Artifact != nil {
		if !r.Storage.ArtifactExist(*repository.Status.Artifact) {
			resetStatus = true
		}
	}

	if len(repository.Status.Conditions) == 0 || resetStatus {
		resetStatus = true
	}

	return resetStatus, sourcev1.GitRepositoryStatus{
		Conditions: []sourcev1.SourceCondition{
			{
				Type:               sourcev1.ReadyCondition,
				Status:             corev1.ConditionUnknown,
				Reason:             sourcev1.InitializingReason,
				LastTransitionTime: metav1.Now(),
			},
		},
	}
}

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

// gc performs a garbage collection on all but current artifacts of
// the given repository.
func (r *GitRepositoryReconciler) gc(repository sourcev1.GitRepository) error {
	if repository.Status.Artifact != nil {
		return r.Storage.RemoveAllButCurrent(*repository.Status.Artifact)
	}
	return nil
}
