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
	"time"

	"github.com/blang/semver"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

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
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

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
	}

	// try to remove old artifacts
	if err := r.gc(repo); err != nil {
		log.Error(err, "artifacts GC failed")
	}

	// try git sync
	syncedRepo, err := r.sync(ctx, *repo.DeepCopy())
	if err != nil {
		log.Error(err, "Git repository sync failed")
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

func (r *GitRepositoryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sourcev1.GitRepository{}).
		WithEventFilter(SourceChangePredicate{}).
		WithEventFilter(GarbageCollectPredicate{Scheme: r.Scheme, Log: r.Log, Storage: r.Storage}).
		Complete(r)
}

func (r *GitRepositoryReconciler) sync(ctx context.Context, repository sourcev1.GitRepository) (sourcev1.GitRepository, error) {
	// set defaults: master branch, no tags fetching, max two commits
	branch := "master"
	revision := ""
	tagMode := git.NoTags
	depth := 2

	// determine ref
	refName := plumbing.NewBranchReferenceName(branch)
	if repository.Spec.Reference != nil {
		if repository.Spec.Reference.Branch != "" {
			branch = repository.Spec.Reference.Branch
			refName = plumbing.NewBranchReferenceName(branch)
		}
		if repository.Spec.Reference.Commit != "" {
			depth = 0
		} else {
			if repository.Spec.Reference.Tag != "" {
				refName = plumbing.NewTagReferenceName(repository.Spec.Reference.Tag)
			}
			if repository.Spec.Reference.SemVer != "" {
				tagMode = git.AllTags
			}
		}
	}

	// determine auth method
	var auth transport.AuthMethod
	if repository.Spec.SecretRef != nil {
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

		method, cleanup, err := intgit.AuthMethodFromSecret(repository.Spec.URL, secret)
		if err != nil {
			err = fmt.Errorf("auth error: %w", err)
			return sourcev1.GitRepositoryNotReady(repository, sourcev1.AuthenticationFailedReason, err.Error()), err
		}
		if cleanup != nil {
			defer cleanup()
		}
		auth = method
	}

	// create tmp dir for the Git clone
	tmpGit, err := ioutil.TempDir("", repository.Name)
	if err != nil {
		err = fmt.Errorf("tmp dir error: %w", err)
		return sourcev1.GitRepositoryNotReady(repository, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	defer os.RemoveAll(tmpGit)

	// clone to tmp
	repo, err := git.PlainClone(tmpGit, false, &git.CloneOptions{
		URL:               repository.Spec.URL,
		Auth:              auth,
		RemoteName:        "origin",
		ReferenceName:     refName,
		SingleBranch:      true,
		NoCheckout:        false,
		Depth:             depth,
		RecurseSubmodules: 0,
		Progress:          nil,
		Tags:              tagMode,
	})
	if err != nil {
		err = fmt.Errorf("git clone error: %w", err)
		return sourcev1.GitRepositoryNotReady(repository, sourcev1.GitOperationFailedReason, err.Error()), err
	}

	// checkout commit or tag
	if repository.Spec.Reference != nil {
		if commit := repository.Spec.Reference.Commit; commit != "" {
			w, err := repo.Worktree()
			if err != nil {
				err = fmt.Errorf("git worktree error: %w", err)
				return sourcev1.GitRepositoryNotReady(repository, sourcev1.GitOperationFailedReason, err.Error()), err
			}

			err = w.Checkout(&git.CheckoutOptions{
				Hash:  plumbing.NewHash(commit),
				Force: true,
			})
			if err != nil {
				err = fmt.Errorf("git checkout '%s' for '%s' error: %w", commit, branch, err)
				return sourcev1.GitRepositoryNotReady(repository, sourcev1.GitOperationFailedReason, err.Error()), err
			}
		} else if exp := repository.Spec.Reference.SemVer; exp != "" {
			rng, err := semver.ParseRange(exp)
			if err != nil {
				err = fmt.Errorf("semver parse range error: %w", err)
				return sourcev1.GitRepositoryNotReady(repository, sourcev1.GitOperationFailedReason, err.Error()), err
			}

			repoTags, err := repo.Tags()
			if err != nil {
				err = fmt.Errorf("git list tags error: %w", err)
				return sourcev1.GitRepositoryNotReady(repository, sourcev1.GitOperationFailedReason, err.Error()), err
			}

			tags := make(map[string]string)
			_ = repoTags.ForEach(func(t *plumbing.Reference) error {
				tags[t.Name().Short()] = t.Strings()[1]
				return nil
			})

			svTags := make(map[string]string)
			var svers []semver.Version
			for tag, _ := range tags {
				v, _ := semver.ParseTolerant(tag)
				if rng(v) {
					svers = append(svers, v)
					svTags[v.String()] = tag
				}
			}

			if len(svers) > 0 {
				semver.Sort(svers)
				v := svers[len(svers)-1]
				t := svTags[v.String()]
				commit := tags[t]
				revision = fmt.Sprintf("%s/%s", t, commit)

				w, err := repo.Worktree()
				if err != nil {
					err = fmt.Errorf("git worktree error: %w", err)
					return sourcev1.GitRepositoryNotReady(repository, sourcev1.GitOperationFailedReason, err.Error()), err
				}

				err = w.Checkout(&git.CheckoutOptions{
					Hash: plumbing.NewHash(commit),
				})
				if err != nil {
					err = fmt.Errorf("git checkout error: %w", err)
					return sourcev1.GitRepositoryNotReady(repository, sourcev1.GitOperationFailedReason, err.Error()), err
				}
			} else {
				err = fmt.Errorf("no match found for semver: %s", repository.Spec.Reference.SemVer)
				return sourcev1.GitRepositoryNotReady(repository, sourcev1.GitOperationFailedReason, err.Error()), err
			}
		}
	}

	// read commit hash
	ref, err := repo.Head()
	if err != nil {
		err = fmt.Errorf("git resolve HEAD error: %w", err)
		return sourcev1.GitRepositoryNotReady(repository, sourcev1.GitOperationFailedReason, err.Error()), err
	}

	// verify PGP signature
	if repository.Spec.Verification != nil {
		commit, err := repo.CommitObject(ref.Hash())
		if err != nil {
			err = fmt.Errorf("git resolve HEAD error: %w", err)
			return sourcev1.GitRepositoryNotReady(repository, sourcev1.GitOperationFailedReason, err.Error()), err
		}

		if commit.PGPSignature == "" {
			err = fmt.Errorf("PGP signature not found for commit '%s'", ref.Hash())
			return sourcev1.GitRepositoryNotReady(repository, sourcev1.VerificationFailedReason, err.Error()), err
		}

		name := types.NamespacedName{
			Namespace: repository.GetNamespace(),
			Name:      repository.Spec.Verification.SecretRef.Name,
		}

		var secret corev1.Secret
		err = r.Client.Get(ctx, name, &secret)
		if err != nil {
			err = fmt.Errorf("PGP public keys secret error: %w", err)
			return sourcev1.GitRepositoryNotReady(repository, sourcev1.VerificationFailedReason, err.Error()), err
		}

		var verified bool
		for _, bytes := range secret.Data {
			if _, err := commit.Verify(string(bytes)); err == nil {
				verified = true
				break
			}
		}

		if !verified {
			err = fmt.Errorf("PGP signature of '%s' can't be verified", commit.Author)
			return sourcev1.GitRepositoryNotReady(repository, sourcev1.VerificationFailedReason, err.Error()), err
		}
	}

	if revision == "" {
		revision = fmt.Sprintf("%s/%s", branch, ref.Hash().String())
	}

	artifact := r.Storage.ArtifactFor(repository.Kind, repository.ObjectMeta.GetObjectMeta(),
		fmt.Sprintf("%s.tar.gz", ref.Hash().String()), revision)

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

	// archive artifact
	err = r.Storage.Archive(artifact, tmpGit, "")
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

	message := fmt.Sprintf("Git repoistory artifacts are available at: %s", artifact.Path)
	return sourcev1.GitRepositoryReady(repository, artifact, url, sourcev1.GitOperationSucceedReason, message), nil
}

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

func (r *GitRepositoryReconciler) gc(repository sourcev1.GitRepository) error {
	if repository.Status.Artifact != nil {
		return r.Storage.RemoveAllButCurrent(*repository.Status.Artifact)
	}
	return nil
}
