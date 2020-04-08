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
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/blang/semver"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	sourcev1 "github.com/fluxcd/source-controller/api/v1alpha1"
)

// GitRepositoryReconciler reconciles a GitRepository object
type GitRepositoryReconciler struct {
	client.Client
	Log         logr.Logger
	Scheme      *runtime.Scheme
	StoragePath string
}

// +kubebuilder:rbac:groups=source.fluxcd.io,resources=gitrepositories,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=source.fluxcd.io,resources=gitrepositories/status,verbs=get;update;patch

func (r *GitRepositoryReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	log := r.Log.WithValues("gitrepository", req.NamespacedName)

	var repo sourcev1.GitRepository
	if err := r.Get(ctx, req.NamespacedName, &repo); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	result := ctrl.Result{RequeueAfter: repo.Spec.Interval.Duration}

	// set initial status
	if r.shouldResetStatus(repo) {
		log.Info("Initialising repository")
		repo.Status.Artifacts = ""
		repo.Status.LastUpdateTime = nil
		repo.Status.Conditions = []sourcev1.RepositoryCondition{
			{
				Type:   sourcev1.RepositoryConditionReady,
				Status: corev1.ConditionUnknown,
			},
		}
		if err := r.Status().Update(ctx, &repo); err != nil {
			log.Error(err, "unable to update GitRepository status")
			return result, err
		}
	}

	// try git clone
	readyCondition, artifacts, err := r.sync(repo)
	if err != nil {
		log.Info("Repository sync failed", "error", err.Error())
	} else {
		// update artifacts if commit hash changed
		if repo.Status.Artifacts != artifacts {
			timeNew := metav1.Now()
			repo.Status.LastUpdateTime = &timeNew
			repo.Status.Artifacts = artifacts
		}
		log.Info("Repository sync succeeded", "msg", readyCondition.Message)
	}

	// update status
	timeNew := metav1.Now()
	readyCondition.LastTransitionTime = &timeNew
	repo.Status.Conditions = []sourcev1.RepositoryCondition{readyCondition}

	if err := r.Status().Update(ctx, &repo); err != nil {
		log.Error(err, "unable to update GitRepository status")
		return result, err
	}

	// requeue repository
	return result, nil
}

func (r *GitRepositoryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sourcev1.GitRepository{}).
		WithEventFilter(RepositoryChangePredicate{}).
		WithEventFilter(predicate.Funcs{
			DeleteFunc: func(e event.DeleteEvent) bool {
				// delete artifacts
				repoDir := filepath.Join(r.StoragePath,
					fmt.Sprintf("repositories/%s-%s", e.Meta.GetName(), e.Meta.GetNamespace()))
				if err := os.RemoveAll(repoDir); err != nil {
					r.Log.Error(err, "unable to delete artifacts",
						"gitrepository", fmt.Sprintf("%s/%s", e.Meta.GetNamespace(), e.Meta.GetName()))
				} else {
					r.Log.Info("Repository artifacts deleted",
						"gitrepository", fmt.Sprintf("%s/%s", e.Meta.GetNamespace(), e.Meta.GetName()))
				}
				return false
			},
		}).
		Complete(r)
}

func (r *GitRepositoryReconciler) sync(gr sourcev1.GitRepository) (sourcev1.RepositoryCondition, string, error) {
	// determine ref
	refName := plumbing.NewBranchReferenceName("master")
	if gr.Spec.Branch != "" {
		refName = plumbing.NewBranchReferenceName(gr.Spec.Branch)
	}
	if gr.Spec.Tag != "" {
		refName = plumbing.NewTagReferenceName(gr.Spec.Tag)
	}

	// create tmp dir
	dir, err := ioutil.TempDir("", gr.Name)
	if err != nil {
		ex := fmt.Errorf("tmp dir error %w", err)
		return sourcev1.RepositoryCondition{
			Type:    sourcev1.RepositoryConditionReady,
			Status:  corev1.ConditionFalse,
			Reason:  "ExecFailed",
			Message: ex.Error(),
		}, "", ex
	}
	defer os.RemoveAll(dir)

	// clone to tmp
	repo, err := git.PlainClone(dir, false, &git.CloneOptions{
		URL:           gr.Spec.Url,
		Depth:         2,
		ReferenceName: refName,
		SingleBranch:  true,
		Tags:          git.AllTags,
	})
	if err != nil {
		ex := fmt.Errorf("git clone error %w", err)
		return sourcev1.RepositoryCondition{
			Type:    sourcev1.RepositoryConditionReady,
			Status:  corev1.ConditionFalse,
			Reason:  "GitCloneFailed",
			Message: ex.Error(),
		}, "", ex
	}

	// checkout tag based on semver expression
	if gr.Spec.SemVer != "" {
		rng, err := semver.ParseRange(gr.Spec.SemVer)
		if err != nil {
			ex := fmt.Errorf("semver parse range error %w", err)
			return sourcev1.RepositoryCondition{
				Type:    sourcev1.RepositoryConditionReady,
				Status:  corev1.ConditionFalse,
				Reason:  "GitCloneFailed",
				Message: ex.Error(),
			}, "", ex
		}

		repoTags, err := repo.Tags()
		if err != nil {
			ex := fmt.Errorf("git list tags error %w", err)
			return sourcev1.RepositoryCondition{
				Type:    sourcev1.RepositoryConditionReady,
				Status:  corev1.ConditionFalse,
				Reason:  "GitCloneFailed",
				Message: ex.Error(),
			}, "", ex
		}

		tags := make(map[string]string)
		_ = repoTags.ForEach(func(t *plumbing.Reference) error {
			tags[t.Name().Short()] = t.Strings()[1]
			return nil
		})

		svTags := make(map[string]string)
		svers := []semver.Version{}
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

			w, err := repo.Worktree()
			if err != nil {
				ex := fmt.Errorf("git worktree error %w", err)
				return sourcev1.RepositoryCondition{
					Type:    sourcev1.RepositoryConditionReady,
					Status:  corev1.ConditionFalse,
					Reason:  "GitCheckoutFailed",
					Message: ex.Error(),
				}, "", ex
			}

			err = w.Checkout(&git.CheckoutOptions{
				Hash: plumbing.NewHash(commit),
			})
			if err != nil {
				ex := fmt.Errorf("git checkout error %w", err)
				return sourcev1.RepositoryCondition{
					Type:    sourcev1.RepositoryConditionReady,
					Status:  corev1.ConditionFalse,
					Reason:  "GitCheckoutFailed",
					Message: ex.Error(),
				}, "", ex
			}
		} else {
			ex := fmt.Errorf("no match found for semver %s", gr.Spec.SemVer)
			return sourcev1.RepositoryCondition{
				Type:    sourcev1.RepositoryConditionReady,
				Status:  corev1.ConditionFalse,
				Reason:  "GitCheckoutFailed",
				Message: ex.Error(),
			}, "", ex
		}
	}

	// read commit hash
	ref, err := repo.Head()
	if err != nil {
		ex := fmt.Errorf("git resolve HEAD error %w", err)
		return sourcev1.RepositoryCondition{
			Type:    sourcev1.RepositoryConditionReady,
			Status:  corev1.ConditionFalse,
			Reason:  "GitHeadFailed",
			Message: ex.Error(),
		}, "", ex
	}

	// create artifacts dir
	repoDir := fmt.Sprintf("repositories/%s-%s", gr.Name, gr.Namespace)
	storage := filepath.Join(r.StoragePath, repoDir)
	err = os.MkdirAll(storage, 0777)
	if err != nil {
		ex := fmt.Errorf("mkdir dir error %w", err)
		return sourcev1.RepositoryCondition{
			Type:    sourcev1.RepositoryConditionReady,
			Status:  corev1.ConditionFalse,
			Reason:  "ExecFailed",
			Message: ex.Error(),
		}, "", ex
	}

	// store artifacts
	artifacts := filepath.Join(storage, fmt.Sprintf("%s.tar.gz", ref.Hash().String()))
	excludes := "--exclude=\\*.{jpg,jpeg,gif,png,wmv,flv,tar.gz,zip} --exclude .git"
	command := exec.Command("/bin/sh", "-c",
		fmt.Sprintf("cd %s && tar -c %s -f - . | gzip > %s", dir, excludes, artifacts))
	err = command.Run()
	if err != nil {
		ex := fmt.Errorf("tar %s error %w", artifacts, err)
		return sourcev1.RepositoryCondition{
			Type:    sourcev1.RepositoryConditionReady,
			Status:  corev1.ConditionFalse,
			Reason:  "ExecFailed",
			Message: ex.Error(),
		}, "", ex
	}

	// compose artifacts URL
	hostname := "localhost"
	if os.Getenv("RUNTIME_NAMESPACE") != "" {
		svcParts := strings.Split(os.Getenv("HOSTNAME"), "-")
		hostname = fmt.Sprintf("%s.%s",
			strings.Join(svcParts[:len(svcParts)-2], "-"), os.Getenv("RUNTIME_NAMESPACE"))
	}
	artifactsURL := fmt.Sprintf("http://%s/repositories/%s-%s/%s.tar.gz",
		hostname, gr.Name, gr.Namespace, ref.Hash().String())

	return sourcev1.RepositoryCondition{
		Type:    sourcev1.RepositoryConditionReady,
		Status:  corev1.ConditionTrue,
		Reason:  "GitCloneSucceed",
		Message: fmt.Sprintf("Fetched artifacts are available at %s", artifacts),
	}, artifactsURL, nil
}

func (r *GitRepositoryReconciler) shouldResetStatus(gr sourcev1.GitRepository) bool {
	resetStatus := false
	if gr.Status.Artifacts != "" {
		pathParts := strings.Split(gr.Status.Artifacts, "/")
		path := fmt.Sprintf("repositories/%s-%s/%s", gr.Name, gr.Namespace, pathParts[len(pathParts)-1])
		if _, err := os.Stat(filepath.Join(r.StoragePath, path)); err != nil {
			resetStatus = true
		}
	}

	// set initial status
	if len(gr.Status.Conditions) == 0 || resetStatus {
		resetStatus = true
	}

	return resetStatus
}
