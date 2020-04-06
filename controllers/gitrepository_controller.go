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
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	sourcerv1 "github.com/fluxcd/sourcer/api/v1alpha1"
)

// GitRepositoryReconciler reconciles a GitRepository object
type GitRepositoryReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=sourcer.fluxcd.io,resources=gitrepositories,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=sourcer.fluxcd.io,resources=gitrepositories/status,verbs=get;update;patch

func (r *GitRepositoryReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	log := r.Log.WithValues("gitrepository", req.NamespacedName)

	var repo sourcerv1.GitRepository
	if err := r.Get(ctx, req.NamespacedName, &repo); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	result := ctrl.Result{RequeueAfter: repo.Spec.Interval.Duration}

	// set initial status
	if len(repo.Status.Conditions) == 0 {
		repo.Status.Conditions = []sourcerv1.RepositoryCondition{
			{
				Type:   sourcerv1.RepositoryConditionReady,
				Status: corev1.ConditionUnknown,
			},
		}
		if err := r.Status().Update(ctx, &repo); err != nil {
			log.Error(err, "unable to update GitRepository status")
			return result, err
		}
	}

	// try git clone
	readyCondition, err := r.sync(repo.Spec)
	if err != nil {
		log.Info("Repository sync failed", "error", err.Error())
	} else {
		log.Info("Repository sync succeeded", "msg", readyCondition.Message)
	}

	// update status
	timeNew := metav1.Now()
	readyCondition.LastTransitionTime = &timeNew
	repo.Status.Conditions = []sourcerv1.RepositoryCondition{readyCondition}

	if err := r.Status().Update(ctx, &repo); err != nil {
		log.Error(err, "unable to update GitRepository status")
		return result, err
	}

	// requeue repository
	return result, nil
}

func (r *GitRepositoryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sourcerv1.GitRepository{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}

func (r *GitRepositoryReconciler) sync(spec sourcerv1.GitRepositorySpec) (sourcerv1.RepositoryCondition, error) {
	// determine ref
	refName := plumbing.NewBranchReferenceName("master")
	if spec.Branch != "" {
		refName = plumbing.NewBranchReferenceName(spec.Branch)
	}
	if spec.Tag != "" {
		refName = plumbing.NewTagReferenceName(spec.Tag)
	}

	// clone
	repo, err := git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
		URL:           spec.Url,
		Depth:         2,
		ReferenceName: refName,
	})
	if err != nil {
		ex := fmt.Errorf("git clone error %w", err)
		return sourcerv1.RepositoryCondition{
			Type:    sourcerv1.RepositoryConditionReady,
			Status:  corev1.ConditionFalse,
			Reason:  "GitCloneFailed",
			Message: ex.Error(),
		}, ex
	}

	// read commit hash
	ref, err := repo.Head()
	if err != nil {
		ex := fmt.Errorf("git resolve HEAD error %w", err)
		return sourcerv1.RepositoryCondition{
			Type:    sourcerv1.RepositoryConditionReady,
			Status:  corev1.ConditionFalse,
			Reason:  "GitCommandFailed",
			Message: ex.Error(),
		}, ex
	}

	return sourcerv1.RepositoryCondition{
		Type:    sourcerv1.RepositoryConditionReady,
		Status:  corev1.ConditionTrue,
		Reason:  "GitCloneSucceed",
		Message: fmt.Sprintf("commit hash %s", ref.Hash().String()),
	}, nil
}
