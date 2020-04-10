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
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"gopkg.in/yaml.v2"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/repo"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	sourcev1 "github.com/fluxcd/source-controller/api/v1alpha1"
)

// HelmRepositoryReconciler reconciles a HelmRepository object
type HelmRepositoryReconciler struct {
	client.Client
	Log     logr.Logger
	Scheme  *runtime.Scheme
	Storage *Storage
	Kind    string
	Getters getter.Providers
}

// +kubebuilder:rbac:groups=source.fluxcd.io,resources=helmrepositories,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=source.fluxcd.io,resources=helmrepositories/status,verbs=get;update;patch

func (r *HelmRepositoryReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	log := r.Log.WithValues("helmrepository", req.NamespacedName)

	var repository sourcev1.HelmRepository
	if err := r.Get(ctx, req.NamespacedName, &repository); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	result := ctrl.Result{RequeueAfter: repository.Spec.Interval.Duration}

	// set initial status
	if reset, status := r.shouldResetStatus(repository); reset {
		log.Info("Initializing repository")
		repository.Status = status
		if err := r.Status().Update(ctx, &repository); err != nil {
			log.Error(err, "unable to update HelmRepository status")
			return result, err
		}
	}

	// try to remove old artifacts
	r.gc(repository)

	// try to download index
	readyCondition, artifact, err := r.index(repository)
	if err != nil {
		log.Info("Helm repository index failed", "error", err.Error())
	} else {
		// update artifact if path changed
		if repository.Status.Artifact != artifact {
			timeNew := metav1.Now()
			repository.Status.LastUpdateTime = &timeNew
			repository.Status.Artifact = artifact
		}
		log.Info("Helm repository index succeeded", "msg", readyCondition.Message)
	}

	// update status
	readyCondition.LastTransitionTime = metav1.Now()
	repository.Status.Conditions = []sourcev1.SourceCondition{readyCondition}

	if err := r.Status().Update(ctx, &repository); err != nil {
		log.Error(err, "unable to update HelmRepository status")
		return result, err
	}

	// requeue repository
	return result, nil
}

func (r *HelmRepositoryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sourcev1.HelmRepository{}).
		WithEventFilter(RepositoryChangePredicate{}).
		WithEventFilter(predicate.Funcs{
			DeleteFunc: func(e event.DeleteEvent) bool {
				// delete artifacts
				artifact := r.Storage.ArtifactFor(r.Kind, e.Meta, "dummy")
				if err := r.Storage.RemoveAll(artifact); err != nil {
					r.Log.Error(err, "unable to delete artifacts",
						r.Kind, fmt.Sprintf("%s/%s", e.Meta.GetNamespace(), e.Meta.GetName()))
				} else {
					r.Log.Info("Repository artifacts deleted",
						r.Kind, fmt.Sprintf("%s/%s", e.Meta.GetNamespace(), e.Meta.GetName()))
				}
				return false
			},
		}).
		Complete(r)
}

func (r *HelmRepositoryReconciler) index(repository sourcev1.HelmRepository) (sourcev1.SourceCondition, string, error) {
	u, err := url.Parse(repository.Spec.URL)
	if err != nil {
		return sourcev1.SourceCondition{
			Type:    sourcev1.ReadyCondition,
			Status:  corev1.ConditionFalse,
			Reason:  sourcev1.InvalidHelmRepositoryURLReason,
			Message: err.Error(),
		}, "", err
	}

	c, err := r.Getters.ByScheme(u.Scheme)
	if err != nil {
		return sourcev1.SourceCondition{
			Type:    sourcev1.ReadyCondition,
			Status:  corev1.ConditionFalse,
			Reason:  sourcev1.InvalidHelmRepositoryURLReason,
			Message: err.Error(),
		}, "", err
	}

	u.RawPath = path.Join(u.RawPath, "index.yaml")
	u.Path = path.Join(u.Path, "index.yaml")

	indexURL := u.String()
	// TODO(hidde): add authentication config
	res, err := c.Get(indexURL, getter.WithURL(repository.Spec.URL))
	if err != nil {
		return sourcev1.SourceCondition{
			Type:    sourcev1.ReadyCondition,
			Status:  corev1.ConditionFalse,
			Reason:  sourcev1.IndexFetchFailedReason,
			Message: err.Error(),
		}, "", err
	}

	data, err := ioutil.ReadAll(res)
	if err != nil {
		return sourcev1.SourceCondition{
			Type:    sourcev1.ReadyCondition,
			Status:  corev1.ConditionFalse,
			Reason:  sourcev1.IndexFetchFailedReason,
			Message: err.Error(),
		}, "", err
	}

	i := &repo.IndexFile{}
	if err := yaml.Unmarshal(data, i); err != nil {
		return sourcev1.SourceCondition{
			Type:    sourcev1.ReadyCondition,
			Status:  corev1.ConditionFalse,
			Reason:  sourcev1.IndexFetchFailedReason,
			Message: err.Error(),
		}, "", err
	}

	index, err := yaml.Marshal(i)
	if err != nil {
		return sourcev1.SourceCondition{
			Type:    sourcev1.ReadyCondition,
			Status:  corev1.ConditionFalse,
			Reason:  sourcev1.IndexFetchFailedReason,
			Message: err.Error(),
		}, "", err
	}

	sum := r.Storage.Checksum(index)
	artifact := r.Storage.ArtifactFor(r.Kind, repository.ObjectMeta.GetObjectMeta(),
		fmt.Sprintf("index-%s.yaml", sum))

	// create artifact dir
	err = r.Storage.MkdirAll(artifact)
	if err != nil {
		err = fmt.Errorf("unable to create repository index directory: %w", err)
		return sourcev1.SourceCondition{
			Type:    sourcev1.ReadyCondition,
			Status:  corev1.ConditionFalse,
			Reason:  sourcev1.IndexFetchFailedReason,
			Message: err.Error(),
		}, "", err
	}

	// save artifact to storage
	err = r.Storage.WriteFile(artifact, index)
	if err != nil {
		err = fmt.Errorf("unable to write repository index file: %w", err)
		return sourcev1.SourceCondition{
			Type:    sourcev1.ReadyCondition,
			Status:  corev1.ConditionFalse,
			Reason:  sourcev1.IndexFetchFailedReason,
			Message: err.Error(),
		}, "", err
	}

	return sourcev1.SourceCondition{
		Type:    sourcev1.ReadyCondition,
		Status:  corev1.ConditionTrue,
		Reason:  sourcev1.IndexFetchSucceededReason,
		Message: fmt.Sprintf("Artifact is available at %s", artifact.Path),
	}, artifact.URL, nil
}

func (r *HelmRepositoryReconciler) shouldResetStatus(repository sourcev1.HelmRepository) (bool, sourcev1.HelmRepositoryStatus) {
	resetStatus := false
	if repository.Status.Artifact != "" {
		parts := strings.Split(repository.Status.Artifact, "/")
		artifact := r.Storage.ArtifactFor(r.Kind, repository.ObjectMeta.GetObjectMeta(), parts[len(parts)-1])
		if !r.Storage.ArtifactExist(artifact) {
			resetStatus = true
		}
	}

	// set initial status
	if len(repository.Status.Conditions) == 0 || resetStatus {
		resetStatus = true
	}

	return resetStatus, sourcev1.HelmRepositoryStatus{
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

func (r *HelmRepositoryReconciler) gc(repository sourcev1.HelmRepository) {
	if repository.Status.Artifact != "" {
		parts := strings.Split(repository.Status.Artifact, "/")
		artifact := r.Storage.ArtifactFor(r.Kind, repository.ObjectMeta.GetObjectMeta(), parts[len(parts)-1])
		if err := r.Storage.RemoveAllButCurrent(artifact); err != nil {
			r.Log.Info("Artifacts GC failed", "error", err)
		}
	}
}
