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

	"github.com/go-logr/logr"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/repo"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kuberecorder "k8s.io/client-go/tools/record"
	"k8s.io/client-go/tools/reference"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/yaml"

	"github.com/fluxcd/pkg/recorder"
	sourcev1 "github.com/fluxcd/source-controller/api/v1alpha1"
	"github.com/fluxcd/source-controller/internal/helm"
)

// HelmRepositoryReconciler reconciles a HelmRepository object
type HelmRepositoryReconciler struct {
	client.Client
	Log                   logr.Logger
	Scheme                *runtime.Scheme
	Storage               *Storage
	Getters               getter.Providers
	EventRecorder         kuberecorder.EventRecorder
	ExternalEventRecorder *recorder.EventRecorder
}

// +kubebuilder:rbac:groups=source.fluxcd.io,resources=helmrepositories,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=source.fluxcd.io,resources=helmrepositories/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=source.fluxcd.io,resources=helmcharts/finalizers,verbs=get;update;patch

func (r *HelmRepositoryReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()

	var repository sourcev1.HelmRepository
	if err := r.Get(ctx, req.NamespacedName, &repository); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log := r.Log.WithValues(repository.Kind, req.NamespacedName)

	// set initial status
	if reset, status := r.shouldResetStatus(repository); reset {
		log.Info("Initializing Helm repository")
		repository.Status = status
		if err := r.Status().Update(ctx, &repository); err != nil {
			log.Error(err, "unable to update HelmRepository status")
			return ctrl.Result{Requeue: true}, err
		}
	} else {
		repository = sourcev1.HelmRepositoryProgressing(repository)
		if err := r.Status().Update(ctx, &repository); err != nil {
			log.Error(err, "unable to update HelmRepository status")
			return ctrl.Result{Requeue: true}, err
		}
	}

	// try to remove old artifacts
	if err := r.gc(repository); err != nil {
		log.Error(err, "artifacts GC failed")
	}

	// try to download index
	syncedRepo, err := r.sync(ctx, *repository.DeepCopy())
	if err != nil {
		log.Error(err, "Helm repository sync failed")
		r.event(repository, recorder.EventSeverityError, err.Error())
		if err := r.Status().Update(ctx, &syncedRepo); err != nil {
			log.Error(err, "unable to update HelmRepository status")
		}
		return ctrl.Result{Requeue: true}, err
	} else {
		// emit revision change event
		if repository.Status.Artifact == nil || syncedRepo.Status.Artifact.Revision != repository.Status.Artifact.Revision {
			r.event(syncedRepo, recorder.EventSeverityInfo, sourcev1.HelmRepositoryReadyMessage(syncedRepo))
		}
	}

	// update status
	if err := r.Status().Update(ctx, &syncedRepo); err != nil {
		log.Error(err, "unable to update HelmRepository status")
		return ctrl.Result{Requeue: true}, err
	}
	log.Info("Helm repository sync succeeded", "msg", sourcev1.HelmRepositoryReadyMessage(syncedRepo))

	// requeue repository
	return ctrl.Result{RequeueAfter: repository.GetInterval().Duration}, nil
}

type HelmRepositoryReconcilerOptions struct {
	MaxConcurrentReconciles int
}

func (r *HelmRepositoryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return r.SetupWithManagerAndOptions(mgr, HelmRepositoryReconcilerOptions{})
}

func (r *HelmRepositoryReconciler) SetupWithManagerAndOptions(mgr ctrl.Manager, opts HelmRepositoryReconcilerOptions) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sourcev1.HelmRepository{}).
		WithEventFilter(SourceChangePredicate{}).
		WithEventFilter(GarbageCollectPredicate{Scheme: r.Scheme, Log: r.Log, Storage: r.Storage}).
		WithOptions(controller.Options{MaxConcurrentReconciles: opts.MaxConcurrentReconciles}).
		Complete(r)
}

func (r *HelmRepositoryReconciler) sync(ctx context.Context, repository sourcev1.HelmRepository) (sourcev1.HelmRepository, error) {
	u, err := url.Parse(repository.Spec.URL)
	if err != nil {
		return sourcev1.HelmRepositoryNotReady(repository, sourcev1.URLInvalidReason, err.Error()), err
	}

	c, err := r.Getters.ByScheme(u.Scheme)
	if err != nil {
		return sourcev1.HelmRepositoryNotReady(repository, sourcev1.URLInvalidReason, err.Error()), err
	}

	u.RawPath = path.Join(u.RawPath, "index.yaml")
	u.Path = path.Join(u.Path, "index.yaml")

	var clientOpts []getter.Option
	if repository.Spec.SecretRef != nil {
		name := types.NamespacedName{
			Namespace: repository.GetNamespace(),
			Name:      repository.Spec.SecretRef.Name,
		}

		var secret corev1.Secret
		err := r.Client.Get(ctx, name, &secret)
		if err != nil {
			err = fmt.Errorf("auth secret error: %w", err)
			return sourcev1.HelmRepositoryNotReady(repository, sourcev1.AuthenticationFailedReason, err.Error()), err
		}

		opts, cleanup, err := helm.ClientOptionsFromSecret(secret)
		if err != nil {
			err = fmt.Errorf("auth options error: %w", err)
			return sourcev1.HelmRepositoryNotReady(repository, sourcev1.AuthenticationFailedReason, err.Error()), err
		}
		if cleanup != nil {
			defer cleanup()
		}
		clientOpts = opts
	}

	// TODO(hidde): implement timeout from the HelmRepository
	//  https://github.com/helm/helm/pull/7950
	res, err := c.Get(u.String(), clientOpts...)
	if err != nil {
		return sourcev1.HelmRepositoryNotReady(repository, sourcev1.IndexationFailedReason, err.Error()), err
	}

	data, err := ioutil.ReadAll(res)
	if err != nil {
		return sourcev1.HelmRepositoryNotReady(repository, sourcev1.IndexationFailedReason, err.Error()), err
	}

	i := &repo.IndexFile{}
	if err := yaml.Unmarshal(data, i); err != nil {
		return sourcev1.HelmRepositoryNotReady(repository, sourcev1.IndexationFailedReason, err.Error()), err
	}
	i.SortEntries()

	index, err := yaml.Marshal(i)
	if err != nil {
		return sourcev1.HelmRepositoryNotReady(repository, sourcev1.IndexationFailedReason, err.Error()), err
	}

	sum := r.Storage.Checksum(index)
	artifact := r.Storage.ArtifactFor(repository.Kind, repository.ObjectMeta.GetObjectMeta(),
		fmt.Sprintf("index-%s.yaml", sum), sum)

	// create artifact dir
	err = r.Storage.MkdirAll(artifact)
	if err != nil {
		err = fmt.Errorf("unable to create repository index directory: %w", err)
		return sourcev1.HelmRepositoryNotReady(repository, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// acquire lock
	unlock, err := r.Storage.Lock(artifact)
	if err != nil {
		err = fmt.Errorf("unable to acquire lock: %w", err)
		return sourcev1.HelmRepositoryNotReady(repository, sourcev1.StorageOperationFailedReason, err.Error()), err
	}
	defer unlock()

	// save artifact to storage
	err = r.Storage.WriteFile(artifact, index)
	if err != nil {
		err = fmt.Errorf("unable to write repository index file: %w", err)
		return sourcev1.HelmRepositoryNotReady(repository, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	// update index symlink
	indexURL, err := r.Storage.Symlink(artifact, "index.yaml")
	if err != nil {
		err = fmt.Errorf("storage error: %w", err)
		return sourcev1.HelmRepositoryNotReady(repository, sourcev1.StorageOperationFailedReason, err.Error()), err
	}

	message := fmt.Sprintf("Fetched revision: %s", artifact.Revision)
	return sourcev1.HelmRepositoryReady(repository, artifact, indexURL, sourcev1.IndexationSucceededReason, message), nil
}

// shouldResetStatus returns a boolean indicating if the status of the
// given repository should be reset and a reset HelmChartStatus.
func (r *HelmRepositoryReconciler) shouldResetStatus(repository sourcev1.HelmRepository) (bool, sourcev1.HelmRepositoryStatus) {
	resetStatus := false
	if repository.Status.Artifact != nil {
		if !r.Storage.ArtifactExist(*repository.Status.Artifact) {
			resetStatus = true
		}
	}

	// set initial status
	if len(repository.Status.Conditions) == 0 {
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

// gc performs a garbage collection on all but current artifacts of
// the given repository.
func (r *HelmRepositoryReconciler) gc(repository sourcev1.HelmRepository) error {
	if repository.Status.Artifact != nil {
		return r.Storage.RemoveAllButCurrent(*repository.Status.Artifact)
	}
	return nil
}

// emit Kubernetes event and forward event to notification controller if configured
func (r *HelmRepositoryReconciler) event(repository sourcev1.HelmRepository, severity, msg string) {
	if r.EventRecorder != nil {
		r.EventRecorder.Eventf(&repository, "Normal", severity, msg)
	}
	if r.ExternalEventRecorder != nil {
		objRef, err := reference.GetReference(r.Scheme, &repository)
		if err != nil {
			r.Log.WithValues(
				strings.ToLower(repository.Kind),
				fmt.Sprintf("%s/%s", repository.GetNamespace(), repository.GetName()),
			).Error(err, "unable to send event")
			return
		}

		if err := r.ExternalEventRecorder.Eventf(*objRef, nil, severity, severity, msg); err != nil {
			r.Log.WithValues(
				strings.ToLower(repository.Kind),
				fmt.Sprintf("%s/%s", repository.GetNamespace(), repository.GetName()),
			).Error(err, "unable to send event")
			return
		}
	}
}
