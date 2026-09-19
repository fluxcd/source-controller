/*
Copyright 2026 The Flux authors

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

package controller

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	sourcev1 "github.com/fluxcd/source-controller/api/v1"
)

const indexKeyGitRepositoryInclude = ".metadata.gitRepositoryInclude"

// indexGitRepositoryIncludes indexes local references, independent of artifact availability.
func indexGitRepositoryIncludes(o client.Object) []string {
	repo, ok := o.(*sourcev1.GitRepository)
	if !ok {
		return nil
	}
	refs := sets.New[string]()
	for _, incl := range repo.Spec.Include {
		refs.Insert(incl.GitRepositoryRef.Name)
	}
	return sets.List(refs)
}

// requestsForIncludeChange enqueues repositories including the changed artifact.
func (r *GitRepositoryReconciler) requestsForIncludeChange(ctx context.Context, o client.Object) []reconcile.Request {
	repo, ok := o.(*sourcev1.GitRepository)
	if !ok || repo.GetArtifact() == nil {
		return nil
	}
	var list sourcev1.GitRepositoryList
	if err := r.List(ctx, &list, client.InNamespace(repo.Namespace), client.MatchingFields{
		indexKeyGitRepositoryInclude: repo.Name,
	}); err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "failed to list GitRepositories for include change")
		return nil
	}
	if len(list.Items) == 0 {
		return nil
	}

	// Do not turn an existing include cycle into an event-driven rebuild loop.
	// Each repository is visited at most once, through the manager's scoped cache.
	ancestors, err := r.includeDependencies(ctx, repo)
	if err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "failed to check GitRepository include dependencies")
		return nil
	}
	var requests []reconcile.Request
	for i := range list.Items {
		dependent := &list.Items[i]
		if dependent.Spec.Suspend || !dependent.DeletionTimestamp.IsZero() || ancestors.Has(dependent.Name) {
			continue
		}
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(dependent)})
	}
	return requests
}

// includeDependencies returns transitive includes and the repository itself.
// Cyclic edges remain interval-driven, as they were before include watches.
func (r *GitRepositoryReconciler) includeDependencies(ctx context.Context, repo *sourcev1.GitRepository) (sets.Set[string], error) {
	seen := sets.New(repo.Name)
	pending := append([]sourcev1.GitRepositoryInclude(nil), repo.Spec.Include...)
	for len(pending) > 0 {
		name := pending[0].GitRepositoryRef.Name
		pending = pending[1:]
		if seen.Has(name) {
			continue
		}
		seen.Insert(name)
		var dep sourcev1.GitRepository
		if err := r.Get(ctx, client.ObjectKey{Namespace: repo.Namespace, Name: name}, &dep); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return nil, err
		}
		pending = append(pending, dep.Spec.Include...)
	}
	return seen, nil
}
