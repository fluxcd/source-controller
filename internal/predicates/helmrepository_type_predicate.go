/*
Copyright 2022 The Flux authors

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

package predicates

import (
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
)

// helmRepositoryTypeFilter filters events for a given HelmRepository type.
// It returns true if the event is for a HelmRepository of the given type.
func helmRepositoryTypeFilter(repositoryType string, o client.Object) bool {
	if o == nil {
		return false
	}

	// return true if the object is a HelmRepository
	// and the type is the same as the one we are looking for.
	hr, ok := o.(*sourcev1.HelmRepository)
	if !ok {
		return false
	}

	return hr.Spec.Type == repositoryType
}

// HelmRepositoryTypePredicate is a predicate that filters events for a given HelmRepository type.
type HelmRepositoryTypePredicate struct {
	RepositoryType string
	predicate.Funcs
}

// Create returns true if the Create event is for a HelmRepository of the given type.
func (h HelmRepositoryTypePredicate) Create(e event.CreateEvent) bool {
	return helmRepositoryTypeFilter(h.RepositoryType, e.Object)
}

// Update returns true if the Update event is for a HelmRepository of the given type.
func (h HelmRepositoryTypePredicate) Update(e event.UpdateEvent) bool {
	if e.ObjectOld == nil || e.ObjectNew == nil {
		return false
	}

	// check if the old object is a HelmRepository
	oldObj, ok := e.ObjectOld.(*sourcev1.HelmRepository)
	if !ok {
		return false
	}

	// check if the new object is a HelmRepository
	newObj, ok := e.ObjectNew.(*sourcev1.HelmRepository)
	if !ok {
		return false
	}

	isOfRepositoryType := newObj.Spec.Type == h.RepositoryType
	wasOfRepositoryType := oldObj.Spec.Type == h.RepositoryType && !isOfRepositoryType
	return isOfRepositoryType || wasOfRepositoryType
}

// Delete returns true if the Delete event is for a HelmRepository of the given type.
func (h HelmRepositoryTypePredicate) Delete(e event.DeleteEvent) bool {
	return helmRepositoryTypeFilter(h.RepositoryType, e.Object)
}

// Generic returns true if the Generic event is for a HelmRepository of the given type.
func (h HelmRepositoryTypePredicate) Generic(e event.GenericEvent) bool {
	return helmRepositoryTypeFilter(h.RepositoryType, e.Object)
}
