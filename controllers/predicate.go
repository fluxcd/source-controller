package controllers

import (
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

type RepositoryChangePredicate struct {
	predicate.Funcs
}

// Update implements default UpdateEvent filter for validating repository change
func (RepositoryChangePredicate) Update(e event.UpdateEvent) bool {
	if e.MetaOld == nil || e.MetaNew == nil {
		// ignore objects without metadata
		return false
	}
	if e.MetaNew.GetGeneration() != e.MetaOld.GetGeneration() {
		// reconcile on spec changes
		return true
	}

	// handle force sync
	if val, ok := e.MetaNew.GetAnnotations()[ForceSyncAnnotation]; ok {
		if valOld, okOld := e.MetaOld.GetAnnotations()[ForceSyncAnnotation]; okOld {
			if val != valOld {
				return true
			}
		} else {
			return true
		}
	}

	return false
}

const (
	ForceSyncAnnotation string = "sourcer.fluxcd.io/syncAt"
)
