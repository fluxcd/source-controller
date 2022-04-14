package controllers

import (
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
)

type OCIHelmRepositoryPredicate struct {
	predicate.Funcs
}

func (OCIHelmRepositoryPredicate) Update(e event.UpdateEvent) bool {
	if e.ObjectNew == nil {
		return false
	}

	newHR, ok := e.ObjectNew.(*sourcev1.HelmRepository)
	if !ok {
		return false
	}

	return newHR.Spec.Type == sourcev1.HelmRepositoryTypeOCI
}

type DefaultHelmRepositoryPredicate struct {
	predicate.Funcs
}

func (DefaultHelmRepositoryPredicate) Update(e event.UpdateEvent) bool {
	if e.ObjectNew == nil {
		return false
	}

	newHR, ok := e.ObjectNew.(*sourcev1.HelmRepository)
	if !ok {
		return false
	}

	return newHR.Spec.Type == sourcev1.HelmRepositoryTypeDefault
}
