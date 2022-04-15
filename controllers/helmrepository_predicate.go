package controllers

import (
	"sigs.k8s.io/controller-runtime/pkg/client"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
)

func HelmRepositoryTypeFilter(typ string) func(client.Object) bool {
	return func(o client.Object) bool {
		if o == nil {
			return false
		}

		hr, ok := o.(*sourcev1.HelmRepository)
		if !ok {
			return false
		}

		return hr.Spec.Type == typ
	}
}
