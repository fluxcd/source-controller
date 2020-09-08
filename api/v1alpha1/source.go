package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Source interface must be supported by all API types.
// +k8s:deepcopy-gen=false
type Source interface {
	// GetArtifact returns the latest artifact from the source
	// if present in the status sub-resource.
	GetArtifact() *Artifact
	// GetInterval returns the interval at which the source is updated.
	GetInterval() metav1.Duration
}

const (
	// ReconcileAtAnnotation is the annotation used for triggering a
	// reconciliation outside of the defined schedule.
	ReconcileAtAnnotation string = "fluxcd.io/reconcileAt"
)

// filterOutSourceCondition returns a new SourceCondition slice without the
// SourceCondition of the given type.
func filterOutSourceCondition(conditions []SourceCondition, condition string) []SourceCondition {
	var newConditions []SourceCondition
	for _, c := range conditions {
		if c.Type == condition {
			continue
		}
		newConditions = append(newConditions, c)
	}
	return newConditions
}
