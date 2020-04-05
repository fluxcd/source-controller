package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RepositoryCondition contains condition information for a repository
type RepositoryCondition struct {
	// Type of the condition, currently ('Ready').
	Type RepositoryConditionType `json:"type"`

	// Status of the condition, one of ('True', 'False', 'Unknown').
	Status corev1.ConditionStatus `json:"status"`

	// LastTransitionTime is the timestamp corresponding to the last status
	// change of this condition.
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`

	// Reason is a brief machine readable explanation for the condition's last
	// transition.
	// +optional
	Reason string `json:"reason,omitempty"`

	// Message is a human readable description of the details of the last
	// transition, complementing reason.
	// +optional
	Message string `json:"message,omitempty"`
}

// RepositoryConditionType represents an repository condition value
type RepositoryConditionType string

const (
	// RepositoryConditionReady represents the fact that a given repository condition
	// is in ready state.
	RepositoryConditionReady RepositoryConditionType = "Ready"
)
