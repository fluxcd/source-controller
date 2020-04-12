package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SourceCondition contains condition information for a source
type SourceCondition struct {
	// Type of the condition, currently ('Ready').
	// +required
	Type string `json:"type"`

	// Status of the condition, one of ('True', 'False', 'Unknown').
	// +required
	Status corev1.ConditionStatus `json:"status"`

	// LastTransitionTime is the timestamp corresponding to the last status
	// change of this condition.
	// +required
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`

	// Reason is a brief machine readable explanation for the condition's last
	// transition.
	// +required
	Reason string `json:"reason,omitempty"`

	// Message is a human readable description of the details of the last
	// transition, complementing reason.
	// +optional
	Message string `json:"message,omitempty"`
}

const (
	// ReadyCondition represents the fact that a given source is in ready state.
	ReadyCondition string = "Ready"

	// InitializingReason represents the fact that a given source is being initialize.
	InitializingReason string = "Initializing"

	// StorageOperationFailedReason signals a failure caused by a storage operation.
	StorageOperationFailedReason string = "StorageOperationFailed"

	// URLInvalidReason represents the fact that a given source has an invalid URL.
	URLInvalidReason string = "URLInvalid"

	// AuthenticationFailedReason represents the fact that a given secret doesn't
	// have the required fields or the provided credentials don't match.
	AuthenticationFailedReason string = "AuthenticationFailed"
)
