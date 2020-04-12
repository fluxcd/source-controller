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

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// HelmRepositorySpec defines the desired state of HelmRepository
type HelmRepositorySpec struct {
	// The repository address
	// +kubebuilder:validation:MinLength=4
	// +required
	URL string `json:"url"`

	// The interval at which to check for repository updates
	// +required
	Interval metav1.Duration `json:"interval"`
}

// HelmRepositoryStatus defines the observed state of HelmRepository
type HelmRepositoryStatus struct {
	// +optional
	Conditions []SourceCondition `json:"conditions,omitempty"`

	// URL is the download link for the last index fetched.
	// +optional
	URL string `json:"url,omitempty"`

	// Artifact represents the output of the last successful repository sync.
	// +optional
	Artifact *Artifact `json:"artifact,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="URL",type=string,JSONPath=`.spec.url`
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status",description=""
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].message",description=""
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description=""

// HelmRepository is the Schema for the helmrepositories API
type HelmRepository struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HelmRepositorySpec   `json:"spec,omitempty"`
	Status HelmRepositoryStatus `json:"status,omitempty"`
}

// HelmRepositoryList contains a list of HelmRepository
// +kubebuilder:object:root=true
type HelmRepositoryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HelmRepository `json:"items"`
}

func init() {
	SchemeBuilder.Register(&HelmRepository{}, &HelmRepositoryList{})
}

const (
	// IndexationFailedReason represents the fact that the indexation
	// of the given Helm repository failed.
	IndexationFailedReason string = "IndexationFailed"

	// IndexationSucceededReason represents the fact that the indexation
	// of the given Helm repository succeeded.
	IndexationSucceededReason string = "IndexationSucceed"
)

func HelmRepositoryReady(repository HelmRepository, artifact Artifact, url, reason, message string) HelmRepository {
	repository.Status.Conditions = []SourceCondition{
		{
			Type:               ReadyCondition,
			Status:             corev1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             reason,
			Message:            message,
		},
	}
	repository.Status.URL = url

	if repository.Status.Artifact != nil {
		if repository.Status.Artifact.Path != artifact.Path {
			repository.Status.Artifact = &artifact
		}
	} else {
		repository.Status.Artifact = &artifact
	}

	return repository
}

func HelmRepositoryNotReady(repository HelmRepository, reason, message string) HelmRepository {
	repository.Status.Conditions = []SourceCondition{
		{
			Type:               ReadyCondition,
			Status:             corev1.ConditionFalse,
			LastTransitionTime: metav1.Now(),
			Reason:             reason,
			Message:            message,
		},
	}
	return repository
}

func HelmRepositoryReadyMessage(repository HelmRepository) string {
	for _, condition := range repository.Status.Conditions {
		if condition.Type == ReadyCondition {
			return condition.Message
		}
	}
	return ""
}
