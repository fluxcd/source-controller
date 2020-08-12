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
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	HelmRepositoryKind    = "HelmRepository"
	HelmRepositoryTimeout = time.Second * 60
)

// HelmRepositorySpec defines the reference to a Helm repository.
type HelmRepositorySpec struct {
	// The Helm repository URL, a valid URL contains at least a
	// protocol and host.
	// +required
	URL string `json:"url"`

	// The name of the secret containing authentication credentials
	// for the Helm repository.
	// For HTTP/S basic auth the secret must contain username and password
	// fields.
	// For TLS the secret must contain caFile, keyFile and caCert fields.
	// +optional
	SecretRef *corev1.LocalObjectReference `json:"secretRef,omitempty"`

	// The interval at which to check the upstream for updates.
	// +required
	Interval metav1.Duration `json:"interval"`

	// The timeout of index downloading, defaults to 60s.
	// +optional
	Timeout *metav1.Duration `json:"timeout,omitempty"`
}

// HelmRepositoryStatus defines the observed state of the HelmRepository.
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

const (
	// IndexationFailedReason represents the fact that the indexation
	// of the given Helm repository failed.
	IndexationFailedReason string = "IndexationFailed"

	// IndexationSucceededReason represents the fact that the indexation
	// of the given Helm repository succeeded.
	IndexationSucceededReason string = "IndexationSucceed"
)

// HelmRepositoryReady sets the given artifact and url on the
// HelmRepository and resets the conditions to SourceCondition of
// type Ready with status true and the given reason and message.
// It returns the modified HelmRepository.
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

// HelmRepositoryProgressing resets the conditions of the HelmRepository
// to SourceCondition of type Ready with status unknown and
// progressing reason and message. It returns the modified HelmRepository.
func HelmRepositoryProgressing(repository HelmRepository) HelmRepository {
	repository.Status.Conditions = []SourceCondition{
		{
			Type:               ReadyCondition,
			Status:             corev1.ConditionUnknown,
			LastTransitionTime: metav1.Now(),
			Reason:             ProgressingReason,
			Message:            "reconciliation in progress",
		},
	}
	return repository
}

// HelmRepositoryNotReady resets the conditions of the HelmRepository
// to SourceCondition of type Ready with status false and the given
// reason and message. It returns the modified HelmRepository.
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

// HelmRepositoryReadyMessage returns the message of the SourceCondition
// of type Ready with status true if present, or an empty string.
func HelmRepositoryReadyMessage(repository HelmRepository) string {
	for _, condition := range repository.Status.Conditions {
		if condition.Type == ReadyCondition && condition.Status == corev1.ConditionTrue {
			return condition.Message
		}
	}
	return ""
}

// GetArtifact returns the latest artifact from the source
// if present in the status sub-resource.
func (in *HelmRepository) GetArtifact() *Artifact {
	return in.Status.Artifact
}

// GetInterval returns the interval at which the source is updated.
func (in *HelmRepository) GetInterval() metav1.Duration {
	return in.Spec.Interval
}

// GetTimeout returns the configured timeout or the default.
func (in *HelmRepository) GetTimeout() time.Duration {
	if in.Spec.Timeout != nil {
		return in.Spec.Timeout.Duration
	}
	return HelmRepositoryTimeout
}

// +genclient
// +genclient:Namespaced
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
