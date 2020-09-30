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

package v1beta1

import (
	"time"

	"github.com/fluxcd/pkg/apis/meta"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	HelmRepositoryKind    = "HelmRepository"
	HelmRepositoryTimeout = time.Second * 60
)

// HelmRepositorySpec defines the reference to a Helm repository.
type HelmRepositorySpec struct {
	// The Helm repository URL, a valid URL contains at least a protocol and host.
	// +required
	URL string `json:"url"`

	// The name of the secret containing authentication credentials for the Helm
	// repository.
	// For HTTP/S basic auth the secret must contain username and
	// password fields.
	// For TLS the secret must contain caFile, keyFile and caCert
	// fields.
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
	// ObservedGeneration is the last observed generation.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions holds the conditions for the HelmRepository.
	// +optional
	Conditions []meta.Condition `json:"conditions,omitempty"`

	// URL is the download link for the last index fetched.
	// +optional
	URL string `json:"url,omitempty"`

	// Artifact represents the output of the last successful repository sync.
	// +optional
	Artifact *Artifact `json:"artifact,omitempty"`
}

const (
	// IndexationFailedReason represents the fact that the indexation of the given
	// Helm repository failed.
	IndexationFailedReason string = "IndexationFailed"

	// IndexationSucceededReason represents the fact that the indexation of the
	// given Helm repository succeeded.
	IndexationSucceededReason string = "IndexationSucceed"
)

// HelmRepositoryProgressing resets the conditions of the HelmRepository to
// meta.Condition of type meta.ReadyCondition with status 'Unknown' and
// meta.ProgressingReason reason and message. It returns the modified
// HelmRepository.
func HelmRepositoryProgressing(repository HelmRepository) HelmRepository {
	repository.Status.ObservedGeneration = repository.Generation
	repository.Status.URL = ""
	repository.Status.Conditions = []meta.Condition{}
	SetHelmRepositoryCondition(&repository, meta.ReadyCondition, corev1.ConditionUnknown, meta.ProgressingReason, "reconciliation in progress")
	return repository
}

// SetHelmRepositoryCondition sets the given condition with the given status,
// reason and message on the HelmRepository.
func SetHelmRepositoryCondition(repository *HelmRepository, condition string, status corev1.ConditionStatus, reason, message string) {
	repository.Status.Conditions = meta.FilterOutCondition(repository.Status.Conditions, condition)
	repository.Status.Conditions = append(repository.Status.Conditions, meta.Condition{
		Type:               condition,
		Status:             status,
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            message,
	})
}

// HelmRepositoryReady sets the given Artifact and URL on the HelmRepository and
// sets the meta.ReadyCondition to 'True', with the given reason and message. It
// returns the modified HelmRepository.
func HelmRepositoryReady(repository HelmRepository, artifact Artifact, url, reason, message string) HelmRepository {
	repository.Status.Artifact = &artifact
	repository.Status.URL = url
	SetHelmRepositoryCondition(&repository, meta.ReadyCondition, corev1.ConditionTrue, reason, message)
	return repository
}

// HelmRepositoryNotReady sets the meta.ReadyCondition on the given
// HelmRepository to 'False', with the given reason and message. It returns the
// modified HelmRepository.
func HelmRepositoryNotReady(repository HelmRepository, reason, message string) HelmRepository {
	SetHelmRepositoryCondition(&repository, meta.ReadyCondition, corev1.ConditionFalse, reason, message)
	return repository
}

// HelmRepositoryReadyMessage returns the message of the meta.Condition of type
// meta.ReadyCondition with status 'True' if present, or an empty string.
func HelmRepositoryReadyMessage(repository HelmRepository) string {
	if c := meta.GetCondition(repository.Status.Conditions, meta.ReadyCondition); c != nil {
		if c.Status == corev1.ConditionTrue {
			return c.Message
		}
	}
	return ""
}

// GetArtifact returns the latest artifact from the source if present in the
// status sub-resource.
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
