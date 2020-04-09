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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// HelmRepositorySpec defines the desired state of HelmRepository
type HelmRepositorySpec struct {
	// The repository address
	// +kubebuilder:validation:MinLength=4
	URL string `json:"url"`

	// The interval at which to check for repository updates
	Interval metav1.Duration `json:"interval"`
}

// HelmRepositoryStatus defines the observed state of HelmRepository
type HelmRepositoryStatus struct {
	// +optional
	Conditions []RepositoryCondition `json:"conditions,omitempty"`

	// LastUpdateTime is the timestamp corresponding to the last status
	// change of this repository.
	// +optional
	LastUpdateTime *metav1.Time `json:"lastUpdateTime,omitempty"`

	// Path to the artifact of the last repository index.
	// +optional
	Artifact string `json:"artifact,omitempty"`
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

// +kubebuilder:object:root=true

// HelmRepositoryList contains a list of HelmRepository
type HelmRepositoryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HelmRepository `json:"items"`
}

func init() {
	SchemeBuilder.Register(&HelmRepository{}, &HelmRepositoryList{})
}

const (
	InvalidHelmRepositoryURLReason string = "InvalidHelmRepositoryURL"
	IndexFetchFailedReason         string = "IndexFetchFailedReason"
	IndexFetchSucceededReason      string = "IndexFetchSucceed"
)
