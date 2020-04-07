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

// GitRepositorySpec defines the desired state of GitRepository
type GitRepositorySpec struct {
	// +kubebuilder:validation:Pattern="^(http|https|ssh)://"

	// The repository URL, can be a HTTP or SSH address.
	Url string `json:"url"`

	// The interval at which to check for repository updates.
	Interval metav1.Duration `json:"interval"`

	// The git branch to checkout, defaults to ('master').
	// +optional
	Branch string `json:"branch"`

	// The git tag to checkout, takes precedence over branch.
	// +optional
	Tag string `json:"tag"`

	// The git tag semver expression, takes precedence over tag.
	// +optional
	SemVer string `json:"semver"`
}

// GitRepositoryStatus defines the observed state of GitRepository
type GitRepositoryStatus struct {
	// +optional
	Conditions []RepositoryCondition `json:"conditions,omitempty"`

	// LastUpdateTime is the timestamp corresponding to the last status
	// change of this repository.
	// +optional
	LastUpdateTime *metav1.Time `json:"lastUpdateTime,omitempty"`

	// Path to the artifacts of the last repository sync.
	// +optional
	Artifacts string `json:"artifacts,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="URL",type=string,JSONPath=`.spec.url`
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status",description=""
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].message",description=""
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description=""

// GitRepository is the Schema for the gitrepositories API
type GitRepository struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GitRepositorySpec   `json:"spec,omitempty"`
	Status GitRepositoryStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// GitRepositoryList contains a list of GitRepository
type GitRepositoryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GitRepository `json:"items"`
}

func init() {
	SchemeBuilder.Register(&GitRepository{}, &GitRepositoryList{})
}
