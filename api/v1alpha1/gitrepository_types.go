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

// GitRepositorySpec defines the desired state of a Git repository.
type GitRepositorySpec struct {
	// The repository URL, can be a HTTP or SSH address.
	// +kubebuilder:validation:Pattern="^(http|https|ssh)://"
	// +required
	URL string `json:"url"`

	// The secret name containing the Git credentials.
	// For HTTPS repositories the secret must contain username and password
	// fields.
	// For SSH repositories the secret must contain identity, identity.pub and
	// known_hosts fields.
	// +optional
	SecretRef *corev1.LocalObjectReference `json:"secretRef,omitempty"`

	// The interval at which to check for repository updates.
	// +required
	Interval metav1.Duration `json:"interval"`

	// The git reference to checkout and monitor for changes, defaults to
	// master branch.
	// +optional
	Reference *GitRepositoryRef `json:"ref,omitempty"`

	// Verify OpenPGP signature for the commit that HEAD points to.
	// +optional
	Verification *GitRepositoryVerification `json:"verify,omitempty"`
}

// GitRepositoryRef defines the git ref used for pull and checkout operations.
type GitRepositoryRef struct {
	// The git branch to checkout, defaults to master.
	// +optional
	Branch string `json:"branch"`

	// The git tag to checkout, takes precedence over branch.
	// +optional
	Tag string `json:"tag"`

	// The git tag semver expression, takes precedence over tag.
	// +optional
	SemVer string `json:"semver"`

	// The git commit sha to checkout, if specified tag filters will be
	// ignored.
	// +optional
	Commit string `json:"commit"`
}

// GitRepositoryVerification defines the OpenPGP signature verification process.
type GitRepositoryVerification struct {
	// Mode describes what git object should be verified, currently ('head').
	// +kubebuilder:validation:Enum=head
	Mode string `json:"mode"`

	// The secret name containing the public keys of all trusted git authors.
	SecretRef corev1.LocalObjectReference `json:"secretRef,omitempty"`
}

// GitRepositoryStatus defines the observed state of a Git repository.
type GitRepositoryStatus struct {
	// +optional
	Conditions []SourceCondition `json:"conditions,omitempty"`

	// URL is the download link for the artifact output of the last repository
	// sync.
	// +optional
	URL string `json:"url,omitempty"`

	// Artifact represents the output of the last successful repository sync.
	// +optional
	Artifact *Artifact `json:"artifact,omitempty"`
}

const (
	// GitOperationSucceedReason represents the fact that the git clone, pull
	// and checkout operations succeeded.
	GitOperationSucceedReason string = "GitOperationSucceed"

	// GitOperationFailedReason represents the fact that the git clone, pull or
	// checkout operations failed.
	GitOperationFailedReason string = "GitOperationFailed"
)

func GitRepositoryReady(repository GitRepository, artifact Artifact, url, reason, message string) GitRepository {
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

func GitRepositoryNotReady(repository GitRepository, reason, message string) GitRepository {
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

func GitRepositoryReadyMessage(repository GitRepository) string {
	for _, condition := range repository.Status.Conditions {
		if condition.Type == ReadyCondition {
			return condition.Message
		}
	}
	return ""
}

// GetArtifact returns the latest artifact from the source
// if present in the status sub-resource.
func (in *GitRepository) GetArtifact() *Artifact {
	return in.Status.Artifact
}

// GetInterval returns the interval at which the source is updated.
func (in *GitRepository) GetInterval() metav1.Duration {
	return in.Spec.Interval
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

// GitRepositoryList contains a list of GitRepository
// +kubebuilder:object:root=true
type GitRepositoryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GitRepository `json:"items"`
}

func init() {
	SchemeBuilder.Register(&GitRepository{}, &GitRepositoryList{})
}
