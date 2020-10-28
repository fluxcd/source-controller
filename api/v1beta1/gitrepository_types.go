/*
Copyright 2020 The Flux authors

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
	GitRepositoryKind    = "GitRepository"
	GitRepositoryTimeout = time.Second * 20
)

// GitRepositorySpec defines the desired state of a Git repository.
type GitRepositorySpec struct {
	// The repository URL, can be a HTTP/S or SSH address.
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

	// The timeout for remote Git operations like cloning, defaults to 20s.
	// +optional
	Timeout *metav1.Duration `json:"timeout,omitempty"`

	// The Git reference to checkout and monitor for changes, defaults to
	// master branch.
	// +optional
	Reference *GitRepositoryRef `json:"ref,omitempty"`

	// Verify OpenPGP signature for the Git commit HEAD points to.
	// +optional
	Verification *GitRepositoryVerification `json:"verify,omitempty"`

	// Ignore overrides the set of excluded patterns in the .sourceignore format
	// (which is the same as .gitignore). If not provided, a default will be used,
	// consult the documentation for your version to find out what those are.
	// +optional
	Ignore *string `json:"ignore,omitempty"`
}

// GitRepositoryRef defines the Git ref used for pull and checkout operations.
type GitRepositoryRef struct {
	// The Git branch to checkout, defaults to master.
	// +optional
	Branch string `json:"branch,omitempty"`

	// The Git tag to checkout, takes precedence over Branch.
	// +optional
	Tag string `json:"tag,omitempty"`

	// The Git tag semver expression, takes precedence over Tag.
	// +optional
	SemVer string `json:"semver,omitempty"`

	// The Git commit SHA to checkout, if specified Tag filters will be ignored.
	// +optional
	Commit string `json:"commit,omitempty"`
}

// GitRepositoryVerification defines the OpenPGP signature verification process.
type GitRepositoryVerification struct {
	// Mode describes what git object should be verified, currently ('head').
	// +kubebuilder:validation:Enum=head
	Mode string `json:"mode"`

	// The secret name containing the public keys of all trusted Git authors.
	SecretRef corev1.LocalObjectReference `json:"secretRef,omitempty"`
}

// GitRepositoryStatus defines the observed state of a Git repository.
type GitRepositoryStatus struct {
	// ObservedGeneration is the last observed generation.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions holds the conditions for the GitRepository.
	// +optional
	Conditions []meta.Condition `json:"conditions,omitempty"`

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

// GitRepositoryProgressing resets the conditions of the GitRepository to
// meta.Condition of type meta.ReadyCondition with status 'Unknown' and
// meta.ProgressingReason reason and message. It returns the modified
// GitRepository.
func GitRepositoryProgressing(repository GitRepository) GitRepository {
	repository.Status.ObservedGeneration = repository.Generation
	repository.Status.URL = ""
	repository.Status.Conditions = []meta.Condition{}
	SetGitRepositoryCondition(&repository, meta.ReadyCondition, corev1.ConditionUnknown, meta.ProgressingReason, "reconciliation in progress")
	return repository
}

// SetGitRepositoryCondition sets the given condition with the given status,
// reason and message on the GitRepository.
func SetGitRepositoryCondition(repository *GitRepository, condition string, status corev1.ConditionStatus, reason, message string) {
	repository.Status.Conditions = meta.FilterOutCondition(repository.Status.Conditions, condition)
	repository.Status.Conditions = append(repository.Status.Conditions, meta.Condition{
		Type:               condition,
		Status:             status,
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            message,
	})
}

// GitRepositoryReady sets the given Artifact and URL on the GitRepository and
// sets the meta.ReadyCondition to 'True', with the given reason and message. It
// returns the modified GitRepository.
func GitRepositoryReady(repository GitRepository, artifact Artifact, url, reason, message string) GitRepository {
	repository.Status.Artifact = &artifact
	repository.Status.URL = url
	SetGitRepositoryCondition(&repository, meta.ReadyCondition, corev1.ConditionTrue, reason, message)
	return repository
}

// GitRepositoryNotReady sets the meta.ReadyCondition on the given GitRepository
// to 'False', with the given reason and message. It returns the modified
// GitRepository.
func GitRepositoryNotReady(repository GitRepository, reason, message string) GitRepository {
	SetGitRepositoryCondition(&repository, meta.ReadyCondition, corev1.ConditionFalse, reason, message)
	return repository
}

// GitRepositoryReadyMessage returns the message of the meta.Condition of type
// meta.ReadyCondition with status 'True' if present, or an empty string.
func GitRepositoryReadyMessage(repository GitRepository) string {
	if c := meta.GetCondition(repository.Status.Conditions, meta.ReadyCondition); c != nil {
		if c.Status == corev1.ConditionTrue {
			return c.Message
		}
	}
	return ""
}

// GetTimeout returns the configured timeout or the default.
func (in *GitRepository) GetTimeout() time.Duration {
	if in.Spec.Timeout != nil {
		return in.Spec.Timeout.Duration
	}
	return GitRepositoryTimeout
}

// GetArtifact returns the latest artifact from the source if present in the
// status sub-resource.
func (in *GitRepository) GetArtifact() *Artifact {
	return in.Status.Artifact
}

// GetInterval returns the interval at which the source is updated.
func (in *GitRepository) GetInterval() metav1.Duration {
	return in.Spec.Interval
}

// +genclient
// +genclient:Namespaced
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
