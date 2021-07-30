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
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/fluxcd/pkg/apis/acl"
	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/runtime/conditions"
)

const (
	// GitRepositoryKind is the string representation of a GitRepository.
	GitRepositoryKind = "GitRepository"

	// GoGitImplementation represents the go-git Git implementation kind.
	GoGitImplementation = "go-git"
	// LibGit2Implementation represents the git2go Git implementation kind.
	LibGit2Implementation = "libgit2"
)

const (
	// ArtifactUnavailableCondition indicates there is no Artifact available for the Source.
	// This is a "negative polarity" or "abnormal-true" type, and is only present on the resource if it is True.
	ArtifactUnavailableCondition string = "ArtifactUnavailable"

	// CheckoutFailedCondition indicates a transient or persistent checkout failure. If True, observations on the
	// upstream Source revision are not possible, and the Artifact available for the Source may be outdated.
	// This is a "negative polarity" or "abnormal-true" type, and is only present on the resource if it is True.
	CheckoutFailedCondition string = "CheckoutFailed"

	// SourceVerifiedCondition indicates the integrity of the Source has been verified. If True, the integrity check
	// succeeded. If False, it failed. The Condition is only present on the resource if the integrity has been verified.
	SourceVerifiedCondition string = "SourceVerified"

	// IncludeUnavailableCondition indicates one of the includes is not available. For example, because it does not
	// exist, or does not have an Artifact.
	// This is a "negative polarity" or "abnormal-true" type, and is only present on the resource if it is True.
	IncludeUnavailableCondition string = "IncludeUnavailable"

	// ArtifactOutdatedCondition indicates the current Artifact of the Source is outdated.
	// This is a "negative polarity" or "abnormal-true" type, and is only present on the resource if it is True.
	ArtifactOutdatedCondition string = "ArtifactOutdated"
)

// GitRepositorySpec defines the desired state of a Git repository.
type GitRepositorySpec struct {
	// The repository URL, can be a HTTP/S or SSH address.
	// +kubebuilder:validation:Pattern="^(http|https|ssh)://"
	// +required
	URL string `json:"url"`

	// The secret name containing the Git credentials.
	// For HTTPS repositories the secret must contain username and password fields.
	// For SSH repositories the secret must contain 'identity', 'identity.pub' and 'known_hosts' fields.
	// +optional
	SecretRef *meta.LocalObjectReference `json:"secretRef,omitempty"`

	// The interval at which to check for repository updates.
	// +required
	Interval metav1.Duration `json:"interval"`

	// The timeout for remote Git operations like cloning, defaults to 20s.
	// +kubebuilder:default="20s"
	// +optional
	Timeout *metav1.Duration `json:"timeout,omitempty"`

	// The Git reference to checkout and monitor for changes, defaults to
	// master branch.
	// +optional
	Reference *GitRepositoryRef `json:"ref,omitempty"`

	// Verification defines the configuration to verify the OpenPGP signature for the Git commit HEAD points to.
	// +optional
	Verification *GitRepositoryVerification `json:"verify,omitempty"`

	// Ignore overrides the set of excluded patterns in the .sourceignore format (which is the same as .gitignore).
	// If not provided, a default will be used, consult the documentation for your version to find out what those are.
	// +optional
	Ignore *string `json:"ignore,omitempty"`

	// Suspend tells the controller to suspend the reconciliation of this source.
	// This flag tells the controller to suspend the reconciliation of this source.
	// +optional
	Suspend bool `json:"suspend,omitempty"`

	// Determines which git client library to use.
	// Defaults to go-git, valid values are ('go-git', 'libgit2').
	// +kubebuilder:validation:Enum=go-git;libgit2
	// +kubebuilder:default:=go-git
	// +optional
	GitImplementation string `json:"gitImplementation,omitempty"`

	// When enabled, after the clone is created, initializes all submodules within, using their default settings.
	// This option is available only when using the 'go-git' GitImplementation.
	// +optional
	RecurseSubmodules bool `json:"recurseSubmodules,omitempty"`

	// Include defines a list of GitRepository resources which artifacts should be included in the artifact produced for
	// this resource.
	Include []GitRepositoryInclude `json:"include,omitempty"`

	// AccessFrom defines an Access Control List for allowing cross-namespace references to this object.
	// +optional
	AccessFrom *acl.AccessFrom `json:"accessFrom,omitempty"`
}

func (in *GitRepositoryInclude) GetFromPath() string {
	return in.FromPath
}

func (in *GitRepositoryInclude) GetToPath() string {
	if in.ToPath == "" {
		return in.GitRepositoryRef.Name
	}
	return in.ToPath
}

// GitRepositoryInclude defines a source with a from and to path.
type GitRepositoryInclude struct {
	// Reference to a GitRepository to include.
	GitRepositoryRef meta.LocalObjectReference `json:"repository"`

	// The path to copy contents from, defaults to the root directory.
	// +optional
	FromPath string `json:"fromPath"`

	// The path to copy contents to, defaults to the name of the source ref.
	// +optional
	ToPath string `json:"toPath"`
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
	// Mode describes what Git object should be verified, currently ('head').
	// +kubebuilder:validation:Enum=head
	Mode string `json:"mode"`

	// SecretRef containing the public keys of all trusted Git authors.
	SecretRef meta.LocalObjectReference `json:"secretRef,omitempty"`
}

// GitRepositoryStatus defines the observed state of a Git repository.
type GitRepositoryStatus struct {
	// ObservedGeneration is the last observed generation.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions holds the conditions for the GitRepository.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// URL is the download link for the artifact output of the last repository sync.
	// +optional
	URL string `json:"url,omitempty"`

	// Artifact represents the output of the last successful repository sync.
	// +optional
	Artifact *Artifact `json:"artifact,omitempty"`

	// IncludedArtifacts represents the included artifacts from the last successful repository sync.
	// +optional
	IncludedArtifacts []*Artifact `json:"includedArtifacts,omitempty"`

	meta.ReconcileRequestStatus `json:",inline"`
}

const (
	// GitOperationSucceedReason represents the fact that the git clone, pull and checkout operations succeeded.
	GitOperationSucceedReason string = "GitOperationSucceed"

	// GitOperationFailedReason represents the fact that the git clone, pull or checkout operations failed.
	GitOperationFailedReason string = "GitOperationFailed"
)

// GitRepositoryProgressing resets the conditions of the GitRepository to
// metav1.Condition of type meta.ReadyCondition with status 'Unknown' and
// meta.ProgressingReason reason and message. It returns the modified
// GitRepository.
func GitRepositoryProgressing(repository GitRepository) GitRepository {
	repository.Status.ObservedGeneration = repository.Generation
	repository.Status.URL = ""
	repository.Status.Conditions = []metav1.Condition{}
	conditions.MarkUnknown(&repository, meta.ReadyCondition, meta.ProgressingReason, "reconciliation in progress")
	return repository
}

// GitRepositoryReady sets the given Artifact and URL on the GitRepository and
// sets the meta.ReadyCondition to 'True', with the given reason and message. It
// returns the modified GitRepository.
func GitRepositoryReady(repository GitRepository, artifact Artifact, includedArtifacts []*Artifact, url, reason, message string) GitRepository {
	repository.Status.Artifact = &artifact
	repository.Status.IncludedArtifacts = includedArtifacts
	repository.Status.URL = url
	conditions.MarkTrue(&repository, meta.ReadyCondition, reason, message)
	return repository
}

// GitRepositoryNotReady sets the meta.ReadyCondition on the given GitRepository
// to 'False', with the given reason and message. It returns the modified
// GitRepository.
func GitRepositoryNotReady(repository GitRepository, reason, message string) GitRepository {
	conditions.MarkFalse(&repository, meta.ReadyCondition, reason, message)
	return repository
}

// GitRepositoryReadyMessage returns the message of the metav1.Condition of type
// meta.ReadyCondition with status 'True' if present, or an empty string.
func GitRepositoryReadyMessage(repository GitRepository) string {
	if c := apimeta.FindStatusCondition(repository.Status.Conditions, meta.ReadyCondition); c != nil {
		if c.Status == metav1.ConditionTrue {
			return c.Message
		}
	}
	return ""
}

// GetConditions returns the status conditions of the object.
func (in GitRepository) GetConditions() []metav1.Condition {
	return in.Status.Conditions
}

// SetConditions sets the status conditions on the object.
func (in *GitRepository) SetConditions(conditions []metav1.Condition) {
	in.Status.Conditions = conditions
}

// GetInterval returns the interval at which the source is reconciled.
func (in GitRepository) GetInterval() metav1.Duration {
	return in.Spec.Interval
}

// GetArtifact returns the latest artifact from the source if present in the status sub-resource.
func (in *GitRepository) GetArtifact() *Artifact {
	return in.Status.Artifact
}

// GetStatusConditions returns a pointer to the Status.Conditions slice.
// Deprecated: use GetConditions instead.
func (in *GitRepository) GetStatusConditions() *[]metav1.Condition {
	return &in.Status.Conditions
}

// +genclient
// +genclient:Namespaced
// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=gitrepo
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
