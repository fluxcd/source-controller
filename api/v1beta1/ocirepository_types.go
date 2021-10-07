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
	"github.com/fluxcd/pkg/apis/meta"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// OCIRepositoryKind is the string representation of a OCIRepository.
	OCIRepositoryKind = "OCIRepository"
)

// OCIRepositorySpec defines the desired state of OCIRepository
type OCIRepositorySpec struct {

	// URL is a reference to an image in a remote registry
	// +required
	URL string `json:"url"`

	// The OCI reference to pull and monitor for changes, defaults to
	// latest tag.
	// +optional
	Reference *OCIRepositoryRef `json:"ref,omitempty"`

	// The credentials to use to pull and monitor for changes, defaults
	// to anonymous access.
	// +optional
	Authentication *OCIRepositoryAuth `json:"auth,omitempty"`

	// The interval at which to check for image updates.
	// +required
	Interval metav1.Duration `json:"interval"`

	// The timeout for remote OCI Repository operations like pulling, defaults to 20s.
	// +kubebuilder:default="20s"
	// +optional
	Timeout *metav1.Duration `json:"timeout,omitempty"`

	// Ignore overrides the set of excluded patterns in the .sourceignore format
	// (which is the same as .gitignore). If not provided, a default will be used,
	// consult the documentation for your version to find out what those are.
	// +optional
	Ignore *string `json:"ignore,omitempty"`

	// This flag tells the controller to suspend the reconciliation of this source.
	// +optional
	Suspend bool `json:"suspend,omitempty"`
}

// OCIRepositoryRef defines the image reference for the OCIRepository's URL
type OCIRepositoryRef struct {

	// Digest is the image digest to pull, takes precedence over SemVer.
	// Value should be in the form sha256:cbbf2f9a99b47fc460d422812b6a5adff7dfee951d8fa2e4a98caa0382cfbdbf
	// +optional
	Digest string `json:"digest,omitempty"`

	// SemVer is the range of tags to pull selecting the latest within
	// the range, takes precedence over Tag.
	// +optional
	SemVer string `json:"semver,omitempty"`

	// Tag is the image tag to pull, defaults to latest.
	// +kubebuilder:default:=latest
	// +optional
	Tag string `json:"tag,omitempty"`
}

// OCIRepositoryAuth defines the desired authentication mechanism of OCIRepository
type OCIRepositoryAuth struct {

	// SecretRef contains the secret name containing the registry login
	// credentials to resolve image metadata.
	// The secret must be of type kubernetes.io/dockerconfigjson.
	// +optional
	SecretRef *meta.LocalObjectReference `json:"secretRef,omitempty"`

	// ServiceAccountName is the name of the Kubernetes ServiceAccount used to authenticate
	// the image pull if the service account has attached pull secrets. For more information:
	// https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#add-imagepullsecrets-to-a-service-account
	// +optional
	ServiceAccountName string `json:"serviceAccountName,omitempty"`
}

// OCIRepositoryStatus defines the observed state of OCIRepository
type OCIRepositoryStatus struct {
	// ObservedGeneration is the last observed generation.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions holds the conditions for the OCIRepository.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// URL is the download link for the artifact output of the last
	//image  sync.
	// +optional
	URL string `json:"url,omitempty"`

	// Artifact represents the output of the last successful image sync.
	// +optional
	Artifact *Artifact `json:"artifact,omitempty"`

	meta.ReconcileRequestStatus `json:",inline"`
}

const (
	// OCIRepositoryOperationSucceedReason represents the fact that the
	// image pull operation succeeded.
	OCIRepositoryOperationSucceedReason string = "OCIRepositoryOperationSucceed"

	// OCIRepositoryOperationFailedReason represents the fact that the
	// image pull operation failed.
	OCIRepositoryOperationFailedReason string = "OCIRepositoryOperationFailed"
)

// OCIRepositoryProgressing resets the conditions of the OCIRepository
// to metav1.Condition of type meta.ReadyCondition with status 'Unknown'
// and meta.ProgressingReason reason and message. It returns the
// modified OCCIRepository.
func OCIRepositoryProgressing(repository OCIRepository) OCIRepository {
	repository.Status.ObservedGeneration = repository.Generation
	repository.Status.URL = ""
	repository.Status.Conditions = []metav1.Condition{}
	meta.SetResourceCondition(&repository, meta.ReadyCondition, metav1.ConditionUnknown, meta.ProgressingReason, "reconciliation in progress")
	return repository
}

// OCIRepositoryReady sets the given Artifact and URL on the
// OCIRepository and sets the meta.ReadyCondition to 'True', with the
// given reason and message. It returns the modified OCIRepository.
func OCIRepositoryReady(repository OCIRepository, artifact Artifact, url, reason, message string) OCIRepository {
	repository.Status.Artifact = &artifact
	repository.Status.URL = url
	meta.SetResourceCondition(&repository, meta.ReadyCondition, metav1.ConditionTrue, reason, message)
	return repository
}

// OCIRepositoryNotReady sets the meta.ReadyCondition on the given
// OCIRepository to 'False', with the given reason and message. It
// returns the modified OCIRepository.
func OCIRepositoryNotReady(repository OCIRepository, reason, message string) OCIRepository {
	meta.SetResourceCondition(&repository, meta.ReadyCondition, metav1.ConditionFalse, reason, message)
	return repository
}

// OCIRepositoryReadyMessage returns the message of the
// metav1.Condition of type meta.ReadyCondition with status 'True' if
// present, or an empty string.
func OCIRepositoryReadyMessage(repository OCIRepository) string {
	if c := apimeta.FindStatusCondition(repository.Status.Conditions, meta.ReadyCondition); c != nil {
		if c.Status == metav1.ConditionTrue {
			return c.Message
		}
	}
	return ""
}

// GetArtifact returns the latest artifact from the source if present in the
// status sub-resource.
func (in *OCIRepository) GetArtifact() *Artifact {
	return in.Status.Artifact
}

// GetStatusConditions returns a pointer to the Status.Conditions slice
func (in *OCIRepository) GetStatusConditions() *[]metav1.Condition {
	return &in.Status.Conditions
}

// GetInterval returns the interval at which the source is updated.
func (in *OCIRepository) GetInterval() metav1.Duration {
	return in.Spec.Interval
}

// +genclient
// +genclient:Namespaced
//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="URL",type=string,JSONPath=`.spec.url`
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status",description=""
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].message",description=""
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description=""

// OCIRepository is the Schema for the ocirepositories API
type OCIRepository struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OCIRepositorySpec   `json:"spec,omitempty"`
	Status OCIRepositoryStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// OCIRepositoryList contains a list of OCIRepository
type OCIRepositoryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OCIRepository `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OCIRepository{}, &OCIRepositoryList{})
}
