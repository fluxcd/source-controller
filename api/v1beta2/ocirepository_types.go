/*
Copyright 2022 The Flux authors

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

package v1beta2

import (
	"github.com/fluxcd/pkg/apis/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"time"
)

const (
	// OCIRepositoryKind is the string representation of a OCIRepository.
	OCIRepositoryKind = "OCIRepository"
)

// OCIRepositorySpec defines the desired state of OCIRepository
type OCIRepositorySpec struct {
	// URL is a reference to an OCI artifact repository hosted
	// on a remote container registry.
	// +required
	URL string `json:"url"`

	// The OCI reference to pull and monitor for changes,
	// defaults to the latest tag.
	// +optional
	Reference *OCIRepositoryRef `json:"ref,omitempty"`

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

	// CertSecretRef can be given the name of a secret containing
	// either or both of
	//
	//  - a PEM-encoded client certificate (`certFile`) and private
	//  key (`keyFile`);
	//  - a PEM-encoded CA certificate (`caFile`)
	//
	//  and whichever are supplied, will be used for connecting to the
	//  registry. The client cert and key are useful if you are
	//  authenticating with a certificate; the CA cert is useful if
	//  you are using a self-signed server certificate.
	// +optional
	CertSecretRef *meta.LocalObjectReference `json:"certSecretRef,omitempty"`

	// Verification specifies the configuration to verify the autheticity
	// of an OCI Artifact.
	// +optional
	Verification *OCIRepositoryVerification `json:"verify,omitempty"`

	// The interval at which to check for image updates.
	// +required
	Interval metav1.Duration `json:"interval"`

	// The timeout for remote OCI Repository operations like pulling, defaults to 60s.
	// +kubebuilder:default="60s"
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
	// The value should be in the format 'sha256:<HASH>'.
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

// OCIRepositoryVerification verifies the authenticity of an OCI Artifact
type OCIRepositoryVerification struct {
	// Provider specifies the technology used to sign the OCI Artifact.
	// +kubebuilder:validation:Enum=cosign
	Provider string `json:"provider"`

	// SecretRef specifies the Kubernetes Secret containing the
	// trusted public keys.
	SecretRef meta.LocalObjectReference `json:"secretRef"`
}

// OCIRepositoryStatus defines the observed state of OCIRepository
type OCIRepositoryStatus struct {
	// ObservedGeneration is the last observed generation.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions holds the conditions for the OCIRepository.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// URL is the download link for the artifact output of the last OCI Repository sync.
	// +optional
	URL string `json:"url,omitempty"`

	// Artifact represents the output of the last successful OCI Repository sync.
	// +optional
	Artifact *Artifact `json:"artifact,omitempty"`

	meta.ReconcileRequestStatus `json:",inline"`
}

const (
	// OCIOperationSucceedReason signals that a Git operation (e.g. pull) succeeded.
	OCIOperationSucceedReason string = "OCIOperationSucceeded"

	// OCIOperationFailedReason signals that an OCI operation (e.g. pull) failed.
	OCIOperationFailedReason string = "OCIOperationFailed"
)

// GetConditions returns the status conditions of the object.
func (in OCIRepository) GetConditions() []metav1.Condition {
	return in.Status.Conditions
}

// SetConditions sets the status conditions on the object.
func (in *OCIRepository) SetConditions(conditions []metav1.Condition) {
	in.Status.Conditions = conditions
}

// GetRequeueAfter returns the duration after which the OCIRepository must be
// reconciled again.
func (in OCIRepository) GetRequeueAfter() time.Duration {
	return in.Spec.Interval.Duration
}

// GetArtifact returns the latest Artifact from the OCIRepository if present in
// the status sub-resource.
func (in *OCIRepository) GetArtifact() *Artifact {
	return in.Status.Artifact
}

// +genclient
// +genclient:Namespaced
// +kubebuilder:storageversion
// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=ocirepo
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="URL",type=string,JSONPath=`.spec.url`
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status",description=""
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].message",description=""
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description=""

// OCIRepository is the Schema for the ocirepositories API
type OCIRepository struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec OCIRepositorySpec `json:"spec,omitempty"`
	// +kubebuilder:default={"observedGeneration":-1}
	Status OCIRepositoryStatus `json:"status,omitempty"`
}

// OCIRepositoryList contains a list of OCIRepository
// +kubebuilder:object:root=true
type OCIRepositoryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OCIRepository `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OCIRepository{}, &OCIRepositoryList{})
}
