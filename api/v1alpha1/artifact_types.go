/*
Copyright 2024 The Flux authors

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

	v1 "github.com/fluxcd/source-controller/api/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// BucketKind is the string representation of a Bucket.
	ArtifactKind = "Artifact"
)

// ArtifactSpec defines the desired state of Artifact
type ArtifactSpec struct {

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	CurrentVersion string `json:"currentVersion,omitempty"`

	// +kubebuilder:validation:Required
	Versions map[string]*v1.Artifact `json:"versions,omitempty"`
}

// ArtifactStatus defines the observed state of Artifact
type ArtifactStatus struct {
}

// +genclient
// +kubebuilder:storageversion
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// Artifact is the Schema for the artifacts API
type Artifact struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ArtifactSpec   `json:"spec,omitempty"`
	Status ArtifactStatus `json:"status,omitempty"`
}

// GetArtifact returns the latest Artifact from the Artifact if present in
// the status sub-resource.
func (in *Artifact) GetArtifact() *v1.Artifact {
	if in.Spec.CurrentVersion == "" {
		return nil
	}
	if in.Spec.Versions == nil {
		return nil
	}
	return in.Spec.Versions[in.Spec.CurrentVersion]
}

func (in *Artifact) GetRequeueAfter() time.Duration {
	return time.Minute
}

// +kubebuilder:object:root=true

// ArtifactList contains a list of Artifact
type ArtifactList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Artifact `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Artifact{}, &ArtifactList{})
}
