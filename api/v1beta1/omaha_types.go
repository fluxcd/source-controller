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

// OmahaSpec defines the desired state of Omaha
type OmahaSpec struct {
	// The Omaha server URL, a valid URL contains at least a protocol and host.
	// +required
	URL string `json:"url"`

	// +required
	AppID string `json:"appid"`

	// +required
	Track string `json:"track"`

	// +optional
	Arch string `json:"arch"`

	// The interval at which to check for omaha updates.
	// +required
	Interval metav1.Duration `json:"interval"`

	// This flag tells the controller to suspend the reconciliation of this source.
	// +optional
	Suspend bool `json:"suspend,omitempty"`
}

// OmahaStatus defines the observed state of Omaha
type OmahaStatus struct {
	// ObservedGeneration is the last observed generation.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions holds the conditions for Ohama.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// URL is the download link for the artifact output of the last Ohama sync.
	// +optional
	URL string `json:"url,omitempty"`

	// TODO
	AppVersion string `json:"appVersion,omitempty"`

	// Artifact represents the output of the last successful Omaha sync.
	// +optional
	Artifact *Artifact `json:"artifact,omitempty"`

	meta.ReconcileRequestStatus `json:",inline"`
}

const (
	// OmahaOperationSucceedReason represents the fact that the omaha listing and
	// download operations succeeded.
	OmahaOperationSucceedReason string = "OmahaOperationSucceed"

	// OmahaOperationFailedReason represents the fact that the omaha listing or
	// download operations failed.
	OmahaOperationFailedReason string = "OmahaOperationFailed"
)

// OmahaProgressing resets the conditions of the Omaha to metav1.Condition of
// type meta.ReadyCondition with status 'Unknown' and meta.ProgressingReason
// reason and message. It returns the modified Omaha.
func OmahaProgressing(omaha Omaha) Omaha {
	omaha.Status.ObservedGeneration = omaha.Generation
	omaha.Status.URL = ""
	omaha.Status.Conditions = []metav1.Condition{}
	meta.SetResourceCondition(&omaha, meta.ReadyCondition, metav1.ConditionUnknown, meta.ProgressingReason, "reconciliation in progress")
	return omaha
}

// OmahaReady sets the given Artifact and URL on the Omaha and sets the
// meta.ReadyCondition to 'True', with the given reason and message. It returns
// the modified Omaha.
func OmahaReady(omaha Omaha, artifact *Artifact, url, reason, message string) Omaha {
	omaha.Status.Artifact = artifact
	omaha.Status.URL = url
	meta.SetResourceCondition(&omaha, meta.ReadyCondition, metav1.ConditionTrue, reason, message)
	return omaha
}

// OmahaNotReady sets the meta.ReadyCondition on the Omaha to 'False', with
// the given reason and message. It returns the modified Omaha.
func OmahaNotReady(omaha Omaha, reason, message string) Omaha {
	meta.SetResourceCondition(&omaha, meta.ReadyCondition, metav1.ConditionFalse, reason, message)
	return omaha
}

// OmahaReadyMessage returns the message of the metav1.Condition of type
// meta.ReadyCondition with status 'True' if present, or an empty string.
func OmahaReadyMessage(omaha Omaha) string {
	if c := apimeta.FindStatusCondition(omaha.Status.Conditions, meta.ReadyCondition); c != nil {
		if c.Status == metav1.ConditionTrue {
			return c.Message
		}
	}
	return ""
}

// GetArtifact returns the latest artifact from the source if present in the
// status sub-resource.
func (in *Omaha) GetArtifact() *Artifact {
	return in.Status.Artifact
}

// GetStatusConditions returns a pointer to the Status.Conditions slice
func (in *Omaha) GetStatusConditions() *[]metav1.Condition {
	return &in.Status.Conditions
}

// GetInterval returns the interval at which the source is updated.
func (in *Omaha) GetInterval() metav1.Duration {
	return in.Spec.Interval
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Omaha is the Schema for the omahas API
type Omaha struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OmahaSpec   `json:"spec,omitempty"`
	Status OmahaStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// OmahaList contains a list of Omaha
type OmahaList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Omaha `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Omaha{}, &OmahaList{})
}
