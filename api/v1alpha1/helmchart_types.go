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

// HelmChartSpec defines the desired state of a Helm chart.
type HelmChartSpec struct {
	// The name of the Helm chart, as made available by the referenced
	// Helm repository.
	// +required
	Name string `json:"name"`

	// The chart version semver expression, defaults to latest when
	// omitted.
	// +optional
	Version string `json:"version,omitempty"`

	// The name of the HelmRepository the chart is available at.
	// +required
	HelmRepositoryRef corev1.LocalObjectReference `json:"helmRepositoryRef"`

	// The interval at which to check the Helm repository for updates.
	// +required
	Interval metav1.Duration `json:"interval"`
}

// HelmChartStatus defines the observed state of the HelmChart.
type HelmChartStatus struct {
	// +optional
	Conditions []SourceCondition `json:"conditions,omitempty"`

	// URL is the download link for the last chart pulled.
	// +optional
	URL string `json:"url,omitempty"`

	// Artifact represents the output of the last successful chart sync.
	// +optional
	Artifact *Artifact `json:"artifact,omitempty"`
}

const (
	// ChartPullFailedReason represents the fact that the pull of the
	// Helm chart failed.
	ChartPullFailedReason string = "ChartPullFailed"

	// ChartPulLSucceededReason represents the fact that the pull of
	// the Helm chart succeeded.
	ChartPullSucceededReason string = "ChartPullSucceeded"
)

// HelmChartReady sets the given artifact and url on the HelmChart
// and resets the conditions to SourceCondition of type Ready with
// status true and the given reason and message. It returns the
// modified HelmChart.
func HelmChartReady(chart HelmChart, artifact Artifact, url, reason, message string) HelmChart {
	chart.Status.Conditions = []SourceCondition{
		{
			Type:               ReadyCondition,
			Status:             corev1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             reason,
			Message:            message,
		},
	}
	chart.Status.URL = url

	if chart.Status.Artifact != nil {
		if chart.Status.Artifact.Path != artifact.Path {
			chart.Status.Artifact = &artifact
		}
	} else {
		chart.Status.Artifact = &artifact
	}

	return chart
}

// HelmChartProgressing resets the conditions of the HelmChart
// to SourceCondition of type Ready with status unknown and
// progressing reason and message. It returns the modified HelmChart.
func HelmChartProgressing(chart HelmChart) HelmChart {
	chart.Status.Conditions = []SourceCondition{
		{
			Type:               ReadyCondition,
			Status:             corev1.ConditionUnknown,
			LastTransitionTime: metav1.Now(),
			Reason:             ProgressingReason,
			Message:            "reconciliation in progress",
		},
	}
	return chart
}

// HelmChartNotReady resets the conditions of the HelmChart to
// SourceCondition of type Ready with status false and the given
// reason and message. It returns the modified HelmChart.
func HelmChartNotReady(chart HelmChart, reason, message string) HelmChart {
	chart.Status.Conditions = []SourceCondition{
		{
			Type:               ReadyCondition,
			Status:             corev1.ConditionFalse,
			LastTransitionTime: metav1.Now(),
			Reason:             reason,
			Message:            message,
		},
	}
	return chart
}

// HelmChartReadyMessage returns the message of the SourceCondition
// of type Ready with status true if present, or an empty string.
func HelmChartReadyMessage(chart HelmChart) string {
	for _, condition := range chart.Status.Conditions {
		if condition.Type == ReadyCondition && condition.Status == corev1.ConditionTrue {
			return condition.Message
		}
	}
	return ""
}

// GetArtifact returns the latest artifact from the source
// if present in the status sub-resource.
func (in *HelmChart) GetArtifact() *Artifact {
	return in.Status.Artifact
}

// GetInterval returns the interval at which the source is updated.
func (in *HelmChart) GetInterval() metav1.Duration {
	return in.Spec.Interval
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Name",type=string,JSONPath=`.spec.name`
// +kubebuilder:printcolumn:name="Version",type=string,JSONPath=`.spec.version`
// +kubebuilder:printcolumn:name="Repository",type=string,JSONPath=`.spec.helmRepositoryRef.name`
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status",description=""
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].message",description=""
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description=""

// HelmChart is the Schema for the helmcharts API
type HelmChart struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HelmChartSpec   `json:"spec,omitempty"`
	Status HelmChartStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// HelmChartList contains a list of HelmChart
type HelmChartList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HelmChart `json:"items"`
}

func init() {
	SchemeBuilder.Register(&HelmChart{}, &HelmChartList{})
}
