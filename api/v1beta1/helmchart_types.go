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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const HelmChartKind = "HelmChart"

// HelmChartSpec defines the desired state of a Helm chart.
type HelmChartSpec struct {
	// The name or path the Helm chart is available at in the SourceRef.
	// +required
	Chart string `json:"chart"`

	// The chart version semver expression, ignored for charts from GitRepository
	// and Bucket sources. Defaults to latest when omitted.
	// +kubebuilder:default:=*
	// +optional
	Version string `json:"version,omitempty"`

	// The reference to the Source the chart is available at.
	// +required
	SourceRef LocalHelmChartSourceReference `json:"sourceRef"`

	// The interval at which to check the Source for updates.
	// +required
	Interval metav1.Duration `json:"interval"`

	// Alternative values file to use as the default chart values, expected to be a
	// relative path in the SourceRef. Ignored when omitted.
	// +optional
	ValuesFile string `json:"valuesFile,omitempty"`
}

// LocalHelmChartSourceReference contains enough information to let you locate
// the typed referenced object at namespace level.
type LocalHelmChartSourceReference struct {
	// APIVersion of the referent.
	// +optional
	APIVersion string `json:"apiVersion,omitempty"`

	// Kind of the referent, valid values are ('HelmRepository', 'GitRepository',
	// 'Bucket').
	// +kubebuilder:validation:Enum=HelmRepository;GitRepository;Bucket
	// +required
	Kind string `json:"kind"`

	// Name of the referent.
	// +required
	Name string `json:"name"`
}

// HelmChartStatus defines the observed state of the HelmChart.
type HelmChartStatus struct {
	// ObservedGeneration is the last observed generation.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions holds the conditions for the HelmChart.
	// +optional
	Conditions []meta.Condition `json:"conditions,omitempty"`

	// URL is the download link for the last chart pulled.
	// +optional
	URL string `json:"url,omitempty"`

	// Artifact represents the output of the last successful chart sync.
	// +optional
	Artifact *Artifact `json:"artifact,omitempty"`
}

const (
	// ChartPullFailedReason represents the fact that the pull of the Helm chart
	// failed.
	ChartPullFailedReason string = "ChartPullFailed"

	// ChartPullSucceededReason represents the fact that the pull of the Helm chart
	// succeeded.
	ChartPullSucceededReason string = "ChartPullSucceeded"

	// ChartPackageFailedReason represent the fact that the package of the Helm
	// chart failed.
	ChartPackageFailedReason string = "ChartPackageFailed"

	// ChartPackageSucceededReason represents the fact that the package of the Helm
	// chart succeeded.
	ChartPackageSucceededReason string = "ChartPackageSucceeded"
)

// HelmChartProgressing resets the conditions of the HelmChart to meta.Condition
// of type meta.ReadyCondition with status 'Unknown' and meta.ProgressingReason
// reason and message. It returns the modified HelmChart.
func HelmChartProgressing(chart HelmChart) HelmChart {
	chart.Status.ObservedGeneration = chart.Generation
	chart.Status.URL = ""
	chart.Status.Conditions = []meta.Condition{}
	SetHelmChartCondition(&chart, meta.ReadyCondition, corev1.ConditionUnknown, meta.ProgressingReason, "reconciliation in progress")
	return chart
}

// SetHelmChartCondition sets the given condition with the given status, reason
// and message on the HelmChart.
func SetHelmChartCondition(chart *HelmChart, condition string, status corev1.ConditionStatus, reason, message string) {
	chart.Status.Conditions = meta.FilterOutCondition(chart.Status.Conditions, condition)
	chart.Status.Conditions = append(chart.Status.Conditions, meta.Condition{
		Type:               condition,
		Status:             status,
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            message,
	})
}

// HelmChartReady sets the given Artifact and URL on the HelmChart and sets the
// meta.ReadyCondition to 'True', with the given reason and message. It returns
// the modified HelmChart.
func HelmChartReady(chart HelmChart, artifact Artifact, url, reason, message string) HelmChart {
	chart.Status.Artifact = &artifact
	chart.Status.URL = url
	SetHelmChartCondition(&chart, meta.ReadyCondition, corev1.ConditionTrue, reason, message)
	return chart
}

// HelmChartNotReady sets the meta.ReadyCondition on the given HelmChart to
// 'False', with the given reason and message. It returns the modified
// HelmChart.
func HelmChartNotReady(chart HelmChart, reason, message string) HelmChart {
	SetHelmChartCondition(&chart, meta.ReadyCondition, corev1.ConditionFalse, reason, message)
	return chart
}

// HelmChartReadyMessage returns the message of the meta.ReadyCondition with
// status 'True', or an empty string.
func HelmChartReadyMessage(chart HelmChart) string {
	if c := meta.GetCondition(chart.Status.Conditions, meta.ReadyCondition); c != nil {
		if c.Status == corev1.ConditionTrue {
			return c.Message
		}
	}
	return ""
}

// GetArtifact returns the latest artifact from the source if present in the
// status sub-resource.
func (in *HelmChart) GetArtifact() *Artifact {
	return in.Status.Artifact
}

// GetInterval returns the interval at which the source is updated.
func (in *HelmChart) GetInterval() metav1.Duration {
	return in.Spec.Interval
}

// +genclient
// +genclient:Namespaced
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Chart",type=string,JSONPath=`.spec.chart`
// +kubebuilder:printcolumn:name="Version",type=string,JSONPath=`.spec.version`
// +kubebuilder:printcolumn:name="Source Kind",type=string,JSONPath=`.spec.sourceRef.kind`
// +kubebuilder:printcolumn:name="Source Name",type=string,JSONPath=`.spec.sourceRef.name`
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
