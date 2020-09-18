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
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	BucketKind    = "Bucket"
	BucketTimeout = time.Second * 20
)

// BucketSpec defines the desired state of an S3 compatible bucket
type BucketSpec struct {
	// The S3 compatible storage provider name, default ('generic').
	// +kubebuilder:validation:Enum=generic;aws
	// +optional
	Provider string `json:"provider,omitempty"`

	// The bucket name.
	// +required
	BucketName string `json:"bucketName"`

	// The bucket endpoint address.
	// +required
	Endpoint string `json:"endpoint"`

	// Insecure allows connecting to a non-TLS S3 HTTP endpoint.
	// +optional
	Insecure bool `json:"insecure,omitempty"`

	// The bucket region.
	// +optional
	Region string `json:"region,omitempty"`

	// The secret name containing the bucket accesskey and secretkey.
	// +optional
	SecretRef *corev1.LocalObjectReference `json:"secretRef,omitempty"`

	// The interval at which to check for bucket updates.
	// +required
	Interval metav1.Duration `json:"interval"`

	// The timeout for download operations, default ('20s').
	// +optional
	Timeout *metav1.Duration `json:"timeout,omitempty"`

	// Ignore overrides the set of excluded patterns in the .sourceignore
	// format (which is the same as .gitignore).
	// +optional
	Ignore *string `json:"ignore,omitempty"`
}

const (
	GenericBucketProvider string = "generic"
	AmazonBucketProvider  string = "aws"
)

// BucketStatus defines the observed state of a bucket
type BucketStatus struct {
	// ObservedGeneration is the last observed generation.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions holds the conditions for the Bucket.
	// +optional
	Conditions []SourceCondition `json:"conditions,omitempty"`

	// URL is the download link for the artifact output of the last Bucket sync.
	// +optional
	URL string `json:"url,omitempty"`

	// Artifact represents the output of the last successful Bucket sync.
	// +optional
	Artifact *Artifact `json:"artifact,omitempty"`
}

const (
	// BucketOperationSucceedReason represents the fact that the bucket listing
	// and download operations succeeded.
	BucketOperationSucceedReason string = "BucketOperationSucceed"

	// BucketOperationFailedReason represents the fact that the bucket listing
	// or download operations failed.
	BucketOperationFailedReason string = "BucketOperationFailed"
)

// BucketProgressing resets the conditions of the Bucket
// to SourceCondition of type Ready with status unknown and
// progressing reason and message. It returns the modified Bucket.
func BucketProgressing(bucket Bucket) Bucket {
	bucket.Status.ObservedGeneration = bucket.Generation
	bucket.Status.URL = ""
	bucket.Status.Conditions = []SourceCondition{}
	SetBucketCondition(&bucket, ReadyCondition, corev1.ConditionUnknown, ProgressingReason, "reconciliation in progress")
	return bucket
}

// SetBucketCondition sets the given condition with the given status, reason and message on the Bucket.
func SetBucketCondition(bucket *Bucket, condition string, status corev1.ConditionStatus, reason, message string) {
	bucket.Status.Conditions = filterOutSourceCondition(bucket.Status.Conditions, condition)
	bucket.Status.Conditions = append(bucket.Status.Conditions, SourceCondition{
		Type:               condition,
		Status:             status,
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            message,
	})
}

// BucketReady sets the given artifact and url on the Bucket
// and sets the ReadyCondition to True, with the given reason and
// message. It returns the modified Bucket.
func BucketReady(repository Bucket, artifact Artifact, url, reason, message string) Bucket {
	repository.Status.Artifact = &artifact
	repository.Status.URL = url
	SetBucketCondition(&repository, ReadyCondition, corev1.ConditionTrue, reason, message)
	return repository
}

// BucketNotReady sets the ReadyCondition on the given Bucket
// to False, with the given reason and message. It returns the modified Bucket.
func BucketNotReady(repository Bucket, reason, message string) Bucket {
	SetBucketCondition(&repository, ReadyCondition, corev1.ConditionFalse, reason, message)
	return repository
}

// BucketReadyMessage returns the message of the SourceCondition
// of type Ready with status true if present, or an empty string.
func BucketReadyMessage(repository Bucket) string {
	for _, condition := range repository.Status.Conditions {
		if condition.Type == ReadyCondition && condition.Status == corev1.ConditionTrue {
			return condition.Message
		}
	}
	return ""
}

// GetTimeout returns the configured timeout or the default.
func (in *Bucket) GetTimeout() time.Duration {
	if in.Spec.Timeout != nil {
		return in.Spec.Timeout.Duration
	}
	return BucketTimeout
}

// GetArtifact returns the latest artifact from the source
// if present in the status sub-resource.
func (in *Bucket) GetArtifact() *Artifact {
	return in.Status.Artifact
}

// GetInterval returns the interval at which the source is updated.
func (in *Bucket) GetInterval() metav1.Duration {
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

// Bucket is the Schema for the buckets API
type Bucket struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BucketSpec   `json:"spec,omitempty"`
	Status BucketStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// BucketList contains a list of Bucket
type BucketList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Bucket `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Bucket{}, &BucketList{})
}
