# Object storage buckets

The `Bucket` API defines a source for artifacts coming from S3 compatible storage
such as Minio, Amazon S3, Google Cloud Storage, Alibaba Cloud OSS and others.

## Specification

Bucket:

```go
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

	// The name of the secret containing authentication credentials
	// for the Bucket.
	// +optional
	SecretRef *corev1.LocalObjectReference `json:"secretRef,omitempty"`

	// The interval at which to check for bucket updates.
	// +required
	Interval metav1.Duration `json:"interval"`

	// The timeout for download operations, default ('20s').
	// +optional
	Timeout *metav1.Duration `json:"timeout,omitempty"`

	// Ignore overrides the set of excluded patterns in the .sourceignore format
	// (which is the same as .gitignore).
	// +optional
	Ignore *string `json:"ignore,omitempty"`
}
```

Supported providers:

```go
const (
	GenericBucketProvider string = "generic"
	AmazonBucketProvider  string = "aws"
)
```

### Status

```go
// BucketStatus defines the observed state of a bucket
type BucketStatus struct {
	// ObservedGeneration is the last observed generation.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions holds the conditions for the Bucket.
	// +optional
	Conditions []meta.Condition `json:"conditions,omitempty"`

	// URL is the download link for the artifact output of the last Bucket sync.
	// +optional
	URL string `json:"url,omitempty"`

	// Artifact represents the output of the last successful Bucket sync.
	// +optional
	Artifact *Artifact `json:"artifact,omitempty"`
}
```

### Condition reasons

```go
const (
	// BucketOperationSucceedReason represents the fact that the bucket listing and
	// download operations succeeded.
	BucketOperationSucceedReason string = "BucketOperationSucceed"

	// BucketOperationFailedReason represents the fact that the bucket listing or
	// download operations failed.
	BucketOperationFailedReason string = "BucketOperationFailed"
)
```

## Artifact

The resource exposes the latest synchronized state from S3 as an artifact 
in a gzip compressed TAR archive (`<bucket checksum>.tar.gz`).

### Excluding files

Git files (`.git/`, `.gitignore`, `.gitmodules`, and `.gitattributes`) are
excluded from the archive by default, as well as some extensions (`.jpg, .jpeg,
.gif, .png, .wmv, .flv, .tar.gz, .zip`)

Excluding additional files from the archive is possible by adding a
`.sourceignore` file in the root of the bucket. The `.sourceignore` file
follows [the `.gitignore` pattern
format](https://git-scm.com/docs/gitignore#_pattern_format), pattern
entries may overrule default exclusions.

Another option is to use the `spec.ignore` field, for example:

```yaml
apiVersion: source.toolkit.fluxcd.io/v1alpha1
kind: Bucket
metadata:
  name: podinfo
spec:
  ignore: |
    # exclude all
    /*
    # include deploy dir
    !/deploy
    # exclude file extensions from deploy dir
    /deploy/**/*.md
    /deploy/**/*.txt
```

When specified, `spec.ignore` overrides the default exclusion list.

## Spec examples

### Static authentication

Authentication credentials can be provided with a Kubernetes secret that contains
`accesskey` and `secretkey` fields:

```yaml
apiVersion: source.toolkit.fluxcd.io/v1alpha1
kind: Bucket
metadata:
  name: podinfo
  namespace: gitops-system
spec:
  interval: 1m
  provider: generic
  bucketName: podinfo
  endpoint: minio.minio.svc.cluster.local:9000
  insecure: true
  secretRef:
    name: minio-credentials
---
apiVersion: v1
kind: Secret
metadata:
  name: minio-credentials
  namespace: gitops-system
type: Opaque
data:
  accesskey: <BASE64> 
  secretkey: <BASE64> 
```

> **Note:** that for Google Cloud Storage you have to enable
> S3 compatible access in your GCP project.

### AWS IAM authentication

When the provider is `aws` and the `secretRef` is not specified,
the credentials are retrieve from the EC2 service:

```yaml
apiVersion: source.toolkit.fluccd.io/v1alpha1
kind: Bucket
metadata:
  name: podinfo
  namespace: gitops-system
spec:
  interval: 5m
  provider: aws
  bucketName: podinfo
  endpoint: s3.amazonaws.com
  region: us-east-1
  timeout: 30s
```

> **Note:** that on EKS you have to create an IAM role for the source-controller
> service account that grants access to the bucket.

## Status examples

Successful download:

```yaml
  status:
    artifact:
      checksum: b249024b8544521792a079c4037d0a06dd0497a9
      lastUpdateTime: "2020-09-18T08:34:49Z"
      path: bucket/gitops-system/podinfo/aeaba8b6dd51c53084f99b098cfae4f5148ad410.tar.gz
      revision: aeaba8b6dd51c53084f99b098cfae4f5148ad410
      url: http://localhost:9090/bucket/gitops-system/podinfo/aeaba8b6dd51c53084f99b098cfae4f5148ad410.tar.gz
    conditions:
    - lastTransitionTime: "2020-09-18T08:34:49Z"
      message: 'Fetched revision: aeaba8b6dd51c53084f99b098cfae4f5148ad410'
      reason: BucketOperationSucceed
      status: "True"
      type: Ready
    observedGeneration: 2
    url: http://localhost:9090/bucket/gitops-system/podinfo/latest.tar.gz
```

Failed download:

```yaml
status:
  conditions:
  - lastTransitionTime: "2020-09-18T08:34:49Z"
    message: "bucket 'test' not found"
    reason: BucketOperationFailed
    status: "False"
    type: Ready
```

Wait for ready condition:

```bash
kubectl -n gitios-system wait bucket/podinfo --for=condition=ready --timeout=1m
```