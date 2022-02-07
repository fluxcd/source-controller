# Object storage buckets

The `Bucket` API defines a source for artifacts coming from S3 compatible storage
such as Minio, Amazon S3, Google Cloud Storage, Alibaba Cloud OSS and others.

## Specification

Bucket:

```go
// BucketSpec defines the desired state of an S3 compatible bucket
type BucketSpec struct {
	// The S3 compatible storage provider name, default ('generic').
	// +kubebuilder:validation:Enum=generic;aws;gcp
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

	// The timeout for download operations, defaults to 60s.
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
```

Supported providers:

```go
const (
	GenericBucketProvider string = "generic"
	AmazonBucketProvider  string = "aws"
	GoogleBucketProvider  string = "gcp"
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

	// LastHandledReconcileAt is the last manual reconciliation request (by
	// annotating the Bucket) handled by the reconciler.
	// +optional
	LastHandledReconcileAt string `json:"lastHandledReconcileAt,omitempty"`
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

The following files and extensions are excluded from the archive by default:

- Git files (`.git/ ,.gitignore, .gitmodules, .gitattributes`)
- File extensions (`.jpg, .jpeg, .gif, .png, .wmv, .flv, .tar.gz, .zip`)
- CI configs (`.github/, .circleci/, .travis.yml, .gitlab-ci.yml, appveyor.yml, .drone.yml, cloudbuild.yaml, codeship-services.yml, codeship-steps.yml`)
- CLI configs (`.goreleaser.yml, .sops.yaml`)
- Flux v1 config (`.flux.yaml`)

Excluding additional files from the archive is possible by adding a
`.sourceignore` file in the root of the bucket. The `.sourceignore` file
follows [the `.gitignore` pattern
format](https://git-scm.com/docs/gitignore#_pattern_format), pattern
entries may overrule default exclusions.

Another option is to use the `spec.ignore` field, for example:

```yaml
apiVersion: source.toolkit.fluxcd.io/v1beta1
kind: Bucket
metadata:
  name: podinfo
  namespace: default
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
apiVersion: source.toolkit.fluxcd.io/v1beta1
kind: Bucket
metadata:
  name: podinfo
  namespace: default
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
  namespace: default
type: Opaque
data:
  accesskey: <BASE64> 
  secretkey: <BASE64> 
```

> **Note:** that when using the generic provider
> for Google Cloud Storage you have to enable
> S3 compatible access in your GCP project.

### AWS IAM authentication

When the provider is `aws` and the `secretRef` is not specified,
the credentials are retrieve from the EC2 service:

```yaml
apiVersion: source.toolkit.fluxcd.io/v1beta1
kind: Bucket
metadata:
  name: podinfo
  namespace: default
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

### AWS IAM bucket policy example

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::podinfo/*"
        },
        {
            "Sid": "",
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::podinfo"
        }
    ]
}
```

### GCP Provider

When the provider is `gcp` and the `secretRef` is not specified,
the GCP client authenticates using workload identity.
The GCP client automatically handles authentication in two ways. 
The first way being that the GCP client library will automatically 
check for the presence of the GOOGLE_APPLICATION_CREDENTIAL 
environment variable. If this is not found, the GCP client library 
will search for the Google Application Credential file in the config directory:

```yaml
apiVersion: source.toolkit.fluccd.io/v1beta1
kind: Bucket
metadata:
  name: podinfo
  namespace: gitops-system
spec:
  interval: 5m
  provider: gcp
  bucketName: podinfo
  endpoint: storage.googleapis.com
  region: us-east-1
  timeout: 30s
```

When the provider is `gcp` and the `secretRef` is specified,
the GCP client authenticates using a Kubernetes secret named serviceaccount
which is a base 64 encoded string of the GCP service account JSON file:

```yaml
apiVersion: source.toolkit.fluccd.io/v1beta1
kind: Bucket
metadata:
  name: podinfo
  namespace: gitops-system
spec:
  interval: 5m
  provider: gcp
  bucketName: podinfo
  endpoint: storage.googleapis.com
  region: us-east-1
  timeout: 30s
  secretRef:
    name: gcp-service-account
---
apiVersion: v1
kind: Secret
metadata:
  name: gcp-service-account
  namespace: gitops-system
type: Opaque
data:
  serviceaccount: "ewogICAgInR5cGUiOiAic2VydmljZV9hY2NvdW50IiwKICAgICJwcm9qZWN0X2lkIjogInBvZGluZm8iLAogICAgInByaXZhdGVfa2V5X2lkIjogIjI4cXdnaDNnZGY1aGozZ2I1ZmozZ3N1NXlmZ2gzNGY0NTMyNDU2OGh5MiIsCiAgICAicHJpdmF0ZV9rZXkiOiAiLS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tXG5Id2V0aGd5MTIzaHVnZ2hoaGJkY3U2MzU2ZGd5amhzdmd2R0ZESFlnY2RqYnZjZGhic3g2M2Ncbjc2dGd5Y2ZlaHVoVkdURllmdzZ0N3lkZ3lWZ3lkaGV5aHVnZ3ljdWhland5NnQzNWZ0aHl1aGVndmNldGZcblRGVUhHVHlnZ2h1Ymh4ZTY1eWd0NnRneWVkZ3kzMjZodWN5dnN1aGJoY3Zjc2poY3NqaGNzdmdkdEhGQ0dpXG5IY3llNnR5eWczZ2Z5dWhjaGNzYmh5Z2NpamRiaHl5VEY2NnR1aGNldnVoZGNiaHVoaHZmdGN1aGJoM3VoN3Q2eVxuZ2d2ZnRVSGJoNnQ1cmZ0aGh1R1ZSdGZqaGJmY3JkNXI2N3l1aHV2Z0ZUWWpndnRmeWdoYmZjZHJoeWpoYmZjdGZkZnlodmZnXG50Z3ZnZ3RmeWdodmZ0NnR1Z3ZURjVyNjZ0dWpoZ3ZmcnR5aGhnZmN0Nnk3eXRmcjVjdHZnaGJoaHZ0Z2hoanZjdHRmeWNmXG5mZnhmZ2hqYnZnY2d5dDY3dWpiZ3ZjdGZ5aFZDN3VodmdjeWp2aGhqdnl1amNcbmNnZ2hndmdjZmhnZzc2NTQ1NHRjZnRoaGdmdHloaHZ2eXZ2ZmZnZnJ5eXU3N3JlcmVkc3dmdGhoZ2ZjZnR5Y2ZkcnR0ZmhmL1xuLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLVxuIiwKICAgICJjbGllbnRfZW1haWwiOiAidGVzdEBwb2RpbmZvLmlhbS5nc2VydmljZWFjY291bnQuY29tIiwKICAgICJjbGllbnRfaWQiOiAiMzI2NTc2MzQ2Nzg3NjI1MzY3NDYiLAogICAgImF1dGhfdXJpIjogImh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbS9vL29hdXRoMi9hdXRoIiwKICAgICJ0b2tlbl91cmkiOiAiaHR0cHM6Ly9vYXV0aDIuZ29vZ2xlYXBpcy5jb20vdG9rZW4iLAogICAgImF1dGhfcHJvdmlkZXJfeDUwOV9jZXJ0X3VybCI6ICJodHRwczovL3d3dy5nb29nbGVhcGlzLmNvbS9vYXV0aDIvdjEvY2VydHMiLAogICAgImNsaWVudF94NTA5X2NlcnRfdXJsIjogImh0dHBzOi8vd3d3Lmdvb2dsZWFwaXMuY29tL3JvYm90L3YxL21ldGFkYXRhL3g1MDkvdGVzdCU0MHBvZGluZm8uaWFtLmdzZXJ2aWNlYWNjb3VudC5jb20iCn0="
```

> **Note:** the serviceaccount secret is a base 64 encoded form of
> the GCP service account json file like so

```json
  {
    "type": "service_account",
    "project_id": "podinfo",
    "private_key_id": "28qwgh3gdf5hj3gb5fj3gsu5yfgh34f45324568hy2",
    "private_key": "-----BEGIN PRIVATE KEY-----\nHwethgy123hugghhhbdcu6356dgyjhsvgvGFDHYgcdjbvcdhbsx63c\n76tgycfehuhVGTFYfw6t7ydgyVgydheyhuggycuhejwy6t35fthyuhegvcetf\nTFUHGTygghubhxe65ygt6tgyedgy326hucyvsuhbhcvcsjhcsjhcsvgdtHFCGi\nHcye6tyyg3gfyuhchcsbhygcijdbhyyTF66tuhcevuhdcbhuhhvftcuhbh3uh7t6y\nggvftUHbh6t5rfthhuGVRtfjhbfcrd5r67yuhuvgFTYjgvtfyghbfcdrhyjhbfctfdfyhvfg\ntgvggtfyghvft6tugvTF5r66tujhgvfrtyhhgfct6y7ytfr5ctvghbhhvtghhjvcttfycf\nffxfghjbvgcgyt67ujbgvctfyhVC7uhvgcyjvhhjvyujc\ncgghgvgcfhgg765454tcfthhgftyhhvvyvvffgfryyu77reredswfthhgfcftycfdrttfhf/\n-----END PRIVATE KEY-----\n",
    "client_email": "test@podinfo.iam.gserviceaccount.com",
    "client_id": "32657634678762536746",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test%40podinfo.iam.gserviceaccount.com"
  }
```
> **Note:** that when using the gcp provider for
> Google Cloud Storage you do not have to enable
> S3 compatible access in your GCP project.

## Status examples

Successful download:

```yaml
  status:
    artifact:
      checksum: b249024b8544521792a079c4037d0a06dd0497a9
      lastUpdateTime: "2020-09-18T08:34:49Z"
      path: bucket/source-system/podinfo/aeaba8b6dd51c53084f99b098cfae4f5148ad410.tar.gz
      revision: aeaba8b6dd51c53084f99b098cfae4f5148ad410
      url: http://localhost:9090/bucket/source-system/podinfo/aeaba8b6dd51c53084f99b098cfae4f5148ad410.tar.gz
    conditions:
    - lastTransitionTime: "2020-09-18T08:34:49Z"
      message: 'Fetched revision: aeaba8b6dd51c53084f99b098cfae4f5148ad410'
      reason: BucketOperationSucceed
      status: "True"
      type: Ready
    observedGeneration: 2
    url: http://localhost:9090/bucket/source-system/podinfo/latest.tar.gz
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
