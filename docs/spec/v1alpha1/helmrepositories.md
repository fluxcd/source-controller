# Helm Repositories

The `HelmRepository` API defines a source for Helm repositories.
The resource exposes the latest synchronized repository index as
an artifact.

## Specification

Helm repository:

```go
// HelmRepository defines the reference to a Helm repository.
type HelmRepositorySpec struct {
	// The Helm repository URL, a valid URL contains at least a
	// protocol and host.
    // +required
	URL string `json:"url"`
    
	// The name of the secret containing authentication credentials
	// for the Helm repository.
	// For HTTP/S basic auth the secret must contain username and password
	// fields.
	// For TLS the secret must contain caFile, keyFile and caCert fields.
	// +optional
	SecretRef *v1.LocalObjectReference `json:"secretRef,omitempty"`

	// The interval at which to check the upstream for updates.
	// +required
	Interval metav1.Duration `json:"interval"`
}
```

### Status

```go
// HelmRepositoryStatus defines the observed state of the HelmRepository.
type HelmRepositoryStatus struct {
	// +optional
	Conditions []SourceCondition `json:"conditions,omitempty"`

	// URL is the download link for the last index fetched.
	// +optional
	URL string `json:"url,omitempty"`

	// Artifact represents the output of the last successful repository sync.
	// +optional
	Artifact *Artifact `json:"artifact,omitempty"`
}
```

### Condition reasons

```go
const (
	// IndexationFailedReason represents the fact that the indexation
	// of the given Helm repository failed.
	IndexationFailedReason  string = "IndexationFailed"

	// IndexationSucceededReason represents the fact that the indexation
	// of the given Helm repository succeeded.
	IndexationSucceedReason string = "IndexationSucceed"
)
```

## Spec examples

Public Helm repository:

```yaml
apiVersion: source.fluxcd.io/v1alpha1
kind: HelmRepository
metadata:
  name: stable
  namespace: default
  annotations:
    # force sync trigger
    source.fluxcd.io/syncAt: "2020-04-06T15:39:52+03:00"
spec:
  url: https://kubernetes-charts.storage.googleapis.com/
  interval: 1m
```

Private Helm repository:

```yaml
apiVersion: source.fluxcd.io/v1alpha1
kind: HelmRepository
metadata:
  name: private
  namespace: default
spec:
  url: https://charts.example.com
  secretRef:
    name: https-credentials
  interval: 1m
---
apiVersion: v1
kind: Secret
metadata:
  name: https-credentials
  namespace: default
type: Opaque
data:
  username: <BASE64> 
  password: <BASE64>
  certFile: <BASE64>
  keyFile:  <BASE64>
  caFile:   <BASE64>
```

## Status examples

Successful indexation:

```yaml
status:
  url: http://<host>/helmrepository/podinfo-default/index.yaml
  conditions:
    - lastTransitionTime: "2020-04-10T09:34:45Z"
      message: Fetched artifact are available at /data/helmrepositories/podinfo-default/index-21c195d78e699e4b656e2885887d019627838993.yaml
      reason: IndexationSucceeded
      status: "True"
      type: Ready
```

Failed indexation:

```yaml
status:
  conditions:
  - lastTransitionTime: "2020-04-10T09:27:21Z"
    message: 'failed to fetch https://invalid.example.com/index.yaml : 404 Not Found'
    reason: IndexationFailed
    status: "False"
    type: Ready
```

Invalid repository URL:

```yaml
status:
  conditions:
  - lastTransitionTime: "2020-04-10T09:27:21Z"
    message: scheme "invalid" not supported
    reason: URLInvalid
    status: "False"
    type: Ready
```
