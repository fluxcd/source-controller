# Helm Repositories

The `HelmRepository` API defines a source for Helm repositories.
The resource exposes the latest synchronized repository index as
an artifact.

## Specification

Helm repository:

```go
// HelmRepositorySpec defines the reference to a Helm repository.
type HelmRepositorySpec struct {
	// The Helm repository URL, a valid URL contains at least a protocol and host.
	// +required
	URL string `json:"url"`

	// The name of the secret containing authentication credentials for the Helm
	// repository.
	// For HTTP/S basic auth the secret must contain username and
	// password fields.
	// For TLS the secret must contain a certFile and keyFile, and/or
	// caFile fields.
	// +optional
	SecretRef *corev1.LocalObjectReference `json:"secretRef,omitempty"`

	// PassCredentials allows the credentials from the SecretRef to be passed on to
	// a host that does not match the host as defined in URL.
	// This may be required if the host of the advertised chart URLs in the index
	// differ from the defined URL.
	// Enabling this should be done with caution, as it can potentially result in
	// credentials getting stolen in a MITM-attack.
	// +optional
	PassCredentials bool `json:"passCredentials,omitempty"`

	// The interval at which to check the upstream for updates.
	// +required
	Interval metav1.Duration `json:"interval"`

	// The timeout of index downloading, defaults to 60s.
	// +optional
	Timeout *metav1.Duration `json:"timeout,omitempty"`

	// This flag tells the controller to suspend the reconciliation of this source.
	// +optional
	Suspend bool `json:"suspend,omitempty"`
}
```

### Status

```go
// HelmRepositoryStatus defines the observed state of the HelmRepository.
type HelmRepositoryStatus struct {
	// ObservedGeneration is the last observed generation.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions holds the conditions for the HelmRepository.
	// +optional
	Conditions []meta.Condition `json:"conditions,omitempty"`

	// URL is the download link for the last index fetched.
	// +optional
	URL string `json:"url,omitempty"`

	// Artifact represents the output of the last successful repository sync.
	// +optional
	Artifact *Artifact `json:"artifact,omitempty"`

	// LastHandledReconcileAt is the last manual reconciliation request (by
	// annotating the HelmRepository) handled by the reconciler.
	// +optional
	LastHandledReconcileAt string `json:"lastHandledReconcileAt,omitempty"`
}
```

### Condition reasons

```go
const (
	// IndexationFailedReason represents the fact that the indexation of the given
	// Helm repository failed.
	IndexationFailedReason string = "IndexationFailed"

	// IndexationSucceededReason represents the fact that the indexation of the
	// given Helm repository succeeded.
	IndexationSucceededReason string = "IndexationSucceed"
)
```

## Spec examples

Pull the index of a public Helm repository every ten minutes:

```yaml
apiVersion: source.werf.io/v1beta1
kind: HelmRepository
metadata:
  name: stable
  namespace: default
spec:
  url: https://kubernetes-charts.storage.googleapis.com/
  interval: 10m
```

Pull the index of a private Helm repository every minute:

```yaml
apiVersion: source.werf.io/v1beta1
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
  url: http://<host>/helmrepository/default/stable/index.yaml
  conditions:
    - lastTransitionTime: "2020-04-10T09:34:45Z"
      message: Helm repository index is available at /data/helmrepository/default/stable/index-21c195d78e699e4b656e2885887d019627838993.yaml
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

Wait for ready condition:

```bash
kubectl wait helmrepository/stable --for=condition=ready --timeout=1m
```
