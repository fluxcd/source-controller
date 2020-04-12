# Helm Repositories

The Helm source API defines two sources for artifact coming from Helm:
`HelmRepository` and `HelmChart`.

## Specification

### Helm repository

```go
// HelmRepository defines the reference to a Helm repository.
type HelmRepositorySpec struct {
	// The Helm repository URL, a valid URL contains at least a
	// protocol and host.
    // +required
	URL string `json:"url"`
    
	// The name of the secret containing authentication credentials
	// for the Helm repository.
	// +optional
	SecretRef *v1.LocalObjectReference `json:"secretRef,omitempty"`

	// The interval at which to check the upstream for updates.
	// +required
	Interval metav1.Duration `json:"interval"`
}
```

#### Helm repository status

```go
// HelmRepositoryStatus defines the observed state of HelmRepository
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

#### Helm repository condition reasons

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

### Helm chart

```go
// HelmChart defines the desired state of a Helm chart.
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
	HelmRepositoryRef v1.LocalObjectReference `json:"helmRepositoryRef"`

	// The interval at which to check the Helm repository for updates.
	// Defaults to the interval of the Helm repository.
	// +optional
	Interval metav1.Duration `json:"interval,omitempty"`
}
```

#### Helm chart status

```go
// HelmChartStatus defines the observed state of the HelmChart.
type HelmRepositoryStatus struct {
	// +optional
	Conditions []SourceCondition `json:"conditions,omitempty"`

	// URL is the download link for the last chart fetched.
	// +optional
	URL string `json:"url,omitempty"`

	// Artifact represents the output of the last successful sync.
	// +optional
	Artifact *Artifact `json:"artifact,omitempty"`
}
```

#### Helm chart condition reasons

```go
const (
	// ChartPullFailedReason represents the fact that the pull of the
	// given Helm chart failed.
	ChartPullFailedReason  string = "ChartPullFailed"
	// ChartPullSucceededReason represents the fact that the pull of
	// the given Helm chart succeeded.
	ChartPullSucceedReason string = "ChartPullSucceeded"
)
```

## Spec examples

### Helm repository

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
  username:              <BASE64> 
  password:              <BASE64>
  certFile:              <BASE64>
  keyFile:               <BASE64>
  caFile:                <BASE64>
  insecureSkipTLSVerify: <base64>
```

### Helm chart

Pinned version:

```yaml
apiVersion: source.fluxcd.io/v1alpha1
kind: HelmChart
metadata:
  name: redis
  namespace: default
  annotations:
    # force sync trigger
    source.fluxcd.io/syncAt: "2020-04-06T15:39:52+03:00"
spec:
  name: redis
  version: 10.5.7
  helmRepositoryRef:
    name: stable
```

Semver range:

```yaml
apiVersion: source.fluxcd.io/v1alpha1
kind: HelmChart
metadata:
  name: redis
  namespace: default
spec:
  name: redis
  version: ^10.0.0
  helmRepositoryRef:
    name: stable
```

Interval:

```yaml
apiVersion: source.fluxcd.io/v1alpha1
kind: HelmChart
metadata:
  name: redis
  namespace: default
spec:
  name: redis
  version: ^10.0.0
  helmRepositoryRef:
    name: stable
  interval: 30m
```

## Status examples

### Helm repository

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

### Helm chart

Successful chart pull:

```yaml
status:
  url: http://<host>/helmcharts/redis-default/redis-10.5.7.tgz
  conditions:
    - lastTransitionTime: "2020-04-10T09:34:45Z"
      message: Fetched artifact are available at /data/helmcharts/redis-default/redis-10.5.7.tgz
      reason: ChartPullSucceeded
      status: "True"
      type: Ready
```

Failed chart pull:

```yaml
status:
  conditions:
    - lastTransitionTime: "2020-04-10T09:34:45Z"
      message: ''
      reason: ChartPullFailed
      status: "False"
      type: Ready
```
