# Helm Charts

The `HelmChart` API defines a source for Helm chart artifacts coming
from [`HelmRepository` sources](helmrepositories.md). The resource
exposes the latest pulled or packaged chart as an artifact.

## Specification

Helm chart:

```go
// HelmChartSpec defines the desired state of a Helm chart.
type HelmChartSpec struct {
	// The name or path the Helm chart is available at in the SourceRef.
	// +required
	Chart string `json:"chart"`

	// The chart version semver expression, ignored for charts from GitRepository
	// and Bucket sources. Defaults to latest when omitted.
	// +optional
	Version string `json:"version,omitempty"`

	// The reference to the Source the chart is available at.
	// +required
	SourceRef LocalHelmChartSourceReference `json:"sourceRef"`

	// The interval at which to check the Source for updates.
	// +required
	Interval metav1.Duration `json:"interval"`

	// Determines what enables the creation of a new artifact. Valid values are
	// ('ChartVersion', 'Revision').
	// See the documentation of the values for an explanation on their behavior.
	// Defaults to ChartVersion when omitted.
	// +kubebuilder:validation:Enum=ChartVersion;Revision
	// +kubebuilder:default:=ChartVersion
	// +optional
	ReconcileStrategy string `json:"reconcileStrategy,omitempty"`

	// Alternative list of values files to use as the chart values (values.yaml
	// is not included by default), expected to be a relative path in the SourceRef.
	// Values files are merged in the order of this list with the last file overriding
	// the first. Ignored when omitted.
	// +optional
	ValuesFiles []string `json:"valuesFiles,omitempty"`

	// Alternative values file to use as the default chart values, expected to
	// be a relative path in the SourceRef. Deprecated in favor of ValuesFiles,
	// for backwards compatibility the file defined here is merged before the
	// ValuesFiles items. Ignored when omitted.
	// +optional
	// +deprecated
	ValuesFile string `json:"valuesFile,omitempty"`

	// This flag tells the controller to suspend the reconciliation of this source.
	// +optional
	Suspend bool `json:"suspend,omitempty"`
}
```

### Reconciliation strategies

```go
const (
	// ReconcileStrategyChartVersion creates a new chart artifact when the version of the Helm chart is different.
	ReconcileStrategyChartVersion string = "ChartVersion"

	// ReconcileStrategyRevision creates a new chart artifact when the Revision of the SourceRef is different.
	ReconcileStrategyRevision string = "Revision"
)
```

### Reference types

```go
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
```

### Status

```go
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

	// LastHandledReconcileAt is the last manual reconciliation request (by
	// annotating the HelmChart) handled by the reconciler.
	// +optional
	LastHandledReconcileAt string `json:"lastHandledReconcileAt,omitempty"`
}
```

### Condition reasons

```go
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
```

## Spec examples

Pull a specific chart version every five minutes:

```yaml
apiVersion: source.toolkit.fluxcd.io/v1beta1
kind: HelmChart
metadata:
  name: redis
  namespace: default
spec:
  chart: redis
  version: 10.5.7
  sourceRef:
    name: stable
    kind: HelmRepository
  interval: 5m
```

Pull the latest chart version that matches the [semver range](https://github.com/Masterminds/semver#checking-version-constraints)
every ten minutes:

```yaml
apiVersion: source.toolkit.fluxcd.io/v1beta1
kind: HelmChart
metadata:
  name: redis
  namespace: default
spec:
  chart: redis
  version: 10.5.x
  sourceRef:
    name: stable
    kind: HelmRepository
  interval: 10m
```

Check a Git repository every ten minutes for a new `version` in the
`Chart.yaml`, and package a new chart if the revision differs:

```yaml
apiVersion: source.toolkit.fluxcd.io/v1beta1
kind: HelmChart
metadata:
  name: podinfo
  namespace: default
spec:
  chart: ./charts/podinfo
  sourceRef:
    name: podinfo
    kind: GitRepository
  interval: 10m
```

Check a S3 compatible bucket every ten minutes for a new `version` in the
`Chart.yaml`, and package a new chart if the revision differs:

```yaml
apiVersion: source.toolkit.fluxcd.io/v1beta1
kind: HelmChart
metadata:
  name: podinfo
  namespace: default
spec:
  chart: ./podinfo
  sourceRef:
    name: charts
    kind: Bucket
  interval: 10m
```

Override default values with alternative values files relative to the
path in the SourceRef:

```yaml
apiVersion: source.toolkit.fluxcd.io/v1beta1
kind: HelmChart
metadata:
  name: redis
  namespace: default
spec:
  chart: redis
  version: 10.5.7
  sourceRef:
    name: stable
    kind: HelmRepository
  interval: 5m
  valuesFiles:
    - values.yaml
    - values-production.yaml
```

```yaml
apiVersion: source.toolkit.fluxcd.io/v1beta1
kind: HelmChart
metadata:
  name: podinfo
  namespace: default
spec:
  chart: ./charts/podinfo
  sourceRef:
    name: podinfo
    kind: GitRepository
  interval: 10m
  valuesFiles:
    - ./charts/podinfo/values.yaml
    - ./charts/podinfo/values-production.yaml
```

Reconcile with every change to the source revision:

```yaml
apiVersion: source.toolkit.fluxcd.io/v1beta1
kind: HelmChart
metadata:
  name: podinfo
  namespace: default
spec:
  chart: ./charts/podinfo
  sourceRef:
    name: podinfo
    kind: GitRepository
  interval: 10m
  reconcileStrategy: Revision
```

## Status examples

Successful chart pull:

```yaml
status:
  url: http://<host>/helmchart/default/redis/redis-10.5.7.tgz
  conditions:
    - lastTransitionTime: "2020-04-10T09:34:45Z"
      message: Helm chart is available at /data/helmchart/default/redis/redis-10.5.7.tgz
      reason: ChartPullSucceeded
      status: "True"
      type: Ready
```

Failed chart pull:

```yaml
status:
  conditions:
    - lastTransitionTime: "2020-04-10T09:34:45Z"
      message: 'invalid chart URL format'
      reason: ChartPullFailed
      status: "False"
      type: Ready
```

Wait for ready condition:

```bash
kubectl wait helmchart/redis --for=condition=ready --timeout=1m
```
