# Helm Charts

The `HelmChart` API defines a Source to produce an Artifact for a Helm chart
archive with a set of specific configurations.

## Example

The following is an example of a HelmChart. It fetches and/or packages a Helm
chart and exposes it as a tarball (`.tgz`) Artifact for the specified
configuration:

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: HelmChart
metadata:
  name: podinfo
  namespace: default
spec:
  interval: 5m0s
  chart: podinfo
  reconcileStrategy: ChartVersion
  sourceRef:
    kind: HelmRepository
    name: podinfo
  version: '5.*'
```

In the above example:

- A HelmChart named `podinfo` is created, indicated by the `.metadata.name`
  field.
- The source-controller fetches the Helm chart every five minutes from the
  `podinfo` HelmRepository source reference, indicated by the
  `.spec.sourceRef.kind` and `.spec.sourceRef.name` fields.
- The fetched Helm chart version is the latest available chart
  version in the range specified in `spec.version`. This version is also used as
  Artifact revision, reported in-cluster in the `.status.artifact.revision`
  field.
- When the current Helm Chart version differs from the latest available chart
  in the version range, it is fetched and/or packaged as a new Artifact.
- The new Artifact is reported in the `.status.artifact` field.

You can run this example by saving the manifest into `helmchart.yaml`.

**NOTE:** HelmChart is usually used by the helm-controller. Based on the
HelmRelease configuration, an associated HelmChart is created by the 
helm-controller.

1. Apply the resource on the cluster:

   ```sh
   kubectl apply -f helmchart.yaml
   ```

2. Run `kubectl get helmchart` to see the HelmChart:

   ```console
   NAME      CHART     VERSION   SOURCE KIND      SOURCE NAME   READY   STATUS                                        AGE
   podinfo   podinfo   5.*       HelmRepository   podinfo       True    pulled 'podinfo' chart with version '5.2.1'   53s
   ```

3. Run `kubectl describe helmchart podinfo` to see the [Artifact](#artifact) and
   [Conditions](#conditions) in the HelmChart's Status:

   ```console
   Status:
     Observed Source Artifact Revision:  83a3c595163a6ff0333e0154c790383b5be441b9db632cb36da11db1c4ece111
     Artifact:
       Checksum:          6c3cc3b955bce1686036ae6822ee2ca0ef6ecb994e3f2d19eaf3ec03dcba84b3
       Last Update Time:  2022-02-13T11:24:10Z
       Path:              helmchart/default/podinfo/podinfo-5.2.1.tgz
       Revision:          5.2.1
       URL:               http://source-controller.flux-system.svc.cluster.local./helmchart/default/podinfo/podinfo-5.2.1.tgz
     Conditions:
       Last Transition Time:  2022-02-13T11:24:10Z
       Message:               pulled 'podinfo' chart with version '5.2.1'
       Observed Generation:   1
       Reason:                ChartPullSucceeded
       Status:                True
       Type:                  Ready
     Observed Chart Name:     podinfo
     Observed Generation:     1
     URL:                     http://source-controller.flux-system.svc.cluster.local./helmchart/default/podinfo/latest.tar.gz
   Events:
     Type    Reason              Age    From               Message
     ----    ------              ----   ----               -------
     Normal  ChartPullSucceeded  2m51s  source-controller  pulled 'podinfo' chart with version '5.2.1'
   ```

## Writing a HelmChart spec

As with all other Kubernetes config, a HelmChart needs `apiVersion`, `kind`, and
`metadata` fields. The name of a HelmChart object must be a valid 
[DNS subdomain name](https://kubernetes.io/docs/concepts/overview/working-with-objects/names#dns-subdomain-names).

A HelmChart also needs a
[`.spec` section](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status).

### Interval

`.spec.interval` is a required field that specifies the interval at which the
Helm Chart source must be checked for updates.

After successfully reconciling a HelmChart object, the source-controller
requeues the object for inspection after the specified interval. The value must
be in a [Go recognized duration string format](https://pkg.go.dev/time#ParseDuration),
e.g. `10m0s` to look at the source for updates every 10 minutes.

If the `.metadata.generation` of a resource changes (due to e.g. applying a
change to the spec), this is handled instantly outside the interval window.

### Source reference

`.spec.sourceRef` is a required field that specifies a reference to the Source
the chart is available at. `.spec.sourceRef.kind` must be one of
`HelmRepository`, `GitRepository` or `Bucket`. `.spec.sourceRef.name` is the
name of the referred kind.

### Chart

`.spec.chart` is a required field that specifies the name or path the Helm chart
is available at in the [Source reference](#source-reference). For HelmRepository
Source reference, it'll be just the name of the chart. For GitRepository and
Bucket Source reference, it'll be the path to the Helm chart directory.

### Version

`.spec.version` is an optional field to specify the version of the chart in
semver. It is applicable only when the Source reference is a HelmRepository. It
is ignored for GitRepository and Bucket Source reference. It defaults to the
latest version of the chart with value `*`.

### Values files

`.spec.valuesFiles` is an optional field to specify an alternative list of
values files to use as the chart values (values.yaml). The file paths are
expected to be relative to the Source reference. Values files are merged in the
order of the list with the last file overriding the first. It is ignored when
omitted.

### Reconcile strategy

`.spec.reconcileStrategy` is an optional field to specify what enables the
creation of a new Artifact. Valid values are `ChartVersion` and `Revision`.
`ChartVersion` is used for creating a new artifact when the chart version
changes in the HelmRepository. `Revision` is used for creating a new artifact
when the source revision changes in GitRepository or Bucket Source references.
It defaults to `ChartVersion`.

### Suspend

`.spec.suspend` is an optional field to suspend the reconciliation of a
HelmChart. When set to `true`, the controller will stop reconciling the
HelmChart, and changes to the resource or the Helm chart Source will not result
in a new Artifact. When the field is set to `false` or removed, it will resume.

For practical information, see
[suspending and resuming](#suspending-and-resuming).

## Working with HelmCharts

### Triggering a reconcile

To manually tell the source-controller to reconcile a HelmChart outside the
[specified interval window](#interval), a HelmCHart can be annotated with
`reconcile.fluxcd.io/requestedAt: <arbitrary value>`. Annotating the resource
queues the object for reconciliation if the `<arbitrary-value>` differs from
the last value the controller acted on, as reported in
[`.status.lastHandledReconcileAt`](#last-handled-reconcile-at).

Using `kubectl`:

```sh
kubectl annotate --overwrite helmchart/<chart-name> reconcile.fluxcd.io/requestedAt="$(date +%s)"
```

### Waiting for `Ready`

When a change is applied, it is possible to wait for the HelmChart to reach a
[ready state](#ready-helmchart) using `kubectl`:

```sh
kubectl wait helmchart/<chart-name> --for=condition=ready --timeout=1m
```

### Suspending and resuming

When you find yourself in a situation where you temporarily want to pause the
reconciliation of a HelmChart, you can suspend it using the
[`.spec.suspend` field](#suspend).

#### Suspend a HelmChart

In your YAML declaration:

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: HelmChart
metadata:
  name: <chart-name>
spec:
  suspend: true
```

Using `kubectl`:

```sh
kubectl patch helmchart <chart-name> -p '{\"spec\": {\"suspend\" : true }}'
```

**Note:** When a HelmChart has an Artifact and is suspended, and this
Artifact later disappears from the storage due to e.g. the source-controller
Pod being evicted from a Node, this will not be reflected in the
HelmChart's Status until it is resumed.

#### Resume a HelmChart

In your YAML declaration, comment out (or remove) the field:

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: HelmChart
metadata:
  name: <chart-name>
spec:
  # suspend: true
```

**Note:** Setting the field value to `false` has the same effect as removing
it, but does not allow for "hot patching" using e.g. `kubectl` while practicing
GitOps; as the manually applied patch would be overwritten by the declared
state in Git.

Using `kubectl`:

```sh
kubectl patch helmchart <chart-name> -p '{\"spec\" : {\"suspend\" : false }}'
```

### Debugging a HelmChart

There are several ways to gather information about a HelmChart for debugging
purposes.

#### Describe the HelmChart

Describing a HelmChart using `kubectl describe helmchart <chart-name>` displays
the latest recorded information for the resource in the `Status` and `Events`
sections:

```console
...
Status:
...
  Conditions:
    Last Transition Time:     2022-02-13T14:06:27Z
    Message:                  invalid chart reference: failed to get chart version for remote reference: no 'podinfo' chart with version matching '9.*' found
    Observed Generation:      3
    Reason:                   InvalidChartReference
    Status:                   True
    Type:                     Stalled
    Last Transition Time:     2022-02-13T14:06:27Z
    Message:                  invalid chart reference: failed to get chart version for remote reference: no 'podinfo' chart with version matching '9.*' found
    Observed Generation:      3
    Reason:                   InvalidChartReference
    Status:                   False
    Type:                     Ready
    Last Transition Time:     2022-02-13T14:06:27Z
    Message:                  invalid chart reference: failed to get chart version for remote reference: no 'podinfo' chart with version matching '9.*' found
    Observed Generation:      3
    Reason:                   InvalidChartReference
    Status:                   True
    Type:                     FetchFailed
  Last Handled Reconcile At:  1644759954
  Observed Chart Name:        podinfo
  Observed Generation:        3
  URL:                        http://source-controller.flux-system.svc.cluster.local./helmchart/default/podinfo/latest.tar.gz
Events:
  Type     Reason                      Age                  From               Message
  ----     ------                      ----                 ----               -------
  Warning  InvalidChartReference       11s                  source-controller  invalid chart reference: failed to get chart version for remote reference: no 'podinfo' chart with ver
sion matching '9.*' found
```

#### Trace emitted Events

To view events for specific HelmChart(s), `kubectl get events` can be used in
combination with `--field-selector` to list the Events for specific objects.
For example, running

```sh
kubectl get events --field-selector involvedObject.kind=HelmChart,involvedObject.name=<chart-name>
```

lists

```console
LAST SEEN   TYPE      REASON                       OBJECT                   MESSAGE
22s         Warning   InvalidChartReference        helmchart/<chart-name>   invalid chart reference: failed to get chart version for remote reference: no 'podinfo' chart with version matching '9.*' found
2s          Normal    ChartPullSucceeded           helmchart/<chart-name>   pulled 'podinfo' chart with version '6.0.3'
```

Besides being reported in Events, the reconciliation errors are also logged by
the controller. The Flux CLI offer commands for filtering the logs for a
specific HelmChart, e.g. `flux logs --level=error --kind=HelmChart --name=<chart-name>`.

## HelmChart Status

### Artifact

The HelmChart reports the last built chart as an Artifact object in the
`.status.artifact` of the resource.

The Artifact file is a gzip compressed TAR archive (`<chart-name>-<chart-version>.tgz`),
and can be retrieved in-cluster from the `.status.artifact.url` HTTP address.

### Artifact example

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: HelmChart
metadata:
  name: <chart-name>
status:
  artifact:
    checksum: e30b95a08787de69ffdad3c232d65cfb131b5b50c6fd44295f48a078fceaa44e
    lastUpdateTime: "2022-02-10T18:53:47Z"
    path: helmchart/<source-namespace>/<chart-name>/<chart-name>-<chart-version>.tgz
    revision: 6.0.3
    url: http://source-controller.flux-system.svc.cluster.local./helmchart/<source-namespace>/<chart-name>/<chart-name>-<chart-version>.tgz
```

### Conditions

A HelmChart enters various states during its lifecycle, reflected as [Kubernetes
Conditions][typical-status-properties].
It can be [reconciling](#reconciling-helmchart) while fetching or building the
chart,  it can be [ready](#ready-helmchart), it can
[fail during reconciliation](#failed-helmchart), or it can
[stall](#stalled-helmchart).

The HelmChart API is compatible with the [kstatus
specification][kstatus-spec],
and reports `Reconciling` and `Stalled` conditions where applicable to
provide better (timeout) support to solutions polling the HelmChart to become
`Ready`.

#### Reconciling HelmChart

The source-controller marks a HelmChart as _reconciling_ when one of the
following is true:

- There is no current Artifact for the HelmChart, or the reported Artifact is
  determined to have disappeared from the storage.
- The generation of the HelmChart is newer than the [Observed
  Generation](#observed-generation).
- The newly fetched Artifact revision differs from the current Artifact.

When the HelmChart is "reconciling", the `Ready` Condition status becomes
`False`, and the controller adds a Condition with the following attributes to
the HelmChart's `.status.conditions`:

- `type: Reconciling`
- `status: "True"`
- `reason: NewGeneration` | `reason: NoArtifact`

If the reconciling state is due to a new version, it adds an additional
Condition with the following attributes:

- `type: ArtifactOutdated`
- `status: "True"`
- `reason: NewChart`

Both Conditions have a ["negative polarity"][typical-status-properties],
and are only present on the HelmChart while their status value is `"True"`.

#### Ready HelmChart

The source-controller marks a HelmChart as _ready_ when it has the following
characteristics:

- The HelmChart reports an [Artifact](#artifact).
- The reported Artifact exists in the controller's Artifact storage.
- The controller was able to fetch and build the Helm chart using the current
  spec.
- The version/revision of the reported Artifact is up-to-date with the
  latest version/revision of the Helm chart.

When the HelmChart is "ready", the controller sets a Condition with the
following attributes in the HelmChart's `.status.conditions`:

- `type: Ready`
- `status: "True"`
- `reason: Succeeded`

This `Ready` Condition will retain a status value of `"True"` until the
HelmChart is marked as [reconciling](#reconciling-helmchart), or e.g.
a [transient error](#failed-helmchart) occurs due to a temporary network issue.

#### Failed HelmChart

The source-controller may get stuck trying to produce an Artifact for a
HelmChart without completing. This can occur due to some of the following
factors:

- The Helm chart Source is temporarily unavailable.
- The credentials in the [Source reference](#source-reference) Secret are
  invalid.
- The HelmChart spec contains a generic misconfiguration.

When this happens, the controller sets the `Ready` Condition status to `False`,
and adds a Condition with the following attributes to the HelmChart's
`.status.conditions`:

- `type: FetchFailed`
- `status: "True"`
- `reason: AuthenticationFailed` | `reason: StorageOperationFailed` | `reason: URLInvalid` | `reason: IllegalPath` | `reason: Failed`

This condition has a ["negative polarity"][typical-status-properties],
and is only present on the HelmChart while the status value is `"True"`.

While the HelmChart has this Condition, the controller will continue to
attempt to produce an Artifact for the resource with an exponential backoff,
until it succeeds and the HelmChart is marked as [ready](#ready-helmchart).

Note that a HelmChart can be [reconciling](#reconciling-helmchart)
while failing at the same time, for example due to a newly introduced
configuration issue in the HelmChart spec.

#### Stalled HelmChart

The source-controller can mark a HelmChart as _stalled_ when it determines that
without changes to the spec, the reconciliation can not succeed.
For example because a HelmChart Version is set to a non-existing version.

When this happens, the controller sets the same Conditions as when it
[fails](#failed-helmchart), but adds another Condition with the following
attributes to the HelmChart's `.status.conditions`:

- `type: Stalled`
- `status: "True"`
- `reason: InvalidChartReference`

While the HelmChart has this Condition, the controller will not requeue the
resource any further, and will stop reconciling the resource until a change to
the spec is made.

### Observed Source Artifact Revision

The source-controller reports the revision of the
[Source reference's](#source-reference) Artifact the current chart was fetched
from in the HelmChart's `.status.observedSourceArtifactRevision`.

### Observed Chart Name

The source-controller reports the resolved chart name of the current Artifact
for the [`.spec.chart` field](#chart) in the HelmChart's
`.status.observedChartName`.

### Observed Generation

The source-controller reports an [observed generation][typical-status-properties]
in the HelmChart's `.status.observedGeneration`. The observed generation is the
latest `.metadata.generation` which resulted in either a [ready state](#ready-helmchart),
or stalled due to error it can not recover from without human
intervention.

### Last Handled Reconcile At

The source-controller reports the last `reconcile.fluxcd.io/requestedAt`
annotation value it acted on in the `.status.lastHandledReconcileAt` field.

For practical information about this field, see [triggering a
reconcile](#triggering-a-reconcile).

[typical-status-properties]: https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties
[kstatus-spec]: https://github.com/kubernetes-sigs/cli-utils/tree/master/pkg/kstatus
