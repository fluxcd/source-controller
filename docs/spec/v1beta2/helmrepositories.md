# Helm Repositories

There are 2 [Helm repository types](#type) defined by the `HelmRepository` API:
- Helm HTTP/S repository, which defines a Source to produce an Artifact for a Helm
repository index YAML (`index.yaml`). 
- OCI Helm repository, which defines a source that does not produce an Artifact. 
Instead a validation of the Helm repository is performed and the outcome is reported in the
`.status.conditions` field.

## Examples

### Helm HTTP/S repository

The following is an example of a HelmRepository. It creates a YAML (`.yaml`)
Artifact from the fetched Helm repository index (in this example the [podinfo
repository](https://github.com/stefanprodan/podinfo)):

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: HelmRepository
metadata:
  name: podinfo
  namespace: default
spec:
  interval: 5m0s
  url: https://stefanprodan.github.io/podinfo
```

In the above example:

- A HelmRepository named `podinfo` is created, indicated by the
  `.metadata.name` field.
- The source-controller fetches the Helm repository index YAML every five
  minutes from `https://stefanprodan.github.io/podinfo`, indicated by the
  `.spec.interval` and `.spec.url` fields.
- The SHA256 sum of the Helm repository index after stable sorting the entries
  is used as Artifact revision, reported in-cluster in the
  `.status.artifact.revision` field.
- When the current HelmRepository revision differs from the latest fetched 
  revision, it is stored as a new Artifact.
- The new Artifact is reported in the `.status.artifact` field.

You can run this example by saving the manifest into `helmrepository.yaml`.

1. Apply the resource on the cluster:

   ```sh
   kubectl apply -f helmrepository.yaml
   ```

2. Run `kubectl get helmrepository` to see the HelmRepository:

   ```console
   NAME      URL                                      AGE   READY   STATUS                                                                                         
   podinfo   https://stefanprodan.github.io/podinfo   4s    True    stored artifact for revision '83a3c595163a6ff0333e0154c790383b5be441b9db632cb36da11db1c4ece111'
   ```

3. Run `kubectl describe helmrepository podinfo` to see the [Artifact](#artifact)
   and [Conditions](#conditions) in the HelmRepository's Status:

   ```console
   ...
   Status:
     Artifact:
       Checksum:          83a3c595163a6ff0333e0154c790383b5be441b9db632cb36da11db1c4ece111
       Last Update Time:  2022-02-04T09:55:58Z
       Path:              helmrepository/default/podinfo/index-83a3c595163a6ff0333e0154c790383b5be441b9db632cb36da11db1c4ece111.yaml
       Revision:          83a3c595163a6ff0333e0154c790383b5be441b9db632cb36da11db1c4ece111
       URL:               http://source-controller.flux-system.svc.cluster.local./helmrepository/default/podinfo/index-83a3c595163a6ff0333e0154c790383b5be441b9db632cb36da11db1c4ece111.yaml
     Conditions:
       Last Transition Time:  2022-02-04T09:55:58Z
       Message:               stored artifact for revision '83a3c595163a6ff0333e0154c790383b5be441b9db632cb36da11db1c4ece111'
       Observed Generation:   1
       Reason:                Succeeded
       Status:                True
       Type:                  Ready
       Last Transition Time:  2022-02-04T09:55:58Z
       Message:               stored artifact for revision '83a3c595163a6ff0333e0154c790383b5be441b9db632cb36da11db1c4ece111'
       Observed Generation:   1
       Reason:                Succeeded
       Status:                True
       Type:                  ArtifactInStorage
     Observed Generation:     1
     URL:                     http://source-controller.flux-system.svc.cluster.local./helmrepository/default/podinfo/index.yaml
   Events:
     Type    Reason                      Age                From               Message
     ----    ------                      ----               ----               -------
     Normal  NewArtifact                 1m                 source-controller  fetched index of size 30.88kB from 'https://stefanprodan.github.io/podinfo'
   ```

### Helm OCI repository

The following is an example of an OCI HelmRepository.

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: HelmRepository
metadata:
  name: podinfo
  namespace: default
spec:
  type: "oci"
  interval: 5m0s
  url: oci://ghcr.io/stefanprodan/charts
```

In the above example:

- A HelmRepository named `podinfo` is created, indicated by the
  `.metadata.name` field.
- The source-controller performs the Helm repository url validation i.e. the url 
is a valid OCI registry url, every five minutes with the information indicated by the
`.spec.interval` and `.spec.url` fields.

You can run this example by saving the manifest into `helmrepository.yaml`.

1. Apply the resource on the cluster:

   ```sh
   kubectl apply -f helmrepository.yaml
   ```

2. Run `kubectl get helmrepository` to see the HelmRepository:

   ```console
   NAME      URL                                 AGE     READY   STATUS
   podinfo   oci://ghcr.io/stefanprodan/charts   3m22s   True    Helm repository "podinfo" is ready
   ```

3. Run `kubectl describe helmrepository podinfo` to see the [Conditions](#conditions) 
in the HelmRepository's Status:

   ```console
   ...
   Status:
     Conditions:
       Last Transition Time:  2022-05-12T14:02:12Z
       Message:               Helm repository "podinfo" is ready
       Observed Generation:   1
       Reason:                Succeeded
       Status:                True
       Type:                  Ready
     Observed Generation:     1
   Events:                    <none>
   ```

## Writing a HelmRepository spec

As with all other Kubernetes config, a HelmRepository needs `apiVersion`,
`kind`, and `metadata` fields. The name of a HelmRepository object must be a
valid [DNS subdomain name](https://kubernetes.io/docs/concepts/overview/working-with-objects/names#dns-subdomain-names).

A HelmRepository also needs a
[`.spec` section](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status).


### Type

`.spec.type` is an optional field that specifies the Helm repository type. 

Possible values are `default` for a Helm HTTP/S repository, or `oci` for an OCI Helm repository.

### Interval

`.spec.interval` is a required field that specifies the interval which the
Helm repository index must be consulted at.

After successfully reconciling a HelmRepository object, the source-controller
requeues the object for inspection after the specified interval. The value
must be in a [Go recognized duration string format](https://pkg.go.dev/time#ParseDuration),
e.g. `10m0s` to fetch the HelmRepository index YAML every 10 minutes.

If the `.metadata.generation` of a resource changes (due to e.g. applying a
change to the spec), this is handled instantly outside the interval window.

### URL

`.spec.url` is a required field that depending on the [type of the HelmRepository object](#type)
specifies the HTTP/S or OCI address of a Helm repository.

For OCI, the URL is expected to point to a registry repository, e.g. `oci://ghcr.io/fluxcd/source-controller`.

For Helm repositories which require authentication, see [Secret reference](#secret-reference).

### Timeout

`.spec.timeout` is an optional field to specify a timeout for the fetch
operation. The value must be in a
[Go recognized duration string format](https://pkg.go.dev/time#ParseDuration),
e.g. `1m30s` for a timeout of one minute and thirty seconds. The default value
is `60s`.

### Secret reference

`.spec.secretRef.name` is an optional field to specify a name reference to a
Secret in the same namespace as the HelmRepository, containing authentication
credentials for the repository.

#### Basic access authentication

To authenticate towards a Helm repository using basic access authentication
(in other words: using a username and password), the referenced Secret is
expected to contain `.data.username` and `.data.password` values.

For example:

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: HelmRepository
metadata:
  name: example
  namespace: default
spec:
  interval: 5m0s
  url: https://example.com
  secretRef:
    name: example-user
---
apiVersion: v1
kind: Secret
metadata:
  name: example-user
  namespace: default
stringData:
  username: example
  password: 123456
```

OCI Helm repository example:

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: HelmRepository
metadata:
  name: podinfo
  namespace: default
spec:
  interval: 5m0s
  url: oci://ghcr.io/stefanprodan/charts
  type: "oci"
  secretRef:
    name: oci-creds
---
apiVersion: v1
kind: Secret
metadata:
  name: oci-creds
  namespace: default
stringData:
  username: example
  password: 123456
```

#### TLS authentication

**Note:** TLS authentication is not yet supported by OCI Helm repositories.

To provide TLS credentials to use while connecting with the Helm repository,
the referenced Secret is expected to contain `.data.certFile` and
`.data.keyFile`, and/or `.data.caFile` values.

For example:

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: HelmRepository
metadata:
  name: example
  namespace: default
spec:
  interval: 5m0s
  url: https://example.com
  secretRef:
    name: example-tls
---
apiVersion: v1
kind: Secret
metadata:
  name: example-tls
  namespace: default
data:
  certFile: <BASE64>
  keyFile: <BASE64>
  # NOTE: Can be supplied without the above values
  caFile: <BASE64>
```

### Pass credentials

`.spec.passCredentials` is an optional field to allow the credentials from the
[Secret reference](#secret-reference) to be passed on to a host that does not
match the host as defined in URL. This may for example be required if the host
advertised chart URLs in the index differ from the specified URL.

Enabling this should be done with caution, as it can potentially result in
credentials getting stolen in a man-in-the-middle attack. This feature only applies
to HTTP/S Helm repositories.

### Suspend

`.spec.suspend` is an optional field to suspend the reconciliation of a
HelmRepository. When set to `true`, the controller will stop reconciling the
HelmRepository, and changes to the resource or the Helm repository index will
not result in a new Artifact. When the field is set to `false` or removed, it
will resume.

For practical information, see
[suspending and resuming](#suspending-and-resuming).

## Working with HelmRepositories
 
### Triggering a reconcile

To manually tell the source-controller to reconcile a HelmRepository outside the
[specified interval window](#interval), a HelmRepository can be annotated with
`reconcile.fluxcd.io/requestedAt: <arbitrary value>`. Annotating the resource
queues the object for reconciliation if the `<arbitrary-value>` differs from
the last value the controller acted on, as reported in
[`.status.lastHandledReconcileAt`](#last-handled-reconcile-at).

Using `kubectl`:

```sh
kubectl annotate --field-manager=flux-client-side-apply --overwrite helmrepository/<repository-name> reconcile.fluxcd.io/requestedAt="$(date +%s)"
```

Using `flux`:

```sh
flux reconcile source helm <repository-name>
```

### Waiting for `Ready`

When a change is applied, it is possible to wait for the HelmRepository to
reach a [ready state](#ready-helmrepository) using `kubectl`:

```sh
kubectl wait helmrepository/<repository-name> --for=condition=ready --timeout=1m
```

### Suspending and resuming

When you find yourself in a situation where you temporarily want to pause the
reconciliation of a HelmRepository, you can suspend it using the
[`.spec.suspend` field](#suspend).

#### Suspend a HelmRepository

In your YAML declaration:

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: HelmRepository
metadata:
  name: <repository-name>
spec:
  suspend: true
```

Using `kubectl`:

```sh
kubectl patch helmrepository <repository-name> --field-manager=flux-client-side-apply -p '{\"spec\": {\"suspend\" : true }}'
```

Using `flux`:

```sh
flux suspend source helm <repository-name>
```

**Note:** When a HelmRepository has an Artifact and is suspended, and this
Artifact later disappears from the storage due to e.g. the source-controller
Pod being  evicted from a Node, this will not be reflected in the
HelmRepository's Status until it is resumed.

#### Resume a HelmRepository

In your YAML declaration, comment out (or remove) the field:

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: HelmRepository
metadata:
  name: <repository-name>
spec:
  # suspend: true
```

**Note:** Setting the field value to `false` has the same effect as removing
it, but does not allow for "hot patching" using e.g. `kubectl` while practicing
GitOps; as the manually applied patch would be overwritten by the declared
state in Git.

Using `kubectl`:

```sh
kubectl patch helmrepository <repository-name> --field-manager=flux-client-side-apply -p '{\"spec\" : {\"suspend\" : false }}'
```

Using `flux`:

```sh
flux resume source helm <repository-name>
```

### Debugging a HelmRepository

There are several ways to gather information about a HelmRepository for debugging
purposes.

#### Describe the HelmRepository

Describing a HelmRepository using `kubectl describe helmrepository <repository-name>`
displays the latest recorded information for the resource in the `Status` and
`Events` sections:

```console
...
Status:
...
  Conditions:
    Last Transition Time:  2022-02-04T13:41:56Z
    Message:               failed to construct Helm client: scheme "invalid" not supported
    Observed Generation:   2
    Reason:                Failed
    Status:                True
    Type:                  Stalled
    Last Transition Time:  2022-02-04T13:41:56Z
    Message:               failed to construct Helm client: scheme "invalid" not supported
    Observed Generation:   2
    Reason:                Failed
    Status:                False
    Type:                  Ready
    Last Transition Time:  2022-02-04T13:41:56Z
    Message:               failed to construct Helm client: scheme "invalid" not supported
    Observed Generation:   2
    Reason:                Failed
    Status:                True
    Type:                  FetchFailed
  Observed Generation:     2
  URL:                     http://source-controller.source-system.svc.cluster.local./helmrepository/default/podinfo/index.yaml
Events:
  Type     Reason                      Age                  From               Message
  ----     ------                      ----                 ----               -------
  Warning  Failed                      6s                   source-controller  failed to construct Helm client: scheme "invalid" not supported
```

#### Trace emitted Events

To view events for specific HelmRepository(s), `kubectl get events` can be used in
combination with `--field-sector` to list the Events for specific objects.
For example, running

```sh
kubectl get events --field-selector involvedObject.kind=HelmRepository,involvedObject.name=<repository-name>
```

lists

```console
LAST SEEN   TYPE      REASON           OBJECT                             MESSAGE
107s        Warning   Failed           helmrepository/<repository-name>   failed to construct Helm client: scheme "invalid" not supported
7s          Normal    NewArtifact      helmrepository/<repository-name>   fetched index of size 30.88kB from 'https://stefanprodan.github.io/podinfo'
3s          Normal    ArtifactUpToDate helmrepository/<repository-name>   artifact up-to-date with remote revision: '83a3c595163a6ff0333e0154c790383b5be441b9db632cb36da11db1c4ece111'
```

Besides being reported in Events, the reconciliation errors are also logged by
the controller. The Flux CLI offer commands for filtering the logs for a
specific HelmRepository, e.g. `flux logs --level=error --kind=HelmRepository --name=<chart-name>`.

## HelmRepository Status

### Artifact

**Note:** This section does not apply to [OCI Helm Repositories](#oci-helm-repositories), they do not emit artifacts.

The HelmRepository reports the last fetched repository index as an Artifact
object in the `.status.artifact` of the resource.

The Artifact file is an exact copy of the Helm repository index YAML
(`index-<revision>.yaml`) as fetched, and can be retrieved in-cluster from the
`.status.artifact.url` HTTP address.

#### Artifact example

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: HelmRepository
metadata:
  name: <repository-name>
status:
  artifact:
    checksum: 83a3c595163a6ff0333e0154c790383b5be441b9db632cb36da11db1c4ece111
    lastUpdateTime: "2022-02-04T09:55:58Z"
    path: helmrepository/<namespace>/<repository-name>/index-83a3c595163a6ff0333e0154c790383b5be441b9db632cb36da11db1c4ece111.yaml
    revision: 83a3c595163a6ff0333e0154c790383b5be441b9db632cb36da11db1c4ece111
    url: http://source-controller.flux-system.svc.cluster.local./helmrepository/<namespace>/<repository-name>/index-83a3c595163a6ff0333e0154c790383b5be441b9db632cb36da11db1c4ece111.yaml
```

### Conditions

A HelmRepository enters various states during its lifecycle, reflected as [Kubernetes
Conditions][typical-status-properties].
It can be [reconciling](#reconciling-helmrepository) while fetching the
repository index,  it can be [ready](#ready-helmrepository), it can
[fail during reconciliation](#failed-helmrepository), or it can
[stall](#stalled-helmrepository).

The HelmRepository API is compatible with the [kstatus
specification][kstatus-spec],
and reports `Reconciling` and `Stalled` conditions where applicable to
provide better (timeout) support to solutions polling the HelmRepository to become
`Ready`.

 OCI Helm repositories use only `Reconciling`, `Ready`, `FetchFailed`, and `Stalled`
 condition types.

#### Reconciling HelmRepository

The source-controller marks a HelmRepository as _reconciling_ when one of the following
is true:

- There is no current Artifact for the HelmRepository, or the reported Artifact
  is determined to have disappeared from the storage.
- The generation of the HelmRepository is newer than the [Observed
  Generation](#observed-generation).
- The newly fetched Artifact revision differs from the current Artifact.

When the HelmRepository is "reconciling", the `Ready` Condition status becomes
`False`, and the controller adds a Condition with the following attributes to
the HelmRepository's `.status.conditions`:

- `type: Reconciling`
- `status: "True"`
- `reason: NewGeneration` | `reason: NoArtifact` | `reason: NewRevision`

If the reconciling state is due to a new revision, it adds an additional
Condition with the following attributes:

- `type: ArtifactOutdated`
- `status: "True"`
- `reason: NewRevision`

Both Conditions have a ["negative polarity"][typical-status-properties],
and are only present on the HelmRepository while their status value is `"True"`.

#### Ready HelmRepository

The source-controller marks a HelmRepository as _ready_ when it has the following
characteristics:

- The HelmRepository reports an [Artifact](#artifact).
- The reported Artifact exists in the controller's Artifact storage.
- The controller was able to fetch the Helm repository index using the current
  spec.
- The revision of the reported Artifact is up-to-date with the latest
  revision of the Helm repository.

When the HelmRepository is "ready", the controller sets a Condition with the following
attributes in the HelmRepository's `.status.conditions`:

- `type: Ready`
- `status: "True"`
- `reason: Succeeded`

This `Ready` Condition will retain a status value of `"True"` until the
HelmRepository is marked as [reconciling](#reconciling-helmrepository), or e.g.
a [transient error](#failed-helmrepository) occurs due to a temporary network
issue.

When the HelmRepository Artifact is archived in the controller's Artifact
storage, the controller sets a Condition with the following attributes in the
HelmRepository's `.status.conditions`:

- `type: ArtifactInStorage`
- `status: "True"`
- `reason: Succeeded`

This `ArtifactInStorage` Condition will retain a status value of `"True"` until
the Artifact in the storage no longer exists.

#### Failed HelmRepository

The source-controller may get stuck trying to produce an Artifact for a
HelmRepository without completing. This can occur due to some of the following
factors:

- The Helm repository [URL](#url) is temporarily unavailable.
- The [Secret reference](#secret-reference) contains a reference to a
  non-existing Secret.
- The credentials in the referenced Secret are invalid.
- The HelmRepository spec contains a generic misconfiguration.
- A storage related failure when storing the artifact.

When this happens, the controller sets the `Ready` Condition status to `False`,
and adds a Condition with the following attributes to the HelmRepository's
`.status.conditions`:

- `type: FetchFailed` | `type: StorageOperationFailed`
- `status: "True"`
- `reason: AuthenticationFailed` | `reason: IndexationFailed` | `reason: Failed`

This condition has a ["negative polarity"][typical-status-properties],
and is only present on the HelmRepository while the status value is `"True"`.
There may be more arbitrary values for the `reason` field to provide accurate
reason for a condition.

While the HelmRepository has this Condition, the controller will continue to
attempt to produce an Artifact for the resource with an exponential backoff,
until it succeeds and the HelmRepository is marked as [ready](#ready-helmrepository).

Note that a HelmRepository can be [reconciling](#reconciling-helmrepository)
while failing at the same time, for example due to a newly introduced
configuration issue in the HelmRepository spec.

#### Stalled HelmRepository

The source-controller can mark a HelmRepository as _stalled_ when it determines
that without changes to the spec, the reconciliation can not succeed.
For example because a Helm repository URL with an unsupported protocol is
specified.

When this happens, the controller sets the same Conditions as when it
[fails](#failed-helmrepository), but adds another Condition with the following
attributes to the HelmRepository's
`.status.conditions`:

- `type: Stalled`
- `status: "True"`
- `reason: URLInvalid`

While the HelmRepository has this Condition, the controller will not requeue
the resource any further, and will stop reconciling the resource until a change
to the spec is made.

### Observed Generation

The source-controller reports an [observed generation][typical-status-properties]
in the HelmRepository's `.status.observedGeneration`. The observed generation is
the latest `.metadata.generation` which resulted in either a [ready state](#ready-helmrepository),
or stalled due to error it can not recover from without human intervention.

### Last Handled Reconcile At

The source-controller reports the last `reconcile.fluxcd.io/requestedAt`
annotation value it acted on in the `.status.lastHandledReconcileAt` field.

For practical information about this field, see [triggering a
reconcile](#triggering-a-reconcile).

[typical-status-properties]: https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties
[kstatus-spec]: https://github.com/kubernetes-sigs/cli-utils/tree/master/pkg/kstatus
