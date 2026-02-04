# Helm Repositories

<!-- menuweight:40 -->

There are 2 [Helm repository types](#type) defined by the `HelmRepository` API:
- Helm HTTP/S repository, which defines a Source to produce an Artifact for a Helm
repository index YAML (`index.yaml`). 
- OCI Helm repository, which defines a source that does not produce an Artifact.
  It's a data container to store the information about the OCI repository that
  can be used by [HelmChart](helmcharts.md) to access OCI Helm charts.

## Examples

### Helm HTTP/S repository

The following is an example of a HelmRepository. It creates a YAML (`.yaml`)
Artifact from the fetched Helm repository index (in this example the [podinfo
repository](https://github.com/stefanprodan/podinfo)):

```yaml
---
apiVersion: source.werf.io/v1beta2
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
- The digest (algorithm defaults to SHA256) of the Helm repository index after
  stable sorting the entries is used as Artifact revision, reported in-cluster
  in the `.status.artifact.revision` field.
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
   podinfo   https://stefanprodan.github.io/podinfo   4s    True    stored artifact for revision 'sha256:83a3c595163a6ff0333e0154c790383b5be441b9db632cb36da11db1c4ece111'
   ```

3. Run `kubectl describe helmrepository podinfo` to see the [Artifact](#artifact)
   and [Conditions](#conditions) in the HelmRepository's Status:

   ```console
   ...
   Status:
     Artifact:
       Digest:            sha256:83a3c595163a6ff0333e0154c790383b5be441b9db632cb36da11db1c4ece111
       Last Update Time:  2022-02-04T09:55:58Z
       Path:              helmrepository/default/podinfo/index-83a3c595163a6ff0333e0154c790383b5be441b9db632cb36da11db1c4ece111.yaml
       Revision:          sha256:83a3c595163a6ff0333e0154c790383b5be441b9db632cb36da11db1c4ece111
       Size:              40898
       URL:               http://source-controller.flux-system.svc.cluster.local./helmrepository/default/podinfo/index-83a3c595163a6ff0333e0154c790383b5be441b9db632cb36da11db1c4ece111.yaml
     Conditions:
       Last Transition Time:  2022-02-04T09:55:58Z
       Message:               stored artifact for revision 'sha256:83a3c595163a6ff0333e0154c790383b5be441b9db632cb36da11db1c4ece111'
       Observed Generation:   1
       Reason:                Succeeded
       Status:                True
       Type:                  Ready
       Last Transition Time:  2022-02-04T09:55:58Z
       Message:               stored artifact for revision 'sha256:83a3c595163a6ff0333e0154c790383b5be441b9db632cb36da11db1c4ece111'
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
apiVersion: source.werf.io/v1beta2
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
- A HelmChart that refers to this HelmRepository uses the URL in the `.spec.url`
  field to access the OCI Helm chart.

**NOTE:** The `.spec.interval` field is only used by the `default` Helm
repository and is ignored for any value in `oci` Helm repository.

You can run this example by saving the manifest into `helmrepository.yaml`.

1. Apply the resource on the cluster:

   ```sh
   kubectl apply -f helmrepository.yaml
   ```

2. Run `kubectl get helmrepository` to see the HelmRepository:

   ```console
   NAME      URL                                 AGE     READY   STATUS
   podinfo   oci://ghcr.io/stefanprodan/charts   3m22s
   ```

Because the OCI Helm repository is a data container, there's nothing to report
for `READY` and `STATUS` columns above. The existence of the object can be
considered to be ready for use.

## Writing a HelmRepository spec

As with all other Kubernetes config, a HelmRepository needs `apiVersion`,
`kind`, and `metadata` fields. The name of a HelmRepository object must be a
valid [DNS subdomain name](https://kubernetes.io/docs/concepts/overview/working-with-objects/names#dns-subdomain-names).

A HelmRepository also needs a
[`.spec` section](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status).

### Type

`.spec.type` is an optional field that specifies the Helm repository type. 

Possible values are `default` for a Helm HTTP/S repository, or `oci` for an OCI Helm repository.

### Provider

`.spec.provider` is an optional field that allows specifying an OIDC provider used
for authentication purposes.

Supported options are:
- `generic`
- `aws`
- `azure`
- `gcp`

The `generic` provider can be used for public repositories or when static credentials
are used for authentication. If you do not specify `.spec.provider`, it defaults
to `generic`.

**Note**: The provider field is supported only for Helm OCI repositories. The `spec.type`
field must be set to `oci`.

#### AWS

The `aws` provider can be used to authenticate automatically using the EKS worker
node IAM role or IAM Role for Service Accounts (IRSA), and by extension gain access
to ECR.

##### EKS Worker Node IAM Role

When the worker node IAM role has access to ECR, source-controller running on it
will also have access to ECR.

##### IAM Role for Service Accounts (IRSA)

When using IRSA to enable access to ECR, add the following patch to your bootstrap
repository, in the `flux-system/kustomization.yaml` file:

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - gotk-components.yaml
  - gotk-sync.yaml
patches:
  - patch: |
      apiVersion: v1
      kind: ServiceAccount
      metadata:
        name: source-controller
        annotations:
          eks.amazonaws.com/role-arn: <role arn>
    target:
      kind: ServiceAccount
      name: source-controller
```

Note that you can attach the AWS managed policy `arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly`
to the IAM role when using IRSA.

#### Azure

The `azure` provider can be used to authenticate automatically using Workload Identity, Kubelet Managed
Identity or Azure Active Directory pod-managed identity (aad-pod-identity), and
by extension gain access to ACR.

##### Kubelet Managed Identity

When the kubelet managed identity has access to ACR, source-controller running on 
it will also have access to ACR.

**Note:** If you have more than one identity configured on the cluster, you have to specify which one to use
by setting the `AZURE_CLIENT_ID` environment variable in the source-controller deployment.

If you are running into further issues, please look at the
[troubleshooting guide](https://github.com/Azure/azure-sdk-for-go/blob/main/sdk/azidentity/TROUBLESHOOTING.md#azure-virtual-machine-managed-identity).

##### Azure Workload Identity

When using Workload Identity to enable access to ACR, add the following patch to
your bootstrap repository, in the `flux-system/kustomization.yaml` file:

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - gotk-components.yaml
  - gotk-sync.yaml
patches:
  - patch: |-
      apiVersion: v1
      kind: ServiceAccount
      metadata:
        name: source-controller
        namespace: flux-system
        annotations:
          azure.workload.identity/client-id: <AZURE_CLIENT_ID>
        labels:
          azure.workload.identity/use: "true"
  - patch: |-
      apiVersion: apps/v1
      kind: Deployment
      metadata:
        name: source-controller
        namespace: flux-system
        labels:
          azure.workload.identity/use: "true"
      spec:
        template:
          metadata:
            labels:
              azure.workload.identity/use: "true"
```

Ensure Workload Identity is properly set up on your cluster and the mutating webhook is installed.
Create an identity that has access to ACR. Next, establish
a federated identity between the source-controller ServiceAccount and the
identity. Patch the source-controller Deployment and ServiceAccount as shown in the patch
above. Please take a look at this [guide](https://azure.github.io/azure-workload-identity/docs/quick-start.html#6-establish-federated-identity-credential-between-the-identity-and-the-service-account-issuer--subject).

##### Deprecated: AAD Pod Identity

**Warning:** The AAD Pod Identity project will be archived in
[September 2023](https://github.com/Azure/aad-pod-identity#-announcement),
and you are advised to use Workload Identity instead.

When using aad-pod-identity to enable access to ACR, add the following patch to
your bootstrap repository, in the `flux-system/kustomization.yaml` file:

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - gotk-components.yaml
  - gotk-sync.yaml
patches:
  - patch: |
      - op: add
        path: /spec/template/metadata/labels/aadpodidbinding
        value: <identity-name>
    target:
      kind: Deployment
      name: source-controller
```

When using pod-managed identity on an AKS cluster, AAD Pod Identity has to be used
to give the `source-controller` pod access to the ACR. To do this, you have to install
`aad-pod-identity` on your cluster, create a managed identity that has access to the
container registry (this can also be the Kubelet identity if it has `AcrPull` role
assignment on the ACR), create an `AzureIdentity` and `AzureIdentityBinding` that describe
the managed identity and then label the `source-controller` deployment with the name of the
AzureIdentity as shown in the patch above. Please take a look at [this guide](https://azure.github.io/aad-pod-identity/docs/)
or [this one](https://docs.microsoft.com/en-us/azure/aks/use-azure-ad-pod-identity)
if you want to use AKS pod-managed identities add-on that is in preview.

#### GCP

The `gcp` provider can be used to authenticate automatically using OAuth scopes or
Workload Identity, and by extension gain access to GCR or Artifact Registry.

##### Access Scopes

When the GKE nodes have the appropriate OAuth scope for accessing GCR and Artifact Registry,
source-controller running on it will also have access to them.

##### GKE Workload Identity

When using Workload Identity to enable access to GCR or Artifact Registry, add the
following patch to your bootstrap repository, in the `flux-system/kustomization.yaml`
file:

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - gotk-components.yaml
  - gotk-sync.yaml
patches:
  - patch: |
      apiVersion: v1
      kind: ServiceAccount
      metadata:
        name: source-controller
        annotations:
          iam.gke.io/gcp-service-account: <identity-name>
    target:
      kind: ServiceAccount
      name: source-controller
```

The Artifact Registry service uses the permission `artifactregistry.repositories.downloadArtifacts`
that is located under the Artifact Registry Reader role. If you are using Google Container Registry service,
the needed permission is instead `storage.objects.list` which can be bound as part
of the Container Registry Service Agent role. Take a look at [this guide](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity)
for more information about setting up GKE Workload Identity.

### Insecure

`.spec.insecure` is an optional field to allow connecting to an insecure (HTTP)
container registry server, if set to `true`. The default value is `false`,
denying insecure non-TLS connections when fetching Helm chart OCI artifacts.

**Note**: The insecure field is supported only for Helm OCI repositories.
The `spec.type` field must be set to `oci`.

### Interval

**Note:** This field is ineffectual for [OCI Helm
Repositories](#helm-oci-repository).

`.spec.interval` is a an optional field that specifies the interval which the
Helm repository index must be consulted at. When not set, the default value is
`1m`.

After successfully reconciling a HelmRepository object, the source-controller
requeues the object for inspection after the specified interval. The value
must be in a [Go recognized duration string format](https://pkg.go.dev/time#ParseDuration),
e.g. `10m0s` to fetch the HelmRepository index YAML every 10 minutes.

If the `.metadata.generation` of a resource changes (due to e.g. applying a
change to the spec), this is handled instantly outside the interval window.

**Note:** The controller can be configured to apply a jitter to the interval in
order to distribute the load more evenly when multiple HelmRepository objects
are set up with the same interval. For more information, please refer to the
[source-controller configuration options](https://fluxcd.io/flux/components/source/options/).

### URL

`.spec.url` is a required field that depending on the [type of the HelmRepository object](#type)
specifies the HTTP/S or OCI address of a Helm repository.

For OCI, the URL is expected to point to a registry repository, e.g. `oci://ghcr.io/fluxcd/source-controller`.

For Helm repositories which require authentication, see [Secret reference](#secret-reference).

### Timeout

**Note:** This field is not applicable to [OCI Helm
Repositories](#helm-oci-repository).

`.spec.timeout` is an optional field to specify a timeout for the fetch
operation. The value must be in a
[Go recognized duration string format](https://pkg.go.dev/time#ParseDuration),
e.g. `1m30s` for a timeout of one minute and thirty seconds. When not set, the
default value is `1m`.

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
apiVersion: source.werf.io/v1beta2
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
  username: "user-123456"
  password: "pass-123456"
```

OCI Helm repository example:

```yaml
---
apiVersion: source.werf.io/v1beta2
kind: HelmRepository
metadata:
  name: podinfo
  namespace: default
spec:
  interval: 5m0s
  url: oci://ghcr.io/my-user/my-private-repo
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
  username: "user-123456"
  password: "pass-123456"
```

For OCI Helm repositories, Kubernetes secrets of type [kubernetes.io/dockerconfigjson](https://kubernetes.io/docs/concepts/configuration/secret/#secret-types) are also supported.
It is possible to create one such secret with `kubectl create secret docker-registry`
or using the Flux CLI:

```yaml
flux create secret oci ghcr-auth \
  --url=ghcr.io \
  --username=flux \
  --password=${GITHUB_PAT}
```

**Warning:** Support for specifying TLS authentication data using this API has been
deprecated. Please use [`.spec.certSecretRef`](#cert-secret-reference) instead.
If the controller uses the secret specified by this field to configure TLS, then
a deprecation warning will be logged.

### Cert secret reference

`.spec.certSecretRef.name` is an optional field to specify a secret containing
TLS certificate data. The secret can contain the following keys:

* `tls.crt` and `tls.key`, to specify the client certificate and private key used
for TLS client authentication. These must be used in conjunction, i.e.
specifying one without the other will lead to an error.
* `ca.crt`, to specify the CA certificate used to verify the server, which is
required if the server is using a self-signed certificate.

If the server is using a self-signed certificate and has TLS client
authentication enabled, all three values are required.

The Secret should be of type `Opaque` or `kubernetes.io/tls`. All the files in
the Secret are expected to be [PEM-encoded][pem-encoding]. Assuming you have
three files; `client.key`, `client.crt` and `ca.crt` for the client private key,
client certificate and the CA certificate respectively, you can generate the
required Secret using the `flux create secret tls` command:

```sh
flux create secret tls --tls-key-file=client.key --tls-crt-file=client.crt --ca-crt-file=ca.crt
```

Example usage:

```yaml
---
apiVersion: source.werf.io/v1beta2
kind: HelmRepository
metadata:
  name: example
  namespace: default
spec:
  interval: 5m0s
  url: https://example.com
  certSecretRef:
    name: example-tls
---
apiVersion: v1
kind: Secret
metadata:
  name: example-tls
  namespace: default
type: kubernetes.io/tls # or Opaque
data:
  tls.crt: <BASE64>
  tls.key: <BASE64>
  # NOTE: Can be supplied without the above values
  ca.crt: <BASE64>
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

**Note:** This field is not applicable to [OCI Helm
Repositories](#helm-oci-repository).

`.spec.suspend` is an optional field to suspend the reconciliation of a
HelmRepository. When set to `true`, the controller will stop reconciling the
HelmRepository, and changes to the resource or the Helm repository index will
not result in a new Artifact. When the field is set to `false` or removed, it
will resume.

For practical information, see
[suspending and resuming](#suspending-and-resuming).

## Working with HelmRepositories

**Note:** This section does not apply to [OCI Helm
Repositories](#helm-oci-repository), being a data container, once created, they
are ready to used by [HelmCharts](helmcharts.md).
 
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
apiVersion: source.werf.io/v1beta2
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
apiVersion: source.werf.io/v1beta2
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

**Note:** This section does not apply to [OCI Helm
Repositories](#helm-oci-repository), being a data container, they are static
objects that don't require debugging if valid.

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

To view events for specific HelmRepository(s), `kubectl events` can be used in
combination with `--for` to list the Events for specific objects. For example,
running

```sh
kubectl events --for HelmRepository/<repository-name>
```

lists

```console
LAST SEEN   TYPE      REASON           OBJECT                             MESSAGE
107s        Warning   Failed           helmrepository/<repository-name>   failed to construct Helm client: scheme "invalid" not supported
7s          Normal    NewArtifact      helmrepository/<repository-name>   fetched index of size 30.88kB from 'https://stefanprodan.github.io/podinfo'
3s          Normal    ArtifactUpToDate helmrepository/<repository-name>   artifact up-to-date with remote revision: 'sha256:83a3c595163a6ff0333e0154c790383b5be441b9db632cb36da11db1c4ece111'
```

Besides being reported in Events, the reconciliation errors are also logged by
the controller. The Flux CLI offer commands for filtering the logs for a
specific HelmRepository, e.g. `flux logs --level=error --kind=HelmRepository --name=<chart-name>`.

## HelmRepository Status

**Note:** This section does not apply to [OCI Helm
Repositories](#helm-oci-repository), they do not contain any information in the
status.

### Artifact

The HelmRepository reports the last fetched repository index as an Artifact
object in the `.status.artifact` of the resource.

The Artifact file is an exact copy of the Helm repository index YAML
(`index-<revision>.yaml`) as fetched, and can be retrieved in-cluster from the
`.status.artifact.url` HTTP address.

#### Artifact example

```yaml
---
apiVersion: source.werf.io/v1beta2
kind: HelmRepository
metadata:
  name: <repository-name>
status:
  artifact:
    digest: sha256:83a3c595163a6ff0333e0154c790383b5be441b9db632cb36da11db1c4ece111
    lastUpdateTime: "2022-02-04T09:55:58Z"
    path: helmrepository/<namespace>/<repository-name>/index-83a3c595163a6ff0333e0154c790383b5be441b9db632cb36da11db1c4ece111.yaml
    revision: sha256:83a3c595163a6ff0333e0154c790383b5be441b9db632cb36da11db1c4ece111
    size: 40898
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

#### Reconciling HelmRepository

The source-controller marks a HelmRepository as _reconciling_ when one of the following
is true:

- There is no current Artifact for the HelmRepository, or the reported Artifact
  is determined to have disappeared from the storage.
- The generation of the HelmRepository is newer than the [Observed
  Generation](#observed-generation).
- The newly fetched Artifact revision differs from the current Artifact.

When the HelmRepository is "reconciling", the `Ready` Condition status becomes
`Unknown` when the controller detects drift, and the controller adds a Condition
with the following attributes to the HelmRepository's `.status.conditions`:

- `type: Reconciling`
- `status: "True"`
- `reason: Progressing` | `reason: ProgressingWithRetry`

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
configuration issue in the HelmRepository spec. When a reconciliation fails, the
`Reconciling` Condition reason would be `ProgressingWithRetry`. When the
reconciliation is performed again after the failure, the reason is updated to
`Progressing`.

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

[pem-encoding]: https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail
[typical-status-properties]: https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties
[kstatus-spec]: https://github.com/kubernetes-sigs/cli-utils/tree/master/pkg/kstatus
