# OCI Repositories

The `OCIRepository` API defines a Source to produce an Artifact for an OCI
repository.

## Example

The following is an example of an OCIRepository. It creates a tarball
(`.tar.gz`) Artifact with the fetched data from an OCI repository for the
resolved digest.

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: OCIRepository
metadata:
  name: podinfo
  namespace: default
spec:
  interval: 5m0s
  url: oci://ghcr.io/stefanprodan/manifests/podinfo
  ref:
    tag: latest
```

In the above example:

- An OCIRepository named `podinfo` is created, indicated by the
  `.metadata.name` field.
- The source-controller checks the OCI repository every five minutes, indicated
  by the `.spec.interval` field.
- It pulls the `latest` tag of the `ghcr.io/stefanprodan/manifests/podinfo`
  repository, indicated by the `.spec.ref.tag` and `.spec.url` fields.
- The resolved SHA256 digest is used as the Artifact
  revision, reported in-cluster in the `.status.artifact.revision` field.
- When the current OCIRepository digest differs from the latest fetched
  digest, a new Artifact is archived.
- The new Artifact is reported in the `.status.artifact` field.

You can run this example by saving the manifest into `ocirepository.yaml`.

1. Apply the resource on the cluster:

   ```sh
   kubectl apply -f ocirepository.yaml
   ```

2. Run `kubectl get ocirepository` to see the OCIRepository:

   ```console
   NAME      URL                                            AGE   READY   STATUS                                                                        
   podinfo   oci://ghcr.io/stefanprodan/manifests/podinfo   5s    True    stored artifact with digest '3b6cdcc7adcc9a84d3214ee1c029543789d90b5ae69debe9efa3f66e982875de'
   ```

3. Run `kubectl describe ocirepository podinfo` to see the [Artifact](#artifact)
   and [Conditions](#conditions) in the OCIRepository's Status:

   ```console
   ...
   Status:
     Artifact:
       Checksum:          d7e924b4882e55b97627355c7b3d2e711e9b54303afa2f50c25377f4df66a83b
       Last Update Time:  2022-06-14T11:23:36Z
       Path:              ocirepository/default/podinfo/3b6cdcc7adcc9a84d3214ee1c029543789d90b5ae69debe9efa3f66e982875de.tar.gz
       Revision:          3b6cdcc7adcc9a84d3214ee1c029543789d90b5ae69debe9efa3f66e982875de
       URL:               http://source-controller.flux-system.svc.cluster.local./ocirepository/oci/podinfo/3b6cdcc7adcc9a84d3214ee1c029543789d90b5ae69debe9efa3f66e982875de.tar.gz
     Conditions:
       Last Transition Time:  2022-06-14T11:23:36Z
       Message:               stored artifact for digest '3b6cdcc7adcc9a84d3214ee1c029543789d90b5ae69debe9efa3f66e982875de'
       Observed Generation:   1
       Reason:                Succeeded
       Status:                True
       Type:                  Ready
       Last Transition Time:  2022-06-14T11:23:36Z
       Message:               stored artifact for digest '3b6cdcc7adcc9a84d3214ee1c029543789d90b5ae69debe9efa3f66e982875de'
       Observed Generation:   1
       Reason:                Succeeded
       Status:                True
       Type:                  ArtifactInStorage
     Observed Generation:     1
     URL:                     http://source-controller.source-system.svc.cluster.local./gitrepository/default/podinfo/latest.tar.gz
   Events:
     Type    Reason               Age   From               Message
     ----    ------               ----  ----               -------
     Normal  NewArtifact          62s   source-controller  stored artifact with digest '3b6cdcc7adcc9a84d3214ee1c029543789d90b5ae69debe9efa3f66e982875de' from 'oci://ghcr.io/stefanprodan/manifests/podinfo'
   ```

## Writing an OCIRepository spec

As with all other Kubernetes config, an OCIRepository needs `apiVersion`,
`kind`, and `metadata` fields. The name of an OCIRepository object must be a
valid [DNS subdomain name](https://kubernetes.io/docs/concepts/overview/working-with-objects/names#dns-subdomain-names).

An OCIRepository also needs a
[`.spec` section](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status).

### URL

`.spec.url` is a required field that specifies the address of the
container image repository in the format `oci://<host>:<port>/<org-name>/<repo-name>`.

**Note:** that specifying a tag or digest is not acceptable for this field.

### Provider

`.spec.provider` is an optional field that allows specifying an OIDC provider used for
authentication purposes.

Supported options are:

- `generic`
- `aws`
- `azure`
- `gcp`

The `generic` provider can be used for public repositories or when
static credentials are used for authentication, either with
`spec.secretRef` or `spec.serviceAccountName`.
If you do not specify `.spec.provider`, it defaults to `generic`.

#### AWS

The `aws` provider can be used to authenticate automatically using the EKS
worker node IAM role or IAM Role for Service Accounts (IRSA), and by extension
gain access to ECR.

When the worker node IAM role has access to ECR, source-controller running on it
will also have access to ECR.

When using IRSA to enable access to ECR, add the following patch to your
bootstrap repository, in the `flux-system/kustomization.yaml` file:

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

The `azure` provider can be used to authenticate automatically using kubelet
managed identity or Azure Active Directory pod-managed identity (aad-pod-identity),
and by extension gain access to ACR.

When the kubelet managed identity has access to ACR, source-controller running
on it will also have access to ACR.

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

When using pod-managed identity on an AKS cluster, AAD Pod Identity
has to be used to give the `source-controller` pod access to the ACR.
To do this, you have to install `aad-pod-identity` on your cluster, create a managed identity
that has access to the container registry (this can also be the Kubelet identity
if it has `AcrPull` role assignment on the ACR), create an `AzureIdentity` and `AzureIdentityBinding`
that describe the managed identity and then label the `source-controller` pods
with the name of the AzureIdentity as shown in the patch above. Please take a look
at [this guide](https://azure.github.io/aad-pod-identity/docs/) or
[this one](https://docs.microsoft.com/en-us/azure/aks/use-azure-ad-pod-identity)
if you want to use AKS pod-managed identities add-on that is in preview.

#### GCP

The `gcp` provider can be used to authenticate automatically using OAuth scopes
or Workload Identity, and by extension gain access to GCR or Artifact Registry.

When the GKE nodes have the appropriate OAuth scope for accessing GCR and
Artifact Registry, source-controller running on it will also have access to them.

When using Workload Identity to enable access to GCR or Artifact Registry, add
the following patch to your bootstrap repository, in the
`flux-system/kustomization.yaml` file:

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
that is located under the Artifact Registry Reader role. If you are using
Google Container Registry service, the needed permission is instead `storage.objects.list`
which can be bound as part of the Container Registry Service Agent role.
Take a look at [this guide](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity)
for more information about setting up GKE Workload Identity.

### Secret reference

`.spec.secretRef.name` is an optional field to specify a name reference to a
Secret in the same namespace as the OCIRepository, containing authentication
credentials for the OCI repository.

This secret is expected to be in the same format as [`imagePullSecrets`][image-pull-secrets].
The usual way to create such a secret is with:

```sh
kubectl create secret docker-registry ...
```

### Service Account reference

`.spec.serviceAccountName` is an optional field to specify a name reference to a
Service Account in the same namespace as the OCIRepository. The controller will
fetch the image pull secrets attached to the service account and use them for authentication.

**Note:** that for a publicly accessible image repository, you don't need to provide a `secretRef`
nor `serviceAccountName`.

### TLS Certificates

`.spec.certSecretRef` field names a secret with TLS certificate data. This is for two separate
purposes:

- to provide a client certificate and private key, if you use a certificate to authenticate with
  the container registry; and,
- to provide a CA certificate, if the registry uses a self-signed certificate.

These will often go together, if you are hosting a container registry yourself. All the files in the
secret are expected to be [PEM-encoded][pem-encoding]. This is an ASCII format for certificates and
keys; `openssl` and such tools will typically give you an option of PEM output.

Assuming you have obtained a certificate file and private key and put them in the files `client.crt`
and `client.key` respectively, you can create a secret with `kubectl` like this:

```bash
kubectl create secret generic tls-certs \
  --from-file=certFile=client.crt \
  --from-file=keyFile=client.key
```

You could also [prepare a secret and encrypt it][sops-guide]; the important bit is that the data
keys in the secret are `certFile` and `keyFile`.

If you have a CA certificate for the client to use, the data key for that is `caFile`. Adapting the
previous example, if you have the certificate in the file `ca.crt`, and the client certificate and
key as before, the whole command would be:

```bash
kubectl create secret generic tls-certs \
  --from-file=certFile=client.crt \
  --from-file=keyFile=client.key \
  --from-file=caFile=ca.crt
```

### Insecure

`.spec.insecure` is an optional field to allow connecting to an insecure (HTTP)
container registry server, if set to `true`. The default value is `false`,
denying insecure (HTTP) connections.

### Interval

`.spec.interval` is a required field that specifies the interval at which the
OCI repository must be fetched.

After successfully reconciling the object, the source-controller requeues it
for inspection after the specified interval. The value must be in a
[Go recognized duration string format](https://pkg.go.dev/time#ParseDuration),
e.g. `10m0s` to reconcile the object every 10 minutes.

If the `.metadata.generation` of a resource changes (due to e.g. a change to
the spec), this is handled instantly outside the interval window.

### Timeout

`.spec.timeout` is an optional field to specify a timeout for OCI operations
like pulling. The value must be in a
[Go recognized duration string format](https://pkg.go.dev/time#ParseDuration),
e.g. `1m30s` for a timeout of one minute and thirty seconds. The default value
is `60s`.

### Reference

`.spec.ref` is an optional field to specify the OCI reference to resolve and
watch for changes. References are specified in one or more subfields
(`.tag`, `.semver`, `.digest`), with latter listed fields taking
precedence over earlier ones. If not specified, it defaults to the `latest`
tag.

#### Tag example

To pull a specific tag, use `.spec.ref.tag`:

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: OCIRepository
metadata:
  name: <repository-name>
spec:
  ref:
    tag: "<tag-name>"
```

#### SemVer example

To pull a tag based on a
[SemVer range](https://github.com/Masterminds/semver#checking-version-constraints),
use `.spec.ref.semver`:

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: OCIRepository
metadata:
  name: <repository-name>
spec:
  ref:
    # SemVer range reference: https://github.com/Masterminds/semver#checking-version-constraints
    semver: "<semver-range>"
```

This field takes precedence over [`.tag`](#tag-example).

#### Digest example

To pull a specific digest, use `.spec.ref.digest`:

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: OCIRepository
metadata:
  name: <repository-name>
spec:
  ref:
    digest: "sha256:<SHA-value>"
``` 

This field takes precedence over all other fields.

### Layer selector

`spec.layerSelector` is an optional field to specify which layer should be extracted from the OCI Artifact.
If not specified, the controller will extract the first layer found in the artifact.

To extract a layer matching a specific
[OCI media type](https://github.com/opencontainers/image-spec/blob/v1.0.2/media-types.md):

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: OCIRepository
metadata:
  name: <repository-name>
spec:
  layerSelector:
    mediaType: "application/deployment.content.v1.tar+gzip"
```

If the layer selector matches more than one layer, the first layer matching the specified media type will be used.
Note that the selected OCI layer must be
[compressed](https://github.com/opencontainers/image-spec/blob/v1.0.2/layer.md#gzip-media-types)
in the `tar+gzip` format.

### Ignore

`.spec.ignore` is an optional field to specify rules in [the `.gitignore`
pattern format](https://git-scm.com/docs/gitignore#_pattern_format). Paths
matching the defined rules are excluded while archiving.

When specified, `.spec.ignore` overrides the [default exclusion
list](#default-exclusions), and may overrule the [`.sourceignore` file
exclusions](#sourceignore-file). See [excluding files](#excluding-files)
for more information.

### Suspend

`.spec.suspend` is an optional field to suspend the reconciliation of a
OCIRepository. When set to `true`, the controller will stop reconciling the
OCIRepository, and changes to the resource or in the OCI repository will not
result in a new Artifact. When the field is set to `false` or removed, it will
resume.

## Working with OCIRepositories

### Excluding files

By default, files which match the [default exclusion rules](#default-exclusions)
are excluded while archiving the OCI repository contents as an Artifact.
It is possible to overwrite and/or overrule the default exclusions using
the [`.spec.ignore` field](#ignore).

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: OCIRepository
metadata:
  name: <repository-name>
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

### Triggering a reconcile

To manually tell the source-controller to reconcile a OCIRepository outside the
[specified interval window](#interval), an OCIRepository can be annotated with
`reconcile.fluxcd.io/requestedAt: <arbitrary value>`. Annotating the resource
queues the OCIRepository for reconciliation if the `<arbitrary-value>` differs
from the last value the controller acted on, as reported in
[`.status.lastHandledReconcileAt`](#last-handled-reconcile-at).

Using `kubectl`:

```sh
kubectl annotate --field-manager=flux-client-side-apply --overwrite ocirepository/<repository-name> reconcile.fluxcd.io/requestedAt="$(date +%s)"
```

Using `flux`:

```sh
flux reconcile source oci <repository-name>
```

### Waiting for `Ready`

When a change is applied, it is possible to wait for the OCIRepository to reach
a [ready state](#ready-gitrepository) using `kubectl`:

```sh
kubectl wait gitrepository/<repository-name> --for=condition=ready --timeout=1m
```

### Suspending and resuming

When you find yourself in a situation where you temporarily want to pause the
reconciliation of an OCIRepository, you can suspend it using the
[`.spec.suspend` field](#suspend).

#### Suspend an OCIRepository

In your YAML declaration:

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: OCIRepository
metadata:
  name: <repository-name>
spec:
  suspend: true
```

Using `kubectl`:

```sh
kubectl patch ocirepository <repository-name> --field-manager=flux-client-side-apply -p '{\"spec\": {\"suspend\" : true }}'
```

Using `flux`:

```sh
flux suspend source oci <repository-name>
```

**Note:** When an OCIRepository has an Artifact and it is suspended, and this
Artifact later disappears from the storage due to e.g. the source-controller
Pod being evicted from a Node, this will not be reflected in the
OCIRepository's Status until it is resumed.

#### Resume an OCIRepository

In your YAML declaration, comment out (or remove) the field:

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: OCIRepository
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
kubectl patch ocirepository <repository-name> --field-manager=flux-client-side-apply -p '{\"spec\" : {\"suspend\" : false }}'
```

Using `flux`:

```sh
flux resume source oci <repository-name>
```

### Debugging an OCIRepository

There are several ways to gather information about a OCIRepository for
debugging purposes.

#### Describe the OCIRepository

Describing an OCIRepository using
`kubectl describe ocirepository <repository-name>`
displays the latest recorded information for the resource in the `Status` and
`Events` sections:

```console
...
Status:
...
  Conditions:
    Last Transition Time:  2022-02-14T09:40:27Z
    Message:               reconciling new object generation (2)
    Observed Generation:   2
    Reason:                NewGeneration
    Status:                True
    Type:                  Reconciling
    Last Transition Time:  2022-02-14T09:40:27Z
    Message:               failed to pull artifact from 'oci://ghcr.io/stefanprodan/manifests/podinfo': couldn't find tag "0.0.1"
    Observed Generation:   2
    Reason:                OCIOperationFailed
    Status:                False
    Type:                  Ready
    Last Transition Time:  2022-02-14T09:40:27Z
    Message:               failed to pull artifact from 'oci://ghcr.io/stefanprodan/manifests/podinfo': couldn't find tag "0.0.1"
    Observed Generation:   2
    Reason:                OCIOperationFailed
    Status:                True
    Type:                  FetchFailed
  Observed Generation:     1
  URL:                     http://source-controller.source-system.svc.cluster.local./ocirepository/default/podinfo/latest.tar.gz
Events:
  Type     Reason                      Age                  From               Message
  ----     ------                      ----                 ----               -------
  Warning  OCIOperationFailed          2s (x9 over 4s)      source-controller  failed to pull artifact from 'oci://ghcr.io/stefanprodan/manifests/podinfo': couldn't find tag "0.0.1"
```

#### Trace emitted Events

To view events for specific OCIRepository(s), `kubectl get events` can be used
in combination with `--field-sector` to list the Events for specific objects.
For example, running

```sh
kubectl get events --field-selector involvedObject.kind=OCIRepository,involvedObject.name=<repository-name>
```

lists

```console
LAST SEEN   TYPE     REASON                OBJECT                               MESSAGE
2m14s       Normal   NewArtifact           ocirepository/<repository-name>      stored artifact for digest '3b6cdcc7adcc9a84d3214ee1c029543789d90b5ae69debe9efa3f66e982875de'
36s         Normal   ArtifactUpToDate      ocirepository/<repository-name>      artifact up-to-date with remote digest: '3b6cdcc7adcc9a84d3214ee1c029543789d90b5ae69debe9efa3f66e982875de'
94s         Warning  OCIOperationFailed    ocirepository/<repository-name>      failed to pull artifact from 'oci://ghcr.io/stefanprodan/manifests/podinfo': couldn't find tag "0.0.1"
```

Besides being reported in Events, the reconciliation errors are also logged by
the controller. The Flux CLI offer commands for filtering the logs for a
specific OCIRepository, e.g.
`flux logs --level=error --kind=OCIRepository --name=<repository-name>`.

## OCIRepository Status

### Artifact

The OCIRepository reports the latest synchronized state from the OCI repository
as an Artifact object in the `.status.artifact` of the resource.

The `.status.artifact.revision` holds the SHA256 digest of the upstream OCI artifact.

The `.status.artifact.metadata` holds the upstream OCI artifact metadata such as the
[OpenContainers standard annotations](https://github.com/opencontainers/image-spec/blob/main/annotations.md).
If the OCI artifact was created with `flux push artifact`, then the `metadata` will contain the following
annotations:
- `org.opencontainers.image.created` the date and time on which the artifact was built
- `org.opencontainers.image.source` the URL of the Git repository containing the source files
- `org.opencontainers.image.revision` the Git branch and commit SHA1 of the source files

The Artifact file is a gzip compressed TAR archive (`<commit sha>.tar.gz`), and
can be retrieved in-cluster from the `.status.artifact.url` HTTP address.

#### Artifact example

```yaml
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: OCIRepository
metadata:
  name: <repository-name>
status:
  artifact:
    checksum: 9f3bc0f341d4ecf2bab460cc59320a2a9ea292f01d7b96e32740a9abfd341088
    lastUpdateTime: "2022-08-08T09:35:45Z"
    metadata:
      org.opencontainers.image.created: "2022-08-08T12:31:41+03:00"
      org.opencontainers.image.revision: 6.1.8/b3b00fe35424a45d373bf4c7214178bc36fd7872
      org.opencontainers.image.source: https://github.com/stefanprodan/podinfo.git
    path: ocirepository/<namespace>/<repository-name>/<digest>.tar.gz
    revision: <digest>
    url: http://source-controller.<namespace>.svc.cluster.local./ocirepository/<namespace>/<repository-name>/<digest>.tar.gz
```

#### Default exclusions

The following files and extensions are excluded from the Artifact by
default:

- Git files (`.git/, .gitignore, .gitmodules, .gitattributes`)
- File extensions (`.jpg, .jpeg, .gif, .png, .wmv, .flv, .tar.gz, .zip`)
- CI configs (`.github/, .circleci/, .travis.yml, .gitlab-ci.yml, appveyor.yml, .drone.yml, cloudbuild.yaml, codeship-services.yml, codeship-steps.yml`)
- CLI configs (`.goreleaser.yml, .sops.yaml`)
- Flux v1 config (`.flux.yaml`)

To define your own exclusion rules, see [excluding files](#excluding-files).

### Conditions

OCIRepository has various states during its lifecycle, reflected as
[Kubernetes Conditions][typical-status-properties].
It can be [reconciling](#reconciling-ocirepository) while fetching the remote
state, it can be [ready](#ready-ocirepository), or it can [fail during
reconciliation](#failed-ocirepository).

The OCIRepository API is compatible with the [kstatus specification][kstatus-spec],
and reports `Reconciling` and `Stalled` conditions where applicable to
provide better (timeout) support to solutions polling the OCIRepository to
become `Ready`.

#### Reconciling OCIRepository

The source-controller marks an OCIRepository as _reconciling_ when one of the
following is true:

- There is no current Artifact for the OCIRepository, or the reported Artifact
  is determined to have disappeared from the storage.
- The generation of the OCIRepository is newer than the [Observed
  Generation](#observed-generation).
- The newly resolved Artifact digest differs from the current Artifact.

When the OCIRepository is "reconciling", the `Ready` Condition status becomes
`False`, and the controller adds a Condition with the following attributes to
the OCIRepository's `.status.conditions`:

- `type: Reconciling`
- `status: "True"`
- `reason: NewGeneration` | `reason: NoArtifact` | `reason: NewRevision`

If the reconciling state is due to a new revision, an additional Condition is
added with the following attributes:

- `type: ArtifactOutdated`
- `status: "True"`
- `reason: NewRevision`

Both Conditions have a ["negative polarity"][typical-status-properties],
and are only present on the OCIRepository while their status value is `"True"`.

#### Ready OCIRepository

The source-controller marks an OCIRepository as _ready_ when it has the
following characteristics:

- The OCIRepository reports an [Artifact](#artifact).
- The reported Artifact exists in the controller's Artifact storage.
- The controller was able to communicate with the remote OCI repository using
  the current spec.
- The digest of the reported Artifact is up-to-date with the latest
  resolved digest of the remote OCI repository.

When the OCIRepository is "ready", the controller sets a Condition with the
following attributes in the OCIRepository's `.status.conditions`:

- `type: Ready`
- `status: "True"`
- `reason: Succeeded`

This `Ready` Condition will retain a status value of `"True"` until the
OCIRepository is marked as [reconciling](#reconciling-gitrepository), or e.g. a
[transient error](#failed-gitrepository) occurs due to a temporary network issue.

When the OCIRepository Artifact is archived in the controller's Artifact
storage, the controller sets a Condition with the following attributes in the
OCIRepository's `.status.conditions`:

- `type: ArtifactInStorage`
- `status: "True"`
- `reason: Succeeded`

This `ArtifactInStorage` Condition will retain a status value of `"True"` until
the Artifact in the storage no longer exists.

#### Failed OCIRepository

The source-controller may get stuck trying to produce an Artifact for a
OCIRepository without completing. This can occur due to some of the following
factors:

- The remote OCI repository [URL](#url) is temporarily unavailable.
- The OCI repository does not exist.
- The [Secret reference](#secret-reference) contains a reference to a
  non-existing Secret.
- The credentials in the referenced Secret are invalid.
- The OCIRepository spec contains a generic misconfiguration.
- A storage related failure when storing the artifact.

When this happens, the controller sets the `Ready` Condition status to `False`,
and adds a Condition with the following attributes to the OCIRepository's
`.status.conditions`:

- `type: FetchFailed` | `type: IncludeUnavailable` | `type: StorageOperationFailed`
- `status: "True"`
- `reason: AuthenticationFailed` | `reason: OCIArtifactPullFailed` | `reason: OCIArtifactLayerOperationFailed`

This condition has a ["negative polarity"][typical-status-properties],
and is only present on the OCIRepository while the status value is `"True"`.
There may be more arbitrary values for the `reason` field to provide accurate
reason for a condition.

While the OCIRepository has one or more of these Conditions, the controller
will continue to attempt to produce an Artifact for the resource with an
exponential backoff, until it succeeds and the OCIRepository is marked as
[ready](#ready-ocirepository).

Note that a OCIRepository can be [reconciling](#reconciling-ocirepository)
while failing at the same time, for example due to a newly introduced
configuration issue in the OCIRepository spec.

### Content Configuration Checksum

The source-controller calculates the SHA256 checksum of the various
configurations of the OCIRepository that indicate a change in source and
records it in `.status.contentConfigChecksum`. This field is used to determine
if the source artifact needs to be rebuilt.

### Observed Generation

The source-controller reports an [observed generation][typical-status-properties]
in the OCIRepository's `.status.observedGeneration`. The observed generation is
the latest `.metadata.generation` which resulted in either a [ready state](#ready-ocirepository),
or stalled due to error it can not recover from without human
intervention.

### Last Handled Reconcile At

The source-controller reports the last `reconcile.fluxcd.io/requestedAt`
annotation value it acted on in the `.status.lastHandledReconcileAt` field.

For practical information about this field, see [triggering a
reconcile](#triggering-a-reconcile).

[typical-status-properties]: https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties
[kstatus-spec]: https://github.com/kubernetes-sigs/cli-utils/tree/master/pkg/kstatus
[image-pull-secrets]: https://kubernetes.io/docs/concepts/containers/images/#specifying-imagepullsecrets-on-a-pod
[image-auto-provider-secrets]: https://fluxcd.io/flux/guides/image-update/#imagerepository-cloud-providers-authentication
[pem-encoding]: https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail
[sops-guide]: https://fluxcd.io/flux/guides/mozilla-sops/
