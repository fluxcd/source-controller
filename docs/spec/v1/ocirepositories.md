# OCI Repositories

<!-- menuweight:20 -->

The `OCIRepository` API defines a Source to produce an Artifact for an OCI
repository.

## Example

The following is an example of an OCIRepository. It creates a tarball
(`.tar.gz`) Artifact with the fetched data from an OCI repository for the
resolved digest.

```yaml
---
apiVersion: source.werf.io/v1
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
- The resolved tag and SHA256 digest is used as the Artifact
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
   podinfo   oci://ghcr.io/stefanprodan/manifests/podinfo   5s    True    stored artifact with revision 'latest@sha256:3b6cdcc7adcc9a84d3214ee1c029543789d90b5ae69debe9efa3f66e982875de'
   ```

3. Run `kubectl describe ocirepository podinfo` to see the [Artifact](#artifact)
   and [Conditions](#conditions) in the OCIRepository's Status:

   ```console
   ...
   Status:
     Artifact:
       Digest:            sha256:d7e924b4882e55b97627355c7b3d2e711e9b54303afa2f50c25377f4df66a83b
       Last Update Time:  2025-06-14T11:23:36Z
       Path:              ocirepository/default/podinfo/3b6cdcc7adcc9a84d3214ee1c029543789d90b5ae69debe9efa3f66e982875de.tar.gz
       Revision:          latest@sha256:3b6cdcc7adcc9a84d3214ee1c029543789d90b5ae69debe9efa3f66e982875de
       Size:              1105
       URL:               http://source-controller.flux-system.svc.cluster.local./ocirepository/oci/podinfo/3b6cdcc7adcc9a84d3214ee1c029543789d90b5ae69debe9efa3f66e982875de.tar.gz
     Conditions:
       Last Transition Time:  2025-06-14T11:23:36Z
       Message:               stored artifact for revision 'latest@sha256:3b6cdcc7adcc9a84d3214ee1c029543789d90b5ae69debe9efa3f66e982875de'
       Observed Generation:   1
       Reason:                Succeeded
       Status:                True
       Type:                  Ready
       Last Transition Time:  2025-06-14T11:23:36Z
       Message:               stored artifact for revision 'latest@sha256:3b6cdcc7adcc9a84d3214ee1c029543789d90b5ae69debe9efa3f66e982875de'
       Observed Generation:   1
       Reason:                Succeeded
       Status:                True
       Type:                  ArtifactInStorage
     Observed Generation:     1
     URL:                     http://source-controller.source-system.svc.cluster.local./gitrepository/default/podinfo/latest.tar.gz
   Events:
     Type    Reason               Age   From               Message
     ----    ------               ----  ----               -------
     Normal  NewArtifact          62s   source-controller  stored artifact with revision 'latest/3b6cdcc7adcc9a84d3214ee1c029543789d90b5ae69debe9efa3f66e982875de' from 'oci://ghcr.io/stefanprodan/manifests/podinfo'
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

For a complete guide on how to set up authentication for cloud providers,
see the integration [docs](/flux/integrations/).

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

The `azure` provider can be used to authenticate automatically using Workload Identity and Kubelet Managed
Identity to gain access to ACR.

##### Kubelet Managed Identity

When the kubelet managed identity has access to ACR, source-controller running
on it will also have access to ACR.

**Note:** If you have more than one identity configured on the cluster, you have to specify which one to use
by setting the `AZURE_CLIENT_ID` environment variable in the source-controller deployment.

If you are running into further issues, please look at the
[troubleshooting guide](https://github.com/Azure/azure-sdk-for-go/blob/main/sdk/azidentity/TROUBLESHOOTING.md#azure-virtual-machine-managed-identity).

##### Workload Identity

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

`.spec.serviceAccountName` is an optional field to specify a Service Account
in the same namespace as OCIRepository with purpose depending on the value of
the `.spec.provider` field:

- When `.spec.provider` is set to `generic`, the controller will fetch the image
  pull secrets attached to the Service Account and use them for authentication.
- When `.spec.provider` is set to `aws`, `azure`, or `gcp`, the Service Account
  will be used for Workload Identity authentication. In this case, the controller
  feature gate `ObjectLevelWorkloadIdentity` must be enabled, otherwise the
  controller will error out.

**Note:** that for a publicly accessible image repository, you don't need to
provide a `secretRef` nor `serviceAccountName`.

For a complete guide on how to set up authentication for cloud providers,
see the integration [docs](/flux/integrations/).

### Mutual TLS Authentication

`.spec.certSecretRef.name` is an optional field to specify a secret containing
TLS certificate data for mutual TLS authentication.

To authenticate towards an OCI repository using mutual TLS,
the referenced Secret's `.data` should contain the following keys:

* `tls.crt` and `tls.key`, to specify the client certificate and private key used
for TLS client authentication. These must be used in conjunction, i.e.
specifying one without the other will lead to an error.
* `ca.crt`, to specify the CA certificate used to verify the server, which is
required if the server is using a self-signed certificate.

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
apiVersion: source.werf.io/v1
kind: OCIRepository
metadata:
  name: example
  namespace: default
spec:
  interval: 5m0s
  url: oci://example.com
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

### Proxy secret reference

`.spec.proxySecretRef.name` is an optional field used to specify the name of a
Secret that contains the proxy settings for the object. These settings are used
for all the remote operations related to the OCIRepository.
The Secret can contain three keys:

- `address`, to specify the address of the proxy server. This is a required key.
- `username`, to specify the username to use if the proxy server is protected by
   basic authentication. This is an optional key.
- `password`, to specify the password to use if the proxy server is protected by
   basic authentication. This is an optional key.

Example:

```yaml
---
apiVersion: v1
kind: Secret
metadata:
  name: http-proxy
type: Opaque
stringData:
  address: http://proxy.com
  username: mandalorian
  password: grogu
```

Proxying can also be configured in the source-controller Deployment directly by
using the standard environment variables such as `HTTPS_PROXY`, `ALL_PROXY`, etc.

`.spec.proxySecretRef.name` takes precedence over all environment variables.

**Warning:** [Cosign](https://github.com/sigstore/cosign) *keyless*
[verification](#verification) is not supported for this API. If you
require cosign keyless verification to use a proxy you must use the
standard environment variables mentioned above. If you specify a
`proxySecretRef` the controller will simply send out the requests
needed for keyless verification without the associated object-level
proxy settings.

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

**Note:** The controller can be configured to apply a jitter to the interval in
order to distribute the load more evenly when multiple OCIRepository objects are
set up with the same interval. For more information, please refer to the
[source-controller configuration options](https://fluxcd.io/flux/components/source/options/).

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
apiVersion: source.werf.io/v1
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
apiVersion: source.werf.io/v1
kind: OCIRepository
metadata:
  name: <repository-name>
spec:
  ref:
    # SemVer range reference: https://github.com/Masterminds/semver#checking-version-constraints
    semver: "<semver-range>"
```

This field takes precedence over [`.tag`](#tag-example).

#### SemverFilter example

`.spec.ref.semverFilter` is an optional field to specify a SemVer filter to apply
when fetching tags from the OCI repository. The filter is a regular expression
that is applied to the tags fetched from the repository. Only tags that match
the filter are considered for the semver range resolution.

**Note:** The filter is only taken into account when the `.spec.ref.semver` field
is set.

```yaml
---
apiVersion: source.werf.io/v1
kind: OCIRepository
metadata:
  name: podinfo
  namespace: default
spec:
  interval: 5m0s
  url: oci://ghcr.io/stefanprodan/manifests/podinfo
  ref:
    # SemVer comparisons using constraints without a prerelease comparator will skip prerelease versions.
    # Adding a `-0` suffix to the semver range will include prerelease versions.
    semver: ">= 6.1.x-0"
    semverFilter: ".*-rc.*"
```

In the above example, the controller fetches tags from the `ghcr.io/stefanprodan/manifests/podinfo`
repository and filters them using the regular expression `.*-rc.*`. Only tags that
contain the `-rc` suffix are considered for the semver range resolution.

#### Digest example

To pull a specific digest, use `.spec.ref.digest`:

```yaml
---
apiVersion: source.werf.io/v1
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
apiVersion: source.werf.io/v1
kind: OCIRepository
metadata:
  name: <repository-name>
spec:
  layerSelector:
    mediaType: "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
    operation: extract # can be 'extract' or 'copy', defaults to 'extract'
```

If the layer selector matches more than one layer, the first layer matching the specified media type will be used.
Note that the selected OCI layer must be
[compressed](https://github.com/opencontainers/image-spec/blob/v1.0.2/layer.md#gzip-media-types)
in the `tar+gzip` format.

When `.spec.layerSelector.operation` is set to `copy`, instead of extracting the
compressed layer, the controller copies the tarball as-is to storage, thus
keeping the original content unaltered.

### Ignore

`.spec.ignore` is an optional field to specify rules in [the `.gitignore`
pattern format](https://git-scm.com/docs/gitignore#_pattern_format). Paths
matching the defined rules are excluded while archiving.

When specified, `.spec.ignore` overrides the [default exclusion
list](#default-exclusions), and may overrule the [`.sourceignore` file
exclusions](#sourceignore-file). See [excluding files](#excluding-files)
for more information.

### Verification

`.spec.verify` is an optional field to enable the verification of [Cosign](https://github.com/sigstore/cosign)
or [Notation](https://github.com/notaryproject/notation)
signatures. The field offers three subfields:

- `.provider`, to specify the verification provider. The supported options are `cosign` and `notation` at present.
- `.secretRef.name`, to specify a reference to a Secret in the same namespace as
  the OCIRepository, containing the Cosign public keys of trusted authors. For Notation this Secret should also
  include the [trust policy](https://github.com/notaryproject/specifications/blob/v1.0.0/specs/trust-store-trust-policy.md#trust-policy) in
  addition to the CA certificate.
- `.matchOIDCIdentity`, to specify a list of OIDC identity matchers (only supported when using `cosign` as the
  verification provider). Please see
   [Keyless verification](#keyless-verification) for more details.

#### Cosign

The `cosign` provider can be used to verify the signature of an OCI artifact using either a known public key
or via the [Cosign Keyless](https://github.com/sigstore/cosign/blob/main/KEYLESS.md) procedure.

```yaml
---
apiVersion: source.werf.io/v1
kind: OCIRepository
metadata:
  name: <repository-name>
spec:
  verify:
    provider: cosign
    secretRef:
      name: cosign-public-keys
```

When the verification succeeds, the controller adds a Condition with the
following attributes to the OCIRepository's `.status.conditions`:

- `type: SourceVerified`
- `status: "True"`
- `reason: Succeeded`

##### Public keys verification

To verify the authenticity of an OCI artifact, create a Kubernetes secret
with the Cosign public keys:

```yaml
---
apiVersion: v1
kind: Secret
metadata:
  name: cosign-public-keys
type: Opaque
data:
  key1.pub: <BASE64>
  key2.pub: <BASE64>
```

Note that the keys must have the `.pub` extension for Flux to make use of them.

Flux will loop over the public keys and use them to verify an artifact's signature.
This allows for older artifacts to be valid as long as the right key is in the secret.

##### Keyless verification

For publicly available OCI artifacts, which are signed using the
[Cosign Keyless](https://github.com/sigstore/cosign/blob/main/KEYLESS.md) procedure,
you can enable the verification by omitting the `.verify.secretRef` field.

To verify the identity's subject and the OIDC issuer present in the Fulcio
certificate, you can specify a list of OIDC identity matchers using
`.spec.verify.matchOIDCIdentity`. The matcher provides two required fields:

- `.issuer`, to specify a regexp that matches against the OIDC issuer.
- `.subject`, to specify a regexp that matches against the subject identity in
   the certificate.
Both values should follow the [Go regular expression syntax](https://golang.org/s/re2syntax).

The matchers are evaluated in an OR fashion, i.e. the identity is deemed to be
verified if any one matcher successfully matches against the identity.

Example of verifying artifacts signed by the
[Cosign GitHub Action](https://github.com/sigstore/cosign-installer) with GitHub OIDC Token:

```yaml
apiVersion: source.werf.io/v1
kind: OCIRepository
metadata:
  name: podinfo
spec:
  interval: 5m
  url: oci://ghcr.io/stefanprodan/manifests/podinfo
  verify:
    provider: cosign
    matchOIDCIdentity:
      - issuer: "^https://token.actions.githubusercontent.com$"
        subject: "^https://github.com/stefanprodan/podinfo.*$"
```

The controller verifies the signatures using the Fulcio root CA and the Rekor
instance hosted at [rekor.sigstore.dev](https://rekor.sigstore.dev/).

Note that keyless verification is an **experimental feature**, using
custom root CAs or self-hosted Rekor instances are not currently supported.

#### Notation

The `notation` provider can be used to verify the signature of an OCI artifact using known
trust policy and CA certificate.

```yaml
---
apiVersion: source.werf.io/v1
kind: OCIRepository
metadata:
  name: <repository-name>
spec:
  verify:
    provider: notation
    secretRef:
      name: notation-config
```

When the verification succeeds, the controller adds a Condition with the
following attributes to the OCIRepository's `.status.conditions`:

- `type: SourceVerified`
- `status: "True"`
- `reason: Succeeded`

To verify the authenticity of an OCI artifact, create a Kubernetes secret
containing Certificate Authority (CA) root certificates and the a `trust policy`

```yaml
---
apiVersion: v1
kind: Secret
metadata:
  name: notation-config
type: Opaque
data:
  certificate1.pem: <BASE64>
  certificate2.crt: <BASE64>
  trustpolicy.json: <BASE64>
```

Note that the CA certificates must have either `.pem` or `.crt` extension and your trust policy must
be named `trustpolicy.json` for Flux to make use of them.

For more information on the signing and verification process see [Signing and Verification Workflow](https://github.com/notaryproject/specifications/blob/v1.0.0/specs/signing-and-verification-workflow.md).

Flux will loop over the certificates and use them to verify an artifact's signature.
This allows for older artifacts to be valid as long as the right certificate is in the secret.

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
apiVersion: source.werf.io/v1
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

#### `.sourceignore` file

Excluding files is possible by adding a `.sourceignore` file in the artifact.
The `.sourceignore` file follows [the `.gitignore` pattern
format](https://git-scm.com/docs/gitignore#_pattern_format), and pattern
entries may overrule [default exclusions](#default-exclusions).

The controller recursively loads ignore files so a `.sourceignore` can be
placed in the artifact root or in subdirectories.

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
a [ready state](#ready-ocirepository) using `kubectl`:

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
apiVersion: source.werf.io/v1
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
apiVersion: source.werf.io/v1
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
    Last Transition Time:  2025-02-14T09:40:27Z
    Message:               processing object: new generation 1 -> 2
    Observed Generation:   2
    Reason:                ProgressingWithRetry
    Status:                True
    Type:                  Reconciling
    Last Transition Time:  2025-02-14T09:40:27Z
    Message:               failed to pull artifact from 'oci://ghcr.io/stefanprodan/manifests/podinfo': couldn't find tag "0.0.1"
    Observed Generation:   2
    Reason:                OCIOperationFailed
    Status:                False
    Type:                  Ready
    Last Transition Time:  2025-02-14T09:40:27Z
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

To view events for specific OCIRepository(s), `kubectl events` can be used
in combination with `--for` to list the Events for specific objects. For
example, running

```sh
kubectl events --for OCIRepository/<repository-name>
```

lists

```console
LAST SEEN   TYPE     REASON                OBJECT                               MESSAGE
2m14s       Normal   NewArtifact           ocirepository/<repository-name>      stored artifact for revision 'latest@sha256:3b6cdcc7adcc9a84d3214ee1c029543789d90b5ae69debe9efa3f66e982875de'
36s         Normal   ArtifactUpToDate      ocirepository/<repository-name>      artifact up-to-date with remote revision: 'latest@sha256:3b6cdcc7adcc9a84d3214ee1c029543789d90b5ae69debe9efa3f66e982875de'
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

The `.status.artifact.revision` holds the tag and SHA256 digest of the upstream OCI artifact.

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
apiVersion: source.werf.io/v1
kind: OCIRepository
metadata:
  name: <repository-name>
status:
  artifact:
    digest: sha256:9f3bc0f341d4ecf2bab460cc59320a2a9ea292f01d7b96e32740a9abfd341088
    lastUpdateTime: "2025-08-08T09:35:45Z"
    metadata:
      org.opencontainers.image.created: "2025-08-08T12:31:41+03:00"
      org.opencontainers.image.revision: 6.1.8/b3b00fe35424a45d373bf4c7214178bc36fd7872
      org.opencontainers.image.source: https://github.com/stefanprodan/podinfo.git
    path: ocirepository/<namespace>/<repository-name>/<digest>.tar.gz
    revision: <tag>@<digest>
    size: 1105
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
`Unknown` when the controller detects drift, and the controller adds a Condition
with the following attributes to the OCIRepository's `.status.conditions`:

- `type: Reconciling`
- `status: "True"`
- `reason: Progressing` | `reason: ProgressingWithRetry`

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
OCIRepository is marked as [reconciling](#reconciling-ocirepository), or e.g. a
[transient error](#failed-ocirepository) occurs due to a temporary network issue.

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

In addition to the above Condition types, when the signature
[verification](#verification) fails. A condition with
the following attributes is added to the GitRepository's `.status.conditions`:

- `type: SourceVerified`
- `status: "False"`
- `reason: VerificationError`

While the OCIRepository has one or more of these Conditions, the controller
will continue to attempt to produce an Artifact for the resource with an
exponential backoff, until it succeeds and the OCIRepository is marked as
[ready](#ready-ocirepository).

Note that a OCIRepository can be [reconciling](#reconciling-ocirepository)
while failing at the same time, for example due to a newly introduced
configuration issue in the OCIRepository spec. When a reconciliation fails, the
`Reconciling` Condition reason would be `ProgressingWithRetry`. When the
reconciliation is performed again after the failure, the reason is updated to
`Progressing`.

### Observed Ignore

The source-controller reports an observed ignore in the OCIRepository's
`.status.observedIgnore`. The observed ignore is the latest `.spec.ignore` value
which resulted in a [ready state](#ready-ocirepository), or stalled due to error
it can not recover from without human intervention. The value is the same as the
[ignore in spec](#ignore). It indicates the ignore rules used in building the
current artifact in storage. It is also used by the controller to determine if
an artifact needs to be rebuilt.

Example:
```yaml
status:
  ...
  observedIgnore: |
    hpa.yaml
    build
  ...
```

### Observed Layer Selector

The source-controller reports an observed layer selector in the OCIRepository's
`.status.observedLayerSelector`. The observed layer selector is the latest
`.spec.layerSelector` value which resulted in a [ready state](#ready-ocirepository),
or stalled due to error it can not recover from without human intervention.
The value is the same as the [layer selector in spec](#layer-selector).
It indicates the layer selection configuration used in building the current
artifact in storage. It is also used by the controller to determine if an
artifact needs to be rebuilt.

Example:
```yaml
status:
  ...
  observedLayerSelector:
    mediaType: application/vnd.cncf.helm.chart.content.v1.tar+gzip
    operation: copy
  ...
```

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
