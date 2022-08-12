# Buckets

The `Bucket` API defines a Source to produce an Artifact for objects from storage
solutions like Amazon S3, Google Cloud Storage buckets, or any other solution
with a S3 compatible API such as Minio, Alibaba Cloud OSS and others.

## Example

The following is an example of a Bucket. It creates a tarball (`.tar.gz`)
Artifact with the fetched objects from an object storage with an S3
compatible API (e.g. [Minio](https://min.io)):

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: Bucket
metadata:
  name: minio-bucket
  namespace: default
spec:
  interval: 5m0s
  endpoint: minio.example.com
  insecure: true
  secretRef:
    name: minio-bucket-secret
  bucketName: example
---
apiVersion: v1
kind: Secret
metadata:
  name: minio-bucket-secret
  namespace: default
type: Opaque
stringData:
  accesskey: <access key>
  secretkey: <secret key>
```

In the above example:

- A Bucket named `minio-bucket` is created, indicated by the
  `.metadata.name` field.
- The source-controller checks the object storage bucket every five minutes,
  indicated by the `.spec.interval` field.
- It authenticates to the `minio.example.com` endpoint with
  the static credentials from the `minio-secret` Secret data, indicated by
  the `.spec.endpoint` and `.spec.secretRef.name` fields.
- A list of object keys and their [etags](https://en.wikipedia.org/wiki/HTTP_ETag)
  in the `.spec.bucketName` bucket is compiled, while filtering the keys using
  [default ignore rules](#default-exclusions).
- The SHA256 sum of the list is used as Artifact revision, reported
  in-cluster in the `.status.artifact.revision` field.
- When the current Bucket revision differs from the latest calculated revision,
  all objects are fetched and archived.
- The new Artifact is reported in the `.status.artifact` field.

You can run this example by saving the manifest into `bucket.yaml`, and
changing the Bucket and Secret values to target a Minio instance you have
control over.

**Note:** For more advanced examples targeting e.g. Amazon S3 or GCP, see
[Provider](#provider).

1. Apply the resource on the cluster:

   ```sh
   kubectl apply -f bucket.yaml
   ```

2. Run `kubectl get buckets` to see the Bucket:

   ```console
   NAME           ENDPOINT            AGE   READY   STATUS                                                                                         
   minio-bucket   minio.example.com   34s   True    stored artifact for revision 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
   ```

3. Run `kubectl describe bucket minio-bucket` to see the [Artifact](#artifact)
   and [Conditions](#conditions) in the Bucket's Status:

   ```console
   ...
   Status:
     Artifact:
       Checksum:          72aa638abb455ca5f9ef4825b949fd2de4d4be0a74895bf7ed2338622cd12686
       Last Update Time:  2022-02-01T23:43:38Z
       Path:              bucket/default/minio-bucket/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.tar.gz
       Revision:          e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
       URL:               http://source-controller.source-system.svc.cluster.local./bucket/default/minio-bucket/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.tar.gz
     Conditions:
       Last Transition Time:  2022-02-01T23:43:38Z
       Message:               stored artifact for revision 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
       Observed Generation:   1
       Reason:                Succeeded
       Status:                True
       Type:                  Ready
       Last Transition Time:  2022-02-01T23:43:38Z
       Message:               stored artifact for revision 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
       Observed Generation:   1
       Reason:                Succeeded
       Status:                True
       Type:                  ArtifactInStorage
     Observed Generation:     1
     URL:                     http://source-controller.source-system.svc.cluster.local./bucket/default/minio-bucket/latest.tar.gz
   Events:
     Type    Reason                  Age   From               Message
     ----    ------                  ----  ----               -------
     Normal  NewArtifact             82s   source-controller  fetched 16 files from 'example'
   ```

## Writing a Bucket spec

As with all other Kubernetes config, a Bucket needs `apiVersion`, `kind`, and
`metadata` fields. The name of a Bucket object must be a valid 
[DNS subdomain name](https://kubernetes.io/docs/concepts/overview/working-with-objects/names#dns-subdomain-names).

A Bucket also needs a
[`.spec` section](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status).

### Provider

The `.spec.provider` field allows for specifying a Provider to enable provider
specific configurations, for example to communicate with a non-S3 compatible
API endpoint, or to change the authentication method.

Supported options are:

- [Generic](#generic)
- [AWS](#aws)
- [Azure](#azure)
- [GCP](#gcp)

If you do not specify `.spec.provider`, it defaults to `generic`.

#### Generic

When a Bucket's `spec.provider` is set to `generic`, the controller will
attempt to communicate with the specified [Endpoint](#endpoint) using the
[Minio Client SDK](https://github.com/minio/minio-go), which can communicate
with any Amazon S3 compatible object storage (including
[GCS](https://cloud.google.com/storage/docs/interoperability),
[Wasabi](https://wasabi-support.zendesk.com/hc/en-us/articles/360002079671-How-do-I-use-Minio-Client-with-Wasabi-),
and many others).

The `generic` Provider _requires_ a [Secret reference](#secret-reference) to a
Secret with `.data.accesskey` and `.data.secretkey` values, used to
authenticate with static credentials.

The Provider allows for specifying a region the bucket is in using the
[`.spec.region` field](#region), if required by the [Endpoint](#endpoint).

##### Generic example

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: Bucket
metadata:
  name: generic-insecure
  namespace: default
spec:
  provider: generic
  interval: 5m0s
  bucketName: podinfo
  endpoint: minio.minio.svc.cluster.local:9000
  timeout: 60s
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

#### AWS

When a Bucket's `.spec.provider` field is set to `aws`, the source-controller
will attempt to communicate with the specified [Endpoint](#endpoint) using the
[Minio Client SDK](https://github.com/minio/minio-go).

Without a [Secret reference](#secret-reference), authorization using
credentials retrieved from the AWS EC2 service is attempted by default. When
a reference is specified, it expects a Secret with `.data.accesskey` and
`.data.secretkey` values, used to authenticate with static credentials.

The Provider allows for specifying the
[Amazon AWS Region](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-available-regions)
using the [`.spec.region` field](#region).

##### AWS EC2 example

**Note:** On EKS you have to create an [IAM role](#aws-iam-role-example) for
the source-controller service account that grants access to the bucket.

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: Bucket
metadata:
  name: aws
  namespace: default
spec:
  interval: 5m0s
  provider: aws
  bucketName: podinfo
  endpoint: s3.amazonaws.com
  region: us-east-1
  timeout: 30s
```

##### AWS IAM role example

Replace `<bucket-name>` with the specified `.spec.bucketName`.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::<bucket-name>/*"
        },
        {
            "Sid": "",
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::<bucket-name>"
        }
    ]
}
```

##### AWS static auth example

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: Bucket
metadata:
  name: aws
  namespace: default
spec:
  interval: 5m0s
  provider: aws
  bucketName: podinfo
  endpoint: s3.amazonaws.com
  region: us-east-1
  secretRef:
    name: aws-credentials
---
apiVersion: v1
kind: Secret
metadata:
  name: aws-credentials
  namespace: default
type: Opaque
data:
  accesskey: <BASE64>
  secretkey: <BASE64>
```

#### Azure

When a Bucket's `.spec.provider` is set to `azure`, the source-controller will
attempt to communicate with the specified [Endpoint](#endpoint) using the
[Azure Blob Storage SDK for Go](https://github.com/Azure/azure-sdk-for-go/tree/main/sdk/storage/azblob).

Without a [Secret reference](#secret-reference), authentication using a chain
with:

- [Environment credentials](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity#EnvironmentCredential)
- [Managed Identity](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity#ManagedIdentityCredential)
  with the `AZURE_CLIENT_ID`
- Managed Identity with a system-assigned identity

is attempted by default. If no chain can be established, the bucket
is assumed to be publicly reachable.

When a reference is specified, it expects a Secret with one of the following
sets of `.data` fields:

- `tenantId`, `clientId` and `clientSecret` for authenticating a Service 
   Principal with a secret.
- `tenantId`, `clientId` and `clientCertificate` (plus optionally
  `clientCertificatePassword` and/or `clientCertificateSendChain`) for 
   authenticating a Service Principal with a certificate.
- `clientId` for authenticating using a Managed Identity.
- `accountKey` for authenticating using a
  [Shared Key](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/storage/azblob#SharedKeyCredential).
- `sasKey` for authenticating using a [SAS Token](https://docs.microsoft.com/en-us/azure/storage/common/storage-sas-overview)

For any Managed Identity and/or Azure Active Directory authentication method,
the base URL can be configured using `.data.authorityHost`. If not supplied,
[`AzurePublicCloud` is assumed](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity#AuthorityHost).

##### Azure example

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: Bucket
metadata:
  name: azure-public
  namespace: default
spec:
  interval: 5m0s
  provider: azure
  bucketName: podinfo
  endpoint: https://podinfoaccount.blob.core.windows.net
  timeout: 30s
```

##### Azure Service Principal Secret example

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: Bucket
metadata:
  name: azure-service-principal-secret
  namespace: default
spec:
  interval: 5m0s
  provider: azure
  bucketName: <bucket-name>
  endpoint: https://<account-name>.blob.core.windows.net
  secretRef:
    name: azure-sp-auth
---
apiVersion: v1
kind: Secret
metadata:
  name: azure-sp-auth
  namespace: default
type: Opaque
data:
  tenantId: <BASE64>
  clientId: <BASE64>
  clientSecret: <BASE64>
```

##### Azure Service Principal Certificate example

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: Bucket
metadata:
  name: azure-service-principal-cert
  namespace: default
spec:
  interval: 5m0s
  provider: azure
  bucketName: <bucket-name>
  endpoint: https://<account-name>.blob.core.windows.net
  secretRef:
    name: azure-sp-auth
---
apiVersion: v1
kind: Secret
metadata:
  name: azure-sp-auth
  namespace: default
type: Opaque
data:
  tenantId: <BASE64>
  clientId: <BASE64>
  clientCertificate: <BASE64>
  # Plus optionally
  clientCertificatePassword: <BASE64>
  clientCertificateSendChain: <BASE64> # either "1" or "true"
```

##### Azure Managed Identity with Client ID example

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: Bucket
metadata:
  name: azure-managed-identity
  namespace: default
spec:
  interval: 5m0s
  provider: azure
  bucketName: <bucket-name>
  endpoint: https://<account-name>.blob.core.windows.net
  secretRef:
    name: azure-smi-auth
---
apiVersion: v1
kind: Secret
metadata:
  name: azure-smi-auth
  namespace: default
type: Opaque
data:
  clientId: <BASE64>
```

##### Azure Blob Shared Key example

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: Bucket
metadata:
  name: azure-shared-key
  namespace: default
spec:
  interval: 5m0s
  provider: azure
  bucketName: <bucket-name>
  endpoint: https://<account-name>.blob.core.windows.net
  secretRef:
    name: azure-key
---
apiVersion: v1
kind: Secret
metadata:
  name: azure-key
  namespace: default
type: Opaque
data:
  accountKey: <BASE64>
```

#### Managed Identity with AAD Pod Identity

If you are using [aad pod identity](https://azure.github.io/aad-pod-identity/docs), you can create an identity that has access to Azure Storage.

```sh
export IDENTITY_NAME="blob-access"

az role assignment create --role "Storage Blob Data Contributor"  \
--assignee-object-id "$(az identity show -n blob-access  -o tsv --query principalId  -g $RESOURCE_GROUP)" \
--scope "/subscriptions/<SUBSCRIPTION-ID>/resourceGroups/aks-somto/providers/Microsoft.Storage/storageAccounts/<account-name>/blobServices/default/containers/<container-name>"

export IDENTITY_CLIENT_ID="$(az identity show -n ${IDENTITY_NAME} -g ${RESOURCE_GROUP} -otsv --query clientId)"
export IDENTITY_RESOURCE_ID="$(az identity show -n ${IDENTITY_NAME} -otsv --query id)"
```

Create an `AzureIdentity` object that references the identity created above:

```yaml
---
apiVersion: aadpodidentity.k8s.io/v1
kind: AzureIdentity
metadata:
  name:  # source-controller label will match this name
  namespace: flux-system
spec:
  clientID: <IDENTITY_CLIENT_ID>
  resourceID: <IDENTITY_RESOURCE_ID>
  type: 0  # user-managed identity
```

Create an `AzureIdentityBinding` object that binds pods with a specific selector with the `AzureIdentity` created:

```yaml
apiVersion: "aadpodidentity.k8s.io/v1"
kind: AzureIdentityBinding
metadata:
  name: ${IDENTITY_NAME}-binding
spec:
  azureIdentity: ${IDENTITY_NAME}
  selector: ${IDENTITY_NAME}
```

Label the source-controller correctly so that it can match an identity binding:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kustomize-controller
  namespace: flux-system
spec:
  template:
    metadata:
      labels:
        aadpodidbinding: ${IDENTITY_NAME}  # match the AzureIdentity name
```

If you have set aad-pod-identity up correctly and labeled the source-controller pod, then you don't need to reference a secret.

```yaml
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: Bucket
metadata:
  name: azure-bucket
  namespace: flux-system
spec:
  interval: 5m0s
  provider: azure
  bucketName: testsas
  endpoint: https://testfluxsas.blob.core.windows.net
```

##### Azure Blob SAS Token example

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: Bucket
metadata:
  name: azure-sas-token
  namespace: default
spec:
  interval: 5m0s
  provider: azure
  bucketName: <bucket-name>
  endpoint: https://<account-name>.blob.core.windows.net
  secretRef:
    name: azure-key
---
apiVersion: v1
kind: Secret
metadata:
  name: azure-key
  namespace: default
type: Opaque
data:
  sasKey: <base64>
```

The sasKey only contains the SAS token e.g `?sv=2020-08-0&ss=bfqt&srt=co&sp=rwdlacupitfx&se=2022-05-26T21:55:35Z&st=2022-05...`.
The leading question mark is optional.
The query values from the `sasKey` data field in the Secrets gets merged with the ones in the `spec.endpoint` of the `Bucket`.
If the same key is present in the both of them, the value in the `sasKey` takes precedence.

Note that the Azure SAS Token has an expiry date and it should be updated before it expires so that Flux can
continue to access Azure Storage.

#### GCP

When a Bucket's `.spec.provider` is set to `gcp`, the source-controller will
attempt to communicate with the specified [Endpoint](#endpoint) using the
[Google Client SDK](https://github.com/googleapis/google-api-go-client).

Without a [Secret reference](#secret-reference), authorization using a
workload identity is attempted by default. The workload identity is obtained
using the `GOOGLE_APPLICATION_CREDENTIALS` environment variable, falling back
to the Google Application Credential file in the config directory.
When a reference is specified, it expects a Secret with a `.data.serviceaccount`
value with a GCP service account JSON file.

The Provider allows for specifying the
[Bucket location](https://cloud.google.com/storage/docs/locations) using the
[`.spec.region` field](#region).

##### GCP example

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: Bucket
metadata:
  name: gcp-workload-identity
  namespace: default
spec:
  interval: 5m0s
  provider: gcp
  bucketName: podinfo
  endpoint: storage.googleapis.com
  region: us-east-1
  timeout: 30s
```

##### GCP static auth example

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: Bucket
metadata:
  name: gcp-secret
  namespace: default
spec:
  interval: 5m0s
  provider: gcp
  bucketName: <bucket-name>
  endpoint: storage.googleapis.com
  region: <bucket-region>
  secretRef:
    name: gcp-service-account
---
apiVersion: v1
kind: Secret
metadata:
  name: gcp-service-account
  namespace: default
type: Opaque
data:
  serviceaccount: <BASE64>
```

Where the (base64 decoded) value of `.data.serviceaccount` looks like this:

```json
{
  "type": "service_account",
  "project_id": "example",
  "private_key_id": "28qwgh3gdf5hj3gb5fj3gsu5yfgh34f45324568hy2",
  "private_key": "-----BEGIN PRIVATE KEY-----\nHwethgy123hugghhhbdcu6356dgyjhsvgvGFDHYgcdjbvcdhbsx63c\n76tgycfehuhVGTFYfw6t7ydgyVgydheyhuggycuhejwy6t35fthyuhegvcetf\nTFUHGTygghubhxe65ygt6tgyedgy326hucyvsuhbhcvcsjhcsjhcsvgdtHFCGi\nHcye6tyyg3gfyuhchcsbhygcijdbhyyTF66tuhcevuhdcbhuhhvftcuhbh3uh7t6y\nggvftUHbh6t5rfthhuGVRtfjhbfcrd5r67yuhuvgFTYjgvtfyghbfcdrhyjhbfctfdfyhvfg\ntgvggtfyghvft6tugvTF5r66tujhgvfrtyhhgfct6y7ytfr5ctvghbhhvtghhjvcttfycf\nffxfghjbvgcgyt67ujbgvctfyhVC7uhvgcyjvhhjvyujc\ncgghgvgcfhgg765454tcfthhgftyhhvvyvvffgfryyu77reredswfthhgfcftycfdrttfhf/\n-----END PRIVATE KEY-----\n",
  "client_email": "test@example.iam.gserviceaccount.com",
  "client_id": "32657634678762536746",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test%40podinfo.iam.gserviceaccount.com"
}
```

### Interval

`.spec.interval` is a required field that specifices the interval which the
object storage bucket must be consulted at.

After successfully reconciling a Bucket object, the source-controller requeues
the object for inspection after the specified interval. The value must be in a
[Go recognized duration string format](https://pkg.go.dev/time#ParseDuration),
e.g. `10m0s` to look at the object storage bucket every 10 minutes.

If the `.metadata.generation` of a resource changes (due to e.g. the apply of a
change to the spec), this is handled instantly outside of the interval window.

### Endpoint

`.spec.endpoint` is a required field that specifies the HTTP/S object storage
endpoint to connect to and fetch objects from. Connecting to an (insecure)
HTTP endpoint requires enabling [`.spec.insecure`](#insecure).

Some endpoints require the specification of a [`.spec.region`](#region),
see [Provider](#provider) for more (provider specific) examples.

### Bucket name

`.spec.bucketName` is a required field that specifies which object storage
bucket on the [Endpoint](#endpoint) objects should be fetched from.

See [Provider](#provider) for more (provider specific) examples.

### Region

`.spec.region` is an optional field to specify the region a
[`.spec.bucketName`](#bucket-name) is located in.

See [Provider](#provider) for more (provider specific) examples.

### Insecure

`.spec.insecure` is an optional field to allow connecting to an insecure (HTTP)
[endpoint](#endpoint), if set to `true`. The default value is `false`,
denying insecure (HTTP) connections.

### Timeout

`.spec.timeout` is an optional field to specify a timeout for object storage
fetch operations. The value must be in a
[Go recognized duration string format](https://pkg.go.dev/time#ParseDuration),
e.g. `1m30s` for a timeout of one minute and thirty seconds.
The default value is `60s`.

### Secret reference

`.spec.secretRef.name` is an optional field to specify a name reference to a
Secret in the same namespace as the Bucket, containing authentication
credentials for the object storage. For some `.spec.provider` implementations
the presence of the field is required, see [Provider](#provider) for more
details and examples.

### Ignore

`.spec.ignore` is an optional field to specify rules in [the `.gitignore`
pattern format](https://git-scm.com/docs/gitignore#_pattern_format). Storage
objects which keys match the defined rules are excluded while fetching.

When specified, `.spec.ignore` overrides the [default exclusion
list](#default-exclusions), and may overrule the [`.sourceignore` file
exclusions](#sourceignore-file). See [excluding files](#excluding-files)
for more information.

### Suspend

`.spec.suspend` is an optional field to suspend the reconciliation of a Bucket.
When set to `true`, the controller will stop reconciling the Bucket, and changes
to the resource or in the object storage bucket will not result in a new
Artifact. When the field is set to `false` or removed, it will resume.

For practical information, see
[suspending and resuming](#suspending-and-resuming).

## Working with Buckets

### Excluding files

By default, storage bucket objects which match the [default exclusion
rules](#default-exclusions) are excluded while fetching. It is possible to
overwrite and/or overrule the default exclusions using a file in the bucket
and/or an in-spec set of rules.

#### `.sourceignore` file

Excluding files is possible by adding a `.sourceignore` file in the root of the
object storage bucket. The `.sourceignore` file follows [the `.gitignore`
pattern format](https://git-scm.com/docs/gitignore#_pattern_format), and
pattern entries may overrule [default exclusions](#default-exclusions).

#### Ignore spec

Another option is to define the exclusions within the Bucket spec, using the
[`.spec.ignore` field](#ignore). Specified rules override the
[default exclusion list](#default-exclusions), and may overrule `.sourceignore`
file exclusions.

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: Bucket
metadata:
  name: <bucket-name>
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

To manually tell the source-controller to reconcile a Bucket outside of the
[specified interval window](#interval), a Bucket can be annotated with
`reconcile.fluxcd.io/requestedAt: <arbitrary value>`. Annotating the resource
queues the Bucket for reconciliation if the `<arbitrary-value>` differs from
the last value the controller acted on, as reported in
[`.status.lastHandledReconcileAt`](#last-handled-reconcile-at).

Using `kubectl`:

```sh
kubectl annotate --field-manager=flux-client-side-apply --overwrite  bucket/<bucket-name> reconcile.fluxcd.io/requestedAt="$(date +%s)"
```

Using `flux`:

```sh
flux reconcile source bucket <bucket-name>
```

### Waiting for `Ready`

When a change is applied, it is possible to wait for the Bucket to reach a
[ready state](#ready-bucket) using `kubectl`:

```sh
kubectl wait bucket/<bucket-name> --for=condition=ready --timeout=1m
```

### Suspending and resuming

When you find yourself in a situation where you temporarily want to pause the
reconciliation of a Bucket, you can suspend it using the [`.spec.suspend`
field](#suspend).

#### Suspend a Bucket

In your YAML declaration:

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: Bucket
metadata:
  name: <bucket-name>
spec:
  suspend: true
```

Using `kubectl`:

```sh
kubectl patch bucket <bucket-name> --field-manager=flux-client-side-apply -p '{\"spec\": {\"suspend\" : true }}'
```

Using `flux`:

```sh
flux suspend source bucket <bucket-name>
```

**Note:** When a Bucket has an Artifact and is suspended, and this Artifact
later disappears from the storage due to e.g. the source-controller Pod being
evicted from a Node, this will not be reflected in the Bucket's Status until it
is resumed.

#### Resume a Bucket

In your YAML declaration, comment out (or remove) the field:

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: Bucket
metadata:
  name: <bucket-name>
spec:
  # suspend: true
```

**Note:** Setting the field value to `false` has the same effect as removing
it, but does not allow for "hot patching" using e.g. `kubectl` while practicing
GitOps; as the manually applied patch would be overwritten by the declared
state in Git.

Using `kubectl`:

```sh
kubectl patch bucket <bucket-name> --field-manager=flux-client-side-apply -p '{\"spec\" : {\"suspend\" : false }}'
```

Using `flux`:

```sh
flux resume source bucket <bucket-name>
```

### Debugging a Bucket

There are several ways to gather information about a Bucket for debugging
purposes.

#### Describe the Bucket

Describing a Bucket using `kubectl describe bucket <bucket-name>` displays the
latest recorded information for the resource in the `Status` and `Events`
sections:

```console
...
Status:
...
  Conditions:
    Last Transition Time:  2022-02-02T13:26:55Z
    Message:               reconciling new object generation (2)
    Observed Generation:   2
    Reason:                NewGeneration
    Status:                True
    Type:                  Reconciling
    Last Transition Time:  2022-02-02T13:26:55Z
    Message:               bucket 'my-new-bucket' does not exist
    Observed Generation:   2
    Reason:                BucketOperationFailed
    Status:                False
    Type:                  Ready
    Last Transition Time:  2022-02-02T13:26:55Z
    Message:               bucket 'my-new-bucket' does not exist
    Observed Generation:   2
    Reason:                BucketOperationFailed
    Status:                True
    Type:                  FetchFailed
  Observed Generation:     1
  URL:                     http://source-controller.source-system.svc.cluster.local./bucket/default/minio-bucket/latest.tar.gz
Events:
  Type     Reason                      Age                 From               Message
  ----     ------                      ----                ----               -------
  Warning  BucketOperationFailed       37s (x11 over 42s)  source-controller  bucket 'my-new-bucket' does not exist
```

#### Trace emitted Events

To view events for specific Bucket(s), `kubectl get events` can be used in
combination with `--field-sector` to list the Events for specific objects.
For example, running

```sh
kubectl get events --field-selector involvedObject.kind=Bucket,involvedObject.name=<bucket-name>
```

lists

```console
LAST SEEN   TYPE      REASON                       OBJECT                 MESSAGE
2m30s       Normal    NewArtifact                  bucket/<bucket-name>   fetched 16 files with revision from 'my-new-bucket'
36s         Normal    ArtifactUpToDate             bucket/<bucket-name>   artifact up-to-date with remote revision: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
18s         Warning   BucketOperationFailed        bucket/<bucket-name>   bucket 'my-new-bucket' does not exist
```

Besides being reported in Events, the reconciliation errors are also logged by
the controller. The Flux CLI offer commands for filtering the logs for a
specific Bucket, e.g. `flux logs --level=error --kind=Bucket --name=<bucket-name>`.

## Bucket Status

### Artifact

The Bucket reports the latest synchronized state from the object storage
bucket as an Artifact object in the `.status.artifact` of the resource.

The Artifact file is a gzip compressed TAR archive
(`<calculated revision>.tar.gz`), and can be retrieved in-cluster from the
`.status.artifact.url` HTTP address.

#### Artifact example

```yaml
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: Bucket
metadata:
  name: <bucket-name>
status:
  artifact:
    checksum: cbec34947cc2f36dee8adcdd12ee62ca6a8a36699fc6e56f6220385ad5bd421a
    lastUpdateTime: "2022-01-28T10:30:30Z"
    path: bucket/<namespace>/<bucket-name>/c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2.tar.gz
    revision: c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2
    url: http://source-controller.<namespace>.svc.cluster.local./bucket/<namespace>/<bucket-name>/c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2.tar.gz
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

A Bucket enters various states during its lifecycle, reflected as
[Kubernetes Conditions][typical-status-properties].
It can be [reconciling](#reconciling-bucket) while fetching storage objects,
it can be [ready](#ready-bucket), or it can [fail during
reconciliation](#failed-bucket).

The Bucket API is compatible with the [kstatus specification][kstatus-spec],
and reports `Reconciling` and `Stalled` conditions where applicable to
provide better (timeout) support to solutions polling the Bucket to become
`Ready`.

#### Reconciling Bucket

The source-controller marks a Bucket as _reconciling_ when one of the following
is true:

- There is no current Artifact for the Bucket, or the reported Artifact is
  determined to have disappeared from the storage.
- The generation of the Bucket is newer than the [Observed Generation](#observed-generation).
- The newly calculated Artifact revision differs from the current Artifact.

When the Bucket is "reconciling", the `Ready` Condition status becomes `False`,
and the controller adds a Condition with the following attributes to the
Bucket's `.status.conditions`:

- `type: Reconciling`
- `status: "True"`
- `reason: NewGeneration` | `reason: NoArtifact` | `reason: NewRevision`

If the reconciling state is due to a new revision, an additional Condition is
added with the following attributes:

- `type: ArtifactOutdated`
- `status: "True"`
- `reason: NewRevision`

Both Conditions have a ["negative polarity"][typical-status-properties],
and are only present on the Bucket while their status value is `"True"`.

#### Ready Bucket

The source-controller marks a Bucket as _ready_ when it has the following
characteristics:

- The Bucket reports an [Artifact](#artifact).
- The reported Artifact exists in the controller's Artifact storage.
- The Bucket was able to communicate with the Bucket's object storage endpoint
  using the current spec.
- The revision of the reported Artifact is up-to-date with the latest
  calculated revision of the object storage bucket.

When the Bucket is "ready", the controller sets a Condition with the following
attributes in the Bucket's `.status.conditions`:

- `type: Ready`
- `status: "True"`
- `reason: Succeeded`

This `Ready` Condition will retain a status value of `"True"` until the Bucket
is marked as [reconciling](#reconciling-bucket), or e.g. a
[transient error](#failed-bucket) occurs due to a temporary network issue.

When the Bucket Artifact is archived in the controller's Artifact
storage, the controller sets a Condition with the following attributes in the
Bucket's `.status.conditions`:

- `type: ArtifactInStorage`
- `status: "True"`
- `reason: Succeeded`

This `ArtifactInStorage` Condition will retain a status value of `"True"` until
the Artifact in the storage no longer exists.

#### Failed Bucket

The source-controller may get stuck trying to produce an Artifact for a Bucket
without completing. This can occur due to some of the following factors: 

- The object storage [Endpoint](#endpoint) is temporarily unavailable.
- The specified object storage bucket does not exist.
- The [Secret reference](#secret-reference) contains a reference to a
  non-existing Secret.
- The credentials in the referenced Secret are invalid.
- The Bucket spec contains a generic misconfiguration.
- A storage related failure when storing the artifact.

When this happens, the controller sets the `Ready` Condition status to `False`,
and adds a Condition with the following attributes to the Bucket's
`.status.conditions`:

- `type: FetchFailed` | `type: StorageOperationFailed`
- `status: "True"`
- `reason: AuthenticationFailed` | `reason: BucketOperationFailed`

This condition has a ["negative polarity"][typical-status-properties],
and is only present on the Bucket while the status value is `"True"`.
There may be more arbitrary values for the `reason` field to provide accurate
reason for a condition.

While the Bucket has this Condition, the controller will continue to attempt
to produce an Artifact for the resource with an exponential backoff, until
it succeeds and the Bucket is marked as [ready](#ready-bucket).

Note that a Bucket can be [reconciling](#reconciling-bucket) while failing at
the same time, for example due to a newly introduced configuration issue in the
Bucket spec.

### Observed Generation

The source-controller reports an
[observed generation][typical-status-properties]
in the Bucket's `.status.observedGeneration`. The observed generation is the
latest `.metadata.generation` which resulted in either a [ready state](#ready-bucket),
or stalled due to error it can not recover from without human
intervention.

### Last Handled Reconcile At

The source-controller reports the last `reconcile.fluxcd.io/requestedAt`
annotation value it acted on in the `.status.lastHandledReconcileAt` field.

For practical information about this field, see [triggering a
reconcile](#triggering-a-reconcile).

[typical-status-properties]: https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties
[kstatus-spec]: https://github.com/kubernetes-sigs/cli-utils/tree/master/pkg/kstatus
