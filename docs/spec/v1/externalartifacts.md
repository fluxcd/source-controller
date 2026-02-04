# External Artifacts

<!-- menuweight:100 -->

The `ExternalArtifact` is a generic API designed for interoperability with Flux.
It allows 3rd party controllers to produce and store [Artifact](#artifact) objects
in the same way as Flux's own source-controller.
For more details on the design and motivation behind this API,
see [RFC-0012](https://github.com/fluxcd/flux2/tree/main/rfcs/0012-external-artifact).

## Example

The following is an example of a ExternalArtifact produced by a 3rd party
source controller:

```yaml
apiVersion: source.werf.io/v1
kind: ExternalArtifact
metadata:
  name: my-artifact
  namespace: flux-system
spec:
  sourceRef:
    apiVersion: example.com/v1
    kind: Source
    name: my-source
status:
  artifact:
    digest: sha256:35d47c9db0eee6ffe08a404dfb416bee31b2b79eabc3f2eb26749163ce487f52
    lastUpdateTime: "2025-08-21T13:37:31Z"
    path: source/flux-system/my-source/35d47c9d.tar.gz
    revision: v1.0.0@sha256:35d47c9db0eee6ffe08a404dfb416bee31b2b79eabc3f2eb26749163ce487f52
    size: 20914
    url: http://example-controller.flux-system.svc.cluster.local./source/flux-system/my-source/35d47c9d.tar.gz
  conditions:
    - lastTransitionTime: "2025-08-21T13:37:31Z"
      message: stored artifact for revision v1.0.0
      observedGeneration: 1
      reason: Succeeded
      status: "True"
      type: Ready
```

## ExternalArtifact spec

### Source reference

The `spec.sourceRef` field is optional and contains a reference
to the custom resource that the ExternalArtifact is based on.

The `spec.sourceRef` contains the following fields:

- `apiVersion`: the API version of the custom resource.
- `kind`: the kind of the custom resource.
- `name`: the name of the custom resource.
- `namespace`: the namespace of the custom resource. If omitted, it defaults to the
  namespace of the ExternalArtifact.

## ExternalArtifact status

### Artifact

The ExternalArtifact reports the latest synchronized state
as an Artifact object in the `.status.artifact`.

The `.status.artifact` contains the following fields:

- `digest`: The checksum of the tar.gz file in the format `<algorithm>:<checksum>`.
- `lastUpdateTime`: Timestamp of the last artifact update.
- `path`: Relative file path of the artifact in storage.
- `revision`: Human-readable identifier with version and checksum in the format `<human-readable-identifier>@<algorithm>:<checksum>`.
- `size`: Number of bytes in the tar.gz file.
- `url`: In-cluster HTTP address for artifact retrieval.

### Conditions

The ExternalArtifact reports its status using Kubernetes standard conditions.

#### Ready ExternalArtifact

When the 3rd party controller has successfully produced and stored an
Artifact in storage, it sets a Condition with the following
attributes in the ExternalArtifact's `.status.conditions`:

- `type: Ready`
- `status: "True"`
- `reason: Succeeded`

The `message` field should contain a human-readable message indicating
the successful storage of the artifact and the associated revision.

If the 3rd party controller performs a signature verification
of the artifact, and the verification is successful, a Condition with the
following attributes is added to the ExternalArtifact's `.status.conditions`:

- `type: SourceVerified`
- `status: "True"`
- `reason: Succeeded`

The `message` field should contain a human-readable message indicating
the successful verification of the artifact and the associated verification method.

#### Failed ExternalArtifact

If the 3rd party controller fails to produce and store an Artifact,
it sets the `Ready` Condition status to `False`, and adds a Condition with
the following attributes to the ExternalArtifact's `.status.conditions`:

- `type: Ready`
- `status: "False"`
- `reason: FetchFailed` | `reason: StorageOperationFailed` | `reason: VerificationFailed`

The `message` field should contain a human-readable message indicating
the reason for the failure.
