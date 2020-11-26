# Common

Common defines resources used across all source types.

## Specification

### Source interface

Source objects adhere to the `Source` interface. This interface exposes the [interval](#source-reconciliation)
and [artifact](#source-status) of the source to clients without the prerequisite of knowing the source kind:

````go
type Source interface {
	// GetInterval returns the interval at which the source is updated.
	GetInterval() metav1.Duration

	// GetArtifact returns the latest artifact from the source, or nil.
	GetArtifact() *Artifact
}
````

### Source reconciliation

Source objects contain a `spec.interval` field that tells the controller at which interval to check for updates:

```go
type SourceSpec struct {
	// The interval at which to check for source updates.
	// +required
	Interval metav1.Duration `json:"interval"`
}
```

Valid time units are `s`, `m` and `h` e.g. `interval: 5m`.

The controller can be told to check for updates right away by setting an annotation on source objects:

```bash
kubectl annotate --overwrite gitrepository/podinfo fluxcd.io/reconcileAt="$(date +%s)"
```

The source objects reconciliation can be suspended by setting `spec.suspend` to `true`.

### Source status

Source objects should contain a status sub-resource that embeds an artifact object:

```go
// Artifact represents the output of a source synchronisation.
type Artifact struct {
	// Path is the relative file path of this artifact.
	// +required
	Path string `json:"path"`

	// URL is the HTTP address of this artifact.
	// +required
	URL string `json:"url"`

	// Revision is a human readable identifier traceable in the origin source
	// system. It can be a Git commit SHA, Git tag, a Helm index timestamp, a Helm
	// chart version, etc.
	// +optional
	Revision string `json:"revision"`

	// Checksum is the SHA1 checksum of the artifact.
	// +optional
	Checksum string `json:"checksum"`

	// LastUpdateTime is the timestamp corresponding to the last
	// update of this artifact.
	// +required
	LastUpdateTime metav1.Time `json:"lastUpdateTime,omitempty"`
}
```

### Source condition

> **Note:** to be replaced with <https://github.com/kubernetes/enhancements/pull/1624>
> once made available.

Source objects should implement the [`meta.Condition`](https://godoc.org/github.com/fluxcd/pkg/apis/meta#Condition).

#### Types

Source objects should implement the [`meta.ReadyCondition`](https://godoc.org/github.com/fluxcd/pkg/apis/meta#pkg-constants),
but may implement additional domain-specific types.

#### Reasons

Source objects may implement the [`meta` condition
reasons](https://godoc.org/github.com/fluxcd/pkg/apis/meta#pkg-constants), but
are allowed to use their own reasons if they provide a better explanation.

In addition, the following source specific reasons are available:

```go
const (
	// URLInvalidReason represents the fact that a given source has an invalid URL.
	URLInvalidReason string = "URLInvalid"

	// StorageOperationFailedReason signals a failure caused by a storage operation.
	StorageOperationFailedReason string = "StorageOperationFailed"

	// AuthenticationFailedReason represents the fact that a given secret does not
	// have the required fields or the provided credentials do not match.
	AuthenticationFailedReason string = "AuthenticationFailed"

	// VerificationFailedReason represents the fact that the cryptographic provenance
	// verification for the source failed.
	VerificationFailedReason string = "VerificationFailed"
)
```

## Examples

See the [`GitRepository`](gitrepositories.md) and [`HelmChart`](helmcharts.md) APIs.
