# Common

Common defines resources used across types.

## Specification

### Source condition

> **Note:** to be replaced with <https://github.com/kubernetes/enhancements/pull/1624>
> once made available.

```go
// SourceCondition contains condition information for a source.
type SourceCondition struct {
	// Type of the condition, currently ('Ready').
	// +required
	Type string `json:"type"`

	// Status of the condition, one of ('True', 'False', 'Unknown').
	// +required
	Status corev1.ConditionStatus `json:"status"`

	// LastTransitionTime is the timestamp corresponding to the last status
	// change of this condition.
	// +required
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`

	// Reason is a brief machine readable explanation for the condition's last
	// transition.
	// +required
	Reason string `json:"reason,omitempty"`

	// Message is a human readable description of the details of the last
	// transition, complementing reason.
	// +optional
	Message string `json:"message,omitempty"`
}
```

#### Types

```go
const (
	// ReadyCondition represents the fact that a given source is in ready state.
	ReadyCondition string = "Ready"
)
```

#### Reasons

```go
const (
	// InitializingReason represents the fact that a given source is being initialized.
	InitializingReason string = "Initializing"
    // URLInvalidReason represents the fact that a given source has an invalid URL.
	URLInvalidReason string = "URLInvalid"
)
```

## Examples

See the [Git repository](gitrepositories.md) and [Helm chart](helmrepositories.md) APIs.
