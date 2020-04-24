# Receivers

The `Receiver` API defines a webhook receiver that triggers
a synchronization for a group of sources.

## Specification

```go
type ReceiverSpec struct {
	// Type of webhook sender, used to determine
	// the validation procedure and payload deserialization.
	// +kubebuilder:validation:Enum=github;gitlab
	// +required
	Type string `json:"type"`

	// A list of sources to be notified about changes.
	// +required
	Sources []corev1.TypedLocalObjectReference `json:"sources"`
}
```

Webhook sender type:

```go
const (
	GitHubWebhook string = "github"
	GitLabWebhook string = "gitlab"
)
```

## Status

```go
type ReceiverStatus struct {
	// Generated webhook URL in the format
	// of '/hook/sha256sum(token)'.
	// +required
	URL string `json:"url"`

	// Generate token used to validate the payload authenticity.
	// +required
	Token string `json:"token"`
}
```

## Implementation

The source controller handles the webhook requests on a dedicated port. This port can be used to create
a Kubernetes LoadBalancer Service or Ingress to expose the receiver endpoint outside the cluster.

When a `Receiver` is created, the controller generates a random token and
sets the `Receiver` status token and URL in the format `/hook/sha256sum(token)`.
The `ReceiverReconciler` creates an indexer for the SHA265 digest
so that it can be used as a field selector.

When source controller receives a POST request:
* extract the SHA265 digest from the URL
* loads the `Receiver` using the digest field selector
* extracts the signature from HTTP headers based on `spec.type`
* validates the signature using `status.Token` based on `spec.type`
* extract the event type from the payload 
* triggers a synchronization for `spec.sources` if the event type is `push`
