# Git Repositories

The `GitReposiory` API defines a source for artifacts coming from Git. The
resource exposes the latest synchronized state from Git as an artifact in
an archive.

## Specification

Git repository:

```go
// GitRepositorySpec defines the desired state of GitRepository.
type GitRepositorySpec struct {
	// The repository URL, can be a HTTP or SSH address.
	// +kubebuilder:validation:Pattern="^(http|https|ssh)://"
	URL string `json:"url"`

	// The secret name containing the Git credentials.
	// +optional
	SecretRef *v1.LocalObjectReference `json:"secretRef,omitempty"`
	
	// The git reference to checkout and monitor for changes, defaults to
	// master branch.
	// +optional
	Reference *GitRepositoryRef `json:"ref,omitempty"`

	// The interval at which to check for repository updates.
	Interval metav1.Duration `json:"interval"`
}
```

Git repository reference:

```go
// GitRepositoryRef defines the git ref used for pull and checkout operations.
type GitRepositoryRef struct {
	// The git branch to checkout, defaults to master.
	// +optional
	Branch string `json:"branch"`

	// The git tag to checkout, takes precedence over branch.
	// +optional
	Tag string `json:"tag"`

	// The git tag semver expression, takes precedence over tag.
	// +optional
	SemVer string `json:"semver"`

	// The git commit sha to checkout, if specified branch and tag filters will
	// be ignored.
	// +optional
	Commit string `json:"commit"`
}
```

### Status

```go
// GitRepositoryStatus defines the observed state of GitRepository.
type GitRepositoryStatus struct {
	// +optional
	Conditions []SourceCondition `json:"conditions,omitempty"`

	// URL is the download link for the artifact output of the last repository
	// sync.
	// +optional
	URL string `json:"url,omitempty"`

	// Artifact represents the output of the last successful repository sync.
	// +optional
	Artifact *Artifact `json:"artifact,omitempty"`
}
```

### Condition reasons

```go
const (
	// GitOperationSucceedReason represents the fact that the git
	// clone, pull and checkout operations succeeded.
	GitOperationSucceedReason string = "GitOperationSucceed"
	// GitOperationFailedReason represents the fact that the git
	// clone, pull or checkout operations failed.
	GitOperationFailedReason  string = "GitOperationFailed"
)
```

## Spec examples

Pull the master branch of a public repository every minute:

```yaml
apiVersion: source.fluxcd.io/v1alpha1
kind: GitRepository
metadata:
  name: podinfo
  namespace: default
spec:
  interval: 1m
  url: https://github.com/stefanprodan/podinfo
```

Pull a specific branch:

```yaml
apiVersion: source.fluxcd.io/v1alpha1
kind: GitRepository
metadata:
  name: podinfo
  namespace: default
spec:
  interval: 1m
  url: https://github.com/stefanprodan/podinfo
  ref:
    branch: v3.x
```

Checkout a specific commit from a branch:

```yaml
apiVersion: source.fluxcd.io/v1alpha1
kind: GitRepository
metadata:
  name: podinfo
  namespace: default
spec:
  interval: 1m
  url: https://github.com/stefanprodan/podinfo
  ref:
    branch: master
    commit: 363a6a8fe6a7f13e05d34c163b0ef02a777da20a
```

Pull a specific tag:

```yaml
apiVersion: source.fluxcd.io/v1alpha1
kind: GitRepository
metadata:
  name: podinfo
  namespace: default
spec:
  interval: 1m
  url: https://github.com/stefanprodan/podinfo
  ref:
    tag: 3.2.0
```

Pull tag based on a [semver range](https://github.com/blang/semver#ranges):

```yaml
apiVersion: source.fluxcd.io/v1alpha1
kind: GitRepository
metadata:
  name: podinfo
  namespace: default
spec:
  interval: 1m
  url: https://github.com/stefanprodan/podinfo
  ref:
    semver: ">=3.1.0-rc.1 <3.2.0"
```

HTTPS authentication (requires a secret with `username` and `password` fields):

```yaml
apiVersion: source.fluxcd.io/v1alpha1
kind: GitRepository
metadata:
  name: podinfo
  namespace: default
spec:
  url: https://github.com/stefanprodan/podinfo
  secretRef:
    name: https-credentials
---
apiVersion: v1
kind: Secret
metadata:
  name: https-credentials
  namespace: default
type: Opaque
data:
  username: <BASE64> 
  password: <BASE64> 
```

SSH authentication (requires a secret with `identity` and `known_hosts` fields):

```yaml
apiVersion: source.fluxcd.io/v1alpha1
kind: GitRepository
metadata:
  name: podinfo
  namespace: default
spec:
  url: ssh://git@github.com/stefanprodan/podinfo
  secretRef:
    name: ssh-credentials
---
apiVersion: v1
kind: Secret
metadata:
  name: ssh-credentials
  namespace: default
type: Opaque
data:
  identity: <BASE64> 
  identity.pub: <BASE64> 
  known_hosts: <BASE64> 
```

> **Note:** that the SSH address does not support SCP syntax. The URL format is
> `ssh://user@host:port/org/repository`.

Example of generating the SSH credentials secret:

```bash
ssh-keygen -q -N "" -f ./identity
ssh-keyscan github.com > ./known_hosts

kubectl create secret generic ssh-credentials \
    --from-file=./identity \
    --from-file=./identity.pub \
    --from-file=./known_hosts
```

## Status examples

Successful sync:

```yaml
status:
  artifact:
    lastUpdateTime: "2020-04-07T06:59:23Z"
    path: /data/gitrepository/podinfo-default/363a6a8fe6a7f13e05d34c163b0ef02a777da20a.tar.gz
    revision: master/363a6a8fe6a7f13e05d34c163b0ef02a777da20a
    url: http://<host>/gitrepository/podinfo-default/363a6a8fe6a7f13e05d34c163b0ef02a777da20a.tar.gz
  conditions:
  - lastTransitionTime: "2020-04-07T06:59:23Z"
    message: 'Fetched artifacts are available at
      /data/gitrepository/podinfo-default/363a6a8fe6a7f13e05d34c163b0ef02a777da20a.tar.gz'
    reason: GitOperationSucceed
    status: "True"
    type: Ready
  url: http://<host>/gitrepository/podinfo-default/latest.tar.gz
```

Failed sync:

```yaml
status:
  conditions:
  - lastTransitionTime: "2020-04-06T06:48:59Z"
    message: 'git clone error ssh: handshake failed: ssh: unable to authenticate,
      attempted methods [none publickey], no supported methods remain'
    reason: AuthenticationFailed
    status: "False"
    type: Ready
```

Wait for condition:

```bash
kubectl wait gitrepository/podinfo --for=condition=ready --timeout=1m
```
