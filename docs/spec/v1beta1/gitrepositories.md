# Git Repositories

The `GitRepository` API defines a source for artifacts coming from Git. The
resource exposes the latest synchronized state from Git as an artifact in a
[gzip compressed TAR archive](#artifact).

## Specification

Git repository:

```go
// GitRepositorySpec defines the desired state of a Git repository.
type GitRepositorySpec struct {
	// The repository URL, can be a HTTP/S or SSH address.
	// +kubebuilder:validation:Pattern="^(http|https|ssh)://"
	// +required
	URL string `json:"url"`

	// The secret name containing the Git credentials.
	// For HTTPS repositories the secret must contain username and password
	// fields.
	// For SSH repositories the secret must contain identity and known_hosts
  // fields.
	// +optional
	SecretRef *corev1.LocalObjectReference `json:"secretRef,omitempty"`

	// The interval at which to check for repository updates.
	// +required
	Interval metav1.Duration `json:"interval"`

	// The timeout for remote Git operations like cloning, defaults to 60s.
	// +optional
	Timeout *metav1.Duration `json:"timeout,omitempty"`

	// The Git reference to checkout and monitor for changes, defaults to
	// master branch.
	// +optional
	Reference *GitRepositoryRef `json:"ref,omitempty"`

	// Verify OpenPGP signature for the Git commit HEAD points to.
	// +optional
	Verification *GitRepositoryVerification `json:"verify,omitempty"`

	// Ignore overrides the set of excluded patterns in the .sourceignore format
	// (which is the same as .gitignore). If not provided, a default will be used,
	// consult the documentation for your version to find out what those are.
	// +optional
	Ignore *string `json:"ignore,omitempty"`

	// This flag tells the controller to suspend the reconciliation of this source.
	// +optional
	Suspend bool `json:"suspend,omitempty"`

	// Determines which git client library to use.
	// Defaults to go-git, valid values are ('go-git', 'libgit2').
	// +kubebuilder:validation:Enum=go-git;libgit2
	// +kubebuilder:default:=go-git
	// +optional
	GitImplementation string `json:"gitImplementation,omitempty"`

	// When enabled, after the clone is created, initializes all submodules within.
	// This option is available only when using the 'go-git' GitImplementation.
	// +optional
	RecurseSubmodules bool `json:"recurseSubmodules,omitempty"`

	// Extra git repositories to map into the repository
	Include []GitRepositoryInclude `json:"include,omitempty"`
}
```

Git repository reference:

```go
// GitRepositoryRef defines the Git ref used for pull and checkout operations.
type GitRepositoryRef struct {
	// The Git branch to checkout, defaults to master.
	// +optional
	Branch string `json:"branch,omitempty"`

	// The Git tag to checkout, takes precedence over Branch.
	// +optional
	Tag string `json:"tag,omitempty"`

	// The Git tag semver expression, takes precedence over Tag.
	// +optional
	SemVer string `json:"semver,omitempty"`

	// The Git commit SHA to checkout, if specified Tag filters will be ignored.
	// +optional
	Commit string `json:"commit,omitempty"`
}
```

Git repository cryptographic provenance verification:

```go
// GitRepositoryVerification defines the OpenPGP signature verification process.
type GitRepositoryVerification struct {
	// Mode describes what git object should be verified, currently ('head').
	// +kubebuilder:validation:Enum=head
	Mode string `json:"mode"`

	// The secret name containing the public keys of all trusted Git authors.
	SecretRef corev1.LocalObjectReference `json:"secretRef,omitempty"`
}
```

### Status

```go
// GitRepositoryStatus defines the observed state of the GitRepository.
type GitRepositoryStatus struct {
	// Conditions holds the conditions for the GitRepository.
	// +optional
	Conditions []meta.Condition `json:"conditions,omitempty"`

	// URL is the download link for the artifact output of the last repository
	// sync.
	// +optional
	URL string `json:"url,omitempty"`

	// Artifact represents the output of the last successful repository sync.
	// +optional
	Artifact *Artifact `json:"artifact,omitempty"`

	// LastHandledReconcileAt is the last manual reconciliation request (by
	// annotating the GitRepository) handled by the reconciler.
	// +optional
	LastHandledReconcileAt string `json:"lastHandledReconcileAt,omitempty"`
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

## Artifact

The `GitRepository` API defines a source for artifacts coming from Git. The
resource exposes the latest synchronized state from Git as an artifact in a
gzip compressed TAR archive (`<commit hash>.tar.gz`).

### Excluding files

The following files and extensions are excluded from the archive by default:

- Git files (`.git/ ,.gitignore, .gitmodules, .gitattributes`)
- File extensions (`.jpg, .jpeg, .gif, .png, .wmv, .flv, .tar.gz, .zip`)
- CI configs (`.github/, .circleci/, .travis.yml, .gitlab-ci.yml, appveyor.yml, .drone.yml, cloudbuild.yaml, codeship-services.yml, codeship-steps.yml`)
- CLI configs (`.goreleaser.yml, .sops.yaml`)
- Flux v1 config (`.flux.yaml`)

Excluding additional files from the archive is possible by adding a
`.sourceignore` file in the root of the repository. The `.sourceignore` file
follows [the `.gitignore` pattern
format](https://git-scm.com/docs/gitignore#_pattern_format), pattern
entries may overrule default exclusions.

Another option is to use the `spec.ignore` field, for example:

```yaml
apiVersion: source.toolkit.fluxcd.io/v1beta1
kind: GitRepository
metadata:
  name: podinfo
  namespace: default
spec:
  interval: 5m
  url: https://github.com/stefanprodan/podinfo
  ignore: |
    # exclude all
    /*
    # include deploy dir
    !/deploy
    # exclude file extensions from deploy dir
    /deploy/**/*.md
    /deploy/**/*.txt
```

When specified, `spec.ignore` overrides the default exclusion list.

## Git Implementation

You can skip this section unless you know that you need support for either
specific git wire protocol functionality. Changing the git implementation
comes with its own set of drawbacks.

Some git providers like Azure DevOps require that the git client supports specific capabilities
to be able to communicate. The initial library used in source-controller did not support
this functionality while other libraries that did were missing other critical functionality,
specifically the ability to do shallow cloning. Shallow cloning is important as it allows
source-controller to only fetch the latest commits, instead of the whole git history.
For some very large repositories this means downloading GB of data that could fill the disk
and also impact the traffic costs.

To be able to support Azure DevOps a compromise solution was built, giving the user the
option to select the git library while accepting the drawbacks.

| Git Implementation | Shallow Clones | Git Submodules | V2 Protocol Support |
| ---                | ---            | ---            | ---                 |
| 'go-git'           | true           | true           | false               |
| 'libgit2'          | false          | false          | true                |

Pull the master branch from a repository in Azure DevOps.

```yaml
apiVersion: source.toolkit.fluxcd.io/v1beta1
kind: GitRepository
metadata:
  name: podinfo
  namespace: default
spec:
  interval: 1m
  url: https://dev.azure.com/org/proj/_git/repo
  gitImplementation: libgit2
```

## Git Proxy

A Git proxy can be configured by setting the appropriate environment variables
for proxy configurations, for example `HTTPS_PROXY`, `NO_PROXY`, etc., in the
source-controller pod. There may be some limitations in the proxy support based
on the Git implementations.

| Git Implementation | HTTP_PROXY | HTTPS_PROXY | NO_PROXY | Self-signed Certs |
| ---                | ---        | ---         | ---      | ---               |
| 'go-git'           | true       | true        | true     | false             |
| 'libgit2'          | false      | true        | false    | true              |

**NOTE:** libgit2 v1.2.0 supports `NO_PROXY`, but source-controller uses
libgit2 v1.1.1 at the moment.

## Spec examples

### Checkout strategies

Pull the master branch of a public repository every minute:

```yaml
apiVersion: source.toolkit.fluxcd.io/v1beta1
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
apiVersion: source.toolkit.fluxcd.io/v1beta1
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
apiVersion: source.toolkit.fluxcd.io/v1beta1
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

Checkout a specific commit:

```yaml
apiVersion: source.toolkit.fluxcd.io/v1beta1
kind: GitRepository
metadata:
  name: podinfo
  namespace: default
spec:
  interval: 1m
  url: https://github.com/stefanprodan/podinfo
  ref:
    commit: 363a6a8fe6a7f13e05d34c163b0ef02a777da20a
```

Pull a specific tag:

```yaml
apiVersion: source.toolkit.fluxcd.io/v1beta1
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

Pull tag based on a [semver range](https://github.com/Masterminds/semver#checking-version-constraints):

```yaml
apiVersion: source.toolkit.fluxcd.io/v1beta1
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

### HTTPS authentication

HTTPS authentication requires a Kubernetes secret with `username` and `password` fields:

```yaml
apiVersion: source.toolkit.fluxcd.io/v1beta1
kind: GitRepository
metadata:
  name: podinfo
  namespace: default
spec:
  interval: 1m
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

### HTTPS self-signed certificates

Cloning over HTTPS from a Git repository with a self-signed certificate:

```yaml
apiVersion: source.toolkit.fluxcd.io/v1beta1
kind: GitRepository
metadata:
  name: podinfo
  namespace: default
spec:
  interval: 1m
  url: https://customdomain.com/stefanprodan/podinfo
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
  caFile: <BASE64>
```

It is also possible to specify a `caFile` for public repositories, in that case the username and password
can be omitted.

### SSH authentication

SSH authentication requires a Kubernetes secret with `identity` and `known_hosts` fields:

```yaml
apiVersion: source.toolkit.fluxcd.io/v1beta1
kind: GitRepository
metadata:
  name: podinfo
  namespace: default
spec:
  interval: 1m
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

If your SSH key is protected with a passphrase,
you can specify it in the Kubernetes secret under the `password` key:

```sh
kubectl create secret generic ssh-credentials \
    --from-file=./identity \
    --from-file=./identity.pub \
    --from-file=./known_hosts \
    --from-literal=password=<passphrase>
```

### GPG signature verification

Verify the OpenPGP signature for the commit that master branch HEAD points to:

```yaml
apiVersion: source.toolkit.fluxcd.io/v1beta1
kind: GitRepository
metadata:
  name: podinfo
  namespace: default
spec:
  interval: 1m
  url: https://github.com/stefanprodan/podinfo
  ref:
    branch: master
  verify:
    mode: head
    secretRef:
      name: pgp-public-keys
---
apiVersion: v1
kind: Secret
metadata:
  name: pgp-public-keys
  namespace: default
type: Opaque
data:
  author1.asc: <BASE64>
  author2.asc: <BASE64>
```

Example of generating the PGP public keys secret:

```bash
gpg --export --armor 3CB12BA185C47B67 > author1.asc
gpg --export --armor 6A7436E8790F8689 > author2.asc

kubectl create secret generic pgp-public-keys \
    --from-file=author1.asc \
    --from-file=author2.asc
```

### Git submodules

With `spec.recurseSubmodules` you can configure the controller to
clone a specific branch including its Git submodules:

```yaml
apiVersion: source.toolkit.fluxcd.io/v1beta1
kind: GitRepository
metadata:
  name: repo-with-submodules
  namespace: default
spec:
  interval: 1m
  url: https://github.com/<organization>/<repository>
  secretRef:
    name: https-credentials
  ref:
    branch: main
  recurseSubmodules: true
---
apiVersion: v1
kind: Secret
metadata:
  name: https-credentials
  namespace: default
type: Opaque
data:
  username: <GitHub Username>
  password: <GitHub Token>
```

Note that deploy keys can't be used to pull submodules from private repositories
as GitHub and GitLab doesn't allow a deploy key to be reused across repositories.
You have to use either HTTPS token-based authentication, or an SSH key belonging
to a user that has access to the main repository and all its submodules.

### Including GitRepository

With `spec.include` you can map the contents of a Git repository into another.
This may look identical to Git submodules but has multiple benefits over
regular submodules:

* Including a `GitRepository` allows you to use different authentication methods for different repositories.
* A change in the included repository will trigger an update of the including repository.
* Multiple `GitRepositories` could include the same repository, which decreases the amount of cloning done compared to using submodules.

```yaml
apiVersion: source.toolkit.fluxcd.io/v1beta1
kind: GitRepository
metadata:
  name: app-repo
  namespace: default
spec:
  interval: 1m
  url: https://github.com/<org>/app-repo
  secretRef:
    name: https-credentials
  ref:
    branch: main
---
apiVersion: source.toolkit.fluxcd.io/v1beta1
kind: GitRepository
metadata:
  name: config-repo
  namespace: default
spec:
  interval: 1m
  url: https://github.com/<org>/config-repo
  secretRef:
    name: https-credentials
  ref:
    branch: main
  include:
    - repository:
        name: app-repo
      fromPath: deploy/kubernetes
      toPath: base/app
---
apiVersion: v1
kind: Secret
metadata:
  name: https-credentials
  namespace: default
type: Opaque
data:
  username: <GitHub Username>
  password: <GitHub Token>
```

The `fromPath` and `toPath` parameters allows you to limit the files included and where they will be
copied to in the main repository. If you do not specify a value for `fromPath` all files in the
repository will be included. The `toPath` value will default to the name of the repository.

## Status examples

Successful sync:

```yaml
status:
  artifact:
    lastUpdateTime: "2020-04-07T06:59:23Z"
    path: /data/gitrepository/default/podinfo/363a6a8fe6a7f13e05d34c163b0ef02a777da20a.tar.gz
    revision: master/363a6a8fe6a7f13e05d34c163b0ef02a777da20a
    url: http://<host>/gitrepository/default/podinfo/363a6a8fe6a7f13e05d34c163b0ef02a777da20a.tar.gz
  conditions:
  - lastTransitionTime: "2020-04-07T06:59:23Z"
    message: 'Git repoistory artifacts are available at:
      /data/gitrepository/default/podinfo/363a6a8fe6a7f13e05d34c163b0ef02a777da20a.tar.gz'
    reason: GitOperationSucceed
    status: "True"
    type: Ready
  url: http://<host>/gitrepository/default/podinfo/latest.tar.gz
```

Failed authentication:

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

Failed PGP signature verification:

```yaml
status:
  conditions:
  - lastTransitionTime: "2020-04-06T06:48:59Z"
    message: 'PGP signature of {Stefan Prodan 2020-04-04 13:36:58 +0300 +0300} can not be verified'
    reason: VerificationFailed
    status: "False"
    type: Ready
```

Wait for ready condition:

```bash
kubectl wait gitrepository/podinfo --for=condition=ready --timeout=1m
```
