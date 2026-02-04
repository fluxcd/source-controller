# Git Repositories

<!-- menuweight:10 -->

The `GitRepository` API defines a Source to produce an Artifact for a Git
repository revision.

## Example

The following is an example of a GitRepository. It creates a tarball
(`.tar.gz`) Artifact with the fetched data from a Git repository for the
resolved reference.

```yaml
---
apiVersion: source.werf.io/v1beta2
kind: GitRepository
metadata:
  name: podinfo
  namespace: default
spec:
  interval: 5m0s
  url: https://github.com/stefanprodan/podinfo
  ref:
    branch: master
```

In the above example:

- A GitRepository named `podinfo` is created, indicated by the
  `.metadata.name` field.
- The source-controller checks the Git repository every five minutes, indicated
  by the `.spec.interval` field.
- It clones the `master` branch of the `https://github.com/stefanprodan/podinfo`
  repository, indicated by the `.spec.ref.branch` and `.spec.url` fields.
- The specified branch and resolved HEAD revision are used as the Artifact
  revision, reported in-cluster in the `.status.artifact.revision` field.
- When the current GitRepository revision differs from the latest fetched
  revision, a new Artifact is archived.
- The new Artifact is reported in the `.status.artifact` field.

You can run this example by saving the manifest into `gitrepository.yaml`.

1. Apply the resource on the cluster:

   ```sh
   kubectl apply -f gitrepository.yaml
   ```

2. Run `kubectl get gitrepository` to see the GitRepository:

   ```console
   NAME      URL                                       AGE   READY   STATUS                                                                        
   podinfo   https://github.com/stefanprodan/podinfo   5s    True    stored artifact for revision 'master@sha1:132f4e719209eb10b9485302f8593fc0e680f4fc'
   ```

3. Run `kubectl describe gitrepository podinfo` to see the [Artifact](#artifact)
   and [Conditions](#conditions) in the GitRepository's Status:

   ```console
   ...
   Status:
     Artifact:
       Digest:            sha256:95e386f421272710c4cedbbd8607dbbaa019d500e7a5a0b6720bc7bebefc7bf2
       Last Update Time:  2022-02-14T11:23:36Z
       Path:              gitrepository/default/podinfo/132f4e719209eb10b9485302f8593fc0e680f4fc.tar.gz
       Revision:          master@sha1:132f4e719209eb10b9485302f8593fc0e680f4fc
       Size:              91318
       URL:               http://source-controller.source-system.svc.cluster.local./gitrepository/default/podinfo/132f4e719209eb10b9485302f8593fc0e680f4fc.tar.gz
     Conditions:
       Last Transition Time:  2022-02-14T11:23:36Z
       Message:               stored artifact for revision 'master@sha1:132f4e719209eb10b9485302f8593fc0e680f4fc'
       Observed Generation:   1
       Reason:                Succeeded
       Status:                True
       Type:                  Ready
       Last Transition Time:  2022-02-14T11:23:36Z
       Message:               stored artifact for revision 'master@sha1:132f4e719209eb10b9485302f8593fc0e680f4fc'
       Observed Generation:   1
       Reason:                Succeeded
       Status:                True
       Type:                  ArtifactInStorage
     Observed Generation:     1
     URL:                     http://source-controller.source-system.svc.cluster.local./gitrepository/default/podinfo/latest.tar.gz
   Events:
     Type    Reason               Age   From               Message
     ----    ------               ----  ----               -------
     Normal  NewArtifact          62s   source-controller  stored artifact for commit 'Merge pull request #160 from stefanprodan/release-6.0.3'
   ```

## Writing a GitRepository spec

As with all other Kubernetes config, a GitRepository needs `apiVersion`,
`kind`, and `metadata` fields. The name of a GitRepository object must be a
valid [DNS subdomain name](https://kubernetes.io/docs/concepts/overview/working-with-objects/names#dns-subdomain-names).

A GitRepository also needs a
[`.spec` section](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status).

### URL

`.spec.url` is a required field that specifies the HTTP/S or SSH address of the
Git repository.

**Note:** Unlike using `git`, the
[shorter scp-like syntax](https://git-scm.com/book/en/v2/Git-on-the-Server-The-Protocols#_the_ssh_protocol)
is not supported for SSH addresses (e.g. `user@example.com:repository.git`).
Instead, the valid URL format is `ssh://user@example.com:22/repository.git`.

### Secret reference

`.spec.secretRef.name` is an optional field to specify a name reference to a
Secret in the same namespace as the GitRepository, containing authentication
credentials for the Git repository.

The required fields in the Secret depend on the specified protocol in the
[URL](#url).

#### Basic access authentication

To authenticate towards a Git repository over HTTPS using basic access
authentication (in other words: using a username and password), the referenced
Secret is expected to contain `.data.username` and `.data.password` values.

```yaml
---
apiVersion: v1
kind: Secret
metadata:
  name: basic-access-auth
type: Opaque
data:
  username: <BASE64>
  password: <BASE64>
```

#### Bearer token authentication

To authenticate towards a Git repository over HTTPS using bearer token
authentication (in other words: using a `Authorization: Bearer` header), the referenced
Secret is expected to contain the token in `.data.bearerToken`.

**Note:** If you are looking to use OAuth tokens with popular servers (e.g.
[GitHub](https://docs.github.com/en/rest/overview/authenticating-to-the-rest-api?apiVersion=2022-11-28#authenticating-with-a-token-generated-by-an-app),
[Bitbucket](https://support.atlassian.com/bitbucket-cloud/docs/using-access-tokens/),
[GitLab](https://docs.gitlab.com/ee/gitlab-basics/start-using-git.html#clone-using-a-token)),
you should use basic access authentication instead. These servers use basic HTTP
authentication, with the OAuth token as the password. Check the documentation of
your Git server for details.

```yaml
---
apiVersion: v1
kind: Secret
metadata:
  name: bearer-token-auth
type: Opaque
data:
  bearerToken: <BASE64>
```

#### HTTPS Certificate Authority

To provide a Certificate Authority to trust while connecting with a Git
repository over HTTPS, the referenced Secret can contain a `.data.caFile`
value.

```yaml
---
apiVersion: v1
kind: Secret
metadata:
  name: https-ca-credentials
  namespace: default
type: Opaque
data:
  caFile: <BASE64>
```

#### SSH authentication

To authenticate towards a Git repository over SSH, the referenced Secret is
expected to contain `identity` and `known_hosts` fields. With the respective
private key of the SSH key pair, and the host keys of the Git repository.

```yaml
---
apiVersion: v1
kind: Secret
metadata:
  name: ssh-credentials
type: Opaque
stringData:
  identity: |
    -----BEGIN OPENSSH PRIVATE KEY-----
    ...
    -----END OPENSSH PRIVATE KEY-----
  known_hosts: |
    github.com ecdsa-sha2-nistp256 AAAA...
```

Alternatively, the Flux CLI can be used to automatically create the
secret, and also populate the known_hosts:

```sh
flux create secret git podinfo-auth \
    --url=ssh://git@github.com/stefanprodan/podinfo \
    --private-key-file=./identity
```

For password-protected SSH private keys, the password must be provided
via an additional `password` field in the secret. Flux CLI also supports
this via the `--password` flag.

### Interval

`.spec.interval` is a required field that specifies the interval at which the
Git repository must be fetched.

After successfully reconciling the object, the source-controller requeues it
for inspection after the specified interval. The value must be in a
[Go recognized duration string format](https://pkg.go.dev/time#ParseDuration),
e.g. `10m0s` to reconcile the object every 10 minutes.

If the `.metadata.generation` of a resource changes (due to e.g. a change to
the spec), this is handled instantly outside the interval window.

### Timeout

`.spec.timeout` is an optional field to specify a timeout for Git operations
like cloning. The value must be in a
[Go recognized duration string format](https://pkg.go.dev/time#ParseDuration),
e.g. `1m30s` for a timeout of one minute and thirty seconds. The default value
is `60s`.

### Reference

`.spec.ref` is an optional field to specify the Git reference to resolve and
watch for changes. References are specified in one or more subfields
(`.branch`, `.tag`, `.semver`, `.name`, `.commit`), with latter listed fields taking
precedence over earlier ones. If not specified, it defaults to a `master`
branch reference.

#### Branch example

To Git checkout a specified branch, use `.spec.ref.branch`:

```yaml
---
apiVersion: source.werf.io/v1beta2
kind: GitRepository
metadata:
  name: <repository-name>
spec:
  ref:
    branch: <branch-name>
```

This will perform a shallow clone to only fetch the specified branch.

#### Tag example

To Git checkout a specified tag, use `.spec.ref.tag`:

```yaml
---
apiVersion: source.werf.io/v1beta2
kind: GitRepository
metadata:
  name: <repository-name>
spec:
  ref:
    tag: <tag-name>
```

This field takes precedence over [`.branch`](#branch-example).

#### SemVer example

To Git checkout a tag based on a
[SemVer range](https://github.com/Masterminds/semver#checking-version-constraints),
use `.spec.ref.semver`:

```yaml
---
apiVersion: source.werf.io/v1beta2
kind: GitRepository
metadata:
  name: <repository-name>
spec:
  ref:
    # SemVer range reference: https://github.com/Masterminds/semver#checking-version-constraints
    semver: "<semver-range>"
```

This field takes precedence over [`.branch`](#branch-example) and
[`.tag`](#tag-example).


#### Name example

To Git checkout a specfied [reference](https://git-scm.com/book/en/v2/Git-Internals-Git-References),
use `.spec.ref.name`:

```yaml
---
apiVersion: source.werf.io/v1beta2
kind: GitRepository
metadata:
  name: <repository-name>
spec:
  ref:
    # Ref name format reference: https://git-scm.com/docs/git-check-ref-format#_description
    name: <reference-name>
```

Valid examples are: `refs/heads/main`, `refs/tags/v0.1.0`, `refs/pull/420/head`,
`refs/merge-requests/1/head`.

This field takes precedence over [`.branch`](#branch-example),
[`.tag`](#tag-example), and [`.semver`](#semver-example).

#### Commit example

To Git checkout a specified commit, use `.spec.ref.commit`:

```yaml
---
apiVersion: source.werf.io/v1beta2
kind: GitRepository
metadata:
  name: <repository-name>
spec:
  ref:
    commit: "<commit SHA>"
``` 

This field takes precedence over all other fields. It can be combined with
`.spec.ref.branch` to perform a shallow clone of the branch, in which the
commit must exist:

```yaml
---
apiVersion: source.werf.io/v1beta2
kind: GitRepository
metadata:
  name: <repository-name>
spec:
  ref:
    branch: <branch>
    commit: "<commit SHA within branch>"
``` 

### Verification

`.spec.verify` is an optional field to enable the verification of Git commit
signatures. The field offers two subfields:

- `.mode`, to specify what Git commit object should be verified. Only supports
  `head` at present.
- `.secretRef.name`, to specify a reference to a Secret in the same namespace as
  the GitRepository. Containing the (PGP) public keys of trusted Git authors.

```yaml
---
apiVersion: source.werf.io/v1beta1
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
```

When the verification succeeds, the controller adds a Condition with the
following attributes to the GitRepository's `.status.conditions`:

- `type: SourceVerifiedCondition`
- `status: "True"`
- `reason: Succeeded`

#### Verification Secret example

```yaml
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

Exporting armored public keys (`.asc` files) using `gpg`, and generating a
Secret:

```sh
# Export armored public keys
gpg --export --armor 3CB12BA185C47B67 > author1.asc
gpg --export --armor 6A7436E8790F8689 > author2.asc
# Generate secret
kubectl create secret generic pgp-public-keys \
    --from-file=author1.asc \
    --from-file=author2.asc \
    -o yaml
```

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
GitRepository. When set to `true`, the controller will stop reconciling the
GitRepository, and changes to the resource or in the Git repository will not
result in a new Artifact. When the field is set to `false` or removed, it will
resume.

### Git implementation

`.spec.gitImplementation` is deprecated and its value ignored, the git
implementation used across Flux is go-git.

#### Optimized Git clones

Optimized Git clones decreases resource utilization for GitRepository
reconciliations.

When enabled, it avoids full Git clone operations by first checking whether
the revision of the last stored artifact is still the head of the remote
repository and none of the other factors that contribute to a change in the
artifact, like ignore rules and included repositories, have changed. If that is
so, the reconciliation is skipped. Else, a full reconciliation is performed as
usual.

This feature is enabled by default. It can be disabled by starting the
controller with the argument `--feature-gates=OptimizedGitClones=false`.

NB: GitRepository objects configured for SemVer or Commit clones are
not affected by this functionality.

#### Proxy support

When a proxy is configured in the source-controller Pod through the appropriate
environment variables, for example `HTTPS_PROXY`, `NO_PROXY`, etc.

### Recurse submodules

`.spec.recurseSubmodules` is an optional field to enable the initialization of
all submodules within the cloned Git repository, using their default settings.
This option defaults to `false`.

Note that for most Git providers (e.g. GitHub and GitLab), deploy keys can not
be used as reusing a key across multiple repositories is not allowed. You have
to use either [HTTPS token-based authentication](#basic-access-authentication),
or an SSH key belonging to a (bot) user who has access to the main repository
and all submodules.

### Include

`.spec.include` is an optional field to map the contents of GitRepository
Artifacts into another. This may look identical to Git submodules but has
multiple benefits over regular submodules:

- Including a `GitRepository` allows you to use different authentication
  methods for different repositories.
- A change in the included repository will trigger an update of the including
  repository.
- Multiple `GitRepository` objects could include the same repository, which
  decreases the amount of cloning done compared to using submodules.

```yaml
---
apiVersion: source.werf.io/v1beta2
kind: GitRepository
metadata:
  name: include-example
spec:
  include:
    - repository:
        name: other-repository
      fromPath: deploy/kubernetes
      toPath: base/app
```

The `.fromPath` and `.toPath` fields allow you to limit the files included, and
where they will be copied to. If you do not specify a value for `.fromPath`,
all files from the referenced GitRepository Artifact will be included. The
`.toPath` defaults to the `.repository.name` (e.g. `./other-repository/*`).

## Working with GitRepositories

### Excluding files

By default, files which match the [default exclusion rules](#default-exclusions)
are excluded while archiving the Git repository contents as an Artifact. It is
possible to overwrite and/or overrule the default exclusions using a file in
the Git repository and/or an in-spec set of rules.

#### `.sourceignore` file

Excluding files is possible by adding a `.sourceignore` file in the Git
repository. The `.sourceignore` file follows [the `.gitignore` pattern
format](https://git-scm.com/docs/gitignore#_pattern_format), and
pattern entries may overrule [default exclusions](#default-exclusions).

The controller recursively loads ignore files so a `.sourceignore` can be
placed in the repository root or in subdirectories.

#### Ignore spec

Another option is to define the exclusions within the GitRepository spec, using
the [`.spec.ignore` field](#ignore). Specified rules override the [default
exclusion list](#default-exclusions), and may overrule `.sourceignore` file
exclusions.

```yaml
---
apiVersion: source.werf.io/v1beta2
kind: GitRepository
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

To manually tell the source-controller to reconcile a GitRepository outside the
[specified interval window](#interval), a GitRepository can be annotated with
`reconcile.fluxcd.io/requestedAt: <arbitrary value>`. Annotating the resource
queues the GitRepository for reconciliation if the `<arbitrary-value>` differs
from the last value the controller acted on, as reported in
[`.status.lastHandledReconcileAt`](#last-handled-reconcile-at).

Using `kubectl`:

```sh
kubectl annotate --field-manager=flux-client-side-apply --overwrite gitrepository/<repository-name> reconcile.fluxcd.io/requestedAt="$(date +%s)"
```

Using `flux`:

```sh
flux reconcile source git <repository-name>
```

### Waiting for `Ready`

When a change is applied, it is possible to wait for the GitRepository to reach
a [ready state](#ready-gitrepository) using `kubectl`:

```sh
kubectl wait gitrepository/<repository-name> --for=condition=ready --timeout=1m
```

### Suspending and resuming

When you find yourself in a situation where you temporarily want to pause the
reconciliation of a GitRepository, you can suspend it using the
[`.spec.suspend` field](#suspend).

#### Suspend a GitRepository

In your YAML declaration:

```yaml
---
apiVersion: source.werf.io/v1beta2
kind: GitRepository
metadata:
  name: <repository-name>
spec:
  suspend: true
```

Using `kubectl`:

```sh
kubectl patch gitrepository <repository-name> --field-manager=flux-client-side-apply -p '{\"spec\": {\"suspend\" : true }}'
```

Using `flux`:

```sh
flux suspend source git <repository-name>
```

**Note:** When a GitRepository has an Artifact and is suspended, and this
Artifact later disappears from the storage due to e.g. the source-controller
Pod being evicted from a Node, this will not be reflected in the
GitRepository's Status until it is resumed.

#### Resume a GitRepository

In your YAML declaration, comment out (or remove) the field:

```yaml
---
apiVersion: source.werf.io/v1beta2
kind: GitRepository
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
kubectl patch gitrepository <repository-name> --field-manager=flux-client-side-apply -p '{\"spec\" : {\"suspend\" : false }}'
```

Using `flux`:

```sh
flux resume source git <repository-name>
```

### Debugging a GitRepository

There are several ways to gather information about a GitRepository for
debugging purposes.

#### Describe the GitRepository

Describing a GitRepository using
`kubectl describe gitrepository <repository-name>`
displays the latest recorded information for the resource in the `Status` and
`Events` sections:

```console
...
Status:
...
  Conditions:
    Last Transition Time:  2022-02-14T09:40:27Z
    Message:               processing object: new generation 1 -> 2
    Observed Generation:   2
    Reason:                ProgressingWithRetry
    Status:                True
    Type:                  Reconciling
    Last Transition Time:  2022-02-14T09:40:27Z
    Message:               failed to checkout and determine revision: unable to clone 'https://github.com/stefanprodan/podinfo': couldn't find remote ref "refs/heads/invalid"
    Observed Generation:   2
    Reason:                GitOperationFailed
    Status:                False
    Type:                  Ready
    Last Transition Time:  2022-02-14T09:40:27Z
    Message:               failed to checkout and determine revision: unable to clone 'https://github.com/stefanprodan/podinfo': couldn't find remote ref "refs/heads/invalid"
    Observed Generation:   2
    Reason:                GitOperationFailed
    Status:                True
    Type:                  FetchFailed
  Observed Generation:     1
  URL:                     http://source-controller.source-system.svc.cluster.local./gitrepository/default/gitrepository-sample/latest.tar.gz
Events:
  Type     Reason                      Age                  From               Message
  ----     ------                      ----                 ----               -------
  Warning  GitOperationFailed          2s (x9 over 4s)      source-controller  failed to checkout and determine revision: unable to clone 'https://github.com/stefanprodan/podinfo': couldn't find remote ref "refs/heads/invalid"
```

#### Trace emitted Events

To view events for specific GitRepository(s), `kubectl get events` can be used
in combination with `--field-sector` to list the Events for specific objects.
For example, running

```sh
kubectl get events --field-selector involvedObject.kind=GitRepository,involvedObject.name=<repository-name>
```

lists

```console
LAST SEEN   TYPE     REASON                OBJECT                               MESSAGE
2m14s       Normal   NewArtifact           gitrepository/<repository-name>      stored artifact for commit 'Merge pull request #160 from stefanprodan/release-6.0.3'
36s         Normal   ArtifactUpToDate      gitrepository/<repository-name>      artifact up-to-date with remote revision: 'master@sha1:132f4e719209eb10b9485302f8593fc0e680f4fc'
94s         Warning  GitOperationFailed    gitrepository/<repository-name>      failed to checkout and determine revision: unable to clone 'https://github.com/stefanprodan/podinfo': couldn't find remote ref "refs/heads/invalid"
```

Besides being reported in Events, the reconciliation errors are also logged by
the controller. The Flux CLI offer commands for filtering the logs for a
specific GitRepository, e.g.
`flux logs --level=error --kind=GitRepository --name=<repository-name>`.

## GitRepository Status

### Artifact

The GitRepository reports the latest synchronized state from the Git repository
as an Artifact object in the `.status.artifact` of the resource.

The Artifact file is a gzip compressed TAR archive (`<commit sha>.tar.gz`), and
can be retrieved in-cluster from the `.status.artifact.url` HTTP address.

#### Artifact example

```yaml
---
apiVersion: source.werf.io/v1beta2
kind: GitRepository
metadata:
  name: <repository-name>
status:
  artifact:
    digest: sha256:e750c7a46724acaef8f8aa926259af30bbd9face2ae065ae8896ba5ee5ab832b
    lastUpdateTime: "2022-01-29T06:59:23Z"
    path: gitrepository/<namespace>/<repository-name>/c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2.tar.gz
    revision: master@sha1:363a6a8fe6a7f13e05d34c163b0ef02a777da20a
    size: 91318
    url: http://source-controller.<namespace>.svc.cluster.local./gitrepository/<namespace>/<repository-name>/363a6a8fe6a7f13e05d34c163b0ef02a777da20a.tar.gz
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

A GitRepository enters various states during its lifecycle, reflected as
[Kubernetes Conditions][typical-status-properties].
It can be [reconciling](#reconciling-gitrepository) while fetching the Git
state, it can be [ready](#ready-gitrepository), or it can [fail during
reconciliation](#failed-gitrepository).

The GitRepository API is compatible with the [kstatus specification][kstatus-spec],
and reports `Reconciling` and `Stalled` conditions where applicable to
provide better (timeout) support to solutions polling the GitRepository to
become `Ready`.

#### Reconciling GitRepository

The source-controller marks a GitRepository as _reconciling_ when one of the
following is true:

- There is no current Artifact for the GitRepository, or the reported Artifact
  is determined to have disappeared from the storage.
- The generation of the GitRepository is newer than the [Observed
  Generation](#observed-generation).
- The newly resolved Artifact revision differs from the current Artifact.

When the GitRepository is "reconciling", the `Ready` Condition status becomes
`Unknown` when the controller detects drift, and the controller adds a Condition
with the following attributes to the GitRepository's
`.status.conditions`:

- `type: Reconciling`
- `status: "True"`
- `reason: Progressing` | `reason: ProgressingWithRetry`

If the reconciling state is due to a new revision, an additional Condition is
added with the following attributes:

- `type: ArtifactOutdated`
- `status: "True"`
- `reason: NewRevision`

Both Conditions have a ["negative polarity"][typical-status-properties],
and are only present on the GitRepository while their status value is `"True"`.

#### Ready GitRepository

The source-controller marks a GitRepository as _ready_ when it has the
following characteristics:

- The GitRepository reports an [Artifact](#artifact).
- The reported Artifact exists in the controller's Artifact storage.
- The controller was able to communicate with the remote Git repository using
  the current spec.
- The revision of the reported Artifact is up-to-date with the latest
  resolved revision of the remote Git repository.

When the GitRepository is "ready", the controller sets a Condition with the
following attributes in the GitRepository's `.status.conditions`:

- `type: Ready`
- `status: "True"`
- `reason: Succeeded`

This `Ready` Condition will retain a status value of `"True"` until the
GitRepository is marked as [reconciling](#reconciling-gitrepository), or e.g. a
[transient error](#failed-gitrepository) occurs due to a temporary network issue.

When the GitRepository Artifact is archived in the controller's Artifact
storage, the controller sets a Condition with the following attributes in the
GitRepository's `.status.conditions`:

- `type: ArtifactInStorage`
- `status: "True"`
- `reason: Succeeded`

This `ArtifactInStorage` Condition will retain a status value of `"True"` until
the Artifact in the storage no longer exists.

#### Failed GitRepository

The source-controller may get stuck trying to produce an Artifact for a
GitRepository without completing. This can occur due to some of the following
factors:

- The remote Git repository [URL](#url) is temporarily unavailable.
- The Git repository does not exist.
- The [Secret reference](#secret-reference) contains a reference to a
  non-existing Secret.
- A specified Include is unavailable.
- The verification of the Git commit signature failed.
- The credentials in the referenced Secret are invalid.
- The GitRepository spec contains a generic misconfiguration.
- A storage related failure when storing the artifact.

When this happens, the controller sets the `Ready` Condition status to `False`,
and adds a Condition with the following attributes to the GitRepository's
`.status.conditions`:

- `type: FetchFailed` | `type: IncludeUnavailable` | `type: StorageOperationFailed`
- `status: "True"`
- `reason: AuthenticationFailed` | `reason: GitOperationFailed`

This condition has a ["negative polarity"][typical-status-properties],
and is only present on the GitRepository while the status value is `"True"`.
There may be more arbitrary values for the `reason` field to provide accurate
reason for a condition.

In addition to the above Condition types, when the
[verification of a Git commit signature](#verification) fails. A condition with
the following attributes is added to the GitRepository's `.status.conditions`:

- `type: SourceVerifiedCondition`
- `status: "False"`
- `reason: Failed`

While the GitRepository has one or more of these Conditions, the controller
will continue to attempt to produce an Artifact for the resource with an
exponential backoff, until it succeeds and the GitRepository is marked as
[ready](#ready-gitrepository).

Note that a GitRepository can be [reconciling](#reconciling-gitrepository)
while failing at the same time, for example due to a newly introduced
configuration issue in the GitRepository spec. When a reconciliation fails, the
`Reconciling` Condition reason would be `ProgressingWithRetry`. When the
reconciliation is performed again after the failure, the reason is updated to
`Progressing`.

### Content Configuration Checksum

The source-controller calculates the SHA256 checksum of the various
configurations of the GitRepository that indicate a change in source and
records it in `.status.contentConfigChecksum`. This field is used to determine
if the source artifact needs to be rebuilt.

**Deprecation Note:** `contentConfigChecksum` is no longer used and will be
removed in the next API version. The individual components used for generating
content configuration checksum now have explicit fields in the status. This
makes the observations used by the controller for making artifact rebuild
decisions more transparent and easier to debug.

### Observed Ignore

The source-controller reports an observed ignore in the GitRepository's
`.status.observedIgnore`. The observed ignore is the latest `.spec.ignore` value
which resulted in a [ready state](#ready-gitrepository), or stalled due to error
it can not recover from without human intervention.
The value is the same as the [ignore in spec](#ignore).
It indicates the ignore rules used in building the current artifact in storage.
It is also used by the controller to determine if an artifact needs to be
rebuilt.

Example:
```yaml
status:
  ...
  observedIgnore: |
    cue
    pkg
  ...
```

### Observed Recurse Submodules

The source-controller reports an observed recurse submodule in the
GitRepository's `.status.observedRecurseSubmodules`. The observed recurse
submodules is the latest `.spec.recurseSubmodules` value which resulted in a
[ready state](#ready-gitrepository), or stalled due to error it can not recover
from without human intervention. The value is the same as the
[recurse submodules in spec](#recurse-submodules). It indicates the recurse
submodules configuration used in building the current artifact in storage. It is
also used by the controller to determine if an artifact needs to be rebuilt.

Example:
```yaml
status:
  ...
  observedRecurseSubmodules: true
  ...
```

### Observed Include

The source-controller reports observed include in the GitRepository's
`.status.observedInclude`. The observed include is the latest
`.spec.recurseSubmodules` value which resulted in a
[ready state](#ready-gitrepository), or stalled due to error it can not recover
from without human intervention. The value is the same as the
[include in spec](#include). It indicates the include configuration used in
building the current artifact in storage. It is also used by the controller to
determine if an artifact needs to be rebuilt.

Example:
```yaml
status:
  ...
  observedInclude:
  - fromPath: deploy/webapp
    repository:
      name: repo1
    toPath: foo
  - fromPath: deploy/secure
    repository:
      name: repo2
    toPath: bar
  ...
```

### Observed Generation

The source-controller reports an [observed generation][typical-status-properties]
in the GitRepository's `.status.observedGeneration`. The observed generation is
the latest `.metadata.generation` which resulted in either a [ready state](#ready-gitrepository),
or stalled due to error it can not recover from without human
intervention.

### Last Handled Reconcile At

The source-controller reports the last `reconcile.fluxcd.io/requestedAt`
annotation value it acted on in the `.status.lastHandledReconcileAt` field.

For practical information about this field, see [triggering a
reconcile](#triggering-a-reconcile).

[typical-status-properties]: https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties
[kstatus-spec]: https://github.com/kubernetes-sigs/cli-utils/tree/master/pkg/kstatus
