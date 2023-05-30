<h1>Source API reference v1</h1>
<p>Packages:</p>
<ul class="simple">
<li>
<a href="#source.toolkit.fluxcd.io%2fv1">source.toolkit.fluxcd.io/v1</a>
</li>
</ul>
<h2 id="source.toolkit.fluxcd.io/v1">source.toolkit.fluxcd.io/v1</h2>
<p>Package v1 contains API Schema definitions for the source v1 API group</p>
Resource Types:
<ul class="simple"><li>
<a href="#source.toolkit.fluxcd.io/v1.GitRepository">GitRepository</a>
</li></ul>
<h3 id="source.toolkit.fluxcd.io/v1.GitRepository">GitRepository
</h3>
<p>GitRepository is the Schema for the gitrepositories API.</p>
<div class="md-typeset__scrollwrap">
<div class="md-typeset__table">
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>apiVersion</code><br>
string</td>
<td>
<code>source.toolkit.fluxcd.io/v1</code>
</td>
</tr>
<tr>
<td>
<code>kind</code><br>
string
</td>
<td>
<code>GitRepository</code>
</td>
</tr>
<tr>
<td>
<code>metadata</code><br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.19/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>spec</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1.GitRepositorySpec">
GitRepositorySpec
</a>
</em>
</td>
<td>
<br/>
<br/>
<table>
<tr>
<td>
<code>url</code><br>
<em>
string
</em>
</td>
<td>
<p>URL specifies the Git repository URL, it can be an HTTP/S or SSH address.</p>
</td>
</tr>
<tr>
<td>
<code>secretRef</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/pkg/apis/meta#LocalObjectReference">
github.com/fluxcd/pkg/apis/meta.LocalObjectReference
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>SecretRef specifies the Secret containing authentication credentials for
the GitRepository.
For HTTPS repositories the Secret must contain &lsquo;username&rsquo; and &lsquo;password&rsquo;
fields for basic auth or &lsquo;bearerToken&rsquo; field for token auth.
For SSH repositories the Secret must contain &lsquo;identity&rsquo;
and &lsquo;known_hosts&rsquo; fields.</p>
</td>
</tr>
<tr>
<td>
<code>interval</code><br>
<em>
<a href="https://pkg.go.dev/k8s.io/apimachinery/pkg/apis/meta/v1#Duration">
Kubernetes meta/v1.Duration
</a>
</em>
</td>
<td>
<p>Interval at which to check the GitRepository for updates.</p>
</td>
</tr>
<tr>
<td>
<code>timeout</code><br>
<em>
<a href="https://pkg.go.dev/k8s.io/apimachinery/pkg/apis/meta/v1#Duration">
Kubernetes meta/v1.Duration
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Timeout for Git operations like cloning, defaults to 60s.</p>
</td>
</tr>
<tr>
<td>
<code>ref</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1.GitRepositoryRef">
GitRepositoryRef
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Reference specifies the Git reference to resolve and monitor for
changes, defaults to the &lsquo;master&rsquo; branch.</p>
</td>
</tr>
<tr>
<td>
<code>verify</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1.GitRepositoryVerification">
GitRepositoryVerification
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Verification specifies the configuration to verify the Git commit
signature(s).</p>
</td>
</tr>
<tr>
<td>
<code>proxySecretRef</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/pkg/apis/meta#LocalObjectReference">
github.com/fluxcd/pkg/apis/meta.LocalObjectReference
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>ProxySecretRef specifies the Secret containing the proxy configuration
to use while communicating with the Git server.</p>
</td>
</tr>
<tr>
<td>
<code>ignore</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Ignore overrides the set of excluded patterns in the .sourceignore format
(which is the same as .gitignore). If not provided, a default will be used,
consult the documentation for your version to find out what those are.</p>
</td>
</tr>
<tr>
<td>
<code>suspend</code><br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>Suspend tells the controller to suspend the reconciliation of this
GitRepository.</p>
</td>
</tr>
<tr>
<td>
<code>recurseSubmodules</code><br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>RecurseSubmodules enables the initialization of all submodules within
the GitRepository as cloned from the URL, using their default settings.</p>
</td>
</tr>
<tr>
<td>
<code>include</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1.GitRepositoryInclude">
[]GitRepositoryInclude
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Include specifies a list of GitRepository resources which Artifacts
should be included in the Artifact produced for this GitRepository.</p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1.GitRepositoryStatus">
GitRepositoryStatus
</a>
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.toolkit.fluxcd.io/v1.Artifact">Artifact
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.toolkit.fluxcd.io/v1.GitRepositoryStatus">GitRepositoryStatus</a>)
</p>
<p>Artifact represents the output of a Source reconciliation.</p>
<div class="md-typeset__scrollwrap">
<div class="md-typeset__table">
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>path</code><br>
<em>
string
</em>
</td>
<td>
<p>Path is the relative file path of the Artifact. It can be used to locate
the file in the root of the Artifact storage on the local file system of
the controller managing the Source.</p>
</td>
</tr>
<tr>
<td>
<code>url</code><br>
<em>
string
</em>
</td>
<td>
<p>URL is the HTTP address of the Artifact as exposed by the controller
managing the Source. It can be used to retrieve the Artifact for
consumption, e.g. by another controller applying the Artifact contents.</p>
</td>
</tr>
<tr>
<td>
<code>revision</code><br>
<em>
string
</em>
</td>
<td>
<p>Revision is a human-readable identifier traceable in the origin source
system. It can be a Git commit SHA, Git tag, a Helm chart version, etc.</p>
</td>
</tr>
<tr>
<td>
<code>digest</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Digest is the digest of the file in the form of &lsquo;<algorithm>:<checksum>&rsquo;.</p>
</td>
</tr>
<tr>
<td>
<code>lastUpdateTime</code><br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.19/#time-v1-meta">
Kubernetes meta/v1.Time
</a>
</em>
</td>
<td>
<p>LastUpdateTime is the timestamp corresponding to the last update of the
Artifact.</p>
</td>
</tr>
<tr>
<td>
<code>size</code><br>
<em>
int64
</em>
</td>
<td>
<em>(Optional)</em>
<p>Size is the number of bytes in the file.</p>
</td>
</tr>
<tr>
<td>
<code>metadata</code><br>
<em>
map[string]string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Metadata holds upstream information such as OCI annotations.</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.toolkit.fluxcd.io/v1.GitRepositoryInclude">GitRepositoryInclude
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.toolkit.fluxcd.io/v1.GitRepositorySpec">GitRepositorySpec</a>, 
<a href="#source.toolkit.fluxcd.io/v1.GitRepositoryStatus">GitRepositoryStatus</a>)
</p>
<p>GitRepositoryInclude specifies a local reference to a GitRepository which
Artifact (sub-)contents must be included, and where they should be placed.</p>
<div class="md-typeset__scrollwrap">
<div class="md-typeset__table">
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>repository</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/pkg/apis/meta#LocalObjectReference">
github.com/fluxcd/pkg/apis/meta.LocalObjectReference
</a>
</em>
</td>
<td>
<p>GitRepositoryRef specifies the GitRepository which Artifact contents
must be included.</p>
</td>
</tr>
<tr>
<td>
<code>fromPath</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>FromPath specifies the path to copy contents from, defaults to the root
of the Artifact.</p>
</td>
</tr>
<tr>
<td>
<code>toPath</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>ToPath specifies the path to copy contents to, defaults to the name of
the GitRepositoryRef.</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.toolkit.fluxcd.io/v1.GitRepositoryRef">GitRepositoryRef
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.toolkit.fluxcd.io/v1.GitRepositorySpec">GitRepositorySpec</a>)
</p>
<p>GitRepositoryRef specifies the Git reference to resolve and checkout.</p>
<div class="md-typeset__scrollwrap">
<div class="md-typeset__table">
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>branch</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Branch to check out, defaults to &lsquo;master&rsquo; if no other field is defined.</p>
</td>
</tr>
<tr>
<td>
<code>tag</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Tag to check out, takes precedence over Branch.</p>
</td>
</tr>
<tr>
<td>
<code>semver</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>SemVer tag expression to check out, takes precedence over Tag.</p>
</td>
</tr>
<tr>
<td>
<code>name</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Name of the reference to check out; takes precedence over Branch, Tag and SemVer.</p>
<p>It must be a valid Git reference: <a href="https://git-scm.com/docs/git-check-ref-format#_description">https://git-scm.com/docs/git-check-ref-format#_description</a>
Examples: &ldquo;refs/heads/main&rdquo;, &ldquo;refs/tags/v0.1.0&rdquo;, &ldquo;refs/pull/420/head&rdquo;, &ldquo;refs/merge-requests/1/head&rdquo;</p>
</td>
</tr>
<tr>
<td>
<code>commit</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Commit SHA to check out, takes precedence over all reference fields.</p>
<p>This can be combined with Branch to shallow clone the branch, in which
the commit is expected to exist.</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.toolkit.fluxcd.io/v1.GitRepositorySpec">GitRepositorySpec
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.toolkit.fluxcd.io/v1.GitRepository">GitRepository</a>)
</p>
<p>GitRepositorySpec specifies the required configuration to produce an
Artifact for a Git repository.</p>
<div class="md-typeset__scrollwrap">
<div class="md-typeset__table">
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>url</code><br>
<em>
string
</em>
</td>
<td>
<p>URL specifies the Git repository URL, it can be an HTTP/S or SSH address.</p>
</td>
</tr>
<tr>
<td>
<code>secretRef</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/pkg/apis/meta#LocalObjectReference">
github.com/fluxcd/pkg/apis/meta.LocalObjectReference
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>SecretRef specifies the Secret containing authentication credentials for
the GitRepository.
For HTTPS repositories the Secret must contain &lsquo;username&rsquo; and &lsquo;password&rsquo;
fields for basic auth or &lsquo;bearerToken&rsquo; field for token auth.
For SSH repositories the Secret must contain &lsquo;identity&rsquo;
and &lsquo;known_hosts&rsquo; fields.</p>
</td>
</tr>
<tr>
<td>
<code>interval</code><br>
<em>
<a href="https://pkg.go.dev/k8s.io/apimachinery/pkg/apis/meta/v1#Duration">
Kubernetes meta/v1.Duration
</a>
</em>
</td>
<td>
<p>Interval at which to check the GitRepository for updates.</p>
</td>
</tr>
<tr>
<td>
<code>timeout</code><br>
<em>
<a href="https://pkg.go.dev/k8s.io/apimachinery/pkg/apis/meta/v1#Duration">
Kubernetes meta/v1.Duration
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Timeout for Git operations like cloning, defaults to 60s.</p>
</td>
</tr>
<tr>
<td>
<code>ref</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1.GitRepositoryRef">
GitRepositoryRef
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Reference specifies the Git reference to resolve and monitor for
changes, defaults to the &lsquo;master&rsquo; branch.</p>
</td>
</tr>
<tr>
<td>
<code>verify</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1.GitRepositoryVerification">
GitRepositoryVerification
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Verification specifies the configuration to verify the Git commit
signature(s).</p>
</td>
</tr>
<tr>
<td>
<code>proxySecretRef</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/pkg/apis/meta#LocalObjectReference">
github.com/fluxcd/pkg/apis/meta.LocalObjectReference
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>ProxySecretRef specifies the Secret containing the proxy configuration
to use while communicating with the Git server.</p>
</td>
</tr>
<tr>
<td>
<code>ignore</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Ignore overrides the set of excluded patterns in the .sourceignore format
(which is the same as .gitignore). If not provided, a default will be used,
consult the documentation for your version to find out what those are.</p>
</td>
</tr>
<tr>
<td>
<code>suspend</code><br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>Suspend tells the controller to suspend the reconciliation of this
GitRepository.</p>
</td>
</tr>
<tr>
<td>
<code>recurseSubmodules</code><br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>RecurseSubmodules enables the initialization of all submodules within
the GitRepository as cloned from the URL, using their default settings.</p>
</td>
</tr>
<tr>
<td>
<code>include</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1.GitRepositoryInclude">
[]GitRepositoryInclude
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Include specifies a list of GitRepository resources which Artifacts
should be included in the Artifact produced for this GitRepository.</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.toolkit.fluxcd.io/v1.GitRepositoryStatus">GitRepositoryStatus
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.toolkit.fluxcd.io/v1.GitRepository">GitRepository</a>)
</p>
<p>GitRepositoryStatus records the observed state of a Git repository.</p>
<div class="md-typeset__scrollwrap">
<div class="md-typeset__table">
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>observedGeneration</code><br>
<em>
int64
</em>
</td>
<td>
<em>(Optional)</em>
<p>ObservedGeneration is the last observed generation of the GitRepository
object.</p>
</td>
</tr>
<tr>
<td>
<code>conditions</code><br>
<em>
<a href="https://pkg.go.dev/k8s.io/apimachinery/pkg/apis/meta/v1#Condition">
[]Kubernetes meta/v1.Condition
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Conditions holds the conditions for the GitRepository.</p>
</td>
</tr>
<tr>
<td>
<code>artifact</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1.Artifact">
Artifact
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Artifact represents the last successful GitRepository reconciliation.</p>
</td>
</tr>
<tr>
<td>
<code>includedArtifacts</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1.Artifact">
[]Artifact
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>IncludedArtifacts contains a list of the last successfully included
Artifacts as instructed by GitRepositorySpec.Include.</p>
</td>
</tr>
<tr>
<td>
<code>observedIgnore</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>ObservedIgnore is the observed exclusion patterns used for constructing
the source artifact.</p>
</td>
</tr>
<tr>
<td>
<code>observedRecurseSubmodules</code><br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>ObservedRecurseSubmodules is the observed resource submodules
configuration used to produce the current Artifact.</p>
</td>
</tr>
<tr>
<td>
<code>observedInclude</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1.GitRepositoryInclude">
[]GitRepositoryInclude
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>ObservedInclude is the observed list of GitRepository resources used to
produce the current Artifact.</p>
</td>
</tr>
<tr>
<td>
<code>ReconcileRequestStatus</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/pkg/apis/meta#ReconcileRequestStatus">
github.com/fluxcd/pkg/apis/meta.ReconcileRequestStatus
</a>
</em>
</td>
<td>
<p>
(Members of <code>ReconcileRequestStatus</code> are embedded into this type.)
</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.toolkit.fluxcd.io/v1.GitRepositoryVerification">GitRepositoryVerification
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.toolkit.fluxcd.io/v1.GitRepositorySpec">GitRepositorySpec</a>)
</p>
<p>GitRepositoryVerification specifies the Git commit signature verification
strategy.</p>
<div class="md-typeset__scrollwrap">
<div class="md-typeset__table">
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>mode</code><br>
<em>
string
</em>
</td>
<td>
<p>Mode specifies what Git object should be verified, currently (&lsquo;head&rsquo;).</p>
</td>
</tr>
<tr>
<td>
<code>secretRef</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/pkg/apis/meta#LocalObjectReference">
github.com/fluxcd/pkg/apis/meta.LocalObjectReference
</a>
</em>
</td>
<td>
<p>SecretRef specifies the Secret containing the public keys of trusted Git
authors.</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.toolkit.fluxcd.io/v1.Source">Source
</h3>
<p>Source interface must be supported by all API types.
Source is the interface that provides generic access to the Artifact and
interval. It must be supported by all kinds of the source.toolkit.fluxcd.io
API group.</p>
<div class="admonition note">
<p class="last">This page was automatically generated with <code>gen-crd-api-reference-docs</code></p>
</div>
