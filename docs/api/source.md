<h1>Source API reference</h1>
<p>Packages:</p>
<ul class="simple">
<li>
<a href="#source.toolkit.fluxcd.io%2fv1alpha1">source.toolkit.fluxcd.io/v1alpha1</a>
</li>
</ul>
<h2 id="source.toolkit.fluxcd.io/v1alpha1">source.toolkit.fluxcd.io/v1alpha1</h2>
<p>Package v1alpha1 contains API Schema definitions for the source v1alpha1 API group</p>
Resource Types:
<ul class="simple"><li>
<a href="#source.toolkit.fluxcd.io/v1alpha1.GitRepository">GitRepository</a>
</li><li>
<a href="#source.toolkit.fluxcd.io/v1alpha1.HelmChart">HelmChart</a>
</li><li>
<a href="#source.toolkit.fluxcd.io/v1alpha1.HelmRepository">HelmRepository</a>
</li></ul>
<h3 id="source.toolkit.fluxcd.io/v1alpha1.GitRepository">GitRepository
</h3>
<p>GitRepository is the Schema for the gitrepositories API</p>
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
<code>source.toolkit.fluxcd.io/v1alpha1</code>
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
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
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
<a href="#source.toolkit.fluxcd.io/v1alpha1.GitRepositorySpec">
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
<p>The repository URL, can be a HTTP or SSH address.</p>
</td>
</tr>
<tr>
<td>
<code>secretRef</code><br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#localobjectreference-v1-core">
Kubernetes core/v1.LocalObjectReference
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The secret name containing the Git credentials.
For HTTPS repositories the secret must contain username and password
fields.
For SSH repositories the secret must contain identity, identity.pub and
known_hosts fields.</p>
</td>
</tr>
<tr>
<td>
<code>interval</code><br>
<em>
<a href="https://godoc.org/k8s.io/apimachinery/pkg/apis/meta/v1#Duration">
Kubernetes meta/v1.Duration
</a>
</em>
</td>
<td>
<p>The interval at which to check for repository updates.</p>
</td>
</tr>
<tr>
<td>
<code>timeout</code><br>
<em>
<a href="https://godoc.org/k8s.io/apimachinery/pkg/apis/meta/v1#Duration">
Kubernetes meta/v1.Duration
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The timeout for remote git operations like cloning, default to 20s.</p>
</td>
</tr>
<tr>
<td>
<code>ref</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1alpha1.GitRepositoryRef">
GitRepositoryRef
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The git reference to checkout and monitor for changes, defaults to
master branch.</p>
</td>
</tr>
<tr>
<td>
<code>verify</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1alpha1.GitRepositoryVerification">
GitRepositoryVerification
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Verify OpenPGP signature for the commit that HEAD points to.</p>
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
<p>Ignore overrides the set of excluded patterns in the .sourceignore
format (which is the same as .gitignore). If not provided, a default will
be used, consult the documentation for your version to find out what those
are.</p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1alpha1.GitRepositoryStatus">
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
<h3 id="source.toolkit.fluxcd.io/v1alpha1.HelmChart">HelmChart
</h3>
<p>HelmChart is the Schema for the helmcharts API</p>
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
<code>source.toolkit.fluxcd.io/v1alpha1</code>
</td>
</tr>
<tr>
<td>
<code>kind</code><br>
string
</td>
<td>
<code>HelmChart</code>
</td>
</tr>
<tr>
<td>
<code>metadata</code><br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
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
<a href="#source.toolkit.fluxcd.io/v1alpha1.HelmChartSpec">
HelmChartSpec
</a>
</em>
</td>
<td>
<br/>
<br/>
<table>
<tr>
<td>
<code>name</code><br>
<em>
string
</em>
</td>
<td>
<p>The name of the Helm chart, as made available by the referenced
Helm repository.</p>
</td>
</tr>
<tr>
<td>
<code>version</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The chart version semver expression, defaults to latest when
omitted.</p>
</td>
</tr>
<tr>
<td>
<code>helmRepositoryRef</code><br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#localobjectreference-v1-core">
Kubernetes core/v1.LocalObjectReference
</a>
</em>
</td>
<td>
<p>The name of the HelmRepository the chart is available at.</p>
</td>
</tr>
<tr>
<td>
<code>interval</code><br>
<em>
<a href="https://godoc.org/k8s.io/apimachinery/pkg/apis/meta/v1#Duration">
Kubernetes meta/v1.Duration
</a>
</em>
</td>
<td>
<p>The interval at which to check the Helm repository for updates.</p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1alpha1.HelmChartStatus">
HelmChartStatus
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
<h3 id="source.toolkit.fluxcd.io/v1alpha1.HelmRepository">HelmRepository
</h3>
<p>HelmRepository is the Schema for the helmrepositories API</p>
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
<code>source.toolkit.fluxcd.io/v1alpha1</code>
</td>
</tr>
<tr>
<td>
<code>kind</code><br>
string
</td>
<td>
<code>HelmRepository</code>
</td>
</tr>
<tr>
<td>
<code>metadata</code><br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
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
<a href="#source.toolkit.fluxcd.io/v1alpha1.HelmRepositorySpec">
HelmRepositorySpec
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
<p>The Helm repository URL, a valid URL contains at least a
protocol and host.</p>
</td>
</tr>
<tr>
<td>
<code>secretRef</code><br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#localobjectreference-v1-core">
Kubernetes core/v1.LocalObjectReference
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The name of the secret containing authentication credentials
for the Helm repository.
For HTTP/S basic auth the secret must contain username and password
fields.
For TLS the secret must contain caFile, keyFile and caCert fields.</p>
</td>
</tr>
<tr>
<td>
<code>interval</code><br>
<em>
<a href="https://godoc.org/k8s.io/apimachinery/pkg/apis/meta/v1#Duration">
Kubernetes meta/v1.Duration
</a>
</em>
</td>
<td>
<p>The interval at which to check the upstream for updates.</p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1alpha1.HelmRepositoryStatus">
HelmRepositoryStatus
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
<h3 id="source.toolkit.fluxcd.io/v1alpha1.Artifact">Artifact
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.toolkit.fluxcd.io/v1alpha1.GitRepositoryStatus">GitRepositoryStatus</a>, 
<a href="#source.toolkit.fluxcd.io/v1alpha1.HelmChartStatus">HelmChartStatus</a>, 
<a href="#source.toolkit.fluxcd.io/v1alpha1.HelmRepositoryStatus">HelmRepositoryStatus</a>)
</p>
<p>Artifact represents the output of a source synchronisation</p>
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
<p>Path is the local file path of this artifact.</p>
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
<p>URL is the HTTP address of this artifact.</p>
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
<em>(Optional)</em>
<p>Revision is a human readable identifier traceable in the origin source system.
It can be a commit sha, git tag, a helm index timestamp,
a helm chart version, a checksum, etc.</p>
</td>
</tr>
<tr>
<td>
<code>lastUpdateTime</code><br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#time-v1-meta">
Kubernetes meta/v1.Time
</a>
</em>
</td>
<td>
<p>LastUpdateTime is the timestamp corresponding to the last
update of this artifact.</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.toolkit.fluxcd.io/v1alpha1.GitRepositoryRef">GitRepositoryRef
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.toolkit.fluxcd.io/v1alpha1.GitRepositorySpec">GitRepositorySpec</a>)
</p>
<p>GitRepositoryRef defines the git ref used for pull and checkout operations.</p>
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
<p>The git branch to checkout, defaults to master.</p>
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
<p>The git tag to checkout, takes precedence over branch.</p>
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
<p>The git tag semver expression, takes precedence over tag.</p>
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
<p>The git commit sha to checkout, if specified tag filters will be ignored.</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.toolkit.fluxcd.io/v1alpha1.GitRepositorySpec">GitRepositorySpec
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.toolkit.fluxcd.io/v1alpha1.GitRepository">GitRepository</a>)
</p>
<p>GitRepositorySpec defines the desired state of a Git repository.</p>
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
<p>The repository URL, can be a HTTP or SSH address.</p>
</td>
</tr>
<tr>
<td>
<code>secretRef</code><br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#localobjectreference-v1-core">
Kubernetes core/v1.LocalObjectReference
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The secret name containing the Git credentials.
For HTTPS repositories the secret must contain username and password
fields.
For SSH repositories the secret must contain identity, identity.pub and
known_hosts fields.</p>
</td>
</tr>
<tr>
<td>
<code>interval</code><br>
<em>
<a href="https://godoc.org/k8s.io/apimachinery/pkg/apis/meta/v1#Duration">
Kubernetes meta/v1.Duration
</a>
</em>
</td>
<td>
<p>The interval at which to check for repository updates.</p>
</td>
</tr>
<tr>
<td>
<code>timeout</code><br>
<em>
<a href="https://godoc.org/k8s.io/apimachinery/pkg/apis/meta/v1#Duration">
Kubernetes meta/v1.Duration
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The timeout for remote git operations like cloning, default to 20s.</p>
</td>
</tr>
<tr>
<td>
<code>ref</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1alpha1.GitRepositoryRef">
GitRepositoryRef
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The git reference to checkout and monitor for changes, defaults to
master branch.</p>
</td>
</tr>
<tr>
<td>
<code>verify</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1alpha1.GitRepositoryVerification">
GitRepositoryVerification
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Verify OpenPGP signature for the commit that HEAD points to.</p>
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
<p>Ignore overrides the set of excluded patterns in the .sourceignore
format (which is the same as .gitignore). If not provided, a default will
be used, consult the documentation for your version to find out what those
are.</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.toolkit.fluxcd.io/v1alpha1.GitRepositoryStatus">GitRepositoryStatus
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.toolkit.fluxcd.io/v1alpha1.GitRepository">GitRepository</a>)
</p>
<p>GitRepositoryStatus defines the observed state of a Git repository.</p>
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
<code>conditions</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1alpha1.SourceCondition">
[]SourceCondition
</a>
</em>
</td>
<td>
<em>(Optional)</em>
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
<em>(Optional)</em>
<p>URL is the download link for the artifact output of the last repository
sync.</p>
</td>
</tr>
<tr>
<td>
<code>artifact</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1alpha1.Artifact">
Artifact
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Artifact represents the output of the last successful repository sync.</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.toolkit.fluxcd.io/v1alpha1.GitRepositoryVerification">GitRepositoryVerification
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.toolkit.fluxcd.io/v1alpha1.GitRepositorySpec">GitRepositorySpec</a>)
</p>
<p>GitRepositoryVerification defines the OpenPGP signature verification process.</p>
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
<p>Mode describes what git object should be verified, currently (&lsquo;head&rsquo;).</p>
</td>
</tr>
<tr>
<td>
<code>secretRef</code><br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#localobjectreference-v1-core">
Kubernetes core/v1.LocalObjectReference
</a>
</em>
</td>
<td>
<p>The secret name containing the public keys of all trusted git authors.</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.toolkit.fluxcd.io/v1alpha1.HelmChartSpec">HelmChartSpec
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.toolkit.fluxcd.io/v1alpha1.HelmChart">HelmChart</a>)
</p>
<p>HelmChartSpec defines the desired state of a Helm chart.</p>
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
<code>name</code><br>
<em>
string
</em>
</td>
<td>
<p>The name of the Helm chart, as made available by the referenced
Helm repository.</p>
</td>
</tr>
<tr>
<td>
<code>version</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The chart version semver expression, defaults to latest when
omitted.</p>
</td>
</tr>
<tr>
<td>
<code>helmRepositoryRef</code><br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#localobjectreference-v1-core">
Kubernetes core/v1.LocalObjectReference
</a>
</em>
</td>
<td>
<p>The name of the HelmRepository the chart is available at.</p>
</td>
</tr>
<tr>
<td>
<code>interval</code><br>
<em>
<a href="https://godoc.org/k8s.io/apimachinery/pkg/apis/meta/v1#Duration">
Kubernetes meta/v1.Duration
</a>
</em>
</td>
<td>
<p>The interval at which to check the Helm repository for updates.</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.toolkit.fluxcd.io/v1alpha1.HelmChartStatus">HelmChartStatus
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.toolkit.fluxcd.io/v1alpha1.HelmChart">HelmChart</a>)
</p>
<p>HelmChartStatus defines the observed state of the HelmChart.</p>
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
<code>conditions</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1alpha1.SourceCondition">
[]SourceCondition
</a>
</em>
</td>
<td>
<em>(Optional)</em>
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
<em>(Optional)</em>
<p>URL is the download link for the last chart pulled.</p>
</td>
</tr>
<tr>
<td>
<code>artifact</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1alpha1.Artifact">
Artifact
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Artifact represents the output of the last successful chart sync.</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.toolkit.fluxcd.io/v1alpha1.HelmRepositorySpec">HelmRepositorySpec
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.toolkit.fluxcd.io/v1alpha1.HelmRepository">HelmRepository</a>)
</p>
<p>HelmRepositorySpec defines the reference to a Helm repository.</p>
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
<p>The Helm repository URL, a valid URL contains at least a
protocol and host.</p>
</td>
</tr>
<tr>
<td>
<code>secretRef</code><br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#localobjectreference-v1-core">
Kubernetes core/v1.LocalObjectReference
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The name of the secret containing authentication credentials
for the Helm repository.
For HTTP/S basic auth the secret must contain username and password
fields.
For TLS the secret must contain caFile, keyFile and caCert fields.</p>
</td>
</tr>
<tr>
<td>
<code>interval</code><br>
<em>
<a href="https://godoc.org/k8s.io/apimachinery/pkg/apis/meta/v1#Duration">
Kubernetes meta/v1.Duration
</a>
</em>
</td>
<td>
<p>The interval at which to check the upstream for updates.</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.toolkit.fluxcd.io/v1alpha1.HelmRepositoryStatus">HelmRepositoryStatus
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.toolkit.fluxcd.io/v1alpha1.HelmRepository">HelmRepository</a>)
</p>
<p>HelmRepositoryStatus defines the observed state of the HelmRepository.</p>
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
<code>conditions</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1alpha1.SourceCondition">
[]SourceCondition
</a>
</em>
</td>
<td>
<em>(Optional)</em>
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
<em>(Optional)</em>
<p>URL is the download link for the last index fetched.</p>
</td>
</tr>
<tr>
<td>
<code>artifact</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1alpha1.Artifact">
Artifact
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Artifact represents the output of the last successful repository sync.</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.toolkit.fluxcd.io/v1alpha1.Source">Source
</h3>
<p>Source interface must be supported by all API types.</p>
<h3 id="source.toolkit.fluxcd.io/v1alpha1.SourceCondition">SourceCondition
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.toolkit.fluxcd.io/v1alpha1.GitRepositoryStatus">GitRepositoryStatus</a>, 
<a href="#source.toolkit.fluxcd.io/v1alpha1.HelmChartStatus">HelmChartStatus</a>, 
<a href="#source.toolkit.fluxcd.io/v1alpha1.HelmRepositoryStatus">HelmRepositoryStatus</a>)
</p>
<p>SourceCondition contains condition information for a source.</p>
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
<code>type</code><br>
<em>
string
</em>
</td>
<td>
<p>Type of the condition, currently (&lsquo;Ready&rsquo;).</p>
</td>
</tr>
<tr>
<td>
<code>status</code><br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#conditionstatus-v1-core">
Kubernetes core/v1.ConditionStatus
</a>
</em>
</td>
<td>
<p>Status of the condition, one of (&lsquo;True&rsquo;, &lsquo;False&rsquo;, &lsquo;Unknown&rsquo;).</p>
</td>
</tr>
<tr>
<td>
<code>lastTransitionTime</code><br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#time-v1-meta">
Kubernetes meta/v1.Time
</a>
</em>
</td>
<td>
<p>LastTransitionTime is the timestamp corresponding to the last status
change of this condition.</p>
</td>
</tr>
<tr>
<td>
<code>reason</code><br>
<em>
string
</em>
</td>
<td>
<p>Reason is a brief machine readable explanation for the condition&rsquo;s last
transition.</p>
</td>
</tr>
<tr>
<td>
<code>message</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Message is a human readable description of the details of the last
transition, complementing reason.</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<div class="admonition note">
<p class="last">This page was automatically generated with <code>gen-crd-api-reference-docs</code></p>
</div>
