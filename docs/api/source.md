<h1>Source API reference</h1>
<p>Packages:</p>
<ul class="simple">
<li>
<a href="#source.toolkit.fluxcd.io%2fv1beta1">source.toolkit.fluxcd.io/v1beta1</a>
</li>
</ul>
<h2 id="source.toolkit.fluxcd.io/v1beta1">source.toolkit.fluxcd.io/v1beta1</h2>
<p>Package v1beta1 contains API Schema definitions for the source v1beta1 API group</p>
Resource Types:
<ul class="simple"><li>
<a href="#source.toolkit.fluxcd.io/v1beta1.Bucket">Bucket</a>
</li><li>
<a href="#source.toolkit.fluxcd.io/v1beta1.GitRepository">GitRepository</a>
</li><li>
<a href="#source.toolkit.fluxcd.io/v1beta1.HelmChart">HelmChart</a>
</li><li>
<a href="#source.toolkit.fluxcd.io/v1beta1.HelmRepository">HelmRepository</a>
</li></ul>
<h3 id="source.toolkit.fluxcd.io/v1beta1.Bucket">Bucket
</h3>
<p>Bucket is the Schema for the buckets API</p>
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
<code>source.toolkit.fluxcd.io/v1beta1</code>
</td>
</tr>
<tr>
<td>
<code>kind</code><br>
string
</td>
<td>
<code>Bucket</code>
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
<a href="#source.toolkit.fluxcd.io/v1beta1.BucketSpec">
BucketSpec
</a>
</em>
</td>
<td>
<br/>
<br/>
<table>
<tr>
<td>
<code>provider</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The S3 compatible storage provider name, default (&lsquo;generic&rsquo;).</p>
</td>
</tr>
<tr>
<td>
<code>bucketName</code><br>
<em>
string
</em>
</td>
<td>
<p>The bucket name.</p>
</td>
</tr>
<tr>
<td>
<code>endpoint</code><br>
<em>
string
</em>
</td>
<td>
<p>The bucket endpoint address.</p>
</td>
</tr>
<tr>
<td>
<code>insecure</code><br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>Insecure allows connecting to a non-TLS S3 HTTP endpoint.</p>
</td>
</tr>
<tr>
<td>
<code>region</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The bucket region.</p>
</td>
</tr>
<tr>
<td>
<code>secretRef</code><br>
<em>
<a href="https://godoc.org/github.com/fluxcd/pkg/apis/meta#LocalObjectReference">
github.com/fluxcd/pkg/apis/meta.LocalObjectReference
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The name of the secret containing authentication credentials
for the Bucket.</p>
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
<p>The interval at which to check for bucket updates.</p>
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
<p>The timeout for download operations, defaults to 20s.</p>
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
<p>This flag tells the controller to suspend the reconciliation of this source.</p>
</td>
</tr>
<tr>
<td>
<code>accessFrom</code><br>
<em>
<a href="https://godoc.org/github.com/fluxcd/pkg/apis/acl#AccessFrom">
github.com/fluxcd/pkg/apis/acl.AccessFrom
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>AccessFrom defines an Access Control List for allowing cross-namespace references to this object.</p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1beta1.BucketStatus">
BucketStatus
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
<h3 id="source.toolkit.fluxcd.io/v1beta1.GitRepository">GitRepository
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
<code>source.toolkit.fluxcd.io/v1beta1</code>
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
<a href="#source.toolkit.fluxcd.io/v1beta1.GitRepositorySpec">
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
<p>The repository URL, can be a HTTP/S or SSH address.</p>
</td>
</tr>
<tr>
<td>
<code>secretRef</code><br>
<em>
<a href="https://godoc.org/github.com/fluxcd/pkg/apis/meta#LocalObjectReference">
github.com/fluxcd/pkg/apis/meta.LocalObjectReference
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The secret name containing the Git credentials.
For HTTPS repositories the secret must contain username and password fields.
For SSH repositories the secret must contain &lsquo;identity&rsquo;, &lsquo;identity.pub&rsquo; and &lsquo;known_hosts&rsquo; fields.</p>
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
<p>The timeout for remote Git operations like cloning, defaults to 20s.</p>
</td>
</tr>
<tr>
<td>
<code>ref</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1beta1.GitRepositoryRef">
GitRepositoryRef
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The Git reference to checkout and monitor for changes, defaults to
master branch.</p>
</td>
</tr>
<tr>
<td>
<code>verify</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1beta1.GitRepositoryVerification">
GitRepositoryVerification
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Verification defines the configuration to verify the OpenPGP signature for the Git commit HEAD points to.</p>
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
<p>Ignore overrides the set of excluded patterns in the .sourceignore format (which is the same as .gitignore).
If not provided, a default will be used, consult the documentation for your version to find out what those are.</p>
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
<p>Suspend tells the controller to suspend the reconciliation of this source.
This flag tells the controller to suspend the reconciliation of this source.</p>
</td>
</tr>
<tr>
<td>
<code>gitImplementation</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Determines which git client library to use.
Defaults to go-git, valid values are (&lsquo;go-git&rsquo;, &lsquo;libgit2&rsquo;).</p>
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
<p>When enabled, after the clone is created, initializes all submodules within, using their default settings.
This option is available only when using the &lsquo;go-git&rsquo; GitImplementation.</p>
</td>
</tr>
<tr>
<td>
<code>include</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1beta1.GitRepositoryInclude">
[]GitRepositoryInclude
</a>
</em>
</td>
<td>
<p>Include defines a list of GitRepository resources which artifacts should be included in the artifact produced for
this resource.</p>
</td>
</tr>
<tr>
<td>
<code>accessFrom</code><br>
<em>
<a href="https://godoc.org/github.com/fluxcd/pkg/apis/acl#AccessFrom">
github.com/fluxcd/pkg/apis/acl.AccessFrom
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>AccessFrom defines an Access Control List for allowing cross-namespace references to this object.</p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1beta1.GitRepositoryStatus">
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
<h3 id="source.toolkit.fluxcd.io/v1beta1.HelmChart">HelmChart
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
<code>source.toolkit.fluxcd.io/v1beta1</code>
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
<a href="#source.toolkit.fluxcd.io/v1beta1.HelmChartSpec">
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
<code>chart</code><br>
<em>
string
</em>
</td>
<td>
<p>The name or path the Helm chart is available at in the SourceRef.</p>
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
<p>The chart version semver expression, ignored for charts from GitRepository
and Bucket sources. Defaults to latest when omitted.</p>
</td>
</tr>
<tr>
<td>
<code>sourceRef</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1beta1.LocalHelmChartSourceReference">
LocalHelmChartSourceReference
</a>
</em>
</td>
<td>
<p>The reference to the Source the chart is available at.</p>
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
<p>The interval at which to check the Source for updates.</p>
</td>
</tr>
<tr>
<td>
<code>reconcileStrategy</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Determines what enables the creation of a new artifact. Valid values are
(&lsquo;ChartVersion&rsquo;, &lsquo;Revision&rsquo;).
See the documentation of the values for an explanation on their behavior.
Defaults to ChartVersion when omitted.</p>
</td>
</tr>
<tr>
<td>
<code>valuesFiles</code><br>
<em>
[]string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Alternative list of values files to use as the chart values (values.yaml
is not included by default), expected to be a relative path in the SourceRef.
Values files are merged in the order of this list with the last file overriding
the first. Ignored when omitted.</p>
</td>
</tr>
<tr>
<td>
<code>valuesFile</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Alternative values file to use as the default chart values, expected to
be a relative path in the SourceRef. Deprecated in favor of ValuesFiles,
for backwards compatibility the file defined here is merged before the
ValuesFiles items. Ignored when omitted.</p>
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
<p>This flag tells the controller to suspend the reconciliation of this source.</p>
</td>
</tr>
<tr>
<td>
<code>accessFrom</code><br>
<em>
<a href="https://godoc.org/github.com/fluxcd/pkg/apis/acl#AccessFrom">
github.com/fluxcd/pkg/apis/acl.AccessFrom
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>AccessFrom defines an Access Control List for allowing cross-namespace references to this object.</p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1beta1.HelmChartStatus">
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
<h3 id="source.toolkit.fluxcd.io/v1beta1.HelmRepository">HelmRepository
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
<code>source.toolkit.fluxcd.io/v1beta1</code>
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
<a href="#source.toolkit.fluxcd.io/v1beta1.HelmRepositorySpec">
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
<p>The Helm repository URL, a valid URL contains at least a protocol and host.</p>
</td>
</tr>
<tr>
<td>
<code>secretRef</code><br>
<em>
<a href="https://godoc.org/github.com/fluxcd/pkg/apis/meta#LocalObjectReference">
github.com/fluxcd/pkg/apis/meta.LocalObjectReference
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The name of the secret containing authentication credentials for the Helm
repository.
For HTTP/S basic auth the secret must contain username and
password fields.
For TLS the secret must contain a certFile and keyFile, and/or
caCert fields.</p>
</td>
</tr>
<tr>
<td>
<code>passCredentials</code><br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>PassCredentials allows the credentials from the SecretRef to be passed on to
a host that does not match the host as defined in URL.
This may be required if the host of the advertised chart URLs in the index
differ from the defined URL.
Enabling this should be done with caution, as it can potentially result in
credentials getting stolen in a MITM-attack.</p>
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
<p>The timeout of index downloading, defaults to 60s.</p>
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
<p>This flag tells the controller to suspend the reconciliation of this source.</p>
</td>
</tr>
<tr>
<td>
<code>accessFrom</code><br>
<em>
<a href="https://godoc.org/github.com/fluxcd/pkg/apis/acl#AccessFrom">
github.com/fluxcd/pkg/apis/acl.AccessFrom
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>AccessFrom defines an Access Control List for allowing cross-namespace references to this object.</p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1beta1.HelmRepositoryStatus">
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
<h3 id="source.toolkit.fluxcd.io/v1beta1.Artifact">Artifact
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.toolkit.fluxcd.io/v1beta1.BucketStatus">BucketStatus</a>, 
<a href="#source.toolkit.fluxcd.io/v1beta1.GitRepositoryStatus">GitRepositoryStatus</a>, 
<a href="#source.toolkit.fluxcd.io/v1beta1.HelmChartStatus">HelmChartStatus</a>, 
<a href="#source.toolkit.fluxcd.io/v1beta1.HelmRepositoryStatus">HelmRepositoryStatus</a>)
</p>
<p>Artifact represents the output of a source synchronisation.</p>
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
<p>Path is the relative file path of this artifact.</p>
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
<p>Revision is a human readable identifier traceable in the origin source
system. It can be a Git commit SHA, Git tag, a Helm index timestamp, a Helm
chart version, etc.</p>
</td>
</tr>
<tr>
<td>
<code>checksum</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Checksum is the SHA256 checksum of the artifact.</p>
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
<p>LastUpdateTime is the timestamp corresponding to the last update of this
artifact.</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.toolkit.fluxcd.io/v1beta1.BucketSpec">BucketSpec
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.toolkit.fluxcd.io/v1beta1.Bucket">Bucket</a>)
</p>
<p>BucketSpec defines the desired state of an S3 compatible bucket</p>
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
<code>provider</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The S3 compatible storage provider name, default (&lsquo;generic&rsquo;).</p>
</td>
</tr>
<tr>
<td>
<code>bucketName</code><br>
<em>
string
</em>
</td>
<td>
<p>The bucket name.</p>
</td>
</tr>
<tr>
<td>
<code>endpoint</code><br>
<em>
string
</em>
</td>
<td>
<p>The bucket endpoint address.</p>
</td>
</tr>
<tr>
<td>
<code>insecure</code><br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>Insecure allows connecting to a non-TLS S3 HTTP endpoint.</p>
</td>
</tr>
<tr>
<td>
<code>region</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The bucket region.</p>
</td>
</tr>
<tr>
<td>
<code>secretRef</code><br>
<em>
<a href="https://godoc.org/github.com/fluxcd/pkg/apis/meta#LocalObjectReference">
github.com/fluxcd/pkg/apis/meta.LocalObjectReference
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The name of the secret containing authentication credentials
for the Bucket.</p>
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
<p>The interval at which to check for bucket updates.</p>
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
<p>The timeout for download operations, defaults to 20s.</p>
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
<p>This flag tells the controller to suspend the reconciliation of this source.</p>
</td>
</tr>
<tr>
<td>
<code>accessFrom</code><br>
<em>
<a href="https://godoc.org/github.com/fluxcd/pkg/apis/acl#AccessFrom">
github.com/fluxcd/pkg/apis/acl.AccessFrom
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>AccessFrom defines an Access Control List for allowing cross-namespace references to this object.</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.toolkit.fluxcd.io/v1beta1.BucketStatus">BucketStatus
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.toolkit.fluxcd.io/v1beta1.Bucket">Bucket</a>)
</p>
<p>BucketStatus defines the observed state of a bucket</p>
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
<p>ObservedGeneration is the last observed generation.</p>
</td>
</tr>
<tr>
<td>
<code>conditions</code><br>
<em>
<a href="https://godoc.org/k8s.io/apimachinery/pkg/apis/meta/v1#Condition">
[]Kubernetes meta/v1.Condition
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Conditions holds the conditions for the Bucket.</p>
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
<p>URL is the download link for the artifact output of the last Bucket sync.</p>
</td>
</tr>
<tr>
<td>
<code>artifact</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1beta1.Artifact">
Artifact
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Artifact represents the output of the last successful Bucket sync.</p>
</td>
</tr>
<tr>
<td>
<code>ReconcileRequestStatus</code><br>
<em>
<a href="https://godoc.org/github.com/fluxcd/pkg/apis/meta#ReconcileRequestStatus">
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
<h3 id="source.toolkit.fluxcd.io/v1beta1.GitRepositoryInclude">GitRepositoryInclude
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.toolkit.fluxcd.io/v1beta1.GitRepositorySpec">GitRepositorySpec</a>)
</p>
<p>GitRepositoryInclude defines a source with a from and to path.</p>
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
<a href="https://godoc.org/github.com/fluxcd/pkg/apis/meta#LocalObjectReference">
github.com/fluxcd/pkg/apis/meta.LocalObjectReference
</a>
</em>
</td>
<td>
<p>Reference to a GitRepository to include.</p>
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
<p>The path to copy contents from, defaults to the root directory.</p>
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
<p>The path to copy contents to, defaults to the name of the source ref.</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.toolkit.fluxcd.io/v1beta1.GitRepositoryRef">GitRepositoryRef
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.toolkit.fluxcd.io/v1beta1.GitRepositorySpec">GitRepositorySpec</a>)
</p>
<p>GitRepositoryRef defines the Git ref used for pull and checkout operations.</p>
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
<p>The Git branch to checkout, defaults to master.</p>
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
<p>The Git tag to checkout, takes precedence over Branch.</p>
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
<p>The Git tag semver expression, takes precedence over Tag.</p>
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
<p>The Git commit SHA to checkout, if specified Tag filters will be ignored.</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.toolkit.fluxcd.io/v1beta1.GitRepositorySpec">GitRepositorySpec
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.toolkit.fluxcd.io/v1beta1.GitRepository">GitRepository</a>)
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
<p>The repository URL, can be a HTTP/S or SSH address.</p>
</td>
</tr>
<tr>
<td>
<code>secretRef</code><br>
<em>
<a href="https://godoc.org/github.com/fluxcd/pkg/apis/meta#LocalObjectReference">
github.com/fluxcd/pkg/apis/meta.LocalObjectReference
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The secret name containing the Git credentials.
For HTTPS repositories the secret must contain username and password fields.
For SSH repositories the secret must contain &lsquo;identity&rsquo;, &lsquo;identity.pub&rsquo; and &lsquo;known_hosts&rsquo; fields.</p>
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
<p>The timeout for remote Git operations like cloning, defaults to 20s.</p>
</td>
</tr>
<tr>
<td>
<code>ref</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1beta1.GitRepositoryRef">
GitRepositoryRef
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The Git reference to checkout and monitor for changes, defaults to
master branch.</p>
</td>
</tr>
<tr>
<td>
<code>verify</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1beta1.GitRepositoryVerification">
GitRepositoryVerification
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Verification defines the configuration to verify the OpenPGP signature for the Git commit HEAD points to.</p>
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
<p>Ignore overrides the set of excluded patterns in the .sourceignore format (which is the same as .gitignore).
If not provided, a default will be used, consult the documentation for your version to find out what those are.</p>
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
<p>Suspend tells the controller to suspend the reconciliation of this source.
This flag tells the controller to suspend the reconciliation of this source.</p>
</td>
</tr>
<tr>
<td>
<code>gitImplementation</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Determines which git client library to use.
Defaults to go-git, valid values are (&lsquo;go-git&rsquo;, &lsquo;libgit2&rsquo;).</p>
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
<p>When enabled, after the clone is created, initializes all submodules within, using their default settings.
This option is available only when using the &lsquo;go-git&rsquo; GitImplementation.</p>
</td>
</tr>
<tr>
<td>
<code>include</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1beta1.GitRepositoryInclude">
[]GitRepositoryInclude
</a>
</em>
</td>
<td>
<p>Include defines a list of GitRepository resources which artifacts should be included in the artifact produced for
this resource.</p>
</td>
</tr>
<tr>
<td>
<code>accessFrom</code><br>
<em>
<a href="https://godoc.org/github.com/fluxcd/pkg/apis/acl#AccessFrom">
github.com/fluxcd/pkg/apis/acl.AccessFrom
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>AccessFrom defines an Access Control List for allowing cross-namespace references to this object.</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.toolkit.fluxcd.io/v1beta1.GitRepositoryStatus">GitRepositoryStatus
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.toolkit.fluxcd.io/v1beta1.GitRepository">GitRepository</a>)
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
<code>observedGeneration</code><br>
<em>
int64
</em>
</td>
<td>
<em>(Optional)</em>
<p>ObservedGeneration is the last observed generation.</p>
</td>
</tr>
<tr>
<td>
<code>conditions</code><br>
<em>
<a href="https://godoc.org/k8s.io/apimachinery/pkg/apis/meta/v1#Condition">
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
<code>url</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>URL is the download link for the artifact output of the last repository sync.</p>
</td>
</tr>
<tr>
<td>
<code>artifact</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1beta1.Artifact">
Artifact
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Artifact represents the output of the last successful repository sync.</p>
</td>
</tr>
<tr>
<td>
<code>includedArtifacts</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1beta1.*./api/v1beta1.Artifact">
[]*./api/v1beta1.Artifact
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>IncludedArtifacts represents the included artifacts from the last successful repository sync.</p>
</td>
</tr>
<tr>
<td>
<code>ReconcileRequestStatus</code><br>
<em>
<a href="https://godoc.org/github.com/fluxcd/pkg/apis/meta#ReconcileRequestStatus">
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
<h3 id="source.toolkit.fluxcd.io/v1beta1.GitRepositoryVerification">GitRepositoryVerification
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.toolkit.fluxcd.io/v1beta1.GitRepositorySpec">GitRepositorySpec</a>)
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
<p>Mode describes what Git object should be verified, currently (&lsquo;head&rsquo;).</p>
</td>
</tr>
<tr>
<td>
<code>secretRef</code><br>
<em>
<a href="https://godoc.org/github.com/fluxcd/pkg/apis/meta#LocalObjectReference">
github.com/fluxcd/pkg/apis/meta.LocalObjectReference
</a>
</em>
</td>
<td>
<p>SecretRef containing the public keys of all trusted Git authors.</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.toolkit.fluxcd.io/v1beta1.HelmChartSpec">HelmChartSpec
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.toolkit.fluxcd.io/v1beta1.HelmChart">HelmChart</a>)
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
<code>chart</code><br>
<em>
string
</em>
</td>
<td>
<p>The name or path the Helm chart is available at in the SourceRef.</p>
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
<p>The chart version semver expression, ignored for charts from GitRepository
and Bucket sources. Defaults to latest when omitted.</p>
</td>
</tr>
<tr>
<td>
<code>sourceRef</code><br>
<em>
<a href="#source.toolkit.fluxcd.io/v1beta1.LocalHelmChartSourceReference">
LocalHelmChartSourceReference
</a>
</em>
</td>
<td>
<p>The reference to the Source the chart is available at.</p>
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
<p>The interval at which to check the Source for updates.</p>
</td>
</tr>
<tr>
<td>
<code>reconcileStrategy</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Determines what enables the creation of a new artifact. Valid values are
(&lsquo;ChartVersion&rsquo;, &lsquo;Revision&rsquo;).
See the documentation of the values for an explanation on their behavior.
Defaults to ChartVersion when omitted.</p>
</td>
</tr>
<tr>
<td>
<code>valuesFiles</code><br>
<em>
[]string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Alternative list of values files to use as the chart values (values.yaml
is not included by default), expected to be a relative path in the SourceRef.
Values files are merged in the order of this list with the last file overriding
the first. Ignored when omitted.</p>
</td>
</tr>
<tr>
<td>
<code>valuesFile</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Alternative values file to use as the default chart values, expected to
be a relative path in the SourceRef. Deprecated in favor of ValuesFiles,
for backwards compatibility the file defined here is merged before the
ValuesFiles items. Ignored when omitted.</p>
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
<p>This flag tells the controller to suspend the reconciliation of this source.</p>
</td>
</tr>
<tr>
<td>
<code>accessFrom</code><br>
<em>
<a href="https://godoc.org/github.com/fluxcd/pkg/apis/acl#AccessFrom">
github.com/fluxcd/pkg/apis/acl.AccessFrom
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>AccessFrom defines an Access Control List for allowing cross-namespace references to this object.</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.toolkit.fluxcd.io/v1beta1.HelmChartStatus">HelmChartStatus
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.toolkit.fluxcd.io/v1beta1.HelmChart">HelmChart</a>)
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
<code>observedGeneration</code><br>
<em>
int64
</em>
</td>
<td>
<em>(Optional)</em>
<p>ObservedGeneration is the last observed generation.</p>
</td>
</tr>
<tr>
<td>
<code>conditions</code><br>
<em>
<a href="https://godoc.org/k8s.io/apimachinery/pkg/apis/meta/v1#Condition">
[]Kubernetes meta/v1.Condition
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Conditions holds the conditions for the HelmChart.</p>
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
<a href="#source.toolkit.fluxcd.io/v1beta1.Artifact">
Artifact
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Artifact represents the output of the last successful chart sync.</p>
</td>
</tr>
<tr>
<td>
<code>ReconcileRequestStatus</code><br>
<em>
<a href="https://godoc.org/github.com/fluxcd/pkg/apis/meta#ReconcileRequestStatus">
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
<h3 id="source.toolkit.fluxcd.io/v1beta1.HelmRepositorySpec">HelmRepositorySpec
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.toolkit.fluxcd.io/v1beta1.HelmRepository">HelmRepository</a>)
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
<p>The Helm repository URL, a valid URL contains at least a protocol and host.</p>
</td>
</tr>
<tr>
<td>
<code>secretRef</code><br>
<em>
<a href="https://godoc.org/github.com/fluxcd/pkg/apis/meta#LocalObjectReference">
github.com/fluxcd/pkg/apis/meta.LocalObjectReference
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The name of the secret containing authentication credentials for the Helm
repository.
For HTTP/S basic auth the secret must contain username and
password fields.
For TLS the secret must contain a certFile and keyFile, and/or
caCert fields.</p>
</td>
</tr>
<tr>
<td>
<code>passCredentials</code><br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>PassCredentials allows the credentials from the SecretRef to be passed on to
a host that does not match the host as defined in URL.
This may be required if the host of the advertised chart URLs in the index
differ from the defined URL.
Enabling this should be done with caution, as it can potentially result in
credentials getting stolen in a MITM-attack.</p>
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
<p>The timeout of index downloading, defaults to 60s.</p>
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
<p>This flag tells the controller to suspend the reconciliation of this source.</p>
</td>
</tr>
<tr>
<td>
<code>accessFrom</code><br>
<em>
<a href="https://godoc.org/github.com/fluxcd/pkg/apis/acl#AccessFrom">
github.com/fluxcd/pkg/apis/acl.AccessFrom
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>AccessFrom defines an Access Control List for allowing cross-namespace references to this object.</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.toolkit.fluxcd.io/v1beta1.HelmRepositoryStatus">HelmRepositoryStatus
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.toolkit.fluxcd.io/v1beta1.HelmRepository">HelmRepository</a>)
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
<code>observedGeneration</code><br>
<em>
int64
</em>
</td>
<td>
<em>(Optional)</em>
<p>ObservedGeneration is the last observed generation.</p>
</td>
</tr>
<tr>
<td>
<code>conditions</code><br>
<em>
<a href="https://godoc.org/k8s.io/apimachinery/pkg/apis/meta/v1#Condition">
[]Kubernetes meta/v1.Condition
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Conditions holds the conditions for the HelmRepository.</p>
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
<a href="#source.toolkit.fluxcd.io/v1beta1.Artifact">
Artifact
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Artifact represents the output of the last successful repository sync.</p>
</td>
</tr>
<tr>
<td>
<code>ReconcileRequestStatus</code><br>
<em>
<a href="https://godoc.org/github.com/fluxcd/pkg/apis/meta#ReconcileRequestStatus">
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
<h3 id="source.toolkit.fluxcd.io/v1beta1.LocalHelmChartSourceReference">LocalHelmChartSourceReference
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.toolkit.fluxcd.io/v1beta1.HelmChartSpec">HelmChartSpec</a>)
</p>
<p>LocalHelmChartSourceReference contains enough information to let you locate
the typed referenced object at namespace level.</p>
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
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>APIVersion of the referent.</p>
</td>
</tr>
<tr>
<td>
<code>kind</code><br>
<em>
string
</em>
</td>
<td>
<p>Kind of the referent, valid values are (&lsquo;HelmRepository&rsquo;, &lsquo;GitRepository&rsquo;,
&lsquo;Bucket&rsquo;).</p>
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
<p>Name of the referent.</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.toolkit.fluxcd.io/v1beta1.Source">Source
</h3>
<p>Source interface must be supported by all API types.</p>
<div class="admonition note">
<p class="last">This page was automatically generated with <code>gen-crd-api-reference-docs</code></p>
</div>
