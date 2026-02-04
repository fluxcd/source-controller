<h1>Source API reference v1beta2</h1>
<p>Packages:</p>
<ul class="simple">
<li>
<a href="#source.werf.io%2fv1beta2">source.werf.io/v1beta2</a>
</li>
</ul>
<h2 id="source.werf.io/v1beta2">source.werf.io/v1beta2</h2>
<p>Package v1beta2 contains API Schema definitions for the source v1beta2 API group</p>
Resource Types:
<ul class="simple"><li>
<a href="#source.werf.io/v1beta2.Bucket">Bucket</a>
</li><li>
<a href="#source.werf.io/v1beta2.GitRepository">GitRepository</a>
</li><li>
<a href="#source.werf.io/v1beta2.HelmChart">HelmChart</a>
</li><li>
<a href="#source.werf.io/v1beta2.HelmRepository">HelmRepository</a>
</li><li>
<a href="#source.werf.io/v1beta2.OCIRepository">OCIRepository</a>
</li></ul>
<h3 id="source.werf.io/v1beta2.Bucket">Bucket
</h3>
<p>Bucket is the Schema for the buckets API.</p>
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
<code>source.werf.io/v1beta2</code>
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
<a href="#source.werf.io/v1beta2.BucketSpec">
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
<p>Provider of the object storage bucket.
Defaults to &lsquo;generic&rsquo;, which expects an S3 (API) compatible object
storage.</p>
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
<p>BucketName is the name of the object storage bucket.</p>
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
<p>Endpoint is the object storage address the BucketName is located at.</p>
</td>
</tr>
<tr>
<td>
<code>sts</code><br>
<em>
<a href="#source.werf.io/v1beta2.BucketSTSSpec">
BucketSTSSpec
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>STS specifies the required configuration to use a Security Token
Service for fetching temporary credentials to authenticate in a
Bucket provider.</p>
<p>This field is only supported for the <code>aws</code> and <code>generic</code> providers.</p>
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
<p>Insecure allows connecting to a non-TLS HTTP Endpoint.</p>
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
<p>Region of the Endpoint where the BucketName is located in.</p>
</td>
</tr>
<tr>
<td>
<code>prefix</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Prefix to use for server-side filtering of files in the Bucket.</p>
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
<p>SecretRef specifies the Secret containing authentication credentials
for the Bucket.</p>
</td>
</tr>
<tr>
<td>
<code>certSecretRef</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/pkg/apis/meta#LocalObjectReference">
github.com/fluxcd/pkg/apis/meta.LocalObjectReference
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>CertSecretRef can be given the name of a Secret containing
either or both of</p>
<ul>
<li>a PEM-encoded client certificate (<code>tls.crt</code>) and private
key (<code>tls.key</code>);</li>
<li>a PEM-encoded CA certificate (<code>ca.crt</code>)</li>
</ul>
<p>and whichever are supplied, will be used for connecting to the
bucket. The client cert and key are useful if you are
authenticating with a certificate; the CA cert is useful if
you are using a self-signed server certificate. The Secret must
be of type <code>Opaque</code> or <code>kubernetes.io/tls</code>.</p>
<p>This field is only supported for the <code>generic</code> provider.</p>
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
to use while communicating with the Bucket server.</p>
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
<p>Interval at which the Bucket Endpoint is checked for updates.
This interval is approximate and may be subject to jitter to ensure
efficient use of resources.</p>
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
<p>Timeout for fetch operations, defaults to 60s.</p>
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
Bucket.</p>
</td>
</tr>
<tr>
<td>
<code>accessFrom</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/pkg/apis/acl#AccessFrom">
github.com/fluxcd/pkg/apis/acl.AccessFrom
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>AccessFrom specifies an Access Control List for allowing cross-namespace
references to this object.
NOTE: Not implemented, provisional as of <a href="https://github.com/fluxcd/flux2/pull/2092">https://github.com/fluxcd/flux2/pull/2092</a></p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code><br>
<em>
<a href="#source.werf.io/v1beta2.BucketStatus">
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
<h3 id="source.werf.io/v1beta2.GitRepository">GitRepository
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
<code>source.werf.io/v1beta2</code>
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
<a href="#source.werf.io/v1beta2.GitRepositorySpec">
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
<a href="#source.werf.io/v1beta2.GitRepositoryRef">
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
<a href="#source.werf.io/v1beta2.GitRepositoryVerification">
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
<code>gitImplementation</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>GitImplementation specifies which Git client library implementation to
use. Defaults to &lsquo;go-git&rsquo;, valid values are (&lsquo;go-git&rsquo;, &lsquo;libgit2&rsquo;).
Deprecated: gitImplementation is deprecated now that &lsquo;go-git&rsquo; is the
only supported implementation.</p>
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
<a href="#source.werf.io/v1beta2.GitRepositoryInclude">
[]GitRepositoryInclude
</a>
</em>
</td>
<td>
<p>Include specifies a list of GitRepository resources which Artifacts
should be included in the Artifact produced for this GitRepository.</p>
</td>
</tr>
<tr>
<td>
<code>accessFrom</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/pkg/apis/acl#AccessFrom">
github.com/fluxcd/pkg/apis/acl.AccessFrom
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>AccessFrom specifies an Access Control List for allowing cross-namespace
references to this object.
NOTE: Not implemented, provisional as of <a href="https://github.com/fluxcd/flux2/pull/2092">https://github.com/fluxcd/flux2/pull/2092</a></p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code><br>
<em>
<a href="#source.werf.io/v1beta2.GitRepositoryStatus">
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
<h3 id="source.werf.io/v1beta2.HelmChart">HelmChart
</h3>
<p>HelmChart is the Schema for the helmcharts API.</p>
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
<code>source.werf.io/v1beta2</code>
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
<a href="#source.werf.io/v1beta2.HelmChartSpec">
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
<p>Chart is the name or path the Helm chart is available at in the
SourceRef.</p>
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
<p>Version is the chart version semver expression, ignored for charts from
GitRepository and Bucket sources. Defaults to latest when omitted.</p>
</td>
</tr>
<tr>
<td>
<code>sourceRef</code><br>
<em>
<a href="#source.werf.io/v1beta2.LocalHelmChartSourceReference">
LocalHelmChartSourceReference
</a>
</em>
</td>
<td>
<p>SourceRef is the reference to the Source the chart is available at.</p>
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
<p>Interval at which the HelmChart SourceRef is checked for updates.
This interval is approximate and may be subject to jitter to ensure
efficient use of resources.</p>
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
<p>ReconcileStrategy determines what enables the creation of a new artifact.
Valid values are (&lsquo;ChartVersion&rsquo;, &lsquo;Revision&rsquo;).
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
<p>ValuesFiles is an alternative list of values files to use as the chart
values (values.yaml is not included by default), expected to be a
relative path in the SourceRef.
Values files are merged in the order of this list with the last file
overriding the first. Ignored when omitted.</p>
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
<p>ValuesFile is an alternative values file to use as the default chart
values, expected to be a relative path in the SourceRef. Deprecated in
favor of ValuesFiles, for backwards compatibility the file specified here
is merged before the ValuesFiles items. Ignored when omitted.</p>
</td>
</tr>
<tr>
<td>
<code>ignoreMissingValuesFiles</code><br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>IgnoreMissingValuesFiles controls whether to silently ignore missing values
files rather than failing.</p>
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
source.</p>
</td>
</tr>
<tr>
<td>
<code>accessFrom</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/pkg/apis/acl#AccessFrom">
github.com/fluxcd/pkg/apis/acl.AccessFrom
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>AccessFrom specifies an Access Control List for allowing cross-namespace
references to this object.
NOTE: Not implemented, provisional as of <a href="https://github.com/fluxcd/flux2/pull/2092">https://github.com/fluxcd/flux2/pull/2092</a></p>
</td>
</tr>
<tr>
<td>
<code>verify</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/source-controller/api/v1#OCIRepositoryVerification">
github.com/fluxcd/source-controller/api/v1.OCIRepositoryVerification
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Verify contains the secret name containing the trusted public keys
used to verify the signature and specifies which provider to use to check
whether OCI image is authentic.
This field is only supported when using HelmRepository source with spec.type &lsquo;oci&rsquo;.
Chart dependencies, which are not bundled in the umbrella chart artifact, are not verified.</p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code><br>
<em>
<a href="#source.werf.io/v1beta2.HelmChartStatus">
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
<h3 id="source.werf.io/v1beta2.HelmRepository">HelmRepository
</h3>
<p>HelmRepository is the Schema for the helmrepositories API.</p>
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
<code>source.werf.io/v1beta2</code>
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
<a href="#source.werf.io/v1beta2.HelmRepositorySpec">
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
<p>URL of the Helm repository, a valid URL contains at least a protocol and
host.</p>
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
<p>SecretRef specifies the Secret containing authentication credentials
for the HelmRepository.
For HTTP/S basic auth the secret must contain &lsquo;username&rsquo; and &lsquo;password&rsquo;
fields.
Support for TLS auth using the &lsquo;certFile&rsquo; and &lsquo;keyFile&rsquo;, and/or &lsquo;caFile&rsquo;
keys is deprecated. Please use <code>.spec.certSecretRef</code> instead.</p>
</td>
</tr>
<tr>
<td>
<code>certSecretRef</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/pkg/apis/meta#LocalObjectReference">
github.com/fluxcd/pkg/apis/meta.LocalObjectReference
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>CertSecretRef can be given the name of a Secret containing
either or both of</p>
<ul>
<li>a PEM-encoded client certificate (<code>tls.crt</code>) and private
key (<code>tls.key</code>);</li>
<li>a PEM-encoded CA certificate (<code>ca.crt</code>)</li>
</ul>
<p>and whichever are supplied, will be used for connecting to the
registry. The client cert and key are useful if you are
authenticating with a certificate; the CA cert is useful if
you are using a self-signed server certificate. The Secret must
be of type <code>Opaque</code> or <code>kubernetes.io/tls</code>.</p>
<p>It takes precedence over the values specified in the Secret referred
to by <code>.spec.secretRef</code>.</p>
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
<p>PassCredentials allows the credentials from the SecretRef to be passed
on to a host that does not match the host as defined in URL.
This may be required if the host of the advertised chart URLs in the
index differ from the defined URL.
Enabling this should be done with caution, as it can potentially result
in credentials getting stolen in a MITM-attack.</p>
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
<em>(Optional)</em>
<p>Interval at which the HelmRepository URL is checked for updates.
This interval is approximate and may be subject to jitter to ensure
efficient use of resources.</p>
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
<p>Insecure allows connecting to a non-TLS HTTP container registry.
This field is only taken into account if the .spec.type field is set to &lsquo;oci&rsquo;.</p>
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
<p>Timeout is used for the index fetch operation for an HTTPS helm repository,
and for remote OCI Repository operations like pulling for an OCI helm
chart by the associated HelmChart.
Its default value is 60s.</p>
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
HelmRepository.</p>
</td>
</tr>
<tr>
<td>
<code>accessFrom</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/pkg/apis/acl#AccessFrom">
github.com/fluxcd/pkg/apis/acl.AccessFrom
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>AccessFrom specifies an Access Control List for allowing cross-namespace
references to this object.
NOTE: Not implemented, provisional as of <a href="https://github.com/fluxcd/flux2/pull/2092">https://github.com/fluxcd/flux2/pull/2092</a></p>
</td>
</tr>
<tr>
<td>
<code>type</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Type of the HelmRepository.
When this field is set to  &ldquo;oci&rdquo;, the URL field value must be prefixed with &ldquo;oci://&rdquo;.</p>
</td>
</tr>
<tr>
<td>
<code>provider</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Provider used for authentication, can be &lsquo;aws&rsquo;, &lsquo;azure&rsquo;, &lsquo;gcp&rsquo; or &lsquo;generic&rsquo;.
This field is optional, and only taken into account if the .spec.type field is set to &lsquo;oci&rsquo;.
When not specified, defaults to &lsquo;generic&rsquo;.</p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code><br>
<em>
<a href="#source.werf.io/v1beta2.HelmRepositoryStatus">
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
<h3 id="source.werf.io/v1beta2.OCIRepository">OCIRepository
</h3>
<p>OCIRepository is the Schema for the ocirepositories API</p>
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
<code>source.werf.io/v1beta2</code>
</td>
</tr>
<tr>
<td>
<code>kind</code><br>
string
</td>
<td>
<code>OCIRepository</code>
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
<a href="#source.werf.io/v1beta2.OCIRepositorySpec">
OCIRepositorySpec
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
<p>URL is a reference to an OCI artifact repository hosted
on a remote container registry.</p>
</td>
</tr>
<tr>
<td>
<code>ref</code><br>
<em>
<a href="#source.werf.io/v1beta2.OCIRepositoryRef">
OCIRepositoryRef
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The OCI reference to pull and monitor for changes,
defaults to the latest tag.</p>
</td>
</tr>
<tr>
<td>
<code>layerSelector</code><br>
<em>
<a href="#source.werf.io/v1beta2.OCILayerSelector">
OCILayerSelector
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>LayerSelector specifies which layer should be extracted from the OCI artifact.
When not specified, the first layer found in the artifact is selected.</p>
</td>
</tr>
<tr>
<td>
<code>provider</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The provider used for authentication, can be &lsquo;aws&rsquo;, &lsquo;azure&rsquo;, &lsquo;gcp&rsquo; or &lsquo;generic&rsquo;.
When not specified, defaults to &lsquo;generic&rsquo;.</p>
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
<p>SecretRef contains the secret name containing the registry login
credentials to resolve image metadata.
The secret must be of type kubernetes.io/dockerconfigjson.</p>
</td>
</tr>
<tr>
<td>
<code>verify</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/source-controller/api/v1#OCIRepositoryVerification">
github.com/fluxcd/source-controller/api/v1.OCIRepositoryVerification
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Verify contains the secret name containing the trusted public keys
used to verify the signature and specifies which provider to use to check
whether OCI image is authentic.</p>
</td>
</tr>
<tr>
<td>
<code>serviceAccountName</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>ServiceAccountName is the name of the Kubernetes ServiceAccount used to authenticate
the image pull if the service account has attached pull secrets. For more information:
<a href="https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#add-imagepullsecrets-to-a-service-account">https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#add-imagepullsecrets-to-a-service-account</a></p>
</td>
</tr>
<tr>
<td>
<code>certSecretRef</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/pkg/apis/meta#LocalObjectReference">
github.com/fluxcd/pkg/apis/meta.LocalObjectReference
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>CertSecretRef can be given the name of a Secret containing
either or both of</p>
<ul>
<li>a PEM-encoded client certificate (<code>tls.crt</code>) and private
key (<code>tls.key</code>);</li>
<li>a PEM-encoded CA certificate (<code>ca.crt</code>)</li>
</ul>
<p>and whichever are supplied, will be used for connecting to the
registry. The client cert and key are useful if you are
authenticating with a certificate; the CA cert is useful if
you are using a self-signed server certificate. The Secret must
be of type <code>Opaque</code> or <code>kubernetes.io/tls</code>.</p>
<p>Note: Support for the <code>caFile</code>, <code>certFile</code> and <code>keyFile</code> keys have
been deprecated.</p>
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
to use while communicating with the container registry.</p>
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
<p>Interval at which the OCIRepository URL is checked for updates.
This interval is approximate and may be subject to jitter to ensure
efficient use of resources.</p>
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
<p>The timeout for remote OCI Repository operations like pulling, defaults to 60s.</p>
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
<code>insecure</code><br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>Insecure allows connecting to a non-TLS HTTP container registry.</p>
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
</table>
</td>
</tr>
<tr>
<td>
<code>status</code><br>
<em>
<a href="#source.werf.io/v1beta2.OCIRepositoryStatus">
OCIRepositoryStatus
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
<h3 id="source.werf.io/v1beta2.Artifact">Artifact
</h3>
<p>Artifact represents the output of a Source reconciliation.</p>
<p>Deprecated: use Artifact from api/v1 instead. This type will be removed in
a future release.</p>
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
<em>(Optional)</em>
<p>Revision is a human-readable identifier traceable in the origin source
system. It can be a Git commit SHA, Git tag, a Helm chart version, etc.</p>
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
<p>Checksum is the SHA256 checksum of the Artifact file.
Deprecated: use Artifact.Digest instead.</p>
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
<h3 id="source.werf.io/v1beta2.BucketSTSSpec">BucketSTSSpec
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.werf.io/v1beta2.BucketSpec">BucketSpec</a>)
</p>
<p>BucketSTSSpec specifies the required configuration to use a Security Token
Service for fetching temporary credentials to authenticate in a Bucket
provider.</p>
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
<p>Provider of the Security Token Service.</p>
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
<p>Endpoint is the HTTP/S endpoint of the Security Token Service from
where temporary credentials will be fetched.</p>
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
<p>SecretRef specifies the Secret containing authentication credentials
for the STS endpoint. This Secret must contain the fields <code>username</code>
and <code>password</code> and is supported only for the <code>ldap</code> provider.</p>
</td>
</tr>
<tr>
<td>
<code>certSecretRef</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/pkg/apis/meta#LocalObjectReference">
github.com/fluxcd/pkg/apis/meta.LocalObjectReference
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>CertSecretRef can be given the name of a Secret containing
either or both of</p>
<ul>
<li>a PEM-encoded client certificate (<code>tls.crt</code>) and private
key (<code>tls.key</code>);</li>
<li>a PEM-encoded CA certificate (<code>ca.crt</code>)</li>
</ul>
<p>and whichever are supplied, will be used for connecting to the
STS endpoint. The client cert and key are useful if you are
authenticating with a certificate; the CA cert is useful if
you are using a self-signed server certificate. The Secret must
be of type <code>Opaque</code> or <code>kubernetes.io/tls</code>.</p>
<p>This field is only supported for the <code>ldap</code> provider.</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.werf.io/v1beta2.BucketSpec">BucketSpec
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.werf.io/v1beta2.Bucket">Bucket</a>)
</p>
<p>BucketSpec specifies the required configuration to produce an Artifact for
an object storage bucket.</p>
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
<p>Provider of the object storage bucket.
Defaults to &lsquo;generic&rsquo;, which expects an S3 (API) compatible object
storage.</p>
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
<p>BucketName is the name of the object storage bucket.</p>
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
<p>Endpoint is the object storage address the BucketName is located at.</p>
</td>
</tr>
<tr>
<td>
<code>sts</code><br>
<em>
<a href="#source.werf.io/v1beta2.BucketSTSSpec">
BucketSTSSpec
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>STS specifies the required configuration to use a Security Token
Service for fetching temporary credentials to authenticate in a
Bucket provider.</p>
<p>This field is only supported for the <code>aws</code> and <code>generic</code> providers.</p>
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
<p>Insecure allows connecting to a non-TLS HTTP Endpoint.</p>
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
<p>Region of the Endpoint where the BucketName is located in.</p>
</td>
</tr>
<tr>
<td>
<code>prefix</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Prefix to use for server-side filtering of files in the Bucket.</p>
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
<p>SecretRef specifies the Secret containing authentication credentials
for the Bucket.</p>
</td>
</tr>
<tr>
<td>
<code>certSecretRef</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/pkg/apis/meta#LocalObjectReference">
github.com/fluxcd/pkg/apis/meta.LocalObjectReference
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>CertSecretRef can be given the name of a Secret containing
either or both of</p>
<ul>
<li>a PEM-encoded client certificate (<code>tls.crt</code>) and private
key (<code>tls.key</code>);</li>
<li>a PEM-encoded CA certificate (<code>ca.crt</code>)</li>
</ul>
<p>and whichever are supplied, will be used for connecting to the
bucket. The client cert and key are useful if you are
authenticating with a certificate; the CA cert is useful if
you are using a self-signed server certificate. The Secret must
be of type <code>Opaque</code> or <code>kubernetes.io/tls</code>.</p>
<p>This field is only supported for the <code>generic</code> provider.</p>
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
to use while communicating with the Bucket server.</p>
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
<p>Interval at which the Bucket Endpoint is checked for updates.
This interval is approximate and may be subject to jitter to ensure
efficient use of resources.</p>
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
<p>Timeout for fetch operations, defaults to 60s.</p>
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
Bucket.</p>
</td>
</tr>
<tr>
<td>
<code>accessFrom</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/pkg/apis/acl#AccessFrom">
github.com/fluxcd/pkg/apis/acl.AccessFrom
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>AccessFrom specifies an Access Control List for allowing cross-namespace
references to this object.
NOTE: Not implemented, provisional as of <a href="https://github.com/fluxcd/flux2/pull/2092">https://github.com/fluxcd/flux2/pull/2092</a></p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.werf.io/v1beta2.BucketStatus">BucketStatus
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.werf.io/v1beta2.Bucket">Bucket</a>)
</p>
<p>BucketStatus records the observed state of a Bucket.</p>
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
<p>ObservedGeneration is the last observed generation of the Bucket object.</p>
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
<p>URL is the dynamic fetch link for the latest Artifact.
It is provided on a &ldquo;best effort&rdquo; basis, and using the precise
BucketStatus.Artifact data is recommended.</p>
</td>
</tr>
<tr>
<td>
<code>artifact</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/source-controller/api/v1#Artifact">
github.com/fluxcd/source-controller/api/v1.Artifact
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Artifact represents the last successful Bucket reconciliation.</p>
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
<h3 id="source.werf.io/v1beta2.GitRepositoryInclude">GitRepositoryInclude
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.werf.io/v1beta2.GitRepositorySpec">GitRepositorySpec</a>, 
<a href="#source.werf.io/v1beta2.GitRepositoryStatus">GitRepositoryStatus</a>)
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
<h3 id="source.werf.io/v1beta2.GitRepositoryRef">GitRepositoryRef
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.werf.io/v1beta2.GitRepositorySpec">GitRepositorySpec</a>)
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
<h3 id="source.werf.io/v1beta2.GitRepositorySpec">GitRepositorySpec
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.werf.io/v1beta2.GitRepository">GitRepository</a>)
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
<a href="#source.werf.io/v1beta2.GitRepositoryRef">
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
<a href="#source.werf.io/v1beta2.GitRepositoryVerification">
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
<code>gitImplementation</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>GitImplementation specifies which Git client library implementation to
use. Defaults to &lsquo;go-git&rsquo;, valid values are (&lsquo;go-git&rsquo;, &lsquo;libgit2&rsquo;).
Deprecated: gitImplementation is deprecated now that &lsquo;go-git&rsquo; is the
only supported implementation.</p>
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
<a href="#source.werf.io/v1beta2.GitRepositoryInclude">
[]GitRepositoryInclude
</a>
</em>
</td>
<td>
<p>Include specifies a list of GitRepository resources which Artifacts
should be included in the Artifact produced for this GitRepository.</p>
</td>
</tr>
<tr>
<td>
<code>accessFrom</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/pkg/apis/acl#AccessFrom">
github.com/fluxcd/pkg/apis/acl.AccessFrom
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>AccessFrom specifies an Access Control List for allowing cross-namespace
references to this object.
NOTE: Not implemented, provisional as of <a href="https://github.com/fluxcd/flux2/pull/2092">https://github.com/fluxcd/flux2/pull/2092</a></p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.werf.io/v1beta2.GitRepositoryStatus">GitRepositoryStatus
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.werf.io/v1beta2.GitRepository">GitRepository</a>)
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
<code>url</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>URL is the dynamic fetch link for the latest Artifact.
It is provided on a &ldquo;best effort&rdquo; basis, and using the precise
GitRepositoryStatus.Artifact data is recommended.</p>
</td>
</tr>
<tr>
<td>
<code>artifact</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/source-controller/api/v1#Artifact">
github.com/fluxcd/source-controller/api/v1.Artifact
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
<a href="https://pkg.go.dev/github.com/fluxcd/source-controller/api/v1#Artifact">
[]github.com/fluxcd/source-controller/api/v1.Artifact
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
<code>contentConfigChecksum</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>ContentConfigChecksum is a checksum of all the configurations related to
the content of the source artifact:
- .spec.ignore
- .spec.recurseSubmodules
- .spec.included and the checksum of the included artifacts
observed in .status.observedGeneration version of the object. This can
be used to determine if the content of the included repository has
changed.
It has the format of <code>&lt;algo&gt;:&lt;checksum&gt;</code>, for example: <code>sha256:&lt;checksum&gt;</code>.</p>
<p>Deprecated: Replaced with explicit fields for observed artifact content
config in the status.</p>
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
<a href="#source.werf.io/v1beta2.GitRepositoryInclude">
[]GitRepositoryInclude
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>ObservedInclude is the observed list of GitRepository resources used to
to produce the current Artifact.</p>
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
<h3 id="source.werf.io/v1beta2.GitRepositoryVerification">GitRepositoryVerification
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.werf.io/v1beta2.GitRepositorySpec">GitRepositorySpec</a>)
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
<h3 id="source.werf.io/v1beta2.HelmChartSpec">HelmChartSpec
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.werf.io/v1beta2.HelmChart">HelmChart</a>)
</p>
<p>HelmChartSpec specifies the desired state of a Helm chart.</p>
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
<p>Chart is the name or path the Helm chart is available at in the
SourceRef.</p>
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
<p>Version is the chart version semver expression, ignored for charts from
GitRepository and Bucket sources. Defaults to latest when omitted.</p>
</td>
</tr>
<tr>
<td>
<code>sourceRef</code><br>
<em>
<a href="#source.werf.io/v1beta2.LocalHelmChartSourceReference">
LocalHelmChartSourceReference
</a>
</em>
</td>
<td>
<p>SourceRef is the reference to the Source the chart is available at.</p>
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
<p>Interval at which the HelmChart SourceRef is checked for updates.
This interval is approximate and may be subject to jitter to ensure
efficient use of resources.</p>
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
<p>ReconcileStrategy determines what enables the creation of a new artifact.
Valid values are (&lsquo;ChartVersion&rsquo;, &lsquo;Revision&rsquo;).
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
<p>ValuesFiles is an alternative list of values files to use as the chart
values (values.yaml is not included by default), expected to be a
relative path in the SourceRef.
Values files are merged in the order of this list with the last file
overriding the first. Ignored when omitted.</p>
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
<p>ValuesFile is an alternative values file to use as the default chart
values, expected to be a relative path in the SourceRef. Deprecated in
favor of ValuesFiles, for backwards compatibility the file specified here
is merged before the ValuesFiles items. Ignored when omitted.</p>
</td>
</tr>
<tr>
<td>
<code>ignoreMissingValuesFiles</code><br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>IgnoreMissingValuesFiles controls whether to silently ignore missing values
files rather than failing.</p>
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
source.</p>
</td>
</tr>
<tr>
<td>
<code>accessFrom</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/pkg/apis/acl#AccessFrom">
github.com/fluxcd/pkg/apis/acl.AccessFrom
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>AccessFrom specifies an Access Control List for allowing cross-namespace
references to this object.
NOTE: Not implemented, provisional as of <a href="https://github.com/fluxcd/flux2/pull/2092">https://github.com/fluxcd/flux2/pull/2092</a></p>
</td>
</tr>
<tr>
<td>
<code>verify</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/source-controller/api/v1#OCIRepositoryVerification">
github.com/fluxcd/source-controller/api/v1.OCIRepositoryVerification
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Verify contains the secret name containing the trusted public keys
used to verify the signature and specifies which provider to use to check
whether OCI image is authentic.
This field is only supported when using HelmRepository source with spec.type &lsquo;oci&rsquo;.
Chart dependencies, which are not bundled in the umbrella chart artifact, are not verified.</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.werf.io/v1beta2.HelmChartStatus">HelmChartStatus
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.werf.io/v1beta2.HelmChart">HelmChart</a>)
</p>
<p>HelmChartStatus records the observed state of the HelmChart.</p>
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
<p>ObservedGeneration is the last observed generation of the HelmChart
object.</p>
</td>
</tr>
<tr>
<td>
<code>observedSourceArtifactRevision</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>ObservedSourceArtifactRevision is the last observed Artifact.Revision
of the HelmChartSpec.SourceRef.</p>
</td>
</tr>
<tr>
<td>
<code>observedChartName</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>ObservedChartName is the last observed chart name as specified by the
resolved chart reference.</p>
</td>
</tr>
<tr>
<td>
<code>observedValuesFiles</code><br>
<em>
[]string
</em>
</td>
<td>
<em>(Optional)</em>
<p>ObservedValuesFiles are the observed value files of the last successful
reconciliation.
It matches the chart in the last successfully reconciled artifact.</p>
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
<p>URL is the dynamic fetch link for the latest Artifact.
It is provided on a &ldquo;best effort&rdquo; basis, and using the precise
BucketStatus.Artifact data is recommended.</p>
</td>
</tr>
<tr>
<td>
<code>artifact</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/source-controller/api/v1#Artifact">
github.com/fluxcd/source-controller/api/v1.Artifact
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Artifact represents the output of the last successful reconciliation.</p>
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
<h3 id="source.werf.io/v1beta2.HelmRepositorySpec">HelmRepositorySpec
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.werf.io/v1beta2.HelmRepository">HelmRepository</a>)
</p>
<p>HelmRepositorySpec specifies the required configuration to produce an
Artifact for a Helm repository index YAML.</p>
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
<p>URL of the Helm repository, a valid URL contains at least a protocol and
host.</p>
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
<p>SecretRef specifies the Secret containing authentication credentials
for the HelmRepository.
For HTTP/S basic auth the secret must contain &lsquo;username&rsquo; and &lsquo;password&rsquo;
fields.
Support for TLS auth using the &lsquo;certFile&rsquo; and &lsquo;keyFile&rsquo;, and/or &lsquo;caFile&rsquo;
keys is deprecated. Please use <code>.spec.certSecretRef</code> instead.</p>
</td>
</tr>
<tr>
<td>
<code>certSecretRef</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/pkg/apis/meta#LocalObjectReference">
github.com/fluxcd/pkg/apis/meta.LocalObjectReference
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>CertSecretRef can be given the name of a Secret containing
either or both of</p>
<ul>
<li>a PEM-encoded client certificate (<code>tls.crt</code>) and private
key (<code>tls.key</code>);</li>
<li>a PEM-encoded CA certificate (<code>ca.crt</code>)</li>
</ul>
<p>and whichever are supplied, will be used for connecting to the
registry. The client cert and key are useful if you are
authenticating with a certificate; the CA cert is useful if
you are using a self-signed server certificate. The Secret must
be of type <code>Opaque</code> or <code>kubernetes.io/tls</code>.</p>
<p>It takes precedence over the values specified in the Secret referred
to by <code>.spec.secretRef</code>.</p>
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
<p>PassCredentials allows the credentials from the SecretRef to be passed
on to a host that does not match the host as defined in URL.
This may be required if the host of the advertised chart URLs in the
index differ from the defined URL.
Enabling this should be done with caution, as it can potentially result
in credentials getting stolen in a MITM-attack.</p>
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
<em>(Optional)</em>
<p>Interval at which the HelmRepository URL is checked for updates.
This interval is approximate and may be subject to jitter to ensure
efficient use of resources.</p>
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
<p>Insecure allows connecting to a non-TLS HTTP container registry.
This field is only taken into account if the .spec.type field is set to &lsquo;oci&rsquo;.</p>
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
<p>Timeout is used for the index fetch operation for an HTTPS helm repository,
and for remote OCI Repository operations like pulling for an OCI helm
chart by the associated HelmChart.
Its default value is 60s.</p>
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
HelmRepository.</p>
</td>
</tr>
<tr>
<td>
<code>accessFrom</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/pkg/apis/acl#AccessFrom">
github.com/fluxcd/pkg/apis/acl.AccessFrom
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>AccessFrom specifies an Access Control List for allowing cross-namespace
references to this object.
NOTE: Not implemented, provisional as of <a href="https://github.com/fluxcd/flux2/pull/2092">https://github.com/fluxcd/flux2/pull/2092</a></p>
</td>
</tr>
<tr>
<td>
<code>type</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Type of the HelmRepository.
When this field is set to  &ldquo;oci&rdquo;, the URL field value must be prefixed with &ldquo;oci://&rdquo;.</p>
</td>
</tr>
<tr>
<td>
<code>provider</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Provider used for authentication, can be &lsquo;aws&rsquo;, &lsquo;azure&rsquo;, &lsquo;gcp&rsquo; or &lsquo;generic&rsquo;.
This field is optional, and only taken into account if the .spec.type field is set to &lsquo;oci&rsquo;.
When not specified, defaults to &lsquo;generic&rsquo;.</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.werf.io/v1beta2.HelmRepositoryStatus">HelmRepositoryStatus
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.werf.io/v1beta2.HelmRepository">HelmRepository</a>)
</p>
<p>HelmRepositoryStatus records the observed state of the HelmRepository.</p>
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
<p>ObservedGeneration is the last observed generation of the HelmRepository
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
<p>URL is the dynamic fetch link for the latest Artifact.
It is provided on a &ldquo;best effort&rdquo; basis, and using the precise
HelmRepositoryStatus.Artifact data is recommended.</p>
</td>
</tr>
<tr>
<td>
<code>artifact</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/source-controller/api/v1#Artifact">
github.com/fluxcd/source-controller/api/v1.Artifact
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Artifact represents the last successful HelmRepository reconciliation.</p>
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
<h3 id="source.werf.io/v1beta2.LocalHelmChartSourceReference">LocalHelmChartSourceReference
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.werf.io/v1beta2.HelmChartSpec">HelmChartSpec</a>)
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
<h3 id="source.werf.io/v1beta2.OCILayerSelector">OCILayerSelector
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.werf.io/v1beta2.OCIRepositorySpec">OCIRepositorySpec</a>, 
<a href="#source.werf.io/v1beta2.OCIRepositoryStatus">OCIRepositoryStatus</a>)
</p>
<p>OCILayerSelector specifies which layer should be extracted from an OCI Artifact</p>
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
<code>mediaType</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>MediaType specifies the OCI media type of the layer
which should be extracted from the OCI Artifact. The
first layer matching this type is selected.</p>
</td>
</tr>
<tr>
<td>
<code>operation</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Operation specifies how the selected layer should be processed.
By default, the layer compressed content is extracted to storage.
When the operation is set to &lsquo;copy&rsquo;, the layer compressed content
is persisted to storage as it is.</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.werf.io/v1beta2.OCIRepositoryRef">OCIRepositoryRef
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.werf.io/v1beta2.OCIRepositorySpec">OCIRepositorySpec</a>)
</p>
<p>OCIRepositoryRef defines the image reference for the OCIRepository&rsquo;s URL</p>
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
<code>digest</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Digest is the image digest to pull, takes precedence over SemVer.
The value should be in the format &lsquo;sha256:<HASH>&rsquo;.</p>
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
<p>SemVer is the range of tags to pull selecting the latest within
the range, takes precedence over Tag.</p>
</td>
</tr>
<tr>
<td>
<code>semverFilter</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>SemverFilter is a regex pattern to filter the tags within the SemVer range.</p>
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
<p>Tag is the image tag to pull, defaults to latest.</p>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<h3 id="source.werf.io/v1beta2.OCIRepositorySpec">OCIRepositorySpec
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.werf.io/v1beta2.OCIRepository">OCIRepository</a>)
</p>
<p>OCIRepositorySpec defines the desired state of OCIRepository</p>
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
<p>URL is a reference to an OCI artifact repository hosted
on a remote container registry.</p>
</td>
</tr>
<tr>
<td>
<code>ref</code><br>
<em>
<a href="#source.werf.io/v1beta2.OCIRepositoryRef">
OCIRepositoryRef
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The OCI reference to pull and monitor for changes,
defaults to the latest tag.</p>
</td>
</tr>
<tr>
<td>
<code>layerSelector</code><br>
<em>
<a href="#source.werf.io/v1beta2.OCILayerSelector">
OCILayerSelector
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>LayerSelector specifies which layer should be extracted from the OCI artifact.
When not specified, the first layer found in the artifact is selected.</p>
</td>
</tr>
<tr>
<td>
<code>provider</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>The provider used for authentication, can be &lsquo;aws&rsquo;, &lsquo;azure&rsquo;, &lsquo;gcp&rsquo; or &lsquo;generic&rsquo;.
When not specified, defaults to &lsquo;generic&rsquo;.</p>
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
<p>SecretRef contains the secret name containing the registry login
credentials to resolve image metadata.
The secret must be of type kubernetes.io/dockerconfigjson.</p>
</td>
</tr>
<tr>
<td>
<code>verify</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/source-controller/api/v1#OCIRepositoryVerification">
github.com/fluxcd/source-controller/api/v1.OCIRepositoryVerification
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Verify contains the secret name containing the trusted public keys
used to verify the signature and specifies which provider to use to check
whether OCI image is authentic.</p>
</td>
</tr>
<tr>
<td>
<code>serviceAccountName</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>ServiceAccountName is the name of the Kubernetes ServiceAccount used to authenticate
the image pull if the service account has attached pull secrets. For more information:
<a href="https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#add-imagepullsecrets-to-a-service-account">https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#add-imagepullsecrets-to-a-service-account</a></p>
</td>
</tr>
<tr>
<td>
<code>certSecretRef</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/pkg/apis/meta#LocalObjectReference">
github.com/fluxcd/pkg/apis/meta.LocalObjectReference
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>CertSecretRef can be given the name of a Secret containing
either or both of</p>
<ul>
<li>a PEM-encoded client certificate (<code>tls.crt</code>) and private
key (<code>tls.key</code>);</li>
<li>a PEM-encoded CA certificate (<code>ca.crt</code>)</li>
</ul>
<p>and whichever are supplied, will be used for connecting to the
registry. The client cert and key are useful if you are
authenticating with a certificate; the CA cert is useful if
you are using a self-signed server certificate. The Secret must
be of type <code>Opaque</code> or <code>kubernetes.io/tls</code>.</p>
<p>Note: Support for the <code>caFile</code>, <code>certFile</code> and <code>keyFile</code> keys have
been deprecated.</p>
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
to use while communicating with the container registry.</p>
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
<p>Interval at which the OCIRepository URL is checked for updates.
This interval is approximate and may be subject to jitter to ensure
efficient use of resources.</p>
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
<p>The timeout for remote OCI Repository operations like pulling, defaults to 60s.</p>
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
<code>insecure</code><br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>Insecure allows connecting to a non-TLS HTTP container registry.</p>
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
</tbody>
</table>
</div>
</div>
<h3 id="source.werf.io/v1beta2.OCIRepositoryStatus">OCIRepositoryStatus
</h3>
<p>
(<em>Appears on:</em>
<a href="#source.werf.io/v1beta2.OCIRepository">OCIRepository</a>)
</p>
<p>OCIRepositoryStatus defines the observed state of OCIRepository</p>
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
<a href="https://pkg.go.dev/k8s.io/apimachinery/pkg/apis/meta/v1#Condition">
[]Kubernetes meta/v1.Condition
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Conditions holds the conditions for the OCIRepository.</p>
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
<p>URL is the download link for the artifact output of the last OCI Repository sync.</p>
</td>
</tr>
<tr>
<td>
<code>artifact</code><br>
<em>
<a href="https://pkg.go.dev/github.com/fluxcd/source-controller/api/v1#Artifact">
github.com/fluxcd/source-controller/api/v1.Artifact
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Artifact represents the output of the last successful OCI Repository sync.</p>
</td>
</tr>
<tr>
<td>
<code>contentConfigChecksum</code><br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>ContentConfigChecksum is a checksum of all the configurations related to
the content of the source artifact:
- .spec.ignore
- .spec.layerSelector
observed in .status.observedGeneration version of the object. This can
be used to determine if the content configuration has changed and the
artifact needs to be rebuilt.
It has the format of <code>&lt;algo&gt;:&lt;checksum&gt;</code>, for example: <code>sha256:&lt;checksum&gt;</code>.</p>
<p>Deprecated: Replaced with explicit fields for observed artifact content
config in the status.</p>
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
<code>observedLayerSelector</code><br>
<em>
<a href="#source.werf.io/v1beta2.OCILayerSelector">
OCILayerSelector
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>ObservedLayerSelector is the observed layer selector used for constructing
the source artifact.</p>
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
<h3 id="source.werf.io/v1beta2.Source">Source
</h3>
<p>Source interface must be supported by all API types.
Source is the interface that provides generic access to the Artifact and
interval. It must be supported by all kinds of the source.werf.io
API group.</p>
<p>Deprecated: use the Source interface from api/v1 instead. This type will be
removed in a future release.</p>
<div class="admonition note">
<p class="last">This page was automatically generated with <code>gen-crd-api-reference-docs</code></p>
</div>
