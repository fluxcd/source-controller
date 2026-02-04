# Changelog

All notable changes to this project are documented in this file.

## 1.7.4

**Release date:** 2025-11-19

This patch release fixes Azure Workload Identity in Azure China Cloud.

Improvements:
- Upgrade k8s to 1.34.2, c-r to 0.22.4 and helm to 3.19.2
  [#1938](https://github.com/fluxcd/source-controller/pull/1938)
- Upgrade Helm to 3.19.1
  [#1934](https://github.com/fluxcd/source-controller/pull/1934)

## 1.7.3

**Release date:** 2025-10-28

This patch release fixes support for SOCKS5 proxy in the controller APIs.

Fixes:
- Restore SOCKS5 proxy support
  [#1916](https://github.com/fluxcd/source-controller/pull/1916)

## 1.7.2

**Release date:** 2025-10-08

This patch release comes with various dependency updates.

The controller is now built with Go 1.25.2 which includes
fixes for vulnerabilities in the Go stdlib:
[CVE-2025-58183](https://github.com/golang/go/issues/75677),
[CVE-2025-58188](https://github.com/golang/go/issues/75675)
and many others. The full list of security fixes can be found
[here](https://groups.google.com/g/golang-announce/c/4Emdl2iQ_bI/m/qZN5nc-mBgAJ).

Improvements:
- Update dependencies to Kubernetes v1.34.1 and Go 1.25.2
  [#1908](https://github.com/fluxcd/source-controller/pull/1908)

## 1.7.1

**Release date:** 2025-10-06

This patch release comes with a fix for TLS certs handling in the
HelmChart reconciler when auth credentials are not specified.

Fixes:
- Fix HelmChart reconciler appending login options when they do not exist
  [#1904](https://github.com/fluxcd/source-controller/pull/1904)

Improvements:
- ci: Fix release workflow
  [#1897](https://github.com/fluxcd/source-controller/pull/1897)
- Point to OCIRepository in HelmRepository docs
  [#1893](https://github.com/fluxcd/source-controller/pull/1893)

## 1.7.0

**Release date:** 2025-09-15

This minor release comes with new features, improvements and bug fixes.

### ExternalArtifact

A new [ExternalArtifact](https://github.com/fluxcd/source-controller/blob/main/docs/spec/v1/externalartifacts.md) API has been added to the `source.werf.io` group. This API enables advanced source composition and decomposition patterns implemented by the [source-watcher](https://github.com/fluxcd/source-watcher) controller.

### GitRepository

GitRepository controller now includes fixes for stalling issues and improved error handling. Multi-tenant workload identity support has been added for Azure repositories when the `ObjectLevelWorkloadIdentity` feature gate is enabled. TLS configuration support has been added for GitHub App authentication.

### Bucket

Bucket controller now supports multi-tenant workload identity for AWS, Azure and GCP providers when the `ObjectLevelWorkloadIdentity` feature gate is enabled. A default service account flag has been added for lockdown scenarios.

### General updates

The controller now supports system certificate pools for improved CA compatibility, and TLS ServerName pinning has been removed from TLS configuration for better flexibility. A `--default-service-account=<sa name>` flag was introduced for workload identity multi-tenancy lockdown.

In addition, the Kubernetes dependencies have been updated to v1.34, Helm
has been updated to v3.19 and various other controller dependencies have
been updated to their latest version. The controller is now built with
Go 1.25.

Fixes:
- Fix GitRepository controller stalling when it shouldn't
  [#1865](https://github.com/fluxcd/source-controller/pull/1865)

Improvements:
- [RFC-0010] Add multi-tenant workload identity support for GCP Bucket
  [#1862](https://github.com/fluxcd/source-controller/pull/1862)
- [RFC-0010] Add multi-tenant workload identity support for AWS Bucket
  [#1868](https://github.com/fluxcd/source-controller/pull/1868)
- [RFC-0010] Add multi-tenant workload identity support for Azure GitRepository
  [#1871](https://github.com/fluxcd/source-controller/pull/1871)
- [RFC-0010] Add default-service-account for lockdown
  [#1872](https://github.com/fluxcd/source-controller/pull/1872)
- [RFC-0010] Add multi-tenant workload identity support for Azure Blob Storage
  [#1875](https://github.com/fluxcd/source-controller/pull/1875)
- [RFC-0012] Add ExternalArtifact API documentation
  [#1881](https://github.com/fluxcd/source-controller/pull/1881)
- [RFC-0012] Refactor controller to use `fluxcd/pkg/artifact`
  [#1883](https://github.com/fluxcd/source-controller/pull/1883)
- Migrate OCIRepository controller to runtime/secrets
  [#1851](https://github.com/fluxcd/source-controller/pull/1851)
- Migrate Bucket controller to runtime/secrets
  [#1852](https://github.com/fluxcd/source-controller/pull/1852)
- Add TLS config for GitHub App authentication
  [#1860](https://github.com/fluxcd/source-controller/pull/1860)
- Remove ServerName pinning from TLS config
  [#1870](https://github.com/fluxcd/source-controller/pull/1870)
- Extract storage operations to a dedicated package
  [#1864](https://github.com/fluxcd/source-controller/pull/1864)
- Remove deprecated APIs in group `source.werf.io/v1beta1`
  [#1861](https://github.com/fluxcd/source-controller/pull/1861)
- Migrate tests from gotest to gomega
  [#1876](https://github.com/fluxcd/source-controller/pull/1876)
- Update dependencies
  [#1888](https://github.com/fluxcd/source-controller/pull/1888)
  [#1880](https://github.com/fluxcd/source-controller/pull/1880)
  [#1878](https://github.com/fluxcd/source-controller/pull/1878)
  [#1876](https://github.com/fluxcd/source-controller/pull/1876)
  [#1874](https://github.com/fluxcd/source-controller/pull/1874)
  [#1850](https://github.com/fluxcd/source-controller/pull/1850)
  [#1844](https://github.com/fluxcd/source-controller/pull/1844)

## 1.6.2

**Release date:** 2025-06-27

This patch release comes with a fix for `rsa-sha2-512` and `rsa-sha2-256` algorithms
not being prioritized for `ssh-rsa` host keys.

Fixes:
- Fix: Prioritize sha2-512 and sha2-256 for ssh-rsa host keys
  [#1839](https://github.com/fluxcd/source-controller/pull/1839)

## 1.6.1

**Release date:** 2025-06-13

This patch release comes with a fix for the `knownhosts: key mismatch`
error in the `GitRepository` API when using SSH authentication, and
a fix for authentication with
[public ECR repositories](https://fluxcd.io/flux/integrations/aws/#for-amazon-public-elastic-container-registry)
in the `OCIRepository` API.

Fix:
- Fix authentication for public ECR
  [#1825](https://github.com/fluxcd/source-controller/pull/1825)
- Fix `knownhosts key mismatch` regression bug
  [#1829](https://github.com/fluxcd/source-controller/pull/1829)

## 1.6.0

**Release date:** 2025-05-27

This minor release promotes the OCIRepository API to GA, and comes with new features,
improvements and bug fixes.

### OCIRepository

The `OCIRepository` API has been promoted from `v1beta2` to `v1` (GA).
The `v1` API is backwards compatible with `v1beta2`.

OCIRepository API now supports object-level workload identity by setting
`.spec.provider` to one of `aws`, `azure`, or `gcp`, and setting
`.spec.serviceAccountName` to the name of a service account in the same
namespace that has been configured with appropriate cloud permissions.
For this feature to work, the controller feature gate
`ObjectLevelWorkloadIdentity` must be enabled. See a complete guide
[here](https://fluxcd.io/flux/integrations/).

OCIRepository API now caches registry credentials for cloud providers
by default. This behavior can be disabled or fine-tuned by adjusting the
token cache controller flags (see [docs](https://fluxcd.io/flux/components/source/options/)).
The token cache also exposes metrics that are documented
[here](https://fluxcd.io/flux/monitoring/metrics/#controller-metrics).

### GitRepository

GitRepository API now supports sparse checkout by setting a list
of directories in the `.spec.sparseCheckout` field. This allows
for optimizing the amount of data fetched from the Git repository.

GitRepository API now supports mTLS authentication for HTTPS Git repositories
by setting the fields `tls.crt`, `tls.key`, and `ca.crt` in the `.data` field
of the referenced Secret in `.spec.secretRef`.

GitRepository API now caches credentials for non-`generic` providers by default.
This behavior can be disabled or fine-tuned by adjusting the
token cache controller flags (see [docs](https://fluxcd.io/flux/components/source/options/)).
The token cache also exposes metrics that are documented
[here](https://fluxcd.io/flux/monitoring/metrics/#controller-metrics).

### General updates

In addition, the Kubernetes dependencies have been updated to v1.33 and
various other controller dependencies have been updated to their latest
version. The controller is now built with Go 1.24.

Fixes:
- Downgrade `Masterminds/semver` to v3.3.0
  [#1785](https://github.com/fluxcd/source-controller/pull/1785)

Improvements:
- Promote OCIRepository API to v1 (GA)
  [#1794](https://github.com/fluxcd/source-controller/pull/1794)
- [RFC-0010] Introduce object-level workload identity for container registry APIs and cache credentials
  [#1790](https://github.com/fluxcd/source-controller/pull/1790)
  [#1802](https://github.com/fluxcd/source-controller/pull/1802)
  [#1811](https://github.com/fluxcd/source-controller/pull/1811)
- Implement Sparse Checkout for `GitRepository`
  [#1774](https://github.com/fluxcd/source-controller/pull/1774)
- Add Mutual TLS support to `GitRepository`
  [#1778](https://github.com/fluxcd/source-controller/pull/1778)
- Introduce token cache for `GitRepository`
  [#1745](https://github.com/fluxcd/source-controller/pull/1745)
  [#1788](https://github.com/fluxcd/source-controller/pull/1788)
  [#1789](https://github.com/fluxcd/source-controller/pull/1789)
- Build controller without CGO
  [#1725](https://github.com/fluxcd/source-controller/pull/1725)
- Various dependency updates
  [#1812](https://github.com/fluxcd/source-controller/pull/1812)
  [#1800](https://github.com/fluxcd/source-controller/pull/1800)
  [#1810](https://github.com/fluxcd/source-controller/pull/1810)
  [#1806](https://github.com/fluxcd/source-controller/pull/1806)
  [#1782](https://github.com/fluxcd/source-controller/pull/1782)
  [#1783](https://github.com/fluxcd/source-controller/pull/1783)
  [#1775](https://github.com/fluxcd/source-controller/pull/1775)
  [#1728](https://github.com/fluxcd/source-controller/pull/1728)
  [#1722](https://github.com/fluxcd/source-controller/pull/1722)

## 1.5.0

**Release date:** 2025-02-13

This minor release comes with various bug fixes and improvements.

### GitRepository

The GitRepository API now supports authenticating through GitHub App
for GitHub repositories. See
[docs](https://fluxcd.io/flux/components/source/gitrepositories/#github).

In addition, the Kubernetes dependencies have been updated to v1.32.1, Helm has
been updated to v3.17.0 and various other controller dependencies have been
updated to their latest version.

Fixes:
- Remove deprecated object metrics from controllers
  [#1686](https://github.com/fluxcd/source-controller/pull/1686)

Improvements:
- [RFC-007] Implement GitHub app authentication for git repositories.
  [#1647](https://github.com/fluxcd/source-controller/pull/1647)
- Various dependency updates
  [#1684](https://github.com/fluxcd/source-controller/pull/1684)
  [#1689](https://github.com/fluxcd/source-controller/pull/1689)
  [#1693](https://github.com/fluxcd/source-controller/pull/1693)
  [#1705](https://github.com/fluxcd/source-controller/pull/1705)
  [#1708](https://github.com/fluxcd/source-controller/pull/1708)
  [#1709](https://github.com/fluxcd/source-controller/pull/1709)
  [#1713](https://github.com/fluxcd/source-controller/pull/1713)
  [#1716](https://github.com/fluxcd/source-controller/pull/1716)

## 1.4.1

**Release date:** 2024-09-26

This patch release comes with a fix to the `GitRepository` API to keep it
backwards compatible by removing the default value for `.spec.provider` field
when not set in the API. The controller will internally consider an empty value
for the provider as the `generic` provider.

Fix:
- GitRepo: Remove provider default value from API
  [#1626](https://github.com/fluxcd/source-controller/pull/1626)

## 1.4.0

**Release date:** 2024-09-25

This minor release promotes the Bucket API to GA, and comes with new features,
improvements and bug fixes.

### Bucket

The `Bucket` API has been promoted from `v1beta2` to `v1` (GA).
The `v1` API is backwards compatible with `v1beta2`.

Bucket API now supports proxy through the field `.spec.proxySecretRef` and custom TLS client certificate and CA through the field `.spec.certSecretRef`.

Bucket API now also supports specifying a custom STS configuration through the field `.spec.sts`. This is currently only supported for the providers `generic` and `aws`. When specifying a custom STS configuration one must specify which STS provider to use. For the `generic` bucket provider we support the `ldap` STS provider, and for the `aws` bucket provider we support the `aws` STS provider. For the `aws` STS provider, one may use the default main STS endpoint, or the regional STS endpoints, or even an interface endpoint.

### OCIRepository

OCIRepository API now supports proxy through the field `.spec.proxySecretRef`.

**Warning**: Proxy is not supported for cosign keyless verification.

### GitRepository

GitRepository API now supports OIDC authentication for Azure DevOps repositories through the field `.spec.provider` using the value `azure`. See the docs for details [here](https://fluxcd.io/flux/components/source/gitrepositories/#provider).

In addition, the Kubernetes dependencies have been updated to v1.31.1, Helm has
been updated to v3.16.1 and various other controller dependencies have been
updated to their latest version. The controller is now built with Go 1.23.

Fixes:
- helm: Use the default transport pool to preserve proxy settings
  [#1490](https://github.com/fluxcd/source-controller/pull/1490)
- Fix incorrect use of format strings with the conditions package.
  [#1529](https://github.com/fluxcd/source-controller/pull/1529)
- Fix HelmChart local dependency resolution for name-based path
  [#1539](https://github.com/fluxcd/source-controller/pull/1539)
- Fix Helm index validation for Artifactory
  [#1516](https://github.com/fluxcd/source-controller/pull/1516)

Improvements:
- Promote Bucket API to v1
  [#1592](https://github.com/fluxcd/source-controller/pull/1592)
- Add .spec.certSecretRef to Bucket API
  [#1475](https://github.com/fluxcd/source-controller/pull/1475)
- Run ARM64 tests on GitHub runners
  [#1512](https://github.com/fluxcd/source-controller/pull/1512)
- Add support for .spec.proxySecretRef for generic provider of Bucket API
  [#1500](https://github.com/fluxcd/source-controller/pull/1500)
- Improve invalid proxy error message for Bucket API
  [#1550](https://github.com/fluxcd/source-controller/pull/1550)
- Add support for AWS STS endpoint in the Bucket API
  [#1552](https://github.com/fluxcd/source-controller/pull/1552)
- Add proxy support for GCS buckets
  [#1565](https://github.com/fluxcd/source-controller/pull/1565)
- azure-blob: Fix VisitObjects() in integration test
  [#1574](https://github.com/fluxcd/source-controller/pull/1574)
- Add proxy support for Azure buckets
  [#1567](https://github.com/fluxcd/source-controller/pull/1567)
- Add proxy support for AWS S3 buckets
  [#1568](https://github.com/fluxcd/source-controller/pull/1568)
- Add proxy support for OCIRepository API
  [#1536](https://github.com/fluxcd/source-controller/pull/1536)
- Add LDAP provider for Bucket STS API
  [#1585](https://github.com/fluxcd/source-controller/pull/1585)
- Introduce Bucket provider constants with the common part as a prefix
  [#1589](https://github.com/fluxcd/source-controller/pull/1589)
- OCIRepository: Configure proxy for OIDC auth
  [#1607](https://github.com/fluxcd/source-controller/pull/1607)
- [RFC-0007] Enable Azure OIDC for Azure DevOps repositories
  [#1591](https://github.com/fluxcd/source-controller/pull/1591)
- Build with Go 1.23
  [#1582](https://github.com/fluxcd/source-controller/pull/1582)
- Various dependency updates
  [#1507](https://github.com/fluxcd/source-controller/pull/1507)
  [#1576](https://github.com/fluxcd/source-controller/pull/1576)
  [#1578](https://github.com/fluxcd/source-controller/pull/1578)
  [#1579](https://github.com/fluxcd/source-controller/pull/1579)
  [#1583](https://github.com/fluxcd/source-controller/pull/1583)
  [#1588](https://github.com/fluxcd/source-controller/pull/1588)
  [#1603](https://github.com/fluxcd/source-controller/pull/1603)
  [#1610](https://github.com/fluxcd/source-controller/pull/1610)
  [#1614](https://github.com/fluxcd/source-controller/pull/1614)
  [#1618](https://github.com/fluxcd/source-controller/pull/1618)

## 1.3.0

**Release date:** 2024-05-03

This minor release promotes the Helm APIs to GA, and comes with new features,
improvements and bug fixes.

### HelmRepository

The `HelmRepository` API has been promoted from `v1beta2` to `v1` (GA).
The `v1` API is backwards compatible with `v1beta2`.

For `HelmRepository` of type `oci`, the `.spec.insecure` field allows connecting
over HTTP to an insecure non-TLS container registry. 

To upgrade from `v1beta2`, after deploying the new CRD and controller,
set  `apiVersion: source.werf.io/v1` in the YAML files that
contain `HelmRepository` definitions.
Bumping the API version in manifests can be done gradually.
It is advised not to delay this procedure as the beta versions will be removed after 6 months.

### HelmChart

The `HelmChart` API have been promoted from `v1beta2` to `v1` (GA).
The `v1` API is backwards compatible with `v1beta2`, with the exception
of the removal of the deprecated field `.spec.valuesFile` which was replaced with `spec.valuesFiles`.

The `HelmChart` API was extended with support for
[Notation signature verification](https://github.com/fluxcd/source-controller/blob/release/v1.3.x/docs/spec/v1/helmcharts.md#notation)
of Helm OCI charts.

A new optional field `.spec.ignoreMissingValuesFiles` has been added,
which allows the controller to ignore missing values files rather than failing to reconcile the `HelmChart`.

### OCIRepository

The `OCIRepository` API was extended with support for
[Notation signature verification](https://github.com/fluxcd/source-controller/blob/release/v1.3.x/docs/spec/v1beta2/ocirepositories.md#notation)
of OCI artifacts.

A new optional field `.spec.ref.semverFilter` has been added,
which allows the controller to filter the tags based on regular expressions
before applying the semver range. This allows 
[picking the latest release candidate](https://github.com/fluxcd/source-controller/blob/release/v1.3.x/docs/spec/v1beta2/ocirepositories.md#semverfilter-example)
instead of the latest stable release.

In addition, the controller has been updated to Kubernetes v1.30.0,
Helm v3.14.4, and various other dependencies to their latest version
to patch upstream CVEs.

Improvements:
- Promote Helm APIs to `source.werf.io/v1` (GA)
  [#1428](https://github.com/fluxcd/source-controller/pull/1428)
- Add `.spec.ignoreMissingValuesFiles` to HelmChart API
  [#1447](https://github.com/fluxcd/source-controller/pull/1447)
- Implement `.spec.ref.semverFilter` in OCIRepository API
  [#1407](https://github.com/fluxcd/source-controller/pull/1407)
- Helm: Allow insecure registry login
  [#1412](https://github.com/fluxcd/source-controller/pull/1442)
- Add support for Notation verification to HelmChart and OCIRepository
  [#1075](https://github.com/fluxcd/source-controller/pull/1075)
- Various dependency updates
  [#1442](https://github.com/fluxcd/source-controller/pull/1442)
  [#1450](https://github.com/fluxcd/source-controller/pull/1450)
  [#1469](https://github.com/fluxcd/source-controller/pull/1469)
  [#1378](https://github.com/fluxcd/source-controller/pull/1378)

Fixes:
- Bind cached helm index to the maximum index size
  [#1457](https://github.com/fluxcd/source-controller/pull/1457)
- Remove `genclient:Namespaced` tag
  [#1386](https://github.com/fluxcd/source-controller/pull/1386)

## 1.2.5

**Release date:** 2024-04-04

This patch release comes with improvements to the `HelmChart` name validation 
and adds logging sanitization of connection error messages for `Bucket` sources.

Fixes:
- Improve chart name validation
  [#1377](https://github.com/fluxcd/source-controller/pull/1377)
- Sanitize URLs for bucket fetch error messages
  [#1430](https://github.com/fluxcd/source-controller/pull/1430)

Improvements:
- Update controller-gen to v0.14.0
  [#1399](https://github.com/fluxcd/source-controller/pull/1399)

## 1.2.4

**Release date:** 2024-02-01

This patch release updates the Kubernetes dependencies to v1.28.6 and various
other dependencies to their latest version to patch upstream CVEs.

Improvements:
- Various dependency updates
  [#1362](https://github.com/fluxcd/source-controller/pull/1362)
  [#1357](https://github.com/fluxcd/source-controller/pull/1357)
  [#1353](https://github.com/fluxcd/source-controller/pull/1353)
  [#1347](https://github.com/fluxcd/source-controller/pull/1347)
  [#1343](https://github.com/fluxcd/source-controller/pull/1343)
  [#1340](https://github.com/fluxcd/source-controller/pull/1340)
  [#1338](https://github.com/fluxcd/source-controller/pull/1338)
  [#1336](https://github.com/fluxcd/source-controller/pull/1336)
  [#1334](https://github.com/fluxcd/source-controller/pull/1334)

## 1.2.3

**Release date:** 2023-12-14

This patch release updates the controller's Helm dependency to v3.13.3.

Improvements:
- Update Helm to v3.13.3
  [#1325](https://github.com/fluxcd/source-controller/pull/1325)
- helmrepo: Remove migration log/event
  [#1324](https://github.com/fluxcd/source-controller/pull/1324)

## 1.2.2

**Release date:** 2023-12-11

This patch release addresses an issue with AWS ECR authentication introduced in
v1.2.0.

In addition, a variety of dependencies have been updated. Including an update
of the container base image to Alpine v3.19.

Fixes:
- Address issue with authenticating towards AWS ECR
  [#1318](https://github.com/fluxcd/source-controller/pull/1318)
  [#1321](https://github.com/fluxcd/source-controller/pull/1318)

Improvements:

- Update dependencies
  [#1314](https://github.com/fluxcd/source-controller/pull/1314)
  [#1318](https://github.com/fluxcd/source-controller/pull/1318)
  [#1321](https://github.com/fluxcd/source-controller/pull/1321)
- build: update Alpine to 3.19
  [#1316](https://github.com/fluxcd/source-controller/pull/1316)

## 1.2.1

**Release date:** 2023-12-08

This patch release ensures the controller is built with the latest Go `1.21.x`
release, to mitigate multiple security vulnerabilities which were published
shortly after the release of v1.2.0.

In addition, a small number of dependencies have been updated to their latest
version.

Improvements:
- Update dependencies
  [#1309](https://github.com/fluxcd/source-controller/pull/1309)

## 1.2.0

**Release date:** 2023-12-05

This minor release comes with API changes, bug fixes and several new features.

### Bucket

A new field, `.spec.prefix`, has been added to the Bucket API, which enables
server-side filtering of files if the object's `.spec.provider` is set to
`generic`/`aws`/`gcp`.

### OCIRepository and HelmChart

Two new fields, `.spec.verify.matchOIDCIdentity.issuer` and
`.spec.verify.matchOIDCIdentity.subject` have been added to the HelmChart and
OCIRepository APIs. If the image has been keylessly signed via Cosign, these
fields can be used to verify the OIDC issuer of the Fulcio certificate and the
OIDC identity's subject respectively.

### HelmRepository

A new boolean field, `.spec.insecure`, has been introduced to the HelmRepository
API, which allows connecting to a non-TLS HTTP container registry. It is only
considered if the object's `.spec.type` is set to `oci`.

From this release onwards, HelmRepository objects of type OCI are treated as
static objects, i.e. they have an empty status.
Existing objects undergo a one-time automatic migration and new objects
will be undergo a one-time reconciliation to remove any status fields.

Additionally, the controller now performs a shallow clone if the
`.spec.ref.name` of the GitRepository object points to a branch or a tag.

Furthermore, a bug has been fixed, where the controller would try to
authenticate against public OCI registries if the HelmRepository object has a
reference to a Secret containing a CA certificate.

Lastly, dependencies have been updated to their latest version, including an
update of Kubernetes to v1.28.4.

Fixes:
- Address miscellaneous issues throughout code base
  [#1257](https://github.com/fluxcd/source-controller/pull/1257)
- helmrepo: only configure tls login option when required
  [#1289](https://github.com/fluxcd/source-controller/pull/1289)
- oci: rename `OCIChartRepository.insecure` to `insecureHTTP`
  [#1299](https://github.com/fluxcd/source-controller/pull/1299)
- Use bitnami Minio oci chart for e2e
  [#1301](https://github.com/fluxcd/source-controller/pull/1301)

Improvements:
- build(deps): bump Go dependencies
  [#1260](https://github.com/fluxcd/source-controller/pull/1260)
  [#1261](https://github.com/fluxcd/source-controller/pull/1261)
  [#1269](https://github.com/fluxcd/source-controller/pull/1269)
  [#1291](https://github.com/fluxcd/source-controller/pull/1291)
- build(deps): bump the ci group dependencies
  [#1265](https://github.com/fluxcd/source-controller/pull/1265)
  [#1266](https://github.com/fluxcd/source-controller/pull/1266)
  [#1272](https://github.com/fluxcd/source-controller/pull/1272)
  [#1277](https://github.com/fluxcd/source-controller/pull/1277)
  [#1281](https://github.com/fluxcd/source-controller/pull/1281)
  [#1285](https://github.com/fluxcd/source-controller/pull/1285)
  [#1296](https://github.com/fluxcd/source-controller/pull/1296)
  [#1303](https://github.com/fluxcd/source-controller/pull/1303)
- bucket: Add prefix filtering capability
  [#1228](https://github.com/fluxcd/source-controller/pull/1228)
- Static HelmRepository OCI
  [#1243](https://github.com/fluxcd/source-controller/pull/1243)
- cosign: allow identity matching for keyless verification
  [#1250](https://github.com/fluxcd/source-controller/pull/1250)
- Upgrade `go-git` to v5.10.0
  [#1271](https://github.com/fluxcd/source-controller/pull/1271)
- storage: change default file permissions
  [#1276](https://github.com/fluxcd/source-controller/pull/1276)
- Update dependencies to Kubernetes v1.28
  [#1286](https://github.com/fluxcd/source-controller/pull/1286)
- Add `.spec.insecure` to `HelmRepository` for `type: oci`
  [#1288](https://github.com/fluxcd/source-controller/pull/1288)
- Update Git dependencies
  [#1300](https://github.com/fluxcd/source-controller/pull/1300)
- Update Go dependencies
  [#1304](https://github.com/fluxcd/source-controller/pull/1304)

## 1.1.2

**Release date:** 2023-10-11

This patch release fixes a bug where OCIRepository objects can't be consumed
when the OCI image layer contains symlinks.

Fixes:
- oci: Skip symlinks found in upstream artifacts
  [#1246](https://github.com/fluxcd/source-controller/pull/1246/)

Improvements:
- build(deps): bump the ci group with 1 update
  [#1256](https://github.com/fluxcd/source-controller/pull/1256)

## 1.1.1

**Release date:** 2023-09-18

This is a patch release that fixes a regression introduced in v1.1.0 where
HelmRepository objects would not be reconciled if they provided a TLS Secret
using `.spec.secretRef` with a type other than `Opaque` or `kubernetes.io/tls`.

In addition, the URL lookup strategy for Buckets has been changed from path to
auto, to widen support for S3-compatible object storage services.

Lastly, several dependencies have been updated to their latest versions.

Fixes:
- bucket: use auto lookup type
  [#1222](https://github.com/fluxcd/source-controller/pull/1222)
- helmrepo: fix Secret type check for TLS via `.spec.secretRef`
  [#1225](https://github.com/fluxcd/source-controller/pull/1225)
- Upgrade github.com/fluxcd/pkg/{git,git/gogit}
  [#1236](https://github.com/fluxcd/source-controller/pull/1236)

Improvements:
- build(deps): bump the ci group dependencies
  [#1213](https://github.com/fluxcd/source-controller/pull/1213)
  [#1224](https://github.com/fluxcd/source-controller/pull/1224)
  [#1230](https://github.com/fluxcd/source-controller/pull/1230)
  [#1235](https://github.com/fluxcd/source-controller/pull/1235)
- docs: Add missing pem-encoding reference
  [#1216](https://github.com/fluxcd/source-controller/pull/1216)
- build(deps): bump github.com/cyphar/filepath-securejoin from 0.2.3 to 0.2.4
  [#1227](https://github.com/fluxcd/source-controller/pull/1227)

## 1.1.0

**Release date:** 2023-08-23

This minor release comes with API changes, bug fixes and several new features.

All APIs that accept TLS data have been modified to adopt Secrets of type
`kubernetes.io/tls`. This includes:
* HelmRepository: The field `.spec.secretRef` has been __deprecated__ in favor
of a new field [`.spec.certSecretRef`](https://github.com/fluxcd/source-controller/blob/v1.1.0/docs/spec/v1beta2/helmrepositories.md#cert-secret-reference).
  This field is also supported by OCI HelmRepositories.
* OCIRepository: Support for the`caFile`, `keyFile` and `certFile` keys in the
  Secret specified in [`.spec.certSecretRef`](https://github.com/fluxcd/source-controller/blob/v1.1.0/docs/spec/v1beta2/ocirepositories.md#cert-secret-reference)
  have been __deprecated__ in favor of `ca.crt`, `tls.key` and `tls.crt`.
  Also, the Secret now must be of type `Opaque` or `kubernete.io/tls`.
* GitRepository: CA certificate can now be provided in the Secret sepcified in
  `.spec.secretRef` using the `ca.crt` key, which takes precedence over the
  existing `caFile` key.

Furthermore, GitRepository has a couple of new features:
* Proxy support: A new field [`.spec.proxySecretRef`](https://github.com/fluxcd/source-controller/blob/v1.1.0/docs/spec/v1/gitrepositories.md#proxy-secret-reference)
  has been introduced which can be used to specify the proxy configuration to
  use for all remote Git operations related to the particular object.
* Tag verification: The field [`.spec.verification.mode`](https://github.com/fluxcd/source-controller/blob/v1.1.0/docs/spec/v1/gitrepositories.md#verification)
  now supports the following values:
    * HEAD: Verify the HEAD of the Git repository.
    * Tag: Verify the tag specified in `.spec.ref`
    * TagAndHead: Verify the tag specified in `.spec.ref` and the commit it
      points to.

Starting with this version, the controller now stops exporting an object's
metrics as soon as the object has been deleted.

In addition, the controller now consumes significantly less CPU and memory when
reconciling Helm repository indexes.

Lastly, a new flag `--interval-jitter-percentage` has been introduced which can
be used to specify a jitter to the reconciliation interval in order to
distribute the load more evenly when multiple objects are set up with the same
interval.

Improvements:
- gitrepo: Add support for specifying proxy per `GitRepository`
  [#1109](https://github.com/fluxcd/source-controller/pull/1109)
- helmrepo: add `.spec.certSecretRef` for specifying TLS auth data
  [#1160](https://github.com/fluxcd/source-controller/pull/1160)
- Update docs on Azure identity
  [#1167](https://github.com/fluxcd/source-controller/pull/1167)
- gitrepo: document limitation of `spec.ref.name` with Azure Devops
  [#1175](https://github.com/fluxcd/source-controller/pull/1175)
- ocirepo: add cosign support for insecure HTTP registries
  [#1176](https://github.com/fluxcd/source-controller/pull/1176)
- Handle delete before adding finalizer
  [#1177](https://github.com/fluxcd/source-controller/pull/1177)
- Store Helm indexes in JSON format
  [#1178](https://github.com/fluxcd/source-controller/pull/1178)
- Unpin go-git and update to v5.8.1
  [#1179](https://github.com/fluxcd/source-controller/pull/1179)
- controller: jitter requeue interval
  [#1184](https://github.com/fluxcd/source-controller/pull/1184)
- cache: ensure new expiration is persisted
  [#1185](https://github.com/fluxcd/source-controller/pull/1185)
- gitrepo: add support for Git tag verification
  [#1187](https://github.com/fluxcd/source-controller/pull/1187)
- Update dependencies
  [#1191](https://github.com/fluxcd/source-controller/pull/1191)
- Adopt Kubernetes style TLS Secrets
  [#1194](https://github.com/fluxcd/source-controller/pull/1194)
- Update dependencies
  [#1196](https://github.com/fluxcd/source-controller/pull/1196)
- Helm OCI: Add support for TLS registries with self-signed certs
  [#1197](https://github.com/fluxcd/source-controller/pull/1197)
- Update dependencies
  [#1202](https://github.com/fluxcd/source-controller/pull/1202)
- Preserve url encoded path in normalized helm repository URL
  [#1203](https://github.com/fluxcd/source-controller/pull/1203)
- Fix link ref in API docs
  [#1204](https://github.com/fluxcd/source-controller/pull/1204)

Fixes:
- Fix the helm cache arguments
  [#1170](https://github.com/fluxcd/source-controller/pull/1170)
- Delete stale metrics on object delete
  [#1183](https://github.com/fluxcd/source-controller/pull/1183)
- Disable system-wide git config in tests
  [#1192](https://github.com/fluxcd/source-controller/pull/1192)
- Fix links in API docs
  [#1200](https://github.com/fluxcd/source-controller/pull/1200)

## 1.0.1

**Release date:** 2023-07-10

This is a patch release that fixes the AWS authentication for cross-region ECR repositories.

Fixes:
- Update `fluxcd/pkg/oci` to fix ECR cross-region auth
  [#1158](https://github.com/fluxcd/source-controller/pull/1158)

## 1.0.0

**Release date:** 2023-07-03

This is the first stable release of the controller. From now on, this controller
follows the [Flux 2 release cadence and support pledge](https://fluxcd.io/flux/releases/).

Starting with this version, the build, release and provenance portions of the
Flux project supply chain [provisionally meet SLSA Build Level 3](https://fluxcd.io/flux/security/slsa-assessment/).

This release includes several minor changes that primarily focus on addressing
forgotten and obsolete bits in the logic related to GitRepository objects.

Including a removal of the `OptimizedGitClones` feature flag. If your
Deployment is configured to disable this flag, you should remove it.

In addition, dependencies have been updated to their latest version, including
an update of Kubernetes to v1.27.3.

For a comprehensive list of changes since `v0.36.x`, please refer to the
changelog for [v1.0.0-rc.1](#100-rc1), [v1.0.0-rc.3](#100-rc3) and
[`v1.0.0-rc.4`](#100-rc4).

Improvements:
- gitrepo: remove `OptimizedGitClones` as a feature gate
  [#1124](https://github.com/fluxcd/source-controller/pull/1124)
  [#1126](https://github.com/fluxcd/source-controller/pull/1126)
- Update dependencies
  [#1127](https://github.com/fluxcd/source-controller/pull/1127)
  [#1147](https://github.com/fluxcd/source-controller/pull/1147)
- Update Cosign to v2.1.0
  [#1132](https://github.com/fluxcd/source-controller/pull/1132)
- Align `go.mod` version with Kubernetes (Go 1.20)
  [#1134](https://github.com/fluxcd/source-controller/pull/1134)
- Add the verification key to the GitRepository verified status condition
- [#1136](https://github.com/fluxcd/source-controller/pull/1136)
- gitrepo: remove obsolete proxy docs
  [#1144](https://github.com/fluxcd/source-controller/pull/1144)

## 1.0.0-rc.5

**Release date:** 2023-06-01

This release candidate fixes a regression introduced in `1.0.0.-rc.4` where
support for Git servers that exclusively use v2 of the wire protocol like Azure
Devops and AWS CodeCommit was broken.

Lastly, the controller's dependencies were updated to mitigate CVE-2023-33199.

Improvements:
- build(deps): bump github.com/sigstore/rekor from 1.1.1 to 1.2.0
  [#1107](https://github.com/fluxcd/source-controller/pull/1107)

Fixes:
-  Bump `fluxcd/pkg/git/gogit` to v0.12.0
  [#1111](https://github.com/fluxcd/source-controller/pull/1111)

## 1.0.0-rc.4

**Release date:** 2023-05-26

This release candidate comes with support for Kubernetes v1.27 and Cosign v2.
It also enables the use of annotated Git tags with `.spec.ref.name` in
`GitRepository`. Furthermore, it fixes a bug related to accessing Helm OCI
charts on ACR using OIDC auth.

Improvements:
- build(deps): bump helm/kind-action from 1.5.0 to 1.7.0
  [#1100](https://github.com/fluxcd/source-controller/pull/1100)
- build(deps): bump sigstore/cosign-installer from 3.0.3 to 3.0.5
  [#1101](https://github.com/fluxcd/source-controller/pull/1101)
- build(deps): bump actions/setup-go from 4.0.0 to 4.0.1
  [#1102](https://github.com/fluxcd/source-controller/pull/1102)
- Update cosign to v2
  [#1096](https://github.com/fluxcd/source-controller/pull/1096)
- build(deps): bump github.com/sigstore/rekor from 0.12.1-0.20220915152154-4bb6f441c1b2 to 1.1.1
  [#1083](https://github.com/fluxcd/source-controller/pull/1083)
- Update controller-runtime and Kubernetes dependencies
  [#1104](https://github.com/fluxcd/source-controller/pull/1104)
- Update dependencies; switch to `go-git/go-git` and `pkg/tar`
  [#1105](https://github.com/fluxcd/source-controller/pull/1105)

## 1.0.0-rc.3

**Release date:** 2023-05-12

This release candidate introduces the verification of the Artifact digest in
storage during reconciliation. This ensures that the Artifact is not tampered
with after it was written to storage. When the digest does not match, the
controller will emit a warning event and remove the file from storage, forcing
the Artifact to be re-downloaded.

In addition, files with executable permissions are now archived with their mode
set to `0o744` instead of `0o644`. Allowing the extracted file to be executable
by the user.

Lastly, the controller's dependencies were updated to mitigate CVE-2023-1732
and CVE-2023-2253, and the controller base image was updated to Alpine 3.18.

Improvements:
- Verify digest of Artifact in Storage
  [#1088](https://github.com/fluxcd/source-controller/pull/1088)
- build(deps): bump github.com/cloudflare/circl from 1.3.2 to 1.3.3
  [#1092](https://github.com/fluxcd/source-controller/pull/1092)
- build(deps): bump github.com/docker/distribution from 2.8.1+incompatible to 2.8.2+incompatible
  [#1093](https://github.com/fluxcd/source-controller/pull/1093)
- storage: set `0o744` for files with exec mode set
  [#1094](https://github.com/fluxcd/source-controller/pull/1094)

## 1.0.0-rc.2

**Release date:** 2023-05-09

This release candidate comes with various updates to the controller's dependencies,
most notable, Helm was updated to v3.11.3.

Improvements:
- Update dependencies
  [#1086](https://github.com/fluxcd/source-controller/pull/1086)
- Set RecoverPanic globally across controllers
  [#1077](https://github.com/fluxcd/source-controller/pull/1077)
- Move controllers to internal/controller
  [#1076](https://github.com/fluxcd/source-controller/pull/1076)

## 1.0.0-rc.1

**Release date:** 2023-03-30

This release candidate promotes the `GitRepository` API from `v1beta2` to `v1`.
The controller now supports horizontal scaling using
sharding based on a label selector.

In addition, support for Azure Workload Identity was added to
`OCIRepositories`, `Buckets` and `HelmRepositories` when using `provider: azure`.

### Highlights

#### API changes

The `GitRepository` kind was promoted from v1beta2 to v1 (GA) and deprecated fields were removed.

The common types `Artifact`, `Conditions` and the `Source` interface were promoted to v1.

The `gitrepositories.source.werf.io` CRD contains the following versions:
- v1 (storage version)
- v1beta2 (deprecated)
- v1beta1 (deprecated)

#### Upgrade procedure

The `GitRepository` v1 API is backwards compatible with v1beta2, except for the following:
- the deprecated field `.spec.gitImplementation` was removed
- the unused field `.spec.accessFrom` was removed
- the deprecated field `.status.contentConfigChecksum` was removed
- the deprecated field `.status.artifact.checksum` was removed
- the `.status.url` was removed in favor of the absolute `.status.artifact.url`

To upgrade from v1beta2, after deploying the new CRD and controller,
set  `apiVersion: source.werf.io/v1` in the YAML files that
contain `GitRepository` definitions and remove the deprecated fields if any.
Bumping the API version in manifests can be done gradually.
It is advised to not delay this procedure as the beta versions will be removed after 6 months.

#### Sharding

Starting with this release, the controller can be configured with
`--watch-label-selector`, after which only objects with this label will
be reconciled by the controller.

This allows for horizontal scaling, where source-controller
can be deployed multiple times with a unique label selector
which is used as the sharding key.

Note that this also requires configuration of the `--storage-adv-addr`
to a unique address (in combination with a proper Service definition).
This to ensure the Artifacts handled by the sharding controller point
to a unique endpoint.

In addition, Source object kinds which have a dependency on another
kind (i.e. a HelmChart on a HelmRepository) need to have the same
labels applied to work as expected.

### Full changelog

Improvements:
- GA: Promote `GitRepository` API to `source.werf.io/v1`
  [#1056](https://github.com/fluxcd/source-controller/pull/1056)
- Add reconciler sharding capability based on label selector
  [#1059](https://github.com/fluxcd/source-controller/pull/1059)
- Support Azure Workload Identity
  [#1048](https://github.com/fluxcd/source-controller/pull/1048)
- Update dependencies
  [#1062](https://github.com/fluxcd/source-controller/pull/1062)
- Update workflows
  [#1054](https://github.com/fluxcd/source-controller/pull/1054)

## 0.36.1

**Release date:** 2023-03-20

This release fixes a bug where after reading a `.sourceignore` file in a
subdirectory, the controller could start to ignore files from directories next
to the directory the `.sourceignore` file was placed in.

Fixes:
- Update sourceignore to fix pattern domain bug
  [#1050](https://github.com/fluxcd/source-controller/pull/1050)

## 0.36.0

**Release date:** 2023-03-08

This release changes the format of the Artifact `Revision` field when using a
GitRepository with a `.spec.ref.name` set (introduced in [`v0.35.0`](#0350)),
changing it from `sha1:<commit>` to `<name>@sha1:<commit>`. Offering a more
precise reflection of the revision the Artifact was created from.

In addition, `klog` is now configured to log using the same logger as the rest
of the controller (providing a consistent log format).

Lastly, the controller is now built using Go `1.20`, and the dependencies have
been updated to their latest versions.

Improvements:
- Advertise absolute reference in Artifact for GitRepository name ref
  [#1036](https://github.com/fluxcd/source-controller/pull/1036)
- Update Go to 1.20
  [#1040](https://github.com/fluxcd/source-controller/pull/1040)
- Update dependencies
  [#1040](https://github.com/fluxcd/source-controller/pull/1040)
  [#1041](https://github.com/fluxcd/source-controller/pull/1041)
  [#1043](https://github.com/fluxcd/source-controller/pull/1043)
- Use `logger.SetLogger` to also configure `klog`
  [#1044](https://github.com/fluxcd/source-controller/pull/1044)

## 0.35.2

**Release date:** 2023-02-23

This release reduces the amount of memory consumed by the controller when
reconciling HelmRepositories, by using only the digest of the YAML file as the
Revision of the Artifact instead of the stable sorted version of the entire
index. This aligns with the behavior before `v0.35.0`, and is therefore
considered a bug fix.

In addition, the dependencies have been updated to include some minor security
patches.

Note that `v0.35.0` contains breaking changes. Please refer to the [changelog
entry](#0350) for more information.

Fixes:
- helm: only use Digest to calculcate index revision
  [#1035](https://github.com/fluxcd/source-controller/pull/1035)

Improvements:
- Update dependencies
  [#1036](https://github.com/fluxcd/source-controller/pull/1036)

## 0.35.1

**Release date:** 2023-02-17

This release addresses a hypothetical issue with the Artifact `Digest` field
validation, where a patch of the Artifact could fail to be applied to an object
due to the lack of an `omitempty` tag on the optional field. In reality, this
issue is not possible to encounter, as the `Digest` field is always set when
the Artifact is created.

Note that `v0.35.0` contains breaking changes. Please refer to the [changelog
entry](#0350) for more information.

Fixes:
- api: omit empty Digest in Artifact
  [#1031](https://github.com/fluxcd/source-controller/pull/1031)

## 0.35.0

**Release date:** 2023-02-16

This release introduces a new format for the Artifact `Revision`, and deprecates
the `Checksum` field in favor of a new `Digest` field. In addition, it adds
support for Git reference names in a GitRepository, and comes with the usual
collection of dependency updates.

### Highlights

#### Support for Git reference names

Starting with this version, it is possible to define a [Git Reference](https://git-scm.com/book/en/v2/Git-Internals-Git-References)
in a GitRepository using `.spec.ref.name`.

This opens the door to a range of functionalities not available before, as it
for example allows the controller to follow pull (`refs/pull/<id>/head`) or
merge (`refs/merge-requests/<id>/head`) requests, and allows a transition from
the HEAD of a branch (`refs/heads/main`) to a tag (`refs/tags/v0.1.0`) by
changing a single field value.

Refer to the [GitRepository specification](https://github.com/fluxcd/source-controller/blob/v0.35.0/docs/spec/v1beta2/gitrepositories.md#name-example)
for more details. 

#### Introduction of Artifact Digest

The Artifact of a Source will now advertise a `Digest` field containing the
checksum of the file advertised in the `Path`, and the alias of the algorithm
used to calculate it. Creating a "digest" in the format of `<algo>:<checksum>`.

The algorithm is configurable using the newly introduced `--artifact-digest-algo`
flag, which allows configuration of other algorithms (`sha384`, `sha512`, and
`blake3`) than the hardcoded `sha256` default of the [now deprecated `Checksum`
field](#deprecation-of-artifact-checksum).

Please note that until the `Checksum` is fully deprecated, changing the
algorithm is not yet advised (albeit supported), as this will result in a
double computation.

### :warning: Breaking changes

#### Artifact Revision format

The `Revision` format for an Artifact consisting of a named pointer (a Git
branch or tag) and/or a specific revision (a Git commit SHA or other calculated
checksum) has changed to contain an `@` separator opposed to `/`, and includes
the algorithm alias as a prefix to a checksum (creating a "digest").
In addition, `HEAD` is no longer used as a named pointer for exact commit
references, but will now only advertise the commit itself.

For example:

- `main/1eabc9a41ca088515cab83f1cce49eb43e84b67f` => `main@sha1:1eabc9a41ca088515cab83f1cce49eb43e84b67f`
- `HEAD/5394cb7f48332b2de7c17dd8b8384bbc84b7e738` => `sha1:5394cb7f48332b2de7c17dd8b8384bbc84b7e738`
- `tag/55609ff9d959589ed917ce32e6bc0f0a36809565f308602c15c3668965979edc` => `tag@sha256:55609ff9d959589ed917ce32e6bc0f0a36809565f308602c15c3668965979edc`
- `8fb62a09c9e48ace5463bf940dc15e85f525be4f230e223bbceef6e13024110c` => `sha256:8fb62a09c9e48ace5463bf940dc15e85f525be4f230e223bbceef6e13024110c`

When the storage of the controller is backed by a Persistent Volume, the
rollout of this new format happens for the next new revision the controller
encounters. Otherwise, the new revision will be advertised as soon as the
Artifact has been reproduced after the controller is deployed.

Other Flux controllers making use of an Artifact are aware of the change in
format, and work with it in a backwards compatible manner. Avoiding observing
a change of revision when this is actually just a change of format. If you
programmatically make use of the Revision, please refer to [the
`TransformLegacyRevision` helper](https://github.com/fluxcd/source-controller/blob/api/v0.35.0/api/v1beta2/artifact_types.go#L121)
to allow a transition period in your application.

For more information around this change, refer to
[RFC-0005](https://github.com/fluxcd/flux2/tree/main/rfcs/0005-artifact-revision-and-digest#establish-an-artifact-revision-format).

#### Deprecation of Artifact Checksum

The `Checksum` field of an Artifact has been deprecated in favor of the newly
introduced `Digest`. Until the deprecated field is removed in the next version
of the API, the controller will continue to produce the SHA-256 checksum in
addition to the digest. Changing the algorithm used to produce the digest using
`--artifact-digest-algo` is therefore not yet advised (albeit supported), as
this will result in a double computation.

For more information around this change, refer to
[RFC-0005](https://github.com/fluxcd/flux2/tree/main/rfcs/0005-artifact-revision-and-digest#introduce-a-digest-field).

### Full changelog

Improvements:
- Introduction of Digest and change of Revision format
  [#1001](https://github.com/fluxcd/source-controller/pull/1001)
- Improve HelmRepository type switching from default to oci
  [#1016](https://github.com/fluxcd/source-controller/pull/1016)
- Apply default permission mode to all files/dirs in an artifact archive
  [#1020](https://github.com/fluxcd/source-controller/pull/1020)
- Add support for checking out Git references
  [#1026](https://github.com/fluxcd/source-controller/pull/1026)
- Update dependencies
  [#1025](https://github.com/fluxcd/source-controller/pull/1025)
  [#1028](https://github.com/fluxcd/source-controller/pull/1028)
  [#1030](https://github.com/fluxcd/source-controller/pull/1030)

Fixes:
- Normalize Helm repository URL with query params properly
  [#1015](https://github.com/fluxcd/source-controller/pull/1015)
- Prevent panic when cloning empty Git repository
  [#1021](https://github.com/fluxcd/source-controller/pull/1021)

## 0.34.0

**Release date:** 2023-01-31

This prerelease comes with support for HTTPS bearer token authentication for Git
repository. The GitRepository authentication Secret is expected to contain the
bearer token in `.data.bearerToken`.

The caching of Secret and ConfigMap resources is disabled by
default to improve memory usage. To opt-out from this behavior, start the
controller with: `--feature-gates=CacheSecretsAndConfigMaps=true`.

All the Source kinds now support progressive status updates. The progress made
by the controller during reconciliation of a Source is reported immediately in
the status of the Source object.

In addition, the controller dependencies have been updated to Kubernetes v1.26.

:warning: **Breaking change:** When using SSH authentication in GitRepository,
if the referenced Secret contained `.data.username`, it was used as the SSH
user. With this version, SSH user will be the username in the SSH address. For
example, if the Git repository address is `ssh://flux@example.com`, `flux` will
be used as the SSH user during SSH authentication. When no username is
specified, `git` remains the default SSH user.

Improvements:
- Garbage collection lock file ignore tests
  [#992](https://github.com/fluxcd/source-controller/pull/992)
- purge minio test container at the end of tests
  [#993](https://github.com/fluxcd/source-controller/pull/993)
- Introduce Progressive status
  [#974](https://github.com/fluxcd/source-controller/pull/974)
- build(deps): bump github.com/containerd/containerd from 1.6.10 to 1.6.12
  [#997](https://github.com/fluxcd/source-controller/pull/997)
- fix typo in helmRepo secretRef spec CRD
  [#996](https://github.com/fluxcd/source-controller/pull/996)
- Fix OCIRepository testdata permissions
  [#998](https://github.com/fluxcd/source-controller/pull/998)
- Set rate limiter option in test reconcilers
  [#999](https://github.com/fluxcd/source-controller/pull/999)
- Update git dependencies for bearer token support
  [#1003](https://github.com/fluxcd/source-controller/pull/1003)
- Document support for bearer token authentication over https in gitrepositories
  [#1000](https://github.com/fluxcd/source-controller/pull/1000)
- Disable caching of secrets and configmaps
  [#989](https://github.com/fluxcd/source-controller/pull/989)
- Update dependencies
  [#1008](https://github.com/fluxcd/source-controller/pull/1008)
- build: Enable SBOM and SLSA Provenance
  [#1009](https://github.com/fluxcd/source-controller/pull/1009)
- Add note about sourceignore recursion
  [#1007](https://github.com/fluxcd/source-controller/pull/1007)
- CI: Replace engineerd/setup-kind with helm/kind-action
  [#1010](https://github.com/fluxcd/source-controller/pull/1010)
- helm/oci: Add context to chart download failure
  [#1013](https://github.com/fluxcd/source-controller/pull/1013)

## 0.33.0

**Release date:** 2022-12-20

This prerelease comes with dedicated mux for the controller's fileserver. All code references to `libgit2` were removed, and the `spec.gitImplementation`
field is no longer being honored, but rather `go-git` is used.
For more information, refer to version 0.32.0's changelog, which started `libgit2`'s
deprecation process.

The controller's garbage collection now takes into consideration
lock files.

The feature gate `ForceGoGitImplementation` was removed, users passing it as their
controller's startup args will need to remove it before upgrading.

Fixes:
- git: Fix issue with recurseSubmodules
  [#975](https://github.com/fluxcd/source-controller/pull/975)
- Fix aliased chart dependencies resolution
  [#988](https://github.com/fluxcd/source-controller/pull/988)

Improvements:
- fileserver: Use new ServeMux
  [#972](https://github.com/fluxcd/source-controller/pull/972)
- Remove libgit2 and git2go from codebase
  [#977](https://github.com/fluxcd/source-controller/pull/977)
- Use Event v1 API metadata keys in notifications
  [#990](https://github.com/fluxcd/source-controller/pull/990)
- storage: take lock files into consideration while garbage collecting
  [#991](https://github.com/fluxcd/source-controller/pull/991)
- Migrate to Go Native fuzz and improve reliability
  [#965](https://github.com/fluxcd/source-controller/pull/965)
- build: Add tidy to make verify
  [#966](https://github.com/fluxcd/source-controller/pull/966)
- build: Add postbuild script for fuzzing
  [#968](https://github.com/fluxcd/source-controller/pull/968)
- build: Link libgit2 via LIB_FUZZING_ENGINE
  [#969](https://github.com/fluxcd/source-controller/pull/969)
- GitRepo: git impl. deprecation test cleanup
  [#980](https://github.com/fluxcd/source-controller/pull/980)
- minio: use container image for tests
  [#981](https://github.com/fluxcd/source-controller/pull/981)
- helm: Update SDK to v3.10.3
  [#982](https://github.com/fluxcd/source-controller/pull/982)
- Update fluxcd/pkg/oci dependency
  [#983](https://github.com/fluxcd/source-controller/pull/983)
- Update dependencies
  [#985](https://github.com/fluxcd/source-controller/pull/985)

## 0.32.1

**Release date:** 2022-11-18

This prerelease rectifies the `v0.32.0` release by retracting the previous Go
version, bumping the controller api version and the controller deployment.

## 0.32.0

**Release date:** 2022-11-17

This prerelease comes with a major refactoring of the controller's Git operations.
The `go-git` implementation now supports all Git servers, including
Azure DevOps, which previously was only supported by `libgit2`.

This version initiates the soft deprecation of the `libgit2` implementation.
The motivation for removing support for `libgit2` being:
- Reliability: over the past months we managed to substantially reduce the
issues users experienced, but there are still crashes happening when the controller
runs over longer periods of time, or when under intense GC pressure.
- Performance: due to the inherit nature of `libgit2` implementation, which
is a C library called via CGO through `git2go`, it will never perform as well as
a pure Go implementations. At scale, memory pressure insues which then triggers
the reliability issues above.
- Lack of Shallow Clone Support.
- Maintainability: supporting two Git implementations is a big task, even more
so when one of them is in a complete different tech stack. Given its nature, to
support `libgit2`, we have to maintain an additional repository. Statically built
`libgit2` libraries need to be cross-compiled for all our supported platforms.
And a lot of "unnecessary" code has to be in place to make building, testing and
fuzzing work seamlessly.

As a result the field `spec.gitImplementation` is ignored and the
reconciliations will use `go-git`. To opt-out from this behaviour, start
the controller with: `--feature-gates=ForceGoGitImplementation=false`.

Users having any issues with `go-git` should report it to the Flux team,
so any issues can be resolved before support for `libgit2` is completely
removed from the codebase.

Improvements:
- Refactor Git operations and introduce go-git support for Azure DevOps and AWS CodeCommit
  [#944](https://github.com/fluxcd/source-controller/pull/944)
- Use Flux Event API v1beta1
  [#952](https://github.com/fluxcd/source-controller/pull/952)
- gogit: Add new ForceGoGitImplementation FeatureGate
  [#945](https://github.com/fluxcd/source-controller/pull/945)
- Remove nsswitch.conf creation from Dockerfile
  [#958](https://github.com/fluxcd/source-controller/pull/958)
- Update dependencies
  [#960](https://github.com/fluxcd/source-controller/pull/960)
  [#950](https://github.com/fluxcd/source-controller/pull/950)
  [#959](https://github.com/fluxcd/source-controller/pull/959)
- Upgrade to azure-sdk-for-go/storage/azblob v0.5.1
  [#931](https://github.com/fluxcd/source-controller/pull/931)

## 0.31.0

**Release date:** 2022-10-21

This prerelease comes with support for Cosign verification of Helm charts.
The signatures verification can be configured by setting `HelmChart.spec.verify` with
`provider` as `cosign` and a `secretRef` to a secret containing the public key.
Cosign keyless verification is also supported, please see the
[HelmChart API documentation](https://github.com/fluxcd/source-controller/blob/api/v0.31.0/docs/spec/v1beta2/helmcharts.md#verification)
for more details.

In addition, the controller dependencies have been updated
to Kubernetes v1.25.3 and Helm v3.10.1.

Improvements:
- Implement Cosign verification for HelmCharts
  [#925](https://github.com/fluxcd/source-controller/pull/925)
- Update dependencies
  [#942](https://github.com/fluxcd/source-controller/pull/942)

Fixes:
- Allow deleting suspended objects
  [#937](https://github.com/fluxcd/source-controller/pull/937)

## 0.30.1

**Release date:** 2022-10-10

This prerelease enables the use of container-level SAS tokens when using `Bucket` objects
to access Azure Storage. The Azure SDK error message has also been enriched to hint Flux
users the potential reasons in case of failure.

Improvements:
- List objects when checking if bucket exists to allow use of container-level SAS token
  [#906](https://github.com/fluxcd/source-controller/pull/906)

## 0.30.0

**Release date:** 2022-09-29

This prerelease adds support for Cosign verification in `OCIRepository` source.
The signatures verification can be configured by setting `OCIRepository.spec.verify` with
`provider` as `cosign` and a `secretRef` to a secret containing the public key.
Cosign keyless verification is also supported, please see the
[OCIRepository API documentation](https://github.com/fluxcd/source-controller/blob/api/v0.30.0/docs/spec/v1beta2/ocirepositories.md#verification)
for more details.

It also comes with strict validation rules for API fields which define a
(time) duration. Effectively, this means values without a time unit (e.g. `ms`,
`s`, `m`, `h`) will now be rejected by the API server. To stimulate sane
configurations, the units `ns`, `us` and `µs` can no longer be configured, nor
can `h` be set for fields defining a timeout value.

In addition, the controller dependencies have been updated
to Kubernetes controller-runtime v0.13.

:warning: **Breaking changes:**
- `.spec.interval` new validation pattern is `"^([0-9]+(\\.[0-9]+)?(ms|s|m|h))+$"`
- `.spec.timeout` new validation pattern is `"^([0-9]+(\\.[0-9]+)?(ms|s|m))+$"`

Improvements:
- api: add custom validation for v1.Duration types
  [#903](https://github.com/fluxcd/source-controller/pull/903)
- [RFC-0003] Implement OCIRepository verification using Cosign
  [#876](https://github.com/fluxcd/source-controller/pull/876)
- Consider bipolarity conditions in Ready condition summarization
  [#907](https://github.com/fluxcd/source-controller/pull/907)
- Update Bucket related SDK dependencies
  [#911](https://github.com/fluxcd/source-controller/pull/911)
- Add custom CA certificates to system certificates
  [#904](https://github.com/fluxcd/source-controller/pull/904)
- [OCIRepository] Optimise OCI artifacts reconciliation
  [#913](https://github.com/fluxcd/source-controller/pull/913)
- Update dependencies
  [#919](https://github.com/fluxcd/source-controller/pull/919)
- Build with Go 1.19
  [#920](https://github.com/fluxcd/source-controller/pull/920)
- Bump libgit2 image and disable cosign verification for CI
  [#921](https://github.com/fluxcd/source-controller/pull/921)
- OCIRepositoryReconciler no-op improvements
  [#917](https://github.com/fluxcd/source-controller/pull/917)
- Accept a slice of remote.Option for cosign verification
  [#916](https://github.com/fluxcd/source-controller/pull/916)
- Update pkg/oci to v0.11.0
  [#922](https://github.com/fluxcd/source-controller/pull/922)

Fixes:
- Handle nil OCI authenticator with malformed registry
  [#897](https://github.com/fluxcd/source-controller/pull/897)

## 0.29.0

**Release date:** 2022-09-09

This prerelease adds support for non-TLS container registries such
as [Kubernetes Kind Docker Registry](https://kind.sigs.k8s.io/docs/user/local-registry/).
Connecting to an in-cluster registry over plain HTTP,
requires setting the `OCIRepository.spec.insecure` field to `true`.

:warning: **Breaking change:** The controller logs have been aligned
with the Kubernetes structured logging. For more details on the new logging
structure please see: [fluxcd/flux2#3051](https://github.com/fluxcd/flux2/issues/3051).

Improvements:
- Align controller logs to Kubernetes structured logging
  [#882](https://github.com/fluxcd/source-controller/pull/882)
- [OCIRepository] Add support for non-TLS insecure container registries
  [#881](https://github.com/fluxcd/source-controller/pull/881)
- Fuzz optimisations
  [#886](https://github.com/fluxcd/source-controller/pull/886)

Fixes:
- [OCI] Static credentials should take precedence over the OIDC provider
  [#884](https://github.com/fluxcd/source-controller/pull/884)

## 0.28.0

**Release date:** 2022-08-29

This prerelease adds support for contextual login to container registries when pulling
Helm charts from Azure Container Registry, Amazon Elastic Container Registry
and Google Artifact Registry. Contextual login for `HelmRepository`
objects can be enabled by setting the `spec.provider` field to `azure`, `aws` or `gcp`.

Selecting the OCI layer containing Kubernetes manifests is now possible
when defining `OCIRepository` objects by setting the `spec.layerSelector.mediaType` field.

In addition, the controller dependencies have been updated to Kubernetes v1.25.0 and Helm v3.9.4.

Improvements:
- [HelmRepository] Enable contextual login for OCI
  [#873](https://github.com/fluxcd/source-controller/pull/873)
- [OCIRepository] Select layer by media type
  [#871](https://github.com/fluxcd/source-controller/pull/871)
- Update Kubernetes packages to v1.25.0
  [#875](https://github.com/fluxcd/source-controller/pull/875)
- Update dependencies
  [#869](https://github.com/fluxcd/source-controller/pull/869)
- Ensure Go 1.18 for fuzz image
  [#872](https://github.com/fluxcd/source-controller/pull/872)

## 0.27.0

**Release date:** 2022-08-17

This prerelease adds support for SAS Keys when authenticating against Azure Blob Storage
and improves the documentation for `OCIRepository`. 

The package `sourceignore`, which is used for excluding files from Flux internal artifacts,
has been moved to `fluxcd/pkg/sourceignore`.

Improvements:
- OCIRepo docs: auto-login setup details
  [#862](https://github.com/fluxcd/source-controller/pull/862)
- Add Support for SAS keys in Azure Blob
  [#738](https://github.com/fluxcd/source-controller/pull/738)
- Use sourceignore from fluxcd/pkg/sourceignore
  [#864](https://github.com/fluxcd/source-controller/pull/864)
- Update dependencies
  [#869](https://github.com/fluxcd/source-controller/pull/869)

## 0.26.1

**Release date:** 2022-08-11

This prerelease comes with panic recovery, to protect the controller from crashing 
when reconciliations lead to a crash. It also adds OCI documentation and improvements
to the controllers CI pipeline.

Improvements:
- Enable panic recovery
  [#859](https://github.com/fluxcd/source-controller/pull/859)
- build: Ignore CI workflows for markdown files
  [#858](https://github.com/fluxcd/source-controller/pull/858)
- oci: Document Auto-Login usage in SC
  [#860](https://github.com/fluxcd/source-controller/pull/860)

## 0.26.0

**Release date:** 2022-08-08

This prerelease comes with a new API kind named `OCIRepository`,
for fetching OCI artifacts from container registries as defined in
[RFC-0003 Flux OCI support for Kubernetes manifests](https://github.com/fluxcd/flux2/tree/main/rfcs/0003-kubernetes-oci).
Please see the
[OCIRepository API documentation](https://github.com/fluxcd/source-controller/blob/api/v0.26.0/docs/spec/v1beta2/ocirepositories.md)
for more details.

In addition, Helm charts stored in Git can now have dependencies to
other charts stored as OCI artifacts in container registries.

Features:
- Implement OCIRepository reconciliation
  [#788](https://github.com/fluxcd/source-controller/pull/788)

Improvements:
- Enable Umbrella Chart with dependencies from OCI repositories
  [#770](https://github.com/fluxcd/source-controller/pull/770)
- Allow for charts from OCI registries to specify a chart path
  [#856](https://github.com/fluxcd/source-controller/pull/856)
- Remove MUSL and enable threadless libgit2 support
  [#853](https://github.com/fluxcd/source-controller/pull/853)
- Upgrade to Go 1.18
  [#816](https://github.com/fluxcd/source-controller/pull/816)
- Update Azure Go SDK to v1.1.0
  [#786](https://github.com/fluxcd/source-controller/pull/786)

Fixes:
- fix(openapi): full regex for url to prevent error
  [#838](https://github.com/fluxcd/source-controller/pull/838)

## 0.25.11

**Release date:** 2022-07-27

This prerelease comes with an improvement in the Helm OCI Chart to use an exact
version when provided. This makes it possible to work with registries that don't
support listing tags.

Improvements:
- Don't fetch tags when exact version is specified in HelmChart
  [#846](https://github.com/fluxcd/source-controller/pull/846)

## 0.25.10

**Release date:** 2022-07-13

This prerelease fixes SIGSEGV when resolving charts dependencies.
It also brings CI improvements and update dependencies to patch upstream CVEs.

Fixes:
- Fix SIGSEGV when resolving charts dependencies
  [#827](https://github.com/fluxcd/source-controller/pull/827)
- Fix Panic when no artifact in source
  [#832](https://github.com/fluxcd/source-controller/pull/832)

Improvements:
- Update go-yaml to v3.0.1
  [#804](https://github.com/fluxcd/source-controller/pull/804)
- build: provenance and tampering checks for libgit2
  [#823](https://github.com/fluxcd/source-controller/pull/823)
- Decrease fs perms to 0o700
  [#818](https://github.com/fluxcd/source-controller/pull/818)
- build: run darwin tests on macos 10.15, 11 and 12
  [#817](https://github.com/fluxcd/source-controller/pull/817)
- Minor comment updates
  [#812](https://github.com/fluxcd/source-controller/pull/812)
- Split GitHub workflows
  [#811](https://github.com/fluxcd/source-controller/pull/811)
- docs: Add password-protected SSH keys information
  [#801](https://github.com/fluxcd/source-controller/pull/801)
- Bump Helm to v3.9.1
  [#833](https://github.com/fluxcd/source-controller/pull/833)
- Update libgit2 to v1.3.2
  [#834](https://github.com/fluxcd/source-controller/pull/834)

## 0.25.9

**Release date:** 2022-06-29

This prerelease fixes an authentication issue for Helm OCI where the credentials
were cached instead of being discarded after each reconciliation.

Fixes:
- helm-oci: disable cache in oci registry client
  [#799](https://github.com/fluxcd/source-controller/pull/799)
- helm-oci: remove the trailing slash in `spec.url`
  [#799](https://github.com/fluxcd/source-controller/pull/799)

## 0.25.8

**Release date:** 2022-06-24

This prerelease fixes an authentication issue when using libgit2 managed
transport to checkout repos on BitBucket server.

Fixes:
- set request auth if both username and password are non empty
  [#794](https://github.com/fluxcd/source-controller/pull/794)

Improvements:
- libgit2/managed/http: test for incomplete creds
  [#796](https://github.com/fluxcd/source-controller/pull/796)

## 0.25.7

**Release date:** 2022-06-22

This prerelease comes with an improvement in the SSH managed transport error
messages related to known hosts check and removes a deadlock in the SSH smart
subtransport.

Fixes:
- libgit2: remove deadlock
  [#785](https://github.com/fluxcd/source-controller/pull/785)

Improvements:
- libgit2: improve known_hosts error messages
  [#783](https://github.com/fluxcd/source-controller/pull/783)

## 0.25.6

**Release date:** 2022-06-14

This prerelease fixes an issue with leaked SSH connections on
managed transport and adds some general build and libgit2
improvements.

Fixes:
- libgit2: dispose connections in SubTransport.Close
  [#775](https://github.com/fluxcd/source-controller/pull/775)

Improvements:
- build: enable -race for go test
  [#615](https://github.com/fluxcd/source-controller/pull/615)
- libgit2: refactor tests to use managed and unmanaged transport cleanly
  [#777](https://github.com/fluxcd/source-controller/pull/777)
- libgit2: add contextual logging to subtransports
  [#778](https://github.com/fluxcd/source-controller/pull/778)
- libgit2: fix managed transport enabled flag update
  [#781](https://github.com/fluxcd/source-controller/pull/781)

## 0.25.5

**Release date:** 2022-06-08

This prerelease fixes a regression for SSH host key verification
and fixes semver sorting for Helm OCI charts.

In addition, the controller dependencies have been updated to Kubernetes v1.24.1.

Fixes:
- helm: Fix sorting semver from OCI repository tags
  [#769](https://github.com/fluxcd/source-controller/pull/769)
- libgit2: Fix SSH host key verification regression
  [#771](https://github.com/fluxcd/source-controller/pull/771)

Improvements:
- libgit2: Improve HTTP redirection observability
  [#772](https://github.com/fluxcd/source-controller/pull/772)
- Update dependencies
  [#773](https://github.com/fluxcd/source-controller/pull/773)

## 0.25.4

**Release date:** 2022-06-07

This prerelease fixes a regression when accessing Gitlab via HTTPS
when the URL does not have the '.git' suffix. Plus some small 
documentation fixes and dependency updates.

Fixes:
- Update link to v1beta2 in the API spec
  [#764](https://github.com/fluxcd/source-controller/pull/764)
- libgit2: fix gitlab redirection for HTTP
  [#765](https://github.com/fluxcd/source-controller/pull/765)

Improvements:
- Update dependencies
  [#766](https://github.com/fluxcd/source-controller/pull/766)

## 0.25.3

**Release date:** 2022-06-06

This prerelease fixes a regression in HelmRepository index caching.

Fixes:
- Fix repository cache regression
  [#761](https://github.com/fluxcd/source-controller/pull/761)

## 0.25.2

**Release date:** 2022-06-03

This prerelease fixes a bug which prevented the use of the `OptimizedGitClones`
feature when using tags to checkout a Git repository, and adds docs on how to
access Azure Blob using managed identities and aad-pod-identity.

Improvements:
- Add docs on managed identity for Azure Blob
  [#752](https://github.com/fluxcd/source-controller/pull/752)

Fixes:
- libgit2: return CheckoutTag with LastRevision
  [#755](https://github.com/fluxcd/source-controller/pull/755)
- Log on new artifact and failure recovery
  [#759](https://github.com/fluxcd/source-controller/pull/759)

## 0.25.1

**Release date:** 2022-06-02

This prerelease fixes some race conditions in the libgit2 managed ssh smart
subtransport.

Fixes:
- libgit2/managed: fix race issues in ssh transport
  [#753](https://github.com/fluxcd/source-controller/pull/753)

## 0.25.0

**Release date:** 2022-06-01

This prerelease adds support for Helm OCI. Users can specify `.spec.type` of
a `HelmRepository` to use an OCI repository instead of an HTTP/S Helm repository.

Please note that this currently has a couple of limitations (which will be addressed in a future release):
* Chart dependencies from OCI repositories are not supported. [#722](https://github.com/fluxcd/source-controller/issues/722)
* Custom CA certificates are not supported. [#723](https://github.com/fluxcd/source-controller/issues/723)

An example of OCI `HelmRepository` can be found [here](https://github.com/fluxcd/source-controller/blob/api/v0.25.0/docs/spec/v1beta2/helmrepositories.md#helm-oci-repository).

A new flag `--feature-gate` has been added to disable/enable new experimental
features. It works in a similar manner to [Kubernetes feature gates](https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/).

The libgit2 managed transport feature has been enabled by default. Furthermore,
a few changes have been made to make the feature more stable and enable quicker
clones. Users that want to opt out and use the unmanaged transports may do so
by passing the flag `--feature-gate=GitManagedTransport=false`, but please note
that we encourage users not to do so.

GitRepository reconciliation has been made more efficient by adding support for
no-op clones, when checking out repositories using branches or tags.
This feature is also enabled by default, and users can opt out
by passing the flag `--feature-gate=OptimizedGitClones=false`.
Please note that this feature is only active when the managed transport feature
is enabled. Disabling managed transports, quietly disables optimzed Git clones.

Improvements:
- Optimise clone operations
  [#665](https://github.com/fluxcd/source-controller/pull/665)
- [RFC 0002] Flux OCI support for Helm
  [#690](https://github.com/fluxcd/source-controller/pull/690)
- Add Git test coverage for supported algorithms
  [#708](https://github.com/fluxcd/source-controller/pull/708)
- Add new flag --ssh-hostkey-algos
  [#711](https://github.com/fluxcd/source-controller/pull/711)
- libgit2: Disable connection caching
  [#713](https://github.com/fluxcd/source-controller/pull/713)
- Update dependencies
  [#717](https://github.com/fluxcd/source-controller/pull/717)
- libgit2: enable managed transport by default
  [#718](https://github.com/fluxcd/source-controller/pull/718)
- libgit2: Add support for hashed known_hosts
  [#720](https://github.com/fluxcd/source-controller/pull/720)
- Remove dependency on libgit2 credentials callback
  [#727](https://github.com/fluxcd/source-controller/pull/727)
- Update Alpine to v3.16
  [#731](https://github.com/fluxcd/source-controller/pull/731)
- Update dependencies
  [#739](https://github.com/fluxcd/source-controller/pull/739)
- libgit2: enforce context timeout
  [#740](https://github.com/fluxcd/source-controller/pull/740)
- libgit2: Pass ctx to all the transport opts
  [#743](https://github.com/fluxcd/source-controller/pull/743)

Fixes:
- Ensure git status is checked at the correct time
  [#575](https://github.com/fluxcd/source-controller/pull/575)
- libgit2: recover from git2go panic
  [#707](https://github.com/fluxcd/source-controller/pull/707)
- Remove minio region
  [#715](https://github.com/fluxcd/source-controller/pull/715)
- GitRepositoryReconciler no-op clone improvements
  [#724](https://github.com/fluxcd/source-controller/pull/724)
- Support dockerconfigjson with OCI HelmRepositories
  [#725](https://github.com/fluxcd/source-controller/pull/725)
- log when the OCI temp credentials file can't be deleted
  [#726](https://github.com/fluxcd/source-controller/pull/726)
- Helm reconcilers conditions and test improvements
  [#728](https://github.com/fluxcd/source-controller/pull/728)
- reconcile: Set observed gen only when conditions exist
  [#729](https://github.com/fluxcd/source-controller/pull/729)
- helmrepo: Fix test flake in type update test
  [#730](https://github.com/fluxcd/source-controller/pull/730)
- Fix tests failing in Ubuntu
  [#732](https://github.com/fluxcd/source-controller/pull/732)
- tests: ignore proxy settings when running tests
  [#734](https://github.com/fluxcd/source-controller/pull/734)
- gitrepo: gitCheckout() return typed errors only
  [#736](https://github.com/fluxcd/source-controller/pull/736)
- gitrepo: set conditions in gitCheckout
  [#741](https://github.com/fluxcd/source-controller/pull/741)
- libgit2: Enable tests
  [#744](https://github.com/fluxcd/source-controller/pull/744)
- OCI HelmRepo: handle status conditions in-line
  [#748](https://github.com/fluxcd/source-controller/pull/748)
- registry: repo URL and dockerconfig URL mismatch
  [#749](https://github.com/fluxcd/source-controller/pull/749)
- libgit2: fix checkout logic for CheckoutBranch
  [#750](https://github.com/fluxcd/source-controller/pull/750)

## 0.24.4

**Release date:** 2022-05-03

This prerelease comes with dependency updates, and improvements around edge-case
handling of reconcile result calculations ensuring an object is always requeued
when its Status Conditions equal `Ready=False` and `Stalled!=True`.

Improvements:
- summarize: Consider obj status condition in result
  [#703](https://github.com/fluxcd/source-controller/pull/703)
- Update dependencies
  [#705](https://github.com/fluxcd/source-controller/pull/705)

Fixes:
- docs: Remove all traces of "identity.pub" from docs
  [#699](https://github.com/fluxcd/source-controller/pull/699)
- test: use `T.TempDir` to create temporary test directory
  [#701](https://github.com/fluxcd/source-controller/pull/701)
- Switch to gen-crd-api-reference-docs from master
  [#702](https://github.com/fluxcd/source-controller/pull/702)

## 0.24.3

**Release date:** 2022-04-28

This prerelease prevents `Reconciling` and `ArtifactOutdated` conditions from
being set on a `HelmRepository` when the checksum of a cached repository index
changes.

Fixes:
- helmrepo: same revision different checksum scenario
  [#691](https://github.com/fluxcd/source-controller/pull/691)

## 0.24.2

**Release date:** 2022-04-26

This prerelease improves the memory consumption while reconciling a
`HelmRepository`, by only validating the YAML of a fetched index when the
checksum of the retrieved file differs from the current Artifact.

Fixes:
- helm: optimise repository index loading
  [#685](https://github.com/fluxcd/source-controller/pull/685)
- tests: Fix flakiness of git related tests
  [#686](https://github.com/fluxcd/source-controller/pull/686)

## 0.24.1

**Release date:** 2022-04-22

This prerelease fixes a regression bug where the controller would panic in
further to be identified edge-case scenarios in which a `HelmRepository`
Artifact would not have a size.

Fixes:
- Fix panic when HelmRepository's artifact size is nil
  [#683](https://github.com/fluxcd/source-controller/pull/683)

## 0.24.0

**Release date:** 2022-04-19

This prerelease enables the Helm chart dependency manager to make use of the
opt-in memory cache introduced in `v0.23.0`, revises the file permissions set
by the controller, and updates various dependencies.

:warning: **Breaking change:** From this release on, the `RUNTIME_NAMESPACE`
environment variable is no longer taken into account to configure the
advertised HTTP/S address of the storage. Instead, [variable
substitution](https://kubernetes.io/docs/tasks/inject-data-application/define-interdependent-environment-variables/#define-an-environment-dependent-variable-for-a-container)
must be used, as described in [the changelog entry for `v0.5.2`](#052).

Improvements:
- Change all file permissions to octal format
  [#653](https://github.com/fluxcd/source-controller/pull/653)
- Enable dependency manager to use in-memory cache
  [#667](https://github.com/fluxcd/source-controller/pull/667)
- Update libgit2 image to v1.3.1
  [#671](https://github.com/fluxcd/source-controller/pull/671)
- Remove hostname hyphen split block
  [#672](https://github.com/fluxcd/source-controller/pull/672)
- Update dependencies
  [#675](https://github.com/fluxcd/source-controller/pull/675)
  [#676](https://github.com/fluxcd/source-controller/pull/676)
  [#677](https://github.com/fluxcd/source-controller/pull/677)

## 0.23.0

**Release date:** 2022-04-12

This prerelease introduces new retention options for Garbage Collection,
a new opt-in in-memory cache for `HelmRepository` index files, improves
notifications following reconciling failures, brings ways to configure 
Key Exchange Algorithms, plus some extra housekeeping awesomeness.

Garbage Collection is enabled by default, and now its retention options
are configurable with the flags: `--artifact-retention-ttl` (default: `60s`)
and `--artifact-retention-records` (default: `2`). They define the minimum
time to live and the maximum amount of artifacts to survive a collection.

A new notification is now emitted to identify recovery from failures. It 
is triggered when a failed reconciliation is followed by a successful one, and
the notification message is the same that's sent in usual successful source
reconciliation message about the stored artifact.

The opt-in in-memory cache for `HelmRepository` addresses issues where the
index file is loaded and unmarshalled in concurrent reconciliation resulting
in a heavy memory footprint. It can be configured using the flags:
`--helm-cache-max-size`, `--helm-cache-ttl`, `--helm-cache-purge-interval`.

The Key Exchange Algorithms used when establishing SSH connections are
based on the defaults configured upstream in `go-git` and `golang.org/x/crypto`.
Now this can be overriden with the flag `--ssh-kex-algos`. Note this applies
to the `go-git` gitImplementation or the `libgit2` gitImplementation but
_only_ when Managed Transport is being used.

Managed Transport for `libgit2` now introduces self-healing capabilities,
to recover from failure when long-running connections become stale. 

The exponental back-off retry can be configured with the new flags:
`--min-retry-delay` (default: `750ms`) and `--max-retry-delay`
(default: `15min`). Previously the defaults were set to `5ms` and `1000s`,
which in some cases impaired the controller's ability to self-heal 
(e.g. retrying failing SSH connections).


Introduction of a secure directory loader which improves the handling
of Helm charts paths.

Improvements:
- update werf.io docs links
  [#651](https://github.com/fluxcd/source-controller/pull/651)
- Add optional in-memory cache of HelmRepository index files
  [#626](https://github.com/fluxcd/source-controller/pull/626)
- Add flag to allow configuration of SSH kex algos
  [#655](https://github.com/fluxcd/source-controller/pull/655)
- Garbage collect with provided retention options
  [#638](https://github.com/fluxcd/source-controller/pull/638)
- Avoid event logging GC failure
  [#659](https://github.com/fluxcd/source-controller/pull/659)
- Add notify() in all the reconcilers
  [#624](https://github.com/fluxcd/source-controller/pull/624)
- Remove leftover timeout in reconcilers
  [#660](https://github.com/fluxcd/source-controller/pull/660)
- libgit2: managed transport improvements
  [#658](https://github.com/fluxcd/source-controller/pull/658)
- helm: introduce customized chart loaders
  [#663](https://github.com/fluxcd/source-controller/pull/663)
- Add flags to configure exponential back-off retry
  [#664](https://github.com/fluxcd/source-controller/pull/664)

## 0.22.5

**Release date:** 2022-03-30

This prerelease improves the Status API of the Source objects to
reflect more accurate Status Condition information.

In addition, it also fixes a bug in `go-git` implementation due to which cloning
public Git repository failed without any credentials since version `0.17.0`, and
some general stability improvements in the libgit2 experimental managed
transport.

Improvements:
- Align fuzzing deps
  [#644](https://github.com/fluxcd/source-controller/pull/644)
- Separate positive polarity conditions for ArtifactInStorage
  [#646](https://github.com/fluxcd/source-controller/pull/646)
- Removes empty credentials from Basic Auth
  [#648](https://github.com/fluxcd/source-controller/pull/648)
- libgit2: fix access to nil t.stdin and improve observability
  [#649](https://github.com/fluxcd/source-controller/pull/649)

## 0.22.4

**Release date:** 2022-03-28

This prerelease improves on the experimental managed transport overall
stability. Changes of note:
- SSH connections now being reused across git operations.
- Leaked HTTP connections are now fixed.
- The long-standing SSH intermittent errors are addressed by the cached connections.

Fixes:
- Various fixes for managed transport
  [#637](https://github.com/fluxcd/source-controller/pull/637)

## 0.22.3

**Release date:** 2022-03-25

This prerelease fixes a regression bug introduced in `v0.22.0`, which would
cause a `GitRepository` to end up in a `Stalled` state if an include did not
have an Artifact available.

Fixes:
- gitrepo: Do not stall when no included artifact
  [#639](https://github.com/fluxcd/source-controller/pull/639)
- Fix dpanic issue when logging odd number of args
  [#641](https://github.com/fluxcd/source-controller/pull/641)

## 0.22.2

**Release date:** 2022-03-23

This prerelease ensures (Kubernetes) Event annotations are prefixed with the
FQDN of the Source API Group. For example, `revision` is now
`source.werf.io/revision`.

This to facilitate improvements to the notification-controller, where
annotations prefixed with the FQDN of the Group of the Involved Object will be
transformed into "fields".

Fixes:
- Prefix event annotations with API Group FQDN
  [#632](https://github.com/fluxcd/source-controller/pull/632)

## 0.22.1

**Release date:** 2022-03-23

This prerelease fixes a regression in which `.sourceignore` rules for a
`GitRepository` would not be matched correctly.

Fixes:
- fix: configure domain for .sourceignore rules
  [#629](https://github.com/fluxcd/source-controller/pull/629)

## 0.22.0

**Release date:** 2022-03-17

This prerelease comes with new reconcilers which make use of `fluxcd/pkg`
utilities for common runtime operations, and graduates the API to `v1beta2`.

:warning: **It is required** to update the source-controller Custom Resource
Definitions on your cluster and/or in Git.

### Breaking changes

- `Bucket` resources do now take the provided etag for object storage items
  into account during the calculation of the revision. As a result, items will
  no longer be downloaded on every reconcile if none of them have changed.
- `HelmChart` resources do now advertise the observed chart name
  (`.status.observedChartName`) and Source (reference) Artifact revision
  (`.status.observedSourceArtifactRevision`) in the Status. The information is 
  used to more efficiently react to source revision and/or chart changes.

### Features and Improvements

#### API specifications in a user-friendly format

[The new specifications for the `v1beta2` API](https://github.com/fluxcd/source-controller/tree/v0.22.0/docs/spec/v1beta2)
have been written in a new format with the aim to be more valuable to a user.
Featuring separate sections with examples, and information on how to write
and work with them.

#### Artifact now advertises size

The size (in bytes) of a tarball Artifact is now advertised in the Size
(`.size`) field of the Artifact. This can be utilized by users to e.g. quickly
see  if `.sourceignore` rules have an effect, or be displayed in a UI.

#### Azure Blob Storage support for `Bucket` resources

The `.spec.provider` of a `Bucket` resource can now be set to `azure` to
instruct the controller to use the
[Azure Blob Storage SDK](https://github.com/Azure/azure-sdk-for-go/tree/main/sdk/storage/azblob#readme)
while fetching objects. This allows for authenticating using Service
Principals, Managed Identities and Shared Keys.

For more information, see the
[Bucket spec about the Azure provider](https://github.com/fluxcd/source-controller/blob/v0.22.0/docs/spec/v1beta2/buckets.md#azure).

#### Enhanced Kubernetes Conditions

Source API resources will now advertise more explicit Condition types (more
about the types in "API changes"), provide `Reconciling` and `Stalled`
Conditions where applicable for
[better integration with `kstatus`](https://github.com/kubernetes-sigs/cli-utils/blob/master/pkg/kstatus/README.md#conditions),
and record the Observed Generation on the Condition.

For a detailed overview per Source type, refer to the spec:

- [GitRepository](https://github.com/fluxcd/source-controller/blob/v0.22.0/docs/spec/v1beta2/gitrepositories.md#conditions)
- [HelmRepository](https://github.com/fluxcd/source-controller/blob/v0.22.0/docs/spec/v1beta2/helmrepositories.md#conditions)
- [HelmChart](https://github.com/fluxcd/source-controller/blob/v0.22.0/docs/spec/v1beta2/helmcharts.md#conditions)
- [Bucket](https://github.com/fluxcd/source-controller/blob/v0.22.0/docs/spec/v1beta2/buckets.md#conditions)

#### Enhanced Kubernetes Events (and notifications)

The Kubernetes Events the controller emits have been reworked to provide a
proper reason, and more informative messages.
Users making use of the notification-controller will notice this as well, as
this same information is used to compose notifications.

#### Experimental managed transport for `libgit2` Git implementation

The `libgit2` Git implementation supports a new experimental transport to
improve reliability, adding timeout enforcement for Git network operations.
Opt-in  by setting the environment variable `EXPERIMENTAL_GIT_TRANSPORT` to
`true` in the controller's Deployment. This will result in the low-level
transport being handled by the controller, instead of `libgit2`. It may result
in an increased number of timeout messages in the logs, however it will remove
the ability of Git operations to make the controllers hang indefinitely.

#### Reuse of HTTP/S transport for Helm repository index and chart downloads

The Helm dependency has been updated to `v3.8.1`, with a patch applied from
https://github.com/helm/helm/pull/10568. Using this patch, the HTTP transports
are now managed by the controller, to prevent the clogging of thousands of open
TCP connections on some instances.

#### Update of `libgit2` Git implementation to `v1.3.x`

The `libgit2` Git implementation has been updated to `v1.3.x`, allowing us to
provide better error signals for authentication, certificate and transport
failures. Effectively, this means that instead of a `unable to clone: User`
error string, a descriptive one is now given.

In addition, `NO_PROXY` settings are now properly taken into account.

#### Preparation of support for `rsa-ssh2-256/512`

The dependency on `golang.org/x/crypto` has been updated to
`v0.0.0-20220315160706-3147a52a75dd`, as preparation of support for
`rsa-ssh2-256/512`. This should theoretically work out of the box for
`known_hosts` entries and `go-git` Git provider credentials, but has not been
widely tested.

### API changes

The `source.werf.io/v1beta2` API is backwards compatible with `v1beta1`.

- Introduction of `Reconciling` and `Stalled` Condition types for [better
  integration with `kstatus`](https://github.com/kubernetes-sigs/cli-utils/blob/master/pkg/kstatus/README.md#conditions).
- Introduction of new Condition types to provide better signals and failure
  indications:
  * `ArtifactOutdated`: indicates the current Artifact of the Source is outdated.
  * `SourceVerified`: indicates the integrity of the Source has been verified.
  * `FetchFailed`: indicates a transient or persistent fetch failure of the
    upstream Source.
  * `BuildFailed`:  indicates a transient or persistent build failure of a
    Source's Artifact.
  * `StorageOperationFailed`: indicates a transient or persistent failure
    related to storage.
  * `IncludeUnavailable`: indicates an include is not available. For example,
    because it does not exist, or does not have an Artifact.
- Introduction of a Size (in bytes) field (`.status.artifact.size`) in the
  Artifact object.
- Introduction of `ObservedChartName` (`.status.observedChartName`) and
  `ObservedSourceArtifactRevision` (`.status.observedSourceArtifactRevision`)
  fields in the `HelmChart` Status.
- Introduction of `azure` provider implementation for `Bucket`.

Updating the manifests in Git to `v1beta2` can be done at any time after the
source-controller upgrade.

### Full list of changes

- Upgrade to golang-with-libgit2:1.1.1.6 and use static libraries for in
  development
  [#562](https://github.com/fluxcd/source-controller/pull/562)
- Initial fuzzing tests
  [#572](https://github.com/fluxcd/source-controller/pull/572)
- Validate libgit2 args are set correctly
  [#574](https://github.com/fluxcd/source-controller/pull/574)
- Download libgit2 libraries for fuzzing
  [#572](https://github.com/fluxcd/source-controller/pull/577)
- Upgrade libgit2 to 1.3.0 and git2go to v33
  [#573](https://github.com/fluxcd/source-controller/pull/573)
- pkg/git: Include commit message and URL in checkout error
  [#579](https://github.com/fluxcd/source-controller/pull/579)
- Add support for multiple fuzz sanitizers
  [#580](https://github.com/fluxcd/source-controller/pull/580)
- Upgrade controller-runtime to v0.11.1 and docker/distribution to v2.8.0
  [#583](https://github.com/fluxcd/source-controller/pull/583)
- Move to `v1beta2` API and rewrite reconcilers
  [#586](https://github.com/fluxcd/source-controller/pull/586)
- git/libgit2: set CheckoutForce on branch strategy
  [#589](https://github.com/fluxcd/source-controller/pull/589)
- Reuse transport for Helm downloads
  [#590](https://github.com/fluxcd/source-controller/pull/590)
- Update object API version in the sample configs
  [#591](https://github.com/fluxcd/source-controller/pull/591)
- api: Move Status in CRD printcolumn to the end
  [#592](https://github.com/fluxcd/source-controller/pull/592)
- Update github.com/sosedoff/gitkit to v0.3.0 (CVE fix)
  [#594](https://github.com/fluxcd/source-controller/pull/594)
- Remove redundant reconciling condition in reconcileArtifact
  [#595](https://github.com/fluxcd/source-controller/pull/595)
- Implement Size field on archived artifacts
  [#597](https://github.com/fluxcd/source-controller/pull/597)
- Add native Azure Blob support
  [#598](https://github.com/fluxcd/source-controller/pull/598)
- Experimental managed transport for libgit2 operations
  [#606](https://github.com/fluxcd/source-controller/pull/606)
- Update Helm to patched v3.8.1
  [#609](https://github.com/fluxcd/source-controller/pull/609)
- Add new condition StorageOperationFailedCondition
  [#612](https://github.com/fluxcd/source-controller/pull/612)
- Prioritize StorageOperationFailedCondition
  [#613](https://github.com/fluxcd/source-controller/pull/613)
- Update dependencies
  [#600](https://github.com/fluxcd/source-controller/pull/600)
  [#616](https://github.com/fluxcd/source-controller/pull/616)
- api/v1beta2: add note on Condition polarity
  [#622](https://github.com/fluxcd/source-controller/pull/622)

## 0.21.2

**Release date:** 2022-02-07

This prerelease changes the default timeout of `GitRepositories` and `Buckets` from `20s` to `60s`.
When using the `libgit2` Git implementation, increasing the timeout helps avoid
`Error waiting on socket` intermittent SSH cloning failures.

Improvements:
- Increase default timeout to 60s
  [#570](https://github.com/fluxcd/source-controller/pull/570)

## 0.21.1

**Release date:** 2022-01-27

This prerelease comes with a bug fix to ensure the `libgit2` Git implementation
respects hostnames with and without port while matching against `known_hosts`.

Fixes:
- Fix host mismatch in libgit2
  [#561](https://github.com/fluxcd/source-controller/pull/561)

## 0.21.0

**Release date:** 2022-01-26

This prerelease comes with changes to the base image used to build and
run the controller, replacing Debian Unstable (Sid) with Alpine 3.15.
The controller is now statically built and includes libgit2 along with
its main dependencies.

The controller container images are signed with
[Cosign and GitHub OIDC](https://github.com/sigstore/cosign/blob/22007e56aee419ae361c9f021869a30e9ae7be03/KEYLESS.md),
and a Software Bill of Materials in [SPDX format](https://spdx.dev) has been published on the release page.

Starting with this version, the controller deployment conforms to the
Kubernetes [restricted pod security standard](https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted):
- all Linux capabilities were dropped
- the root filesystem was set to read-only
- the seccomp profile was set to the runtime default
- run as non-root was enabled
- the filesystem group was set to 1337
- the user and group ID was set to 65534

**Breaking changes**:
- The use of new seccomp API requires Kubernetes 1.19.
- The controller container is now executed under 65534:65534 (userid:groupid).
  This change may break deployments that hard-coded the user ID of 'controller' in their PodSecurityPolicy.

Improvements:
- Statically build using musl toolchain and target alpine
  [#558](https://github.com/fluxcd/source-controller/pull/558)
- Publish SBOM and sign release artifacts
  [#550](https://github.com/fluxcd/source-controller/pull/550)
- security: Drop capabilities, set userid and enable seccomp
  [#521](https://github.com/fluxcd/source-controller/pull/521)
- docs: Add git proxy support docs
  [#547](https://github.com/fluxcd/source-controller/pull/547)
- libgit2: Configured libgit2 clone ProxyOptions
  [#524](https://github.com/fluxcd/source-controller/pull/524)
- storage: include directories in artifact tarball
  [#543](https://github.com/fluxcd/source-controller/pull/543)
- Add Permissions to GitHub Workflows
  [#551](https://github.com/fluxcd/source-controller/pull/551)
- Update git2go to v31.7.6
  [#554](https://github.com/fluxcd/source-controller/pull/554)
- Update dev docs
  [#555](https://github.com/fluxcd/source-controller/pull/555)

Fixes:
- e2e: Set timeout to fix intermittent errors
  [#549](https://github.com/fluxcd/source-controller/pull/549)
- git/libgit2: Fix failing tests when the default branch is not "master"
  [#545](https://github.com/fluxcd/source-controller/pull/545)
- Remove temp file name from Helm index cache err
  [#540](https://github.com/fluxcd/source-controller/pull/540)
- Fix makefile envtest and controller-gen usage
  [#539](https://github.com/fluxcd/source-controller/pull/539)
- Update file close operation to not use defer and add test case for CopyFromPath
  [#538](https://github.com/fluxcd/source-controller/pull/538)
- Fix the missing protocol for the first port in manager config
  [#556](https://github.com/fluxcd/source-controller/pull/556)

## 0.20.1

**Release date:** 2022-01-07

This prerelease comes with an update for `github.com/containerd/containerd` to `v1.5.9`
to please static security analysers and fix any warnings for CVE-2021-43816.

Improvements:
- Log the error when tmp cleanup fails
  [#533](https://github.com/fluxcd/source-controller/pull/533)
- Update containerd to v1.5.9 (fix CVE-2021-43816)
  [#532](https://github.com/fluxcd/source-controller/pull/532)

## 0.20.0

**Release date:** 2022-01-05

This prerelease comes with an update to the Kubernetes and controller-runtime dependencies
to align them with the Kubernetes 1.23 release, including an update of Helm to `v3.7.2`.

In addition, the controller is now built with Go 1.17, and 
`github.com/containerd/containerd` was updated to `v1.5.8` to please
static security analysers and fix any warnings for GHSA-5j5w-g665-5m35.

Improvements:
- Update Go to v1.17
  [#473](https://github.com/fluxcd/source-controller/pull/473)
- Update build dependencies
  [#520](https://github.com/fluxcd/source-controller/pull/520)
- Update containerd to v1.5.8 (fix GHSA-5j5w-g665-5m35)
  [#529](https://github.com/fluxcd/source-controller/pull/529)

## 0.19.2

**Release date:** 2021-12-09

This prerelease ensures the API resources are not prematurely marked as `Ready`
by tools like `kstatus`, while the controller has not observed a newly created
resource yet, by defaulting the `ObservedGeneration` in the status of the
resource to `-1`.

In addition, it changes the faulty `URL` column for `Bucket` resources to
`Endpoint`, and updates `github.com/opencontainers/runc` to `v1.0.3` to please
static security analysers and fix any warnings for CVE-2021-43784.

Improvements:
- crds: set default observedGeneration to -1
  [#517](https://github.com/fluxcd/source-controller/pull/517)
- Update github.com/opencontainers/runc to v1.0.3 (fix CVE-2021-43784)
  [#518](https://github.com/fluxcd/source-controller/pull/518)

Fixes:
- Change bucket JSONPath from URL to endpoint
  [#514](https://github.com/fluxcd/source-controller/pull/514)

## 0.19.1

**Release date:** 2021-12-03

This prerelease changes the length of the SHA hex added to the SemVer metadata
of a `HelmChart`, when `ReconcileStrategy` is set to `Revision`, to a short SHA
hex of the first 12 characters. This is to prevent situations in which the
SemVer would exceed the length limit of 63 characters when utilized in a Helm
chart as a label value.

Concrete example: `1.2.3+a4303ff0f6fb560ea032f9981c6bd7c7f146d083.1` becomes
`1.2.3+a4303ff0f6fb.1`

:warning: There have been additional user reports about charts complaining
about a `+` character in the label:

```
metadata.labels: Invalid value: "1.2.3+a4303ff0f6fb560ea032f9981c6bd7c7f146d083.1": a valid label must be an empty string or consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyValue', or 'my_value', or '12345', regex used for validation is '(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?')
```

Given the [Helm chart best practices mention to replace this character with a
`_`](https://helm.sh/docs/chart_best_practices/conventions/#version-numbers),
we encourage you to patch this in your (upstream) chart.
Pseudo example using [template functions](https://helm.sh/docs/chart_template_guide/function_list/):

```yaml
{{- replace "+" "_" .Chart.Version | trunc 63 }}
```

Fixes:
- controllers: use short SHA in chart SemVer meta
  [#507](https://github.com/fluxcd/source-controller/pull/507)

## 0.19.0

**Release date:** 2021-11-23

For this prerelease we focused on improving the logic around Helm resources,
with as goal to be more efficient, and increase code and testing quality.

It contains **breaking behavioral changes** to `HelmRepository` and
`HelmChart` resources:

- Helm repository index files and/or charts **must** not exceed the new declared 
  runtime default limits to [avoid out-of-memory crashes](https://github.com/fluxcd/source-controller/issues/470),
  overwriting the default configuration is possible.

  | Type | Default max size **(in MiB)** | Option flag to overwrite |
  |---|---|---|
  | Helm repository index | 50MiB | `--helm-index-max-size=<bytes>` |
  | Helm chart | 10MiB | `--helm-chart-max-size=<bytes>` |
  | Singe file from Helm chart | 5MiB | `--helm-chart-file-max-size=<bytes>` |

- Using `ValuesFiles` in a `HelmChart` will now append a `.<Generation>` to the SemVer
  metadata of the packaged chart and the revision of the Artifact. For example,
  `v1.2.3+.5` for a `HelmChart` resource with generation `5`. This ensures consumers
  of the chart are able to notice changes to the merged values without the underlying
  chart source (revision) changing.

While an optional ACL field has been added to the API resources, there is no
implementation at time of release.

Improvements:
- helm: factor out logic from controller into package
  [#485](https://github.com/fluxcd/source-controller/pull/485)
- Add ACL option field to Source API
  [#495](https://github.com/fluxcd/source-controller/pull/495)
- Update various dependencies to mitigate CVE warning
  [#493](https://github.com/fluxcd/source-controller/pull/493)
- Update controller-runtime to v0.10.2
  [#497](https://github.com/fluxcd/source-controller/pull/497)
- Update github.com/minio/minio-go to `v7.0.15`
  [#498](https://github.com/fluxcd/source-controller/pull/498)
- internal/helm: LoadChartMetadataFromArchive improvements
  [#502](https://github.com/fluxcd/source-controller/pull/502)
- internal/helm: validate loaded chart metadata obj
  [#503](https://github.com/fluxcd/source-controller/pull/503)

Fixes:
- tests: ensure proper garbage collection
  [#489](https://github.com/fluxcd/source-controller/pull/489)
- controllers: Fix helmchart values file merge test
  [#494](https://github.com/fluxcd/source-controller/pull/494)
- Update test shield link
  [#496](https://github.com/fluxcd/source-controller/pull/496)
- controllers: absolute local path for cached chart
  [#500](https://github.com/fluxcd/source-controller/pull/500)
- Various small fixes across the code base
  [#501](https://github.com/fluxcd/source-controller/pull/501)

## 0.18.0

**Release date:** 2021-11-12

This prerelease changes the format of the artifact checksum from `SHA1` to `SHA256`
to mitigate chosen-prefix and length extension attacks.

Improvements:
* storage: change Artifact checksum to SHA256
  [#487](https://github.com/fluxcd/source-controller/pull/487)

## 0.17.2

**Release date:** 2021-11-04

This prerelease comes with a bug fix to ensure the `libgit2` Git implementation
respects the operation `timeout` specified in `GitRepositorySpec`.

Fixes:
* libgit2: ensure context timeout cancels transfer
  [#477](https://github.com/fluxcd/source-controller/pull/477)

## 0.17.1

**Release date:** 2021-10-30

This prerelease fixes a pointer error that was returned in v0.17.0 during
the import of public keys to verify a commit.

Fixes:
* Fix pointer error during public key import
  [#479](https://github.com/fluxcd/source-controller/pull/479)

## 0.17.0

**Release date:** 2021-10-28

For this prerelease we focused on further improving the Git implementations, partly
to increase stability and test coverage, partly to ensure they are prepared to be
moved out into a separate module. With this work, it is now possible to define just
a Git commit as a reference, which will result in an `Artifact` with a `Revision`
format of `HEAD/<commit SHA>`.

For the `go-git` implementation, defining the branch and a commit reference will
result in a more efficient shallow clone, and using this information when it is
available to you is therefore encouraged.

Improvements:
* git: refactor authentication, checkout and verification
  [#462](https://github.com/fluxcd/source-controller/pull/462)

Fixes:
* libgit2: handle EOF in parseKnownHosts()
  [#475](https://github.com/fluxcd/source-controller/pull/475)

## 0.16.1

**Release date:** 2021-10-22

This prerelease adds support for GCP storage authentication using the
`GOOGLE_APPLICATION_CREDENTIALS` environment variable available in the container,
or by defining a `secretRef` with a `serviceaccount` JSON data blob. See
[#434](https://github.com/fluxcd/source-controller/pull/434) for more information.

In addition, several bug fixes and improvements have been made to the `libgit2`
Git implementation, ensuring the checkout logic is more rigorously tested.

During this work, it was discovered that both Git implementation had a minor bug
resulting in `v` prefixed tags with metadata added to it (e.g. `v0.1.0+build-1`
and `v0.1.0+build-2`) were not properly sorted by their commit timestamp, which
has been addressed as well.

Improvements:
* Add GCP storage authentication
  [#434](https://github.com/fluxcd/source-controller/pull/434)

Fixes:
* libgit2: correctly resolve (annotated) tags
  [#457](https://github.com/fluxcd/source-controller/pull/457)
* libgit2: add remaining checkout strategy tests
  [#458](https://github.com/fluxcd/source-controller/pull/458)
* git: ensure original tag is used for TS lookup
  [#459](https://github.com/fluxcd/source-controller/pull/459)

## 0.16.0

**Release date:** 2021-10-08

This prerelease improves the configuration of the `libgit2` C library, solving
most issues around private key formats (e.g. PKCS#8 and ED25519) by ensuring
it is linked against OpenSSL and LibSSH2.

In addition, the `HelmChart` resource does now allow setting a `ReconcileStrategy`
to define when a new artifact for a chart should be created for charts from
`Bucket` and `GitRepository` sources. By setting this to `Revision`, you no
longer have to bump the version in the `Chart.yaml` file, but a new chart will
automatically be made available when the revision of the Source changes.

Fixes:
* Update containerd and runc to fix CVEs
  [#446](https://github.com/fluxcd/source-controller/pull/446)

Improvements:
* Add reconcile strategy for HelmCharts
  [#308](https://github.com/fluxcd/source-controller/pull/308)
* Update github.com/libgit2/git2go to v31.6.1
  [#437](https://github.com/fluxcd/source-controller/pull/437)

## 0.15.4

**Release date:** 2021-08-05

This prerelease comes with a series of bug fixes, and updates the Kubernetes
dependencies to `v1.21.3` and Helm to `v3.6.3`.

Fixes:
* Fix tag checkout with libgit2
  [#394](https://github.com/fluxcd/source-controller/pull/394)
* Take relative paths in account for Bucket revision
  [#403](https://github.com/fluxcd/source-controller/pull/403)
* Ensure rel path never traverses outside Storage
  [#417](https://github.com/fluxcd/source-controller/pull/417)
* Use same SemVer logic in both Git implementations
  [#417](https://github.com/fluxcd/source-controller/pull/417)
* storage: strip env specific data during archive
  [#417](https://github.com/fluxcd/source-controller/pull/417)

Improvements:
* e2e: Update Kubernetes to v1.21
  [#396](https://github.com/fluxcd/source-controller/pull/396)
* Update Helm to v3.6.3
  [#400](https://github.com/fluxcd/source-controller/pull/400)
* Add setup-envtest in Makefile
  [#404](https://github.com/fluxcd/source-controller/pull/404)
* Use ObjectKeyFromObject instead of ObjectKey
  [#405](https://github.com/fluxcd/source-controller/pull/405)
* Drop deprecated `io/ioutil`
  [#409](https://github.com/fluxcd/source-controller/pull/409)
* Update dependencies
  [#416](https://github.com/fluxcd/source-controller/pull/416)

## 0.15.3

**Release date:** 2021-06-29

This prerelease comes with a bug fix to the Git tag checkout when using `libgit2`.

Fixes:
* Fix tag checkout with libgit2
  [#394](https://github.com/fluxcd/source-controller/pull/394)

## 0.15.2

**Release date:** 2021-06-22

This prerelease updates the build constraints for `libgit2`, ensuring
the underlying `libssh2-1-dev` dependency is linked against
`libssl-dev` instead of `libgcrypt` so that PKCS* private keys can
be used without any issues.

Fixes:
* Use libgit2 from "unstable" / "sid"
  [#391](https://github.com/fluxcd/source-controller/pull/391)

## 0.15.1

**Release date:** 2021-06-18

This prerelease updates the Helm dependency to `v3.6.1`, this update
is a security update and ensures credentials are only passed to the
defined URL in a `HelmRelease`.

**Note:** there have been reports from the Helm user community that
this new behavior may cause issues with Helm repository providers
like Artifactory. If this happens to be a problem for you, the
behavior can be disabled by setting `PassCredentials` in the
`HelmRepositorySpec`.

For more details, see:
https://github.com/helm/helm/security/advisories/GHSA-56hp-xqp3-w2jf

Improvements:
* Update Helm to v3.6.1
  [#388](https://github.com/fluxcd/source-controller/pull/388)

## 0.15.0

**Release date:** 2021-06-17

This prerelease comes with changes to the base image used to build
the controller, replacing Alpine with Debian slim. This change
allows the controller to run on ARM64, previously broken in v0.14.0.

Improvements:
* Use Debian instead of Alpine for multi-arch builds
  [#386](https://github.com/fluxcd/source-controller/pull/386)
* Panic on non-nil AddToScheme errors in main init
  [#387](https://github.com/fluxcd/source-controller/pull/387)

## 0.14.0

**Release date:** 2021-06-09

This prerelease comes with an update to the Kubernetes and controller-runtime
dependencies to align them with the Kubernetes 1.21 release, including an update
of Helm to `v3.6.0`.

After a failed ARMv7 build during the initial release attempt of this version,
`binutils-gold` has been introduced to the `builder` image [to allow `gccgo` to
build using the Gold linker](https://golang.org/doc/install/gccgo#Gold).

Improvements:
* Update K8s, controller-runtime and fluxcd/pkg deps
  [#374](https://github.com/fluxcd/source-controller/pull/374)
* Add nightly builds workflow
  [#376](https://github.com/fluxcd/source-controller/pull/376)

Fixes:
* Reinstate Git cloning timeout
  [#372](https://github.com/fluxcd/source-controller/pull/372)
* Use `binutils-gold` in builder image
  [#377](https://github.com/fluxcd/source-controller/pull/377)
* Use `github.repository` property for image name
  [#378](https://github.com/fluxcd/source-controller/pull/378)

## 0.13.2

**Release date:** 2021-06-02

This prerelease comes with an update to the `go-git` implementation
dependency, bumping the version to `v5.4.2`. This should resolve any
issues with `object not found` and `empty git-upload-pack given`
errors that were thrown for some Git repositories since `0.13.0`.

Fixes:
* Update go-git to v5.4.2
  [#370](https://github.com/fluxcd/source-controller/pull/370)

## 0.13.1

**Release date:** 2021-05-28

This prerelease comes with a bug fix to the `GitRepository` include feature.

Fixes:
* Fix GitRepository include for nested paths
  [#367](https://github.com/fluxcd/source-controller/pull/367)

## 0.13.0

**Release date:** 2021-05-26

This prerelease comes with support for including the contents of a Git repository into another.

The [include feature](https://github.com/fluxcd/source-controller/blob/api/v0.13.0/docs/spec/v1beta1/gitrepositories.md#including-gitrepository)
has multiple benefits over regular Git submodules:

* Including a `GitRepository` allows you to use different authentication methods for different repositories.
* A change in the included repository will trigger an update of the including repository.
* Multiple `GitRepositories` could include the same repository, which decreases the amount of cloning done compared to using submodules.

Features:
* Add include property to GitRepositories
  [#348](https://github.com/fluxcd/source-controller/pull/348)

Improvements:
* Update Git packages
  [#365](https://github.com/fluxcd/source-controller/pull/365)

## 0.12.2

**Release date:** 2021-05-10

This prerelease comes with a bug fix to `Bucket` source ignore
handling.

Fixes:
* Split bucket item key by `/` to satisfy matcher
  [#356](https://github.com/fluxcd/source-controller/pull/356)

## 0.12.1

**Release date:** 2021-04-23

This prerelease comes with a bug fix to source ignore handling.

Fixes:
* Configure ignore domain for GitRepository rules
  [#351](https://github.com/fluxcd/source-controller/pull/351)

## 0.12.0

**Release date:** 2021-04-21

This prerelease comes with support for SSH keys with a passphrase.

The `.sourceignore` files are now loaded by traversing through the directory tree,
instead of just looking at the root.

The HelmChart `ValueFile` string field has been deprecated in favour of
`ValuesFiles` string array.

Features:
* Support SSH private key with password
  [#338](https://github.com/fluxcd/source-controller/pull/338)
  [#339](https://github.com/fluxcd/source-controller/pull/339)
* Add `ValuesFiles` to HelmChart spec
  [#305](https://github.com/fluxcd/source-controller/pull/305)

Improvements:
* Check ignore matches before Bucket item downloads
  [#337](https://github.com/fluxcd/source-controller/pull/337)
* Add short name for Git and Helm repositories
  [#334](https://github.com/fluxcd/source-controller/pull/334)
* Update Helm to v3.5.4
  [#340](https://github.com/fluxcd/source-controller/pull/340)

Fixes:
* Write chart data on identical values overwrite
  [#345](https://github.com/fluxcd/source-controller/pull/345)
* Fix HelmChart values tests
  [#332](https://github.com/fluxcd/source-controller/pull/332)

## 0.11.0

**Release date:** 2021-03-31

This prerelease comes with support for
[Git submodules](https://github.com/fluxcd/source-controller/blob/api/v0.11.0/docs/spec/v1beta1/gitrepositories.md#git-submodules)
and [self-signed TLS certs](https://github.com/fluxcd/source-controller/blob/api/v0.11.0/docs/spec/v1beta1/gitrepositories.md#https-self-signed-certificates)
when using `gitProvider: go-git`.

Features:
* Add support for Git submodules with go-git
  [#327](https://github.com/fluxcd/source-controller/pull/327)
* Enable self-signed certs for go-git
  [#324](https://github.com/fluxcd/source-controller/pull/324)

Improvements:
* Add well-known CI configs to exclusion list
  [#329](https://github.com/fluxcd/source-controller/pull/329)

## 0.10.0

**Release date:** 2021-03-26

This is the tenth MINOR prerelease.

This prerelease comes with a breaking change to the leader election ID
from `305740c0.fluxcd.io` to `source-controller-leader-election`
to be more descriptive. This change should not have an impact on most
installations, as the default replica count is `1`. If you are running
a setup with multiple replicas, it is however advised to scale down
before  upgrading.

The suspended status of resources is now recorded to a
`gotk_suspend_status` Prometheus gauge metric.

Improvements:
* Record suspend metrics in controllers
  [#311](https://github.com/fluxcd/source-controller/pull/311)
* Set leader election deadline to 30s
  [#318](https://github.com/fluxcd/notification-controller/pull/318)
* Change leader election ID to be more descriptive
  [#319](https://github.com/fluxcd/notification-controller/pull/319)

## 0.9.1

**Release date:** 2021-03-15

This prerelease comes with improvements to Git clone errors and
patch updates to dependencies.

Improvements:
* Tidy git clone errors
  [#304](https://github.com/fluxcd/source-controller/pull/304)
* Update dependencies
  [#307](https://github.com/fluxcd/source-controller/pull/307)

## 0.9.0

**Release date:** 2021-02-23

This is the ninth MINOR prerelease.

Due to changes in Helm [v3.5.2](https://github.com/helm/helm/releases/tag/v3.5.2),
charts not versioned using **strict semver** are no longer compatible with
source-controller. When using charts from Git, make sure that the `version`
field is set in `Chart.yaml`.

Improvements:
* Update dependencies
  [#299](https://github.com/fluxcd/source-controller/pull/299)
* Refactor release workflow
  [#300](https://github.com/fluxcd/source-controller/pull/300)

## 0.8.1

**Release date:** 2021-02-18

This prerelease fixes a bug where only one dependency of a Helm
chart would be included.

Fixes:
* Copy loop iterator var for use by goroutine
  [#294](https://github.com/fluxcd/source-controller/pull/294)

## 0.8.0

**Release date:** 2021-02-12

This is the eight MINOR prerelease.

The `libgit2` Git implementation now has support for Certificate Authority
validation for Git over HTTPS, as well as various bug fixes around working
with SSH host key fingerprints.

Alpine has been updated to `3.13`, making it possible to move away from `edge`
for `libgit2` and `musl` dependencies.

`pprof` endpoints have been enabled on the metrics server, making it easier to
collect runtime information to for example debug performance issues.

Features:
* Add custom CA validation for Git over HTTPS
  [#283](https://github.com/fluxcd/source-controller/pull/283)

Improvements:
* Rename Git packages to implementations
  [#270](https://github.com/fluxcd/source-controller/pull/270)
* Enable pprof endpoints on metrics server
  [#282](https://github.com/fluxcd/source-controller/pull/282)
* Add fsGroup to pod security context
  [#285](https://github.com/fluxcd/source-controller/pull/285)
* Use musl and libit2 packages from v3.13 branch
  [#289](https://github.com/fluxcd/source-controller/pull/289)

Fixes:
* Fix chart with custom valuesFile (0bytes tgz)
  [#286](https://github.com/fluxcd/source-controller/pull/286)
* libgit2: use provided host to validate public key
  [#288](https://github.com/fluxcd/source-controller/pull/288)
* libgit2: check hostkey type when validating hostkey
  [#290](https://github.com/fluxcd/source-controller/pull/290)

## 0.7.4

**Release date:** 2021-02-03

This prerelease fixes a bug where the controller tried to update dependencies
for Helm charts even when dependencies were already present.

## 0.7.3

**Release date:** 2021-02-02

This prerelease changes the strategy of the controller's deployment to Recreate
to prevent a deadlock during upgrades and to ensure safe usage of backing
persistent (RW) volumes.

## 0.7.2

**Release date:** 2021-02-01

This prerelease ensures the file server of the controller only starts for the
elected leader, and improves the visibility of chart name validation errors.

## 0.7.1

**Release date:** 2021-01-25

This prerelease changes the recorded revision for a `HelmRepository` resource
to a SHA1 checksum, this to improve the detection of changes for repositories
that do not correctly update their advertised generation timestamp.

## 0.7.0

**Release date:** 2021-01-21

This is the seventh MINOR prerelease.

Two new argument flags are introduced to support configuring the QPS
(`--kube-api-qps`) and burst (`--kube-api-burst`) while communicating
with the Kubernetes API server.

The `LocalObjectReference` from the Kubernetes core has been replaced
with our own, making `Name` a required field. The impact of this should
be limited to direct API consumers only, as the field was already
required by controller logic.

Overwrite of chart values has been patched to correctly read the data
from the defined YAML file.

## 0.6.3

**Release date:** 2021-01-19

This prereleases comes with bug fixes to the `HelmChart` indexes,
watches, and the overwrite of chart values.

## 0.6.2

**Release date:** 2021-01-16

This prerelease comes with updates to Kubernetes and Helm dependencies.
The Kubernetes packages were updated to v1.20.2 and Helm to v3.5.0.

## 0.6.1

**Release date:** 2021-01-14

This prerelease fixes a regression bug introduced in `v0.6.0` that caused
reconciliation request annotations to be ignored in certain scenarios.

## 0.6.0

**Release date:** 2021-01-12

This is the sixth MINOR prerelease, upgrading the `controller-runtime`
dependencies to `v0.7.0`.

The container image for ARMv7 and ARM64 that used to be published
separately as `source-controller:*-arm64` has been merged with the
AMD64 image.

## 0.5.6

**Release date:** 2020-12-18

This prerelease fixes a regression bug that made it impossible to
reference to a `HelmChart.ValuesFile` in a path relative to the
root of the `Bucket` or `GitRepository` source.

## 0.5.5

**Release date:** 2020-12-16

This prerelease adds safe guards for user defined relative paths,
ensuring they never traverse outside working directories.

Other notable changes:

* ListObjects V1 fallback for GCS S3 endpoints, ensuring generic
  `Bucket` resources connecting to GCS are able to list object
* HelmChart controller panic regression bug fix, introduced in
  `v0.5.0`

## 0.5.4

**Release date:** 2020-12-12

This prerelease fixes a bug in the build process that caused the
ARMv7 image to fail due to `libgit2` requiring `musl>=1.2.0`.

## 0.5.3

**Release date:** 2020-12-11

This prerelease fixes a regression bug causing the commit hash for the
`go-git` implementation to not be forwarded, introduced by the support
for multiple Git implementations. 

## 0.5.2

**Release date:** 2020-12-11

This prerelease adds the option to configure the advertised storage
address using the `--storage-adv-addr` flag.

The default deployment manifest uses this to configure the FQDN of
the service (`source-controller.$(RUNTIME_NAMESPACE).svc.cluster.local.`),
but omitting the flag will result in a fallback to the previous behavior
for backwards compatibility.

## 0.5.1

**Release date:** 2020-12-09

This prerelease fixes a bug in the build process that caused the
ARMv7 build to fail due to `libgit2` requiring `musl>=1.2.0`.

## 0.5.0

**Release date:** 2020-12-09

This is the fifth MINOR prerelease, adding a new Git implementation
(`libgit2`) to allow for communication with Git servers that just
support the Git v2 protocol, like Azure Devops.

The new Git implementation can be enabled by configuring the
`GitImplementation` in a `GitRepository` to `libgit2` (default:
`go-git`). Note that this implementation does not support shallow
cloning, and it is therefore advised to only resort to this option
if a connection fails with the default configuration.

Other notable changes in this release:

* Bug fix to respect the configured SSH user in `GitRepository` URLs
* Chart name validation for charts from a `HelmRepository` resource
* Kubernetes dependency upgrades to `v1.19.4`
* Helm upgrade to `v3.4.2`

## 0.4.1

**Release date:** 2020-11-26

This prerelease fixes a bug in the listing of HelmChart resources
for GitRepository changes.

## 0.4.0

**Release date:** 2020-11-26

This is the fourth MINOR prerelease, adding support for suspension
of resources using `.spec.suspend`, and watchers for the upstream
sources of `HelmChart` resources to detect revision changes faster.

## 0.3.0

**Release date:** 2020-11-19

This prerelease comes with a fix to garbage collection.
The status sub-resource has a new field called `LastHandledReconcileAt`
that can be used to track the reconciliation progress.

This version comes with a breaking change to the API package:
the status condition type is imported from Kubernetes API machinery 1.19.

## 0.2.2

**Release date:** 2020-11-12

This prerelease comes with improvements to status reporting.
The Kubernetes packages have been updated to v1.19.

## 0.2.1

**Release date:** 2020-10-30

This prerelease comes with a fix for a regression bug (introduced in
`v0.2.0`) where dependency entries in the `Chart.yaml` file during the
(re)packaging of the Helm chart artifact would have their names
overwritten with the alias if defined.

## 0.2.0

**Release date:** 2020-10-29

This is the second MINOR prerelease, it comes with breaking changes:

* Due to a change of semver library to exclude pre-releases from `1.0.x`
  ranges, support for more complex ranges like
  `>=1.0.0 <2.0.0 || >=3.0.0 !3.0.1-beta.1` has been dropped.
* The histogram metric `gotk_reconcile_duration` was renamed to `gotk_reconcile_duration_seconds`

Other notable changes:

* Ambiguous semver matches are now sorted by the timestamp of the source
  system to use the most recent match.
* Added support for downloading dependencies for Helm charts from
  `GitRepository` and `Bucket` sources.
* Added support for creating artifacts for packaged Helm charts (`.tgz`)
  from `GitRepository` and `Bucket` sources.
* The annotation `fluxcd.io/reconcileAt` was renamed to `reconcile.fluxcd.io/requestedAt`,
  the former will be removed in a next release but is backwards
  compatible for now.

## 0.1.1

**Release date:** 2020-10-13

This prerelease comes with Prometheus instrumentation for the controller's resources.

For each kind, the controller exposes a gauge metric to track the `Ready` condition status,
and a histogram with the reconciliation duration in seconds:

* `gotk_reconcile_condition{kind, name, namespace, status, type="Ready"}`
* `gotk_reconcile_duration{kind, name, namespace}`

## 0.1.0

**Release date:** 2020-09-30

This is the first MINOR prerelease, it promotes the
`source.werf.io` API to `v1beta1` and removes support for
`v1alpha1`.

Going forward, changes to the API will be accompanied by a conversion
mechanism. With this release the API becomes more stable, but while in
beta phase there are no guarantees about backwards compatibility
between beta releases.

## 0.0.18

**Release date:** 2020-09-23

This prerelease fixes a reconciliation bug that prevented
resources recovering from transient errors.
Container images for ARMv7 and ARMv8 are published to
`ghcr.io/fluxcd/source-controller-arm64`.
The Helm package was updated to v3.3.4.

## 0.0.17

**Release date:** 2020-09-18

This prerelease comes with support for S3 compatible storage sources
defined as [buckets](https://github.com/fluxcd/source-controller/blob/main/docs/spec/v1alpha1/buckets.md).
The Helm package was updated to v3.3.2.

## 0.0.16

**Release date:** 2020-09-12

This prerelease comes with the option to watch for resources
in the runtime namespace of the controller or at cluster level.

## 0.0.15

**Release date:** 2020-09-11

This prerelease adds support for overwriting the default values of a
`HelmChart` by defining a `ValuesFile`, adds a `Checksum` field to the
`Artifact` object, and comes with several improvements to the storage
and handling of artifacts.

## 0.0.14

**Release date:** 2020-09-04

This prerelease comes with Helm v3.3.1.
Container images for linux/amd64 and linux/arm64 are published to GHCR.

## 0.0.13

**Release date:** 2020-09-01

This prerelease fixes a bug in the packaging of `HelmChart` artifacts
build from `GitRepository` sources, and improves the logic of the
`Storage.ArtifactExist` method to not follow symlinks and only return
`true` for regular files.

## 0.0.12

**Release date:** 2020-08-31

This prerelease adds support for `HelmChart` artifacts build from
`GitRepository` sources, and includes several (breaking) changes
to the API:

* The `Name` field in the `HelmChartSpec` has been renamed to `Chart`,
  and may now contain the path a chart is available at in a referred
  Source.
* The `HelmRepositoryRef` field in the `HelmChartSpec` has been renamed
  to `SourceRef`, and may now contain a reference to `HelmRepository`
  and `GitRepository` resources.
* The `Kind` field in the `SourceRef` object is now mandatory.

Other notable changes: the `HelmChart` `Version` field now supports the
same ranges as the `GitRepository` SemVer checkout strategy, support for
relative URLs in `HelmRepository` indexes, and several other bug fixes.

## 0.0.11

**Release date:** 2020-08-21

This prerelease only included a version change of
`github.com/fluxcd/source-controller/api` to publish `go.mod`
changes.

## 0.0.10

**Release date:** 2020-08-18

This prerelease comes with a bug fix to the Git semver checkout.

## 0.0.9

**Release date:** 2020-08-17

This prerelease upgrades the `github.com/fluxcd/pkg/*` dependencies
to dedicated versioned modules.

## 0.0.8

**Release date:** 2020-08-12

This prerelease comes with improvements to Helm repository
index fetching. The Helm getter was upgraded to v3.3.0,
and it's possible to configure the timeout of index downloads.

## 0.0.7

**Release date:** 2020-07-31

This prerelease comes with a breaking change, the 
CRDs group has been renamed to `source.werf.io`.

## 0.0.6

**Release date:** 2020-07-20

This prerelease drops support for Kubernetes <1.16.
The CRDs have been updated to `apiextensions.k8s.io/v1`.

## 0.0.5

**Release date:** 2020-07-13

This prerelease comes with improvements to logging.
The default logging format is JSON and the timestamp format is ISO8601.
Introduce `fluxcd.io/reconcileA` annotation for on-demand reconciliation
of source objects.

## 0.0.4

**Release date:** 2020-07-10

This prerelease comes with fixes to the testing framework.

## 0.0.3

**Release date:** 2020-07-09

This prerelease adds support for
[ignore patterns](docs/spec/v1alpha1/gitrepositories.md#excluding-files)
to be specified on `GitRepository` objects.

## 0.0.2

**Release date:** 2020-07-03

This prerelease comes with Kubernetes events dispatching.
The reconciliation events can be forwarded to notification controller
and alerting can be configured for Slack, MS Teams, Discord and Rocket chat
using the [notification.fluxcd.io API](https://github.com/fluxcd/notification-controller/tree/main/docs/spec).

## 0.0.1

**Release date:** 2020-06-24

This is the first prerelease ready for public testing. To get started
testing, see the [GitOps Toolkit guide](https://fluxcd.io/flux/get-started/).

## 0.0.1-beta.2

**Release date:** 2020-06-10

This beta release comes with improvements to the
[artifacts archiving](https://github.com/fluxcd/source-controller/pull/59).

## 0.0.1-beta.1

**Release date:** 2020-05-29

This is the first beta release of source controller. This release adds
support for [excluding files](https://github.com/fluxcd/source-controller/pull/55)
when packaging artifacts from Git repositories.

## 0.0.1-alpha.6

**Release date:** 2020-05-06

This alpha release comes with [improvements](https://github.com/fluxcd/source-controller/pull/52)
to the `GitRepository` reconciler. Starting with this version, the controller
watches for sources only in the namespace where it's deployed.

## 0.0.1-alpha.5

**Release date:** 2020-04-30

This alpha release contains several bug fixes
[#47](https://github.com/fluxcd/source-controller/pull/47)
[#49](https://github.com/fluxcd/source-controller/pull/49)
[#50](https://github.com/fluxcd/source-controller/pull/50).
After a successful synchronization, the controller reports the revision in the 
status ready condition.

## 0.0.1-alpha.4

**Release date:** 2020-04-28

This alpha release comes with [integrity checks](https://github.com/fluxcd/source-controller/pull/45)
for artifacts produced from Git repositories.

## 0.0.1-alpha.3

**Release date:** 2020-04-27

This alpha release contains a [bug fix](https://github.com/fluxcd/source-controller/pull/42)
for `GitRepositories` status reporting and allows
[waiting for sources on-demand sync](https://github.com/fluxcd/source-controller/pull/43).

## 0.0.1-alpha.2

**Release date:** 2020-04-24

This is the second alpha release of source controller.

It introduces a timeout field to the [`GitRepositoriesSpec`](docs/spec/v1alpha1/gitrepositories.md)
and [`SyncAt` annotation to the common spec](docs/spec/v1alpha1/common.md#source-synchronization).
Furthermore, it allows configuring the amount of concurrent reconciliation
operations per reconciler using the newly introduced `--concurrent` flag
(defaults to `2`), and introduces a `--log-json` flag to enable JSON logging.

Liveness and readiness probes have been added to the deployment manifest, and
the security has been strengthened by running the controller as a non-root user
by default and adding a container security context. 

Tests have been added to ensure correct behaviour of the `HelmChartReconciler`
and `HelmRepositoryReconciler`.

## 0.0.1-alpha.1

**Release date:** 2020-04-16

This is the first alpha release of source controller.
The controller is an implementation of the
[source.fluxcd.io/v1alpha1](https://github.com/fluxcd/source-controller/tree/v0.0.1-alpha.1/docs/spec/v1alpha1) API
based on the specifications described in the
[Source Controller Proposal](https://github.com/fluxcd/source-controller/tree/v0.0.1-alpha.1/docs/spec). 
