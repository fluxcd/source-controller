# Changelog

All notable changes to this project are documented in this file.

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
`source.toolkit.fluxcd.io` API to `v1beta1` and removes support for
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
CRDs group has been renamed to `source.toolkit.fluxcd.io`.

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
testing, see the [GitOps Toolkit guide](https://toolkit.fluxcd.io/get-started/).

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
