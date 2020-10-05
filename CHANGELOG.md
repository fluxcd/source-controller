# Changelog

All notable changes to this project are documented in this file.

## 0.1.0 (2020-09-30)

This is the first MINOR prerelease, it promotes the
`source.toolkit.fluxcd.io` API to `v1beta1` and removes support for
`v1alpha1`.

Going forward, changes to the API will be accompanied by a conversion
mechanism. With this release the API becomes more stable, but while in
beta phase there are no guarantees about backwards compatibility
between beta releases.

## 0.0.18 (2020-09-23)

This prerelease fixes a reconciliation bug that prevented
resources recovering from transient errors.
Container images for ARMv7 and ARMv8 are published to
`ghcr.io/fluxcd/source-controller-arm64`.
The Helm package was updated to v3.3.4.

## 0.0.17 (2020-09-18)

This prerelease comes with support for S3 compatible storage sources
defined as [buckets](https://github.com/fluxcd/source-controller/blob/main/docs/spec/v1alpha1/buckets.md).
The Helm package was updated to v3.3.2.

## 0.0.16 (2020-09-12)

This prerelease comes with the option to watch for resources
in the runtime namespace of the controller or at cluster level.

## 0.0.15 (2020-09-11)

This prerelease adds support for overwriting the default values of a
`HelmChart` by defining a `ValuesFile`, adds a `Checksum` field to the
`Artifact` object, and comes with several improvements to the storage
and handling of artifacts.

## 0.0.14 (2020-09-04)

This prerelease comes with Helm v3.3.1.
Container images for linux/amd64 and linux/arm64 are published to GHCR.

## 0.0.13 (2020-09-01)

This prerelease fixes a bug in the packaging of `HelmChart` artifacts
build from `GitRepository` sources, and improves the logic of the
`Storage.ArtifactExist` method to not follow symlinks and only return
`true` for regular files.

## 0.0.12 (2020-08-31)

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

## 0.0.11 (2020-08-21)

This prerelease only included a version change of
`github.com/fluxcd/source-controller/api` to publish `go.mod`
changes.

## 0.0.10 (2020-08-18)

This prerelease comes with a bug fix to the Git semver checkout.

## 0.0.9 (2020-08-17)

This prerelease upgrades the `github.com/fluxcd/pkg/*` dependencies
to dedicated versioned modules.

## 0.0.8 (2020-08-12)

This prerelease comes with improvements to Helm repository
index fetching. The Helm getter was upgraded to v3.3.0,
and it's possible to configure the timeout of index downloads.

## 0.0.7 (2020-07-31)

This prerelease comes with a breaking change, the 
CRDs group has been renamed to `source.toolkit.fluxcd.io`.

## 0.0.6 (2020-07-20)

This prerelease drops support for Kubernetes <1.16.
The CRDs have been updated to `apiextensions.k8s.io/v1`.

## 0.0.5 (2020-07-13)

This prerelease comes with improvements to logging.
The default logging format is JSON and the timestamp format is ISO8601.
Introduce `fluxcd.io/reconcileA` annotation for on-demand reconciliation
of source objects.

## 0.0.4 (2020-07-10)

This prerelease comes with fixes to the testing framework.

## 0.0.3 (2020-07-09)

This prerelease adds support for
[ignore patterns](docs/spec/v1alpha1/gitrepositories.md#excluding-files)
to be specified on `GitRepository` objects.

## 0.0.2 (2020-07-03)

This prerelease comes with Kubernetes events dispatching.
The reconciliation events can be forwarded to notification controller
and alerting can be configured for Slack, MS Teams, Discord and Rocket chat
using the [notification.fluxcd.io API](https://github.com/fluxcd/notification-controller/tree/main/docs/spec).

## 0.0.1 (2020-06-24)

This is the first prerelease ready for public testing. To get started
testing, see the [GitOps Toolkit guide](https://toolkit.fluxcd.io/get-started/).

## 0.0.1-beta.2 (2020-06-10)

This beta release comes with improvements to the
[artifacts archiving](https://github.com/fluxcd/source-controller/pull/59).

## 0.0.1-beta.1 (2020-05-29)

This is the first beta release of source controller. This release adds
support for [excluding files](https://github.com/fluxcd/source-controller/pull/55)
when packaging artifacts from Git repositories.

## 0.0.1-alpha.6 (2020-05-06)

This alpha release comes with [improvements](https://github.com/fluxcd/source-controller/pull/52)
to the `GitRepository` reconciler. Starting with this version, the controller
watches for sources only in the namespace where it's deployed.

## 0.0.1-alpha.5 (2020-04-30)

This alpha release contains several bug fixes
[#47](https://github.com/fluxcd/source-controller/pull/47)
[#49](https://github.com/fluxcd/source-controller/pull/49)
[#50](https://github.com/fluxcd/source-controller/pull/50).
After a successful synchronization, the controller reports the revision in the 
status ready condition.

## 0.0.1-alpha.4 (2020-04-28)

This alpha release comes with [integrity checks](https://github.com/fluxcd/source-controller/pull/45)
for artifacts produced from Git repositories.

## 0.0.1-alpha.3 (2020-04-27)

This alpha release contains a [bug fix](https://github.com/fluxcd/source-controller/pull/42)
for `GitRepositories` status reporting and allows
[waiting for sources on-demand sync](https://github.com/fluxcd/source-controller/pull/43).

## 0.0.1-alpha.2 (2020-04-24)

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

## 0.0.1-alpha.1 (2020-04-16)

This is the first alpha release of source controller.
The controller is an implementation of the
[source.fluxcd.io/v1alpha1](https://github.com/fluxcd/source-controller/tree/v0.0.1-alpha.1/docs/spec/v1alpha1) API
based on the specifications described in the
[Source Controller Proposal](https://github.com/fluxcd/source-controller/tree/v0.0.1-alpha.1/docs/spec). 
