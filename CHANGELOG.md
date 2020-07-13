# Changelog

All notable changes to this project are documented in this file.

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
using the [notification.fluxcd.io API](https://github.com/fluxcd/notification-controller/tree/master/docs/spec).

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
[source.fluxcd.io/v1alpha1](https://github.com/fluxcd/source-controller/tree/master/docs/spec/v1alpha1) API
based on the specifications described in the
[Source Controller Proposal](https://github.com/fluxcd/source-controller/tree/master/docs/spec). 
