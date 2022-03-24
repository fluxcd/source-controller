# Source Controller

The main goal is to define a set of Kubernetes objects that cluster
admins and various automated operators can interact with to offload
the sources (e.g. Git and Helm repositories) registration, authentication,
verification and resource fetching to a dedicated controller.

## Motivation

Each Flux and each Helm operator mirrors the Git repositories they are
using, in the same way, using the same code. But other components
might benefit from access to the source mirrors, and Flux and the Helm
operator could work more in sympathy with Kubernetes by factoring it out.

If "sources" (usually git repos, but also Helm charts and potentially
other things) existed in their own right as Kubernetes resources,
components like Flux and Helm operator could use standard Kubernetes
mechanisms to build on them; and, they could be managed independently
of the components using them.

## API Specification

* [v1beta2](v1beta2/README.md)
* [v1beta1](v1beta1/README.md)

## Implementation

The controller implementation will watch for source objects in a cluster and act on them.
The actions performed by the source controller could be:

* validate source definitions
* authenticate to sources and validate authenticity
* detect source changes based on update policies (semver)
* fetch resources on-demand and on-a-schedule
* package the fetched resources into a well known format (tar.gz, yaml)
* store the artifacts locally
* make the artifacts addressable by their source identifier (sha, version, ts)
* make the artifacts available in-cluster to interested 3rd parties
* notify interested 3rd parties of source changes and availability (status conditions, events, hooks)

## Impact to Flux

Having a dedicated controller that manages Git repositories defined with Kubernetes custom resources would:

* simplify Flux configuration as fluxd could subscribe to Git sources in-cluster and pull the artifacts
automatically without manual intervention from users to reconfigure and redeploy FLux
* improve the installation experience as users will not have to patch fluxd's deployment to inject
the HTTPS basic auth credentials, change the source URL or other Git and PGP related settings
* enable fluxd to compose the desired state of a cluster from multiple sources by applying all artifacts present in flux namespace
* enable fluxd to apply manifests coming from other sources than Git, e.g. S3 buckets
* allow fluxd to run under a non-root user as it wouldn't need to shell out to ssh-keygen, git or pgp 
* enable fluxd to apply manifests coming from the most recent semver tag of a Git repository
* allow user to pin the cluster desired state to a specific Git commit or Git tag

## Impact to Helm Operator

Having a dedicated controller that manages Helm repositories and charts defined with Kubernetes custom
resources would:

* simplify the Helm Operator configuration as repository and chart definitions can be re-used across
  `HelmRelease` resources (see [fluxcd/helm-operator#142](https://github.com/fluxcd/helm-operator/issues/142))
* improve the user experience as repositories requiring authentication will no longer require a
  `repositories.yaml` import / file mount
* simplify the architecture of the Helm Operator as it allows the operator to work with a single
  source type (`HelmChart`) and way of preparing and executing installations and/or upgrades
* allow the Helm Operator to run under a non-root user as it wouldn't need to shell out to git
