# source.werf.io/v1

This is the v1 API specification for defining the desired state sources of Kubernetes clusters.

## Specification

* Source kinds:
  + [GitRepository](gitrepositories.md)
  + [OCIRepository](ocirepositories.md)
  + [HelmRepository](helmrepositories.md)
  + [HelmChart](helmcharts.md)
  + [Bucket](buckets.md)

## Implementation

* [source-controller](https://github.com/fluxcd/source-controller/)

## Consumers

* [kustomize-controller](https://github.com/fluxcd/kustomize-controller/)
* [helm-controller](https://github.com/fluxcd/helm-controller/)
* [source-watcher](https://github.com/fluxcd/source-watcher/)
