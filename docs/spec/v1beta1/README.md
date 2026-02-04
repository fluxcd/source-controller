# source.werf.io/v1beta1

This is the v1beta1 API specification for defining the desired state sources of Kubernetes clusters.

## Specification

* [Common](common.md)
* Source kinds:
  + [GitRepository](gitrepositories.md)
  + [HelmRepository](helmrepositories.md)
  + [HelmChart](helmcharts.md)
  + [Bucket](buckets.md)
  
## Implementation

* [source-controller](https://github.com/fluxcd/source-controller/)

## Consumers

* [kustomize-controller](https://github.com/fluxcd/kustomize-controller/)
* [helm-controller](https://github.com/fluxcd/helm-controller/)
