# source.fluxcd.io/v1alpha1

The is the v1alpha1 API specification for defining the desired state sources of Kubernetes clusters.

## Specification

* [Common](common.md)
* Source kinds:
  + [GitRepository](gitrepositories.md)
  + [HelmRepository](helmrepositories.md)
    - [HelmChart](helmrepositories.md)

## Implementation

* source-controller [v0.0.1-alpha.1](https://github.com/fluxcd/source-controller/releases)
