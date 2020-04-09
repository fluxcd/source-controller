# Source Controller Proposal

## Context

The desired state of a cluster is made out of Kubernetes objects, these objects are expressed in `.yaml` format and 
are applied on the cluster by operators running inside the cluster. An operator's role is to fetch the Kubernetes
objects, run transformations on them and reconcile the cluster state with the resulting manifest.

For an operator to acquire the resources that make up the desired state it needs to understand the communication 
protocol and the authentication scheme, verify the authenticity of a source and deal with rate limits and retries.
In the FluxCD organization there are currently two operators that perform such operations. Both Flux and 
Helm Operator connect to Git repositories to fetch Kubernetes objects, they need to maintain an up-to-date mirror 
of one or several repos. Besides Git, Helm Operator needs to connect to Helm repositories hosted on public or 
private HTTPS servers.

## Motivation

Each Flux or Helm Operator instance maintains its own Git repository mirror even if all of them
point to the same source. If the Git repository host becomes unavailable, the cluster state will diverge from the last
know desired state since the operators will stop the reconciliation due to pull errors. 

Decoupling the Kubernetes objects acquisition from the reconciliation process with an in-cluster 
source manager would make Flux and Helm Operator resilient to outbound connectivity issues and would
simplify the state machine(s) that these controllers operate.

Managing the source operations in a dedicated controller could enable Flux to compose the desire state of a cluster
from multiple source.
Further more the manifests transformation process could be performed by 3rd party tools
(e.g. kustomize, jk, tanka, cue run by Tekton pipelines or Kubernetes Jobs)
that subscribe to source changes events.

## Goals

The main goal is to define a set of Kubernetes objects that cluster admins and various automated operators
can interact with to offload the sources (e.g. Git and Helm repositories)
registration, authentication and resource fetching to a dedicated controller.

The controller implementation will watch for source objects in a cluster and act on them.
The actions performed by the source controller could be:
* validate source definitions
* authenticate to sources and validate authenticity
* detect source changes based on update policies (semver)
* fetch resources on-demand and on-a-schedule
* package the fetched resources into a well known format (tar.gz)
* store the artifacts locally
* make the artifacts addressable by their source identifier (sha, version, ts)
* make the artifacts available in-cluster to interested 3rd parties
* notify interested 3rd parties of source changes and availability (status conditions, events, hooks)

## API Specification

* [v1alpha1](v1alpha1/README.md)
