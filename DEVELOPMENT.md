# Development

> **Note:** Please take a look at <https://fluxcd.io/docs/contributing/flux/>
> to find out about how to contribute to Flux and how to interact with the
> Flux Development team.

## Installing required dependencies

There are a number of dependencies required to be able to run the controller and its test suite locally:

- [Install Go](https://golang.org/doc/install)
- [Install Kustomize](https://kubernetes-sigs.github.io/kustomize/installation/)
- [Install Docker](https://docs.docker.com/engine/install/)
- (Optional) [Install Kubebuilder](https://book.kubebuilder.io/quick-start.html#installation)

The dependency [libgit2](https://libgit2.org/) also needs to be installed to be able
to run `source-controller` or its test-suite locally (not in a container).

In case this dependency is not present on your system (at the expected
version), the first invocation of a `make` target that requires the
dependency will attempt to compile it locally to `hack/libgit2`. For this build
to succeed ensure the following dependencies are present on your system:
- [CMake](https://cmake.org/download/)
- [OpenSSL 1.1](https://www.openssl.org/source/)
- [LibSSH2](https://www.libssh2.org/)
- [pkg-config](https://freedesktop.org/wiki/Software/pkg-config/)

Triggering a manual build of the dependency is possible as well by running
`make libgit2`. To enforce the build, for example if your system dependencies
match but are not linked in a compatible way, append `LIBGIT2_FORCE=1` to the
`make` command.

Follow the instructions below to install these dependencies to your system.

### macOS

```console
$ # Ensure libgit2 dependencies are available
$ brew install cmake openssl@1.1 libssh2 pkg-config
$ LIBGIT2_FORCE=1 make libgit2
```

### Linux

```console
$ # Ensure libgit2 dependencies are available
$ pacman -S cmake openssl libssh2
$ LIBGIT2_FORCE=1 make libgit2
```

**Note:** Example shown is for Arch Linux, but likewise procedure can be
followed using any other package manager. Some distributions may have slight 
variation of package names (e.g. `apt install -y cmake openssl libssh2-1-dev`).

In addition to the above, the following dependencies are also used by some of the `make` targets:

- `controller-gen` (v0.7.0)
- `gen-crd-api-reference-docs` (v0.3.0)
- `setup-envtest` (latest)

If any of the above dependencies are not present on your system, the first invocation of a `make` target that requires them will install them.

## How to run the test suite

Prerequisites:
* Go >= 1.17

You can run the test suite by simply doing

```sh
make test
```

## How to run the controller locally

Install the controller's CRDs on your test cluster:

```sh
make install
```

Run the controller locally:

```sh
make run
```

## How to install the controller

### Building the container image

Set the name of the container image to be created from the source code. This will be used 
when building, pushing and referring to the image on YAML files:

```sh
export IMG=registry-path/source-controller
export TAG=latest # optional
```

Build the container image, tagging it as `$(IMG):$(TAG)`:

```sh
make docker-build
```

Push the image into the repository:

```sh
make docker-push
```

Alternatively, the three steps above can be done in a single line:
  
```sh
IMG=registry-path/source-controller TAG=latest BUILD_ARGS=--push \
    make docker-build
```
For an extensive list of `BUILD_ARGS`, refer to the docker [buildx build options] documentation.

**Note:** `make docker-build` will build images for all supported architecture by default.
Limit this to a specific architecture for faster builds:

```sh
IMG=registry-path/source-controller TAG=latest BUILD_ARGS=--push BUILD_PLATFORMS=amd64 \
    make docker-build
```

[buildx build options]: https://docs.docker.com/engine/reference/commandline/buildx_build/#options

If you get the following error when building the docker container:
```
Multiple platforms feature is currently not supported for docker driver.
Please switch to a different driver (eg. "docker buildx create --use")
```

you may need to create and switch to a new builder that supports multiple platforms:

```sh
docker buildx create --use
```

### Deploying into a cluster

Deploy `source-controller` into the cluster that is configured in the local kubeconfig file (i.e. `~/.kube/config`):

```sh
make deploy
```
