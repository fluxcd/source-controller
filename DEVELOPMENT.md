# Development

> **Note:** Please take a look at <https://fluxcd.io/docs/contributing/flux/>
> to find out about how to contribute to Flux and how to interact with the
> Flux Development team.

## Installing required dependencies

The dependency [libgit2](https://libgit2.org/) needs to be installed to be able
to run source-controller or its test-suite locally (not in a container).

In case this dependency is not present on your system (at the expected
version), the first invocation of a `make` target that requires the
dependency will attempt to compile it locally to `hack/libgit2`. For this build
to succeed; CMake, Docker, OpenSSL 1.1 and LibSSH2 must be present on the system.

Triggering a manual build of the dependency is possible as well by running
`make libgit2`. To enforce the build, for example if your system dependencies
match but are not linked in a compatible way, append `LIBGIT2_FORCE=1` to the
`make` command.

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

## How to run the test suite

The test suite depends on [envtest] being installed. For minimum required 
version refer to the variable `ENVTEST_BIN_VERSION` in the [Makefile](./Makefile).

You can run the unit tests by simply doing:

```bash
make test
```

[envtest]: https://book.kubebuilder.io/reference/envtest.html#installation


## How to run the controller locally

Install flux on your test cluster:

```sh
flux install
```

Scale the in-cluster controller to zero:

```sh
kubectl -n flux-system scale deployment/source-controller --replicas=0
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


### Deploying into a cluster

Deploy `source-controller` into the cluster that is configured in the local kubeconfig file (i.e. `~/.kube/config`):

```sh
make dev-deploy
```
