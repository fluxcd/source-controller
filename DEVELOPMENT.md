# Development

> **Note:** Please take a look at <https://fluxcd.io/contributing/flux/>
> to find out about how to contribute to Flux and how to interact with the
> Flux Development team.

## Installing required dependencies

There are a number of dependencies required to be able to run the controller and its test suite locally:

- [Install Go](https://golang.org/doc/install)
- [Install Kustomize](https://kubectl.docs.kubernetes.io/installation/kustomize/)
- [Install Docker](https://docs.docker.com/engine/install/)
- (Optional) [Install Kubebuilder](https://book.kubebuilder.io/quick-start.html#installation)

The [libgit2](https://libgit2.org/) dependency is now automatically managed by the Makefile logic.
However, it depends on [pkg-config](https://freedesktop.org/wiki/Software/pkg-config/) being installed:

### macOS

```console
$ # Ensure pkg-config is installed
$ brew install pkg-config
```

### Linux

```console
$ # Ensure pkg-config is installed
$ pacman -S pkgconf
```

**Note:** Example shown is for Arch Linux, but likewise procedure can be
followed using any other package manager. Some distributions may have slight 
variation of package names (e.g. `apt install -y pkg-config`).

In addition to the above, the following dependencies are also used by some of the `make` targets:

- `controller-gen` (v0.7.0)
- `gen-crd-api-reference-docs` (v0.3.0)
- `setup-envtest` (latest)

If any of the above dependencies are not present on your system, the first invocation of a `make` target that requires them will install them.

## How to run the test suite

Prerequisites:
* Go >= 1.18

You can run the test suite by simply doing

```sh
make test
```

### Additional test configuration

By setting the `GO_TEST_ARGS` environment variable you can pass additional flags to [`go test`](https://pkg.go.dev/cmd/go#hdr-Test_packages):

```sh
make test GO_TEST_ARGS="-v -run=TestReadIgnoreFile/with_domain"
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

### Debugging controller with VSCode

Create a `.vscode/launch.json` file:
```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Launch Package",
            "type": "go",
            "request": "launch",
            "mode": "auto",
            "envFile": "${workspaceFolder}/build/.env",
            "program": "${workspaceFolder}/main.go"
        }
    ]
}
```

Create the environment file containing details on how to load 
`libgit2` dependencies:
```bash
make env
```

Start debugging by either clicking `Run` > `Start Debugging` or using
the relevant shortcut.
