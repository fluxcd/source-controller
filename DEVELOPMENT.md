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

In addition to the above, the following dependencies are also used by some of the `make` targets:

- `controller-gen` (v0.19.0)
- `gen-crd-api-reference-docs` (v0.3.0)
- `setup-envtest` (latest)

If any of the above dependencies are not present on your system, the first invocation of a `make` target that requires them will install them.

## How to run the test suite

Prerequisites:
* Go >= 1.25

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

### Debugging tips

**Limit watched namespaces**

Set `RUNTIME_NAMESPACE` to restrict the controller to a single namespace,
which reduces noise when debugging a specific issue:

```sh
export RUNTIME_NAMESPACE=flux-system
make run
```

**Decrease concurrency**

Lower `--concurrent` to `1` so that reconcile loops run sequentially,
making it easier to follow logs and reproduce ordering issues:

```sh
make run ARGS="--concurrent=1"
```

**Set the controller hostname**

The controller uses the `HOSTNAME` environment variable as its identity
for leader election. When running locally, set it to match the
in-cluster deployment name to avoid lease conflicts:

```sh
export HOSTNAME=source-controller
make run
```

**Suspend irrelevant objects**

Suspend Flux objects that are unrelated to the issue you are
investigating so that their reconciliation does not add log noise:

```sh
kubectl -n flux-system patch gitrepository <name> \
  --type=merge -p '{"spec":{"suspend":true}}'
```

Replace `gitrepository` with `helmrepository`, `ocirepository`, or
`bucket` as appropriate.

**Scale down the in-cluster controller**

If `source-controller` is already running in your cluster, scale it
down before running locally to avoid competing reconciliations:

```sh
kubectl -n flux-system scale deployment/source-controller --replicas=0
# restore when done:
kubectl -n flux-system scale deployment/source-controller --replicas=1
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
            "program": "${workspaceFolder}/main.go",
            "args": ["--storage-adv-addr=:0", "--storage-path=${workspaceFolder}/bin/data"]
        }
    ]
}
```

Start debugging by either clicking `Run` > `Start Debugging` or using
the relevant shortcut.
