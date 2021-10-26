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
followed using any other package manager, e.g. `apt`.

## How to run the test suite

You can run the unit tests by simply doing

```bash
make test
```
