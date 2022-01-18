ARG BASE_VARIANT=bullseye
ARG GO_VERSION=1.17
ARG XX_VERSION=1.1.0

ARG LIBGIT2_IMG=ghcr.io/fluxcd/golang-with-libgit2
ARG LIBGIT2_TAG=libgit2-1.1.1-3

FROM --platform=$BUILDPLATFORM tonistiigi/xx:${XX_VERSION} AS xx
FROM ${LIBGIT2_IMG}:${LIBGIT2_TAG} as libgit2

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-${BASE_VARIANT} as gostable

FROM gostable AS go-linux

FROM go-${TARGETOS} AS build-base-bullseye

# Copy the build utilities
COPY --from=xx / /

# Align golang base image with bookworm. 
# TODO: Replace this with a golang bookworm variant, once that is released.
RUN echo "deb http://deb.debian.org/debian bookworm main" > /etc/apt/sources.list.d/bookworm.list \
	&& echo "deb-src http://deb.debian.org/debian bookworm main" /etc/apt/sources.list.d/bookworm.list \
	&& xx-apt update \
	&& xx-apt -t bookworm upgrade -y \
	&& xx-apt -t bookworm install -y curl

COPY --from=libgit2 /Makefile /libgit2/

# Install the libgit2 build dependencies
RUN make -C /libgit2 cmake

ARG TARGETPLATFORM
RUN make -C /libgit2 dependencies

FROM build-base-${BASE_VARIANT} as libgit2-bullseye

ARG TARGETPLATFORM

# First build libgit2 statically, this ensures that all its dependencies
# will be statically available as well.
ARG BUILD_SHARED_LIBS=OFF
RUN FLAGS=$(xx-clang --print-cmake-defines) make -C /libgit2 libgit2

# Rebuild libgit2 this time to generate the shared libraries.
ARG BUILD_SHARED_LIBS=ON
RUN FLAGS=$(xx-clang --print-cmake-defines) make -C /libgit2 libgit2
# Logs glibc version used at built time. The final image must be compatible with it.
RUN ldd --version ldd > /libgit2/built-on-glibc-version


FROM libgit2-${BASE_VARIANT} as build

# Configure workspace
WORKDIR /workspace

# Copy api submodule
COPY api/ api/

# Copy modules manifests
COPY go.mod go.mod
COPY go.sum go.sum

# Cache modules
RUN go mod download

# Copy source code
COPY main.go main.go
COPY controllers/ controllers/
COPY pkg/ pkg/
COPY internal/ internal/

# Build the binary
ENV CGO_ENABLED=1
ARG TARGETPLATFORM

# The dependencies being statically built are: libgit2, libssh2, libssl, libcrypto and libz.
# Others (such as libc, librt, libdl and libpthread) are resolved at run-time.
# To decrease the likelihood of such dependencies being out of sync, the base build image
# should be aligned with the target (i.e. same debian variant).
RUN FLAGS=$(pkg-config --static --libs --cflags libssh2 libgit2 libssl libcrypto zlib openssl) \
	xx-go build \
        -ldflags "-s -w -extldflags \"/usr/lib/$(xx-info triple)/libssh2.a /usr/lib/$(xx-info triple)/libssl.a /usr/lib/$(xx-info triple)/libcrypto.a /usr/lib/$(xx-info triple)/libz.a -Wl,--unresolved-symbols=ignore-in-object-files -Wl,-allow-shlib-undefined ${FLAGS} -static\"" \
        -tags 'netgo,osusergo,static_build' \
        -o source-controller -trimpath main.go;

# The target image must aligned with apt sources used for libgit2.
FROM debian:bookworm-slim as controller

# Link repo to the GitHub Container Registry image
LABEL org.opencontainers.image.source="https://github.com/fluxcd/source-controller"

# Configure user
RUN addgroup --gid 65532 controller && \
	useradd -u 65532 -s /sbin/nologin -g controller controller

ARG TARGETPLATFORM
RUN apt update && apt install -y ca-certificates

# Copy over binary from build
COPY --from=build /workspace/source-controller /usr/local/bin/
COPY --from=libgit2-bullseye /libgit2/built-on-glibc-version /
COPY ATTRIBUTIONS.md /

USER controller
ENTRYPOINT [ "source-controller" ]
