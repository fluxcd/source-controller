ARG BASE_VARIANT=bullseye
ARG GO_VERSION=1.17
ARG XX_VERSION=1.1.0

ARG LIBGIT2_IMG=ghcr.io/fluxcd/golang-with-libgit2
ARG LIBGIT2_TAG=libgit2-1.1.1-2

FROM --platform=$BUILDPLATFORM tonistiigi/xx:${XX_VERSION} AS xx
FROM ${LIBGIT2_IMG}:${LIBGIT2_TAG} as libgit2

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-${BASE_VARIANT} as gostable

FROM gostable AS go-linux

FROM go-${TARGETOS} AS build-base-bullseye

# Copy the build utilities
COPY --from=xx / /
COPY --from=libgit2 /Makefile /libgit2/

# Install the libgit2 build dependencies
RUN make -C /libgit2 cmake

ARG TARGETPLATFORM
RUN make -C /libgit2 dependencies

FROM build-base-${BASE_VARIANT} as libgit2-bullseye

ARG TARGETPLATFORM

# build libgit2 in release mode
ARG BUILD_TYPE=Release

# First build libgit2 statically, this ensures that all its dependencies
# will be statically available as well.
ARG BUILD_SHARED_LIBS=OFF
RUN FLAGS=$(xx-clang --print-cmake-defines) make -C /libgit2 libgit2

# Rebuild libgit2 this time to generate the shared libraries.
ARG BUILD_SHARED_LIBS=ON
RUN FLAGS=$(xx-clang --print-cmake-defines) make -C /libgit2 libgit2


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

# ARCH armv7 requires additional linking to build correctly.
# Note that the order in which the libraries appear in -extldflags are relevant, changing them will cause the build to break.
RUN if [ "$(xx-info march)" = "armv7l" ]; then export ADDITIONAL_LINKING="/lib/ld-linux-armhf.so.3"; else export ADDITIONAL_LINKING=""; fi && \
        xx-go build \
            -ldflags "-s -w -extldflags \"/usr/lib/$(xx-info triple)/libssh2.a /usr/lib/$(xx-info triple)/libssl.a /usr/lib/$(xx-info triple)/libcrypto.a /usr/lib/$(xx-info triple)/libz.a /usr/lib/$(xx-info triple)/libdl.a /usr/lib/$(xx-info triple)/libc.a ${ADDITIONAL_LINKING} -static\"" \
            -tags 'netgo osusergo static_build' -o source-controller -trimpath main.go;

# Cannot use distroless/static due to lingering dependencies on libnss.
FROM gcr.io/distroless/base-debian11 as controller

# Link repo to the GitHub Container Registry image
LABEL org.opencontainers.image.source="https://github.com/fluxcd/source-controller"

# Copy over binary from build
COPY --from=build /workspace/source-controller /usr/local/bin/
COPY ATTRIBUTIONS.md /

# leverages nonroot available in gcr.io/distroless/base-debian11
USER nonroot
ENTRYPOINT [ "source-controller" ]
