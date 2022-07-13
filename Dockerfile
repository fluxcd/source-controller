ARG BASE_VARIANT=alpine
ARG GO_VERSION=1.17
ARG XX_VERSION=1.1.0

ARG LIBGIT2_IMG=ghcr.io/fluxcd/golang-with-libgit2-all
ARG LIBGIT2_TAG=v0.1.1

FROM ${LIBGIT2_IMG}:${LIBGIT2_TAG} AS libgit2-libs

FROM --platform=$BUILDPLATFORM tonistiigi/xx:${XX_VERSION} AS xx

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-${BASE_VARIANT} as gostable

FROM gostable AS go-linux

# Build-base consists of build platform dependencies and xx.
# These will be used at current arch to yield execute the cross compilations.
FROM go-${TARGETOS} AS build-base

RUN apk add --no-cache clang lld pkgconfig

COPY --from=xx / /

# build-go-mod can still be cached at build platform architecture.
FROM build-base as build-go-mod

# Configure workspace
WORKDIR /workspace

# Copy api submodule
COPY api/ api/

# Copy modules manifests
COPY go.mod go.mod
COPY go.sum go.sum

# Cache modules
RUN go mod download

# The musl-tool-chain layer is an adhoc solution
# for the problem in which xx gets confused during compilation
# and a) looks for gold linker and then b) cannot find musl's dynamic linker.
FROM --platform=$BUILDPLATFORM alpine as musl-tool-chain

COPY --from=xx / /

RUN apk add bash curl tar

WORKDIR /workspace
COPY hack/download-musl.sh .

ARG TARGETPLATFORM
ARG TARGETARCH
RUN ROOT_DIR="$(pwd)" TARGET_ARCH="$(xx-info alpine-arch)" ENV_FILE=true \
        ./download-musl.sh

# Build stage install per target platform
# dependency and effectively cross compile the application.
FROM build-go-mod as build

ARG TARGETPLATFORM

COPY --from=libgit2-libs /usr/local/ /usr/local/

# Some dependencies have to installed 
# for the target platform: https://github.com/tonistiigi/xx#go--cgo
RUN xx-apk add musl-dev gcc lld

WORKDIR /workspace

# Copy source code
COPY main.go main.go
COPY controllers/ controllers/
COPY pkg/ pkg/
COPY internal/ internal/

COPY --from=musl-tool-chain /workspace/build /workspace/build

ARG TARGETPLATFORM
ARG TARGETARCH
ENV CGO_ENABLED=1

# Instead of using xx-go, (cross) compile with vanilla go leveraging musl tool chain.
RUN export $(cat build/musl/$(xx-info alpine-arch).env | xargs) && \
    export LIBRARY_PATH="/usr/local/$(xx-info triple):/usr/local/$(xx-info triple)/lib64" && \
    export PKG_CONFIG_PATH="/usr/local/$(xx-info triple)/lib/pkgconfig:/usr/local/$(xx-info triple)/lib64/pkgconfig" && \
    export CGO_LDFLAGS="$(pkg-config --static --libs --cflags libssh2 openssl libgit2) -static" && \
    GOARCH=$TARGETARCH go build  \
        -ldflags "-s -w" \
        -tags 'netgo,osusergo,static_build' \
        -o /source-controller -trimpath main.go;

# Ensure that the binary was cross-compiled correctly to the target platform.
RUN xx-verify --static /source-controller


FROM alpine:3.16

ARG TARGETPLATFORM
RUN apk --no-cache add ca-certificates \
  && update-ca-certificates

# Create minimal nsswitch.conf file to prioritize the usage of /etc/hosts over DNS queries.
# https://github.com/gliderlabs/docker-alpine/issues/367#issuecomment-354316460
RUN [ ! -e /etc/nsswitch.conf ] && echo 'hosts: files dns' > /etc/nsswitch.conf

# Copy over binary from build
COPY --from=build /source-controller /usr/local/bin/
COPY ATTRIBUTIONS.md /

USER 65534:65534
ENTRYPOINT [ "source-controller" ]
