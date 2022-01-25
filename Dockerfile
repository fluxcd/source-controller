ARG BASE_VARIANT=alpine
ARG GO_VERSION=1.17
ARG XX_VERSION=1.1.0

ARG LIBGIT2_IMG=ghcr.io/fluxcd/golang-with-libgit2
ARG LIBGIT2_TAG=libgit2-1.3.0

FROM ${LIBGIT2_IMG}:${LIBGIT2_TAG} as build

# Configure workspace
WORKDIR /workspace

# Copy api submodule
COPY api/ api/

# Copy modules manifests
COPY go.mod go.mod
COPY go.sum go.sum

# Cache modules
RUN go mod download

RUN apk add clang lld pkgconfig ca-certificates

ENV CGO_ENABLED=1
ARG TARGETPLATFORM

RUN xx-apk add --no-cache \
        musl-dev gcc lld binutils-gold

# Performance related changes:
# - Use read-only bind instead of copying go source files.
# - Cache go packages.
RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    export LIBRARY_PATH="/usr/local/$(xx-info triple)/lib:/usr/local/$(xx-info triple)/lib64:${LIBRARY_PATH}" && \
    export PKG_CONFIG_PATH="/usr/local/$(xx-info triple)/lib/pkgconfig:/usr/local/$(xx-info triple)/lib64/pkgconfig" && \
	export FLAGS="$(pkg-config --static --libs --cflags libssh2 openssl libgit2)" && \
    CGO_LDFLAGS="${FLAGS} -static" \
	xx-go build \
        -ldflags "-s -w" \
        -tags 'netgo,osusergo,static_build' \
        -o /source-controller -trimpath main.go;

# Ensure that the binary was cross-compiled correctly to the target platform.
RUN xx-verify --static /source-controller


FROM gcr.io/distroless/static

# Link repo to the GitHub Container Registry image
LABEL org.opencontainers.image.source="https://github.com/fluxcd/source-controller"

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /source-controller /usr/local/bin/
COPY ATTRIBUTIONS.md /

USER 65534:65534
ENTRYPOINT [ "source-controller" ]
