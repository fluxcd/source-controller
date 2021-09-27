ARG BASE_IMG=ghcr.io/hiddeco/golang-with-libgit2
ARG BASE_TAG=dev
FROM ${BASE_IMG}:${BASE_TAG} AS build

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
RUN xx-go build -o source-controller -trimpath \
    main.go

FROM debian:bullseye-slim as controller

# Link repo to the GitHub Container Registry image
LABEL org.opencontainers.image.source="https://github.com/fluxcd/source-controller"

# Configure user
RUN groupadd controller && \
    useradd --gid controller --shell /bin/sh --create-home controller

# Copy libgit2
COPY --from=build /libgit2/lib/ /usr/local/lib/
RUN ldconfig

# Upgrade packages and install runtime dependencies
RUN echo "deb http://deb.debian.org/debian sid main" >> /etc/apt/sources.list \
    && echo "deb-src http://deb.debian.org/debian sid main" >> /etc/apt/sources.list \
    && apt update \
    && apt install --no-install-recommends -y zlib1g/sid libssl1.1/sid libssh2-1/sid \
    && apt install --no-install-recommends -y ca-certificates \
    && apt clean \
    && apt autoremove --purge -y \
    && rm -rf /var/lib/apt/lists/*

# Copy over binary from build
COPY --from=build /workspace/source-controller /usr/local/bin/

USER controller
ENTRYPOINT [ "source-controller" ]
