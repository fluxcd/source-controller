ARG GO_VERSION=1.24
ARG XX_VERSION=1.6.1

FROM --platform=$BUILDPLATFORM tonistiigi/xx:${XX_VERSION} AS xx

# Docker buildkit multi-arch build requires golang alpine
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder

# Copy the build utilities.
COPY --from=xx / /

ARG TARGETPLATFORM

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
COPY pkg/ pkg/
COPY internal/ internal/

ARG TARGETPLATFORM
ARG TARGETARCH

# build without specifing the arch
ENV CGO_ENABLED=0
RUN xx-go build -trimpath -a -o source-controller main.go

FROM alpine:3.21

ARG TARGETPLATFORM
RUN apk --no-cache add ca-certificates \
  && update-ca-certificates

COPY --from=builder /workspace/source-controller /usr/local/bin/

USER 65534:65534
ENTRYPOINT [ "source-controller" ]
