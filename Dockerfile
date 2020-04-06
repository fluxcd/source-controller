# Build the manager binary
FROM golang:1.13 as builder

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY main.go main.go
COPY api/ api/
COPY controllers/ controllers/

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -o sourcer main.go

FROM alpine:3.11

RUN apk add --no-cache openssh-client ca-certificates tini 'git>=2.12.0' socat curl bash

COPY --from=builder /workspace/sourcer /usr/local/bin/

ENTRYPOINT [ "/sbin/tini", "--", "sourcer" ]
