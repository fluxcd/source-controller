FROM golang:1.13 as builder

WORKDIR /workspace

# copy modules manifests
COPY go.mod go.mod
COPY go.sum go.sum

# cache modules
RUN go mod download

# copy source code
COPY main.go main.go
COPY api/ api/
COPY controllers/ controllers/

# build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -o sourcer main.go

FROM alpine:3.11

RUN apk add --no-cache openssh-client ca-certificates tini 'git>=2.12.0' socat curl bash

COPY --from=builder /workspace/sourcer /usr/local/bin/

ENTRYPOINT [ "/sbin/tini", "--", "sourcer" ]
