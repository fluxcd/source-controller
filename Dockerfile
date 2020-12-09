# Docker buildkit multi-arch build requires golang alpine
FROM golang:1.15-alpine as builder

RUN apk add gcc pkgconfig libc-dev
RUN apk add --no-cache --repository http://dl-cdn.alpinelinux.org/alpine/edge/community libgit2-dev~=1.1
# TODO: replace with non-edge musl 1.2.x when made available
#  musl 1.2.x is a strict requirement of libgit2 due to time_t changes
#  ref: https://musl.libc.org/time64.html
RUN apk add --no-cache --repository http://dl-cdn.alpinelinux.org/alpine/edge/main musl~=1.2

WORKDIR /workspace

# copy api submodule
COPY api/ api/

# copy modules manifests
COPY go.mod go.mod
COPY go.sum go.sum

# cache modules
RUN go mod download

# copy source code
COPY main.go main.go
COPY controllers/ controllers/
COPY pkg/ pkg/
COPY internal/ internal/

# build without specifing the arch
RUN CGO_ENABLED=1 go build -o source-controller main.go

FROM alpine:3.12

# link repo to the GitHub Container Registry image
LABEL org.opencontainers.image.source="https://github.com/fluxcd/source-controller"

RUN apk add --no-cache ca-certificates tini
RUN apk add --no-cache --repository http://dl-cdn.alpinelinux.org/alpine/edge/community libgit2~=1.1

COPY --from=builder /workspace/source-controller /usr/local/bin/

# Create minimal nsswitch.conf file to prioritize the usage of /etc/hosts over DNS queries.
# https://github.com/gliderlabs/docker-alpine/issues/367#issuecomment-354316460
RUN [ ! -e /etc/nsswitch.conf ] && echo 'hosts: files dns' > /etc/nsswitch.conf

RUN addgroup -S controller && adduser -S -g controller controller

USER controller

ENTRYPOINT [ "/sbin/tini", "--", "source-controller" ]
