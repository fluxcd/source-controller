FROM golang:1.16-alpine

# Add any build or testing essential system packages
RUN apk add --no-cache build-base git pkgconf
RUN apk add --no-cache --repository http://dl-cdn.alpinelinux.org/alpine/edge/community libgit2-dev~=1.1

# Use the GitHub Actions uid:gid combination for proper fs permissions
RUN addgroup -g 116 -S test && adduser -u 1001 -S -g test test

# Run as test user
USER test

ENTRYPOINT ["/bin/sh", "-c"]
