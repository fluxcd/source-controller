ARG BASE_VARIANT=bullseye
ARG GO_VERSION=1.17.5
ARG XX_VERSION=1.1.0

ARG LIBGIT2_IMG=ghcr.io/fluxcd/golang-with-libgit2
ARG LIBGIT2_TAG=libgit2-1.1.1-1

FROM tonistiigi/xx:${XX_VERSION} AS xx
FROM ${LIBGIT2_IMG}:${LIBGIT2_TAG} as libgit2

FROM golang:${GO_VERSION}-${BASE_VARIANT} as gostable

# Copy the build utiltiies
COPY --from=xx / /
COPY --from=libgit2 /Makefile /libgit2/

# Install the libgit2 build dependencies
RUN make -C /libgit2 cmake

RUN make -C /libgit2 dependencies

# Compile and install libgit2
RUN FLAGS=$(xx-clang --print-cmake-defines) make -C /libgit2 libgit2

# Use the GitHub Actions uid:gid combination for proper fs permissions
RUN groupadd -g 116 test && \
    useradd -u 1001 --gid test --shell /bin/sh --create-home test

# Set path to envtest binaries.
ENV PATH="/github/workspace/envtest:${PATH}"

# Run as test user
USER test

ENTRYPOINT [ "/bin/sh", "-c" ]
