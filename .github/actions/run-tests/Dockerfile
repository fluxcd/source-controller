FROM ghcr.io/hiddeco/golang-with-libgit2:dev as builder

# Use the GitHub Actions uid:gid combination for proper fs permissions
RUN groupadd -g 116 test && \
    useradd -u 1001 --gid test --shell /bin/sh --create-home test

# Set path to envtest binaries.
ENV PATH="/github/workspace/envtest:${PATH}"

# Run as test user
USER test

ENTRYPOINT [ "/bin/sh", "-c" ]
