FROM golang:1.16-buster as builder

# Up-to-date libgit2 dependencies are only available in
# unstable, as libssh2 in testing/bullseye has been linked
# against gcrypt which causes issues with PKCS* formats.
# Ref: https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=668271
RUN echo "deb http://deb.debian.org/debian unstable main" >> /etc/apt/sources.list \
    && echo "deb-src http://deb.debian.org/debian unstable main" >> /etc/apt/sources.list
RUN set -eux; \
    apt-get update \
    && apt-get install -y libgit2-dev/unstable \
    && apt-get clean \
    && apt-get autoremove --purge -y \
    && rm -rf /var/lib/apt/lists/*

# Use the GitHub Actions uid:gid combination for proper fs permissions
RUN groupadd -g 116 test && \
    useradd -u 1001 --gid test --shell /bin/sh --create-home test

# Run as test user
USER test

ENTRYPOINT [ "/bin/sh", "-c" ]
