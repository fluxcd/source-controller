FROM golang:1.16-buster as builder

RUN echo "deb http://deb.debian.org/debian unstable main" >> /etc/apt/sources.list \
    && echo "deb-src http://deb.debian.org/debian unstable main" >> /etc/apt/sources.list
RUN set -eux; \
    apt-get update \
    && apt-get install -y \
        libgit2-dev/unstable \
        zlib1g-dev/unstable \
        libssh2-1-dev/unstable \
        libpcre3-dev/unstable \
    clang \
    curl \
    cmake \
    vim \
    zlib1g-dev \
    && apt-get clean \
    && apt-get autoremove --purge -y \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/fluxcd/source-controller /workspace
WORKDIR /workspace

# BUILD STATIC DEPENDENCIES TO LINK WITH OUR FUZZER:

# Make dir for .a files
RUN mkdir /static_a_files

# Build libgit2
ARG LIBGIT2_VER=1.1.0
RUN curl -L https://github.com/libgit2/libgit2/releases/download/v$LIBGIT2_VER/libgit2-$LIBGIT2_VER.tar.gz -o /tmp/libgit2.tar.gz \
    && cd /tmp \
    && tar -xvf /tmp/libgit2.tar.gz \
    && cd libgit2-1.1.0 \
    && mkdir build && cd build \
    && cmake .. -DBUILD_SHARED_LIBS=OFF \
    && make \
    && mv libgit2.a /static_a_files/

# Build openssl
ARG OPENSSL_VERSION=1.1.1g
ARG OPENSSL_HASH=ddb04774f1e32f0c49751e21b67216ac87852ceb056b75209af2443400636d46
RUN set -ex \
    && curl -s -O https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz \
    && echo "${OPENSSL_HASH}  openssl-${OPENSSL_VERSION}.tar.gz" | sha256sum -c \
    && tar -xzf openssl-${OPENSSL_VERSION}.tar.gz \
    && cd openssl-${OPENSSL_VERSION} \
    && ./Configure linux-x86_64 no-shared --static \
    && make \
    && mv libcrypto.a /static_a_files/ \
    && mv libssl.a /static_a_files/

# Build libssh2
RUN git clone https://github.com/libssh2/libssh2 \
    && cd libssh2 \
    && mkdir build \
    && cd build \
    && cmake .. -DBUILD_SHARED_LIBS=OFF \
    && make \
    && mv ./src/libssh2.a /static_a_files/

COPY fuzz.go /workspace/controllers/
RUN go mod download

RUN go get -u github.com/dvyukov/go-fuzz/go-fuzz@latest github.com/dvyukov/go-fuzz/go-fuzz-build@latest
RUN go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest
RUN go get github.com/AdaLogics/go-fuzz-headers

RUN go mod download golang.org/x/sync
# A few fixes, see: https://github.com/dvyukov/go-fuzz/issues/325
RUN sed -i '23 a type X = fs.FileInfo\n' /go/pkg/mod/k8s.io/client-go@v0.21.3/util/homedir/homedir.go
RUN sed -i '22 a "io/fs" \n' /go/pkg/mod/k8s.io/client-go@v0.21.3/util/homedir/homedir.go


RUN mkdir /fuzzers
RUN cd /workspace && rm -r hack && rm -r docs \
    && go mod download \
    && go mod tidy \
    && go get github.com/dvyukov/go-fuzz/go-fuzz-dep


# Build the fuzzers
RUN cd /workspace/controllers \
    && go-fuzz-build -libfuzzer -func=FuzzStorageArchive\
    && clang -o /fuzzers/FuzzStorageArchive reflect-fuzz.a \
        /static_a_files/libgit2.a \
        /static_a_files/libssh2.a \
        /static_a_files/libssl.a \
        /static_a_files/libcrypto.a \
        -lz -lpcre -fsanitize=fuzzer

RUN cd /workspace/controllers \
    && go-fuzz-build -libfuzzer -func=FuzzStorageCopy\
    && clang -o /fuzzers/FuzzStorageCopy \
        reflect-fuzz.a \
        /static_a_files/libgit2.a \
        /static_a_files/libssh2.a \
        /static_a_files/libssl.a \
        /static_a_files/libcrypto.a \
        -lz -lpcre -fsanitize=fuzzer

RUN cd /workspace/controllers \
    && go-fuzz-build -libfuzzer -func=FuzzRandomGitFiles\
    && clang -o /fuzzers/FuzzRandomGitFiles \
        reflect-fuzz.a \
        /static_a_files/libgit2.a \
        /static_a_files/libssh2.a \
        /static_a_files/libssl.a \
        /static_a_files/libcrypto.a \
        -lz -lpcre -fsanitize=fuzzer

RUN cd /workspace/controllers \
    && go-fuzz-build -libfuzzer -func=FuzzGitResourceObject\
    && clang -o /fuzzers/FuzzGitResourceObject \
        reflect-fuzz.a \
        /static_a_files/libgit2.a \
        /static_a_files/libssh2.a \
        /static_a_files/libssl.a \
        /static_a_files/libcrypto.a \
        -lz -lpcre -fsanitize=fuzzer

RUN cd /workspace/controllers \
    && go-fuzz-build -libfuzzer -func=FuzzHelmchartController\
    && clang -o /fuzzers/FuzzHelmchartController \
        reflect-fuzz.a \
        /static_a_files/libgit2.a \
        /static_a_files/libssh2.a \
        /static_a_files/libssl.a \
        /static_a_files/libcrypto.a \
        -lz -lpcre -fsanitize=fuzzer


# The fuzzers can now be executed from /fuzzers/fuzzer_name.
# Uncomment below to run:
#RUN cd controllers && /fuzzers/FuzzRandomGitFiles