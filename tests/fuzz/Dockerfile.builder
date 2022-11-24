FROM gcr.io/oss-fuzz-base/base-builder-go

RUN apt-get update && apt-get install -y cmake pkg-config

COPY ./ $GOPATH/src/github.com/fluxcd/source-controller/
COPY ./tests/fuzz/oss_fuzz_build.sh $SRC/build.sh
COPY tests/fuzz/compile_native_go_fuzzer /usr/local/bin/

WORKDIR $SRC
