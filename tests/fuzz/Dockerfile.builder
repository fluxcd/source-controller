FROM gcr.io/oss-fuzz-base/base-builder-go-codeintelligencetesting

COPY ./ $GOPATH/src/github.com/fluxcd/source-controller/
COPY ./tests/fuzz/oss_fuzz_build.sh $SRC/build.sh

WORKDIR $SRC
