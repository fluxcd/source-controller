# Image URL to use all building/pushing image targets
IMG ?= fluxcd/source-controller
TAG ?= latest

# Base image used to build the Go binary
LIBGIT2_IMG ?= ghcr.io/fluxcd/golang-with-libgit2-all
LIBGIT2_TAG ?= v0.1.1

# Allows for defining additional Go test args, e.g. '-tags integration'.
GO_TEST_ARGS ?= -race

# Allows for defining additional Docker buildx arguments,
# e.g. '--push'.
BUILD_ARGS ?=
# Architectures to build images for
BUILD_PLATFORMS ?= linux/amd64,linux/arm64,linux/arm/v7

# Go additional tag arguments, e.g. 'integration',
# this is append to the tag arguments required for static builds
GO_TAGS ?=

# Produce CRDs that work back to Kubernetes 1.16
CRD_OPTIONS ?= crd:crdVersions=v1

# Repository root based on Git metadata
REPOSITORY_ROOT := $(shell git rev-parse --show-toplevel)
BUILD_DIR := $(REPOSITORY_ROOT)/build

# Other dependency versions
ENVTEST_BIN_VERSION ?= 1.19.2

# Caches libgit2 versions per tag, "forcing" rebuild only when needed.
LIBGIT2_PATH := $(BUILD_DIR)/libgit2/$(LIBGIT2_TAG)
LIBGIT2_LIB_PATH := $(LIBGIT2_PATH)/lib
LIBGIT2_LIB64_PATH := $(LIBGIT2_PATH)/lib64
LIBGIT2 := $(LIBGIT2_LIB_PATH)/libgit2.a
MUSL-CC =

export CGO_ENABLED=1
export PKG_CONFIG_PATH=$(LIBGIT2_LIB_PATH)/pkgconfig
export LIBRARY_PATH=$(LIBGIT2_LIB_PATH)
export CGO_CFLAGS=-I$(LIBGIT2_PATH)/include -I$(LIBGIT2_PATH)/include/openssl


# The pkg-config command will yield warning messages until libgit2 is downloaded.
ifeq ($(shell uname -s),Darwin)
export CGO_LDFLAGS=$(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) pkg-config --libs --static --cflags libssh2 openssl libgit2 2>/dev/null)
GO_STATIC_FLAGS=-ldflags "-s -w" -tags 'netgo,osusergo,static_build$(addprefix ,,$(GO_TAGS))'
else
export PKG_CONFIG_PATH:=$(PKG_CONFIG_PATH):$(LIBGIT2_LIB64_PATH)/pkgconfig
export LIBRARY_PATH:=$(LIBRARY_PATH):$(LIBGIT2_LIB64_PATH)
export CGO_LDFLAGS=$(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) pkg-config --libs --static --cflags libssh2 openssl libgit2 2>/dev/null)
endif


ifeq ($(shell uname -s),Linux)
ifeq ($(shell uname -m),x86_64)
# Linux x86_64 seem to be able to cope with the static libraries 
# by having only musl-dev installed, without the need of using musl toolchain.
	GO_STATIC_FLAGS=-ldflags "-s -w" -tags 'netgo,osusergo,static_build$(addprefix ,,$(GO_TAGS))'
else
	MUSL-PREFIX=$(BUILD_DIR)/musl/$(shell uname -m)-linux-musl-native/bin/$(shell uname -m)-linux-musl
	MUSL-CC=$(MUSL-PREFIX)-gcc
	export CC=$(MUSL-PREFIX)-gcc
	export CXX=$(MUSL-PREFIX)-g++
	export AR=$(MUSL-PREFIX)-ar
	GO_STATIC_FLAGS=-ldflags "-s -w -extldflags \"-static\"" -tags 'netgo,osusergo,static_build$(addprefix ,,$(GO_TAGS))'
endif
endif

# API (doc) generation utilities
CONTROLLER_GEN_VERSION ?= v0.7.0
GEN_API_REF_DOCS_VERSION ?= v0.3.0

# If gobin not set, create one on ./build and add to path.
ifeq (,$(shell go env GOBIN))
export GOBIN=$(BUILD_DIR)/gobin
else
export GOBIN=$(shell go env GOBIN)
endif
export PATH:=${GOBIN}:${PATH}

# Architecture to use envtest with
ifeq ($(shell uname -m),x86_64)
ENVTEST_ARCH ?= amd64
else
ENVTEST_ARCH ?= arm64
endif

ifeq ($(shell uname -s),Darwin)
# Envtest only supports darwin-amd64
ENVTEST_ARCH=amd64
endif

all: build

build: check-deps $(LIBGIT2) ## Build manager binary
	go build $(GO_STATIC_FLAGS) -o $(BUILD_DIR)/bin/manager main.go

KUBEBUILDER_ASSETS?="$(shell $(ENVTEST) --arch=$(ENVTEST_ARCH) use -i $(ENVTEST_KUBERNETES_VERSION) --bin-dir=$(ENVTEST_ASSETS_DIR) -p path)"
test: $(LIBGIT2) install-envtest test-api check-deps ## Run tests
	HTTPS_PROXY="" HTTP_PROXY="" \
	KUBEBUILDER_ASSETS=$(KUBEBUILDER_ASSETS) \
	GIT_CONFIG_GLOBAL=/dev/null \
	go test $(GO_STATIC_FLAGS) \
	  ./... \
	  $(GO_TEST_ARGS) \
	  -coverprofile cover.out

check-deps:
ifeq ($(shell uname -s),Darwin)
	if ! command -v pkg-config &> /dev/null; then echo "pkg-config is required"; exit 1; fi
endif

test-api: ## Run api tests
	cd api; go test $(GO_TEST_ARGS) ./... -coverprofile cover.out

run: $(LIBGIT2) generate fmt vet manifests  ## Run against the configured Kubernetes cluster in ~/.kube/config
	go run $(GO_STATIC_FLAGS) ./main.go

install: manifests  ## Install CRDs into a cluster
	kustomize build config/crd | kubectl apply -f -

uninstall: manifests  ## Uninstall CRDs from a cluster
	kustomize build config/crd | kubectl delete -f -

deploy: manifests  ## Deploy controller in the configured Kubernetes cluster in ~/.kube/config
	cd config/manager && kustomize edit set image fluxcd/source-controller=$(IMG):$(TAG)
	kustomize build config/default | kubectl apply -f -

dev-deploy:  ## Deploy controller dev image in the configured Kubernetes cluster in ~/.kube/config
	mkdir -p config/dev && cp config/default/* config/dev
	cd config/dev && kustomize edit set image fluxcd/source-controller=$(IMG):$(TAG)
	kustomize build config/dev | kubectl apply -f -
	rm -rf config/dev

manifests: controller-gen  ## Generate manifests, e.g. CRD, RBAC, etc.
	$(CONTROLLER_GEN) $(CRD_OPTIONS) rbac:roleName=manager-role paths="./..." output:crd:artifacts:config="config/crd/bases"
	cd api; $(CONTROLLER_GEN) $(CRD_OPTIONS) rbac:roleName=manager-role paths="./..." output:crd:artifacts:config="../config/crd/bases"

api-docs: gen-crd-api-reference-docs  ## Generate API reference documentation
	$(GEN_CRD_API_REFERENCE_DOCS) -api-dir=./api/v1beta2 -config=./hack/api-docs/config.json -template-dir=./hack/api-docs/template -out-file=./docs/api/source.md

tidy:  ## Run go mod tidy
	cd api; rm -f go.sum; go mod tidy -compat=1.17
	rm -f go.sum; go mod tidy -compat=1.17

fmt:  ## Run go fmt against code
	go fmt ./...
	cd api; go fmt ./...
	cd tests/fuzz; go fmt .

vet: $(LIBGIT2)	## Run go vet against code
	go vet ./...
	cd api; go vet ./...

generate: controller-gen  ## Generate API code
	cd api; $(CONTROLLER_GEN) object:headerFile="../hack/boilerplate.go.txt" paths="./..."

docker-build:  ## Build the Docker image
	docker buildx build \
		--build-arg LIBGIT2_IMG=$(LIBGIT2_IMG) \
		--build-arg LIBGIT2_TAG=$(LIBGIT2_TAG) \
		--platform=$(BUILD_PLATFORMS) \
		-t $(IMG):$(TAG) \
		$(BUILD_ARGS) .

docker-push:  ## Push Docker image
	docker push $(IMG):$(TAG)

# Find or download controller-gen
CONTROLLER_GEN = $(GOBIN)/controller-gen
.PHONY: controller-gen
controller-gen: ## Download controller-gen locally if necessary.
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen@v0.7.0)

# Find or download gen-crd-api-reference-docs
GEN_CRD_API_REFERENCE_DOCS = $(GOBIN)/gen-crd-api-reference-docs
.PHONY: gen-crd-api-reference-docs
gen-crd-api-reference-docs: ## Download gen-crd-api-reference-docs locally if necessary
	$(call go-install-tool,$(GEN_CRD_API_REFERENCE_DOCS),github.com/ahmetb/gen-crd-api-reference-docs@3f29e6853552dcf08a8e846b1225f275ed0f3e3b)

ENVTEST = $(GOBIN)/setup-envtest
.PHONY: envtest
setup-envtest: ## Download setup-envtest locally if necessary.
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest@latest)

ENVTEST_ASSETS_DIR=$(BUILD_DIR)/testbin
ENVTEST_KUBERNETES_VERSION?=latest
install-envtest: setup-envtest ## Download envtest binaries locally.
	mkdir -p ${ENVTEST_ASSETS_DIR}
	$(ENVTEST) use $(ENVTEST_KUBERNETES_VERSION) --arch=$(ENVTEST_ARCH) --bin-dir=$(ENVTEST_ASSETS_DIR)
# setup-envtest sets anything below k8s to 0555
	chmod -R u+w $(BUILD_DIR)/testbin

libgit2: $(LIBGIT2)  ## Detect or download libgit2 library

COSIGN = $(GOBIN)/cosign
$(LIBGIT2): $(MUSL-CC)
	$(call go-install-tool,$(COSIGN),github.com/sigstore/cosign/cmd/cosign@latest)

	IMG=$(LIBGIT2_IMG) TAG=$(LIBGIT2_TAG) PATH=$(PATH):$(GOBIN) ./hack/install-libraries.sh

$(MUSL-CC):
ifneq ($(shell uname -s),Darwin)
	./hack/download-musl.sh
endif

.PHONY: help
help:  ## Display this help menu
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

update-attributions:
	./hack/update-attributions.sh

e2e:
	./hack/ci/e2e.sh

verify: update-attributions fmt vet manifests api-docs
ifneq ($(shell grep -o 'LIBGIT2_IMG ?= \w.*' Makefile | cut -d ' ' -f 3):$(shell grep -o 'LIBGIT2_TAG ?= \w.*' Makefile | cut -d ' ' -f 3), \
		$(shell grep -o "LIBGIT2_IMG=\w.*" Dockerfile | cut -d'=' -f2):$(shell grep -o "LIBGIT2_TAG=\w.*" Dockerfile | cut -d'=' -f2))
	@{ \
	echo "LIBGIT2_IMG and LIBGIT2_TAG must match in both Makefile and Dockerfile"; \
	exit 1; \
	}
endif
ifneq ($(shell grep -o 'LIBGIT2_TAG ?= \w.*' Makefile | cut -d ' ' -f 3), $(shell grep -o "LIBGIT2_TAG=.*" tests/fuzz/oss_fuzz_build.sh | sed 's;LIBGIT2_TAG="$${LIBGIT2_TAG:-;;g' | sed 's;}";;g'))
	@{ \
	echo "LIBGIT2_TAG must match in both Makefile and tests/fuzz/oss_fuzz_build.sh"; \
	exit 1; \
	}
endif

	@if [ ! "$$(git status --porcelain --untracked-files=no)" = "" ]; then \
		echo "working directory is dirty:"; \
		git --no-pager diff; \
		exit 1; \
	fi

# go-install-tool will 'go install' any package $2 and install it to $1.
define go-install-tool
@[ -f $(1) ] || { \
set -e ;\
TMP_DIR=$$(mktemp -d) ;\
cd $$TMP_DIR ;\
go mod init tmp ;\
echo "Downloading $(2)" ;\
env -i bash -c "GOBIN=$(GOBIN) PATH=$(PATH) GOPATH=$(shell go env GOPATH) GOCACHE=$(shell go env GOCACHE) go install $(2)" ;\
rm -rf $$TMP_DIR ;\
}
endef

# Build fuzzers
fuzz-build: $(LIBGIT2)
	rm -rf $(BUILD_DIR)/fuzz/
	mkdir -p $(BUILD_DIR)/fuzz/out/

	docker build . --tag local-fuzzing:latest -f tests/fuzz/Dockerfile.builder
	docker run --rm \
		-e FUZZING_LANGUAGE=go -e SANITIZER=address \
		-e CIFUZZ_DEBUG='True' -e OSS_FUZZ_PROJECT_NAME=fluxcd \
		-v "$(BUILD_DIR)/fuzz/out":/out \
		local-fuzzing:latest

fuzz-smoketest: fuzz-build
	docker run --rm \
		-v "$(BUILD_DIR)/fuzz/out":/out \
		-v "$(shell pwd)/tests/fuzz/oss_fuzz_run.sh":/runner.sh \
		local-fuzzing:latest \
		bash -c "/runner.sh"

# Creates an env file that can be used to load all source-controller's dependencies
# this is handy when you want to run adhoc debug sessions on tests or start the 
# controller in a new debug session.
env: $(LIBGIT2)
	echo 'GO_ENABLED="1"' > $(BUILD_DIR)/.env
	echo 'PKG_CONFIG_PATH="$(PKG_CONFIG_PATH)"' >> $(BUILD_DIR)/.env
	echo 'LIBRARY_PATH="$(LIBRARY_PATH)"' >> $(BUILD_DIR)/.env
	echo 'CGO_CFLAGS="$(CGO_CFLAGS)"' >> $(BUILD_DIR)/.env
	echo 'CGO_LDFLAGS="$(CGO_LDFLAGS)"' >> $(BUILD_DIR)/.env
	echo 'KUBEBUILDER_ASSETS=$(KUBEBUILDER_ASSETS)' >> $(BUILD_DIR)/.env
	echo 'GIT_CONFIG_GLOBAL=/dev/null' >> $(BUILD_DIR)/.env
