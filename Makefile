# Image URL to use all building/pushing image targets
IMG ?= fluxcd/source-controller
TAG ?= latest

# Base image used to build the Go binary
LIBGIT2_IMG ?= ghcr.io/fluxcd/golang-with-libgit2
LIBGIT2_TAG ?= libgit2-1.1.1-4

# Allows for defining additional Docker buildx arguments,
# e.g. '--push'.
BUILD_ARGS ?=
# Architectures to build images for
BUILD_PLATFORMS ?= linux/amd64

# Produce CRDs that work back to Kubernetes 1.16
CRD_OPTIONS ?= crd:crdVersions=v1

# Repository root based on Git metadata
REPOSITORY_ROOT := $(shell git rev-parse --show-toplevel)

# Libgit2 version
LIBGIT2_VERSION ?= 1.1.1

# Other dependency versions
ENVTEST_BIN_VERSION ?= 1.19.2

# libgit2 related magical paths
# These are used to determine if the target libgit2 version is already available on
# the system, or where they should be installed to
SYSTEM_LIBGIT2_VERSION := $(shell pkg-config --modversion libgit2 2>/dev/null)
LIBGIT2_PATH := $(REPOSITORY_ROOT)/hack/libgit2
LIBGIT2_LIB_PATH := $(LIBGIT2_PATH)/lib
LIBGIT2 := $(LIBGIT2_LIB_PATH)/libgit2.so.$(LIBGIT2_VERSION)

ifneq ($(LIBGIT2_VERSION),$(SYSTEM_LIBGIT2_VERSION))
	LIBGIT2_FORCE ?= 1
endif

ifeq ($(shell uname -s),Darwin)
	LIBGIT2 := $(LIBGIT2_LIB_PATH)/libgit2.$(LIBGIT2_VERSION).dylib
	HAS_BREW := $(shell brew --version 2>/dev/null)
ifdef HAS_BREW
	HAS_OPENSSL := $(shell brew --prefix openssl@1.1)
endif
endif


# API (doc) generation utilities
CONTROLLER_GEN_VERSION ?= v0.7.0
GEN_API_REF_DOCS_VERSION ?= v0.3.0

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

ifeq ($(strip ${PKG_CONFIG_PATH}),)
	MAKE_PKG_CONFIG_PATH = $(LIBGIT2_LIB_PATH)/pkgconfig
else
	MAKE_PKG_CONFIG_PATH = ${PKG_CONFIG_PATH}:$(LIBGIT2_LIB_PATH)/pkgconfig
endif

ifdef HAS_OPENSSL
	MAKE_PKG_CONFIG_PATH := $(MAKE_PKG_CONFIG_PATH):$(HAS_OPENSSL)/lib/pkgconfig
endif

# Architecture to use envtest with
ENVTEST_ARCH ?= amd64

all: build

build: $(LIBGIT2) ## Build manager binary
ifeq ($(shell uname -s),Darwin)
	PKG_CONFIG_PATH=$(MAKE_PKG_CONFIG_PATH) \
	CGO_LDFLAGS="-Wl,-rpath,$(LIBGIT2_LIB_PATH)" \
	go build -o bin/manager main.go
else
	PKG_CONFIG_PATH=$(MAKE_PKG_CONFIG_PATH) \
	go build -o bin/manager main.go
endif

KUBEBUILDER_ASSETS?="$(shell $(ENVTEST) --arch=$(ENVTEST_ARCH) use -i $(ENVTEST_KUBERNETES_VERSION) --bin-dir=$(ENVTEST_ASSETS_DIR) -p path)"
test: $(LIBGIT2) install-envtest test-api  ## Run tests
ifeq ($(shell uname -s),Darwin)
	LD_LIBRARY_PATH=$(LIBGIT2_LIB_PATH) \
	PKG_CONFIG_PATH=$(MAKE_PKG_CONFIG_PATH) \
	CGO_LDFLAGS="-Wl,-rpath,$(LIBGIT2_LIB_PATH)" \
	KUBEBUILDER_ASSETS=$(KUBEBUILDER_ASSETS) \
	go test ./... -coverprofile cover.out
else
	LD_LIBRARY_PATH=$(LIBGIT2_LIB_PATH) \
	PKG_CONFIG_PATH=$(MAKE_PKG_CONFIG_PATH) \
	KUBEBUILDER_ASSETS=$(KUBEBUILDER_ASSETS) \
	go test ./... -coverprofile cover.out
endif

test-api: ## Run api tests
	cd api; go test ./... -coverprofile cover.out

run: $(LIBGIT2) generate fmt vet manifests  ## Run against the configured Kubernetes cluster in ~/.kube/config
ifeq ($(shell uname -s),Darwin)
	LD_LIBRARY_PATH=$(LIBGIT2_LIB_PATH) \
	CGO_LDFLAGS="-Wl,-rpath,$(LIBGIT2_LIB_PATH)" \
	go run ./main.go
else
	LD_LIBRARY_PATH=$(LIBGIT2_LIB_PATH) \
	go run ./main.go
endif


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
	$(GEN_CRD_API_REFERENCE_DOCS) -api-dir=./api/v1beta1 -config=./hack/api-docs/config.json -template-dir=./hack/api-docs/template -out-file=./docs/api/source.md

tidy:  ## Run go mod tidy
	go mod tidy
	cd api; go mod tidy

fmt:  ## Run go fmt against code
	go fmt ./...
	cd api; go fmt ./...

vet: $(LIBGIT2)	## Run go vet against code
ifeq ($(shell uname -s),Darwin)
	PKG_CONFIG_PATH=$(MAKE_PKG_CONFIG_PATH) \
	CGO_LDFLAGS="-Wl,-rpath,$(LIBGIT2_LIB_PATH)" \
	go vet ./...
	cd api; go vet ./...
else
	PKG_CONFIG_PATH=$(MAKE_PKG_CONFIG_PATH) \
	go vet ./...
	cd api; go vet ./...
endif

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
CONTROLLER_GEN = $(shell pwd)/bin/controller-gen
.PHONY: controller-gen
controller-gen: ## Download controller-gen locally if necessary.
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen@v0.7.0)

# Find or download gen-crd-api-reference-docs
GEN_CRD_API_REFERENCE_DOCS = $(shell pwd)/bin/gen-crd-api-reference-docs
.PHONY: gen-crd-api-reference-docs
gen-crd-api-reference-docs: ## Download gen-crd-api-reference-docs locally if necessary
	$(call go-install-tool,$(GEN_CRD_API_REFERENCE_DOCS),github.com/ahmetb/gen-crd-api-reference-docs@v0.3.0)

ENVTEST = $(shell pwd)/bin/setup-envtest
.PHONY: envtest
setup-envtest: ## Download setup-envtest locally if necessary.
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest@latest)

ENVTEST_ASSETS_DIR=$(shell pwd)/testbin
ENVTEST_KUBERNETES_VERSION?=latest
install-envtest: setup-envtest ## Download envtest binaries locally.
	mkdir -p ${ENVTEST_ASSETS_DIR}
	$(ENVTEST) use $(ENVTEST_KUBERNETES_VERSION) --arch=$(ENVTEST_ARCH) --bin-dir=$(ENVTEST_ASSETS_DIR)

libgit2: $(LIBGIT2)  ## Detect or download libgit2 library

$(LIBGIT2):
ifeq (1, $(LIBGIT2_FORCE))
	@{ \
	set -e; \
	mkdir -p $(LIBGIT2_PATH); \
	curl -sL https://raw.githubusercontent.com/fluxcd/golang-with-libgit2/$(LIBGIT2_TAG)/hack/Makefile -o $(LIBGIT2_PATH)/Makefile; \
	INSTALL_PREFIX=$(LIBGIT2_PATH) make -C $(LIBGIT2_PATH) libgit2; \
	}
endif

.PHONY: help
help:  ## Display this help menu
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

update-attributions:
	./hack/update-attributions.sh

e2e:
	./hack/ci/e2e.sh

verify: update-attributions fmt vet manifests api-docs
ifneq (, $(shell git status --porcelain --untracked-files=no))
	@{ \
	echo "working directory is dirty:"; \
	git --no-pager diff; \
	exit 1; \
	}
endif

# go-install-tool will 'go install' any package $2 and install it to $1.
PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
define go-install-tool
@[ -f $(1) ] || { \
set -e ;\
TMP_DIR=$$(mktemp -d) ;\
cd $$TMP_DIR ;\
go mod init tmp ;\
echo "Downloading $(2)" ;\
GOBIN=$(PROJECT_DIR)/bin go install $(2) ;\
rm -rf $$TMP_DIR ;\
}
endef
