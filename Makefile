# Image URL to use all building/pushing image targets
IMG ?= fluxcd/source-controller
TAG ?= latest

# Allows for defining additional Go test args, e.g. '-tags integration'.
GO_TEST_ARGS ?= -race

# Allows for filtering tests based on the specified prefix
GO_TEST_PREFIX ?=

# Defines whether cosign verification should be skipped.
SKIP_COSIGN_VERIFICATION ?= false

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
ENVTEST_BIN_VERSION ?= 1.24.0

# FUZZ_TIME defines the max amount of time, in Go Duration,
# each fuzzer should run for.
FUZZ_TIME ?= 1m

GO_STATIC_FLAGS=-ldflags "-s -w" -tags 'netgo,osusergo,static_build$(addprefix ,,$(GO_TAGS))'

# API (doc) generation utilities
CONTROLLER_GEN_VERSION ?= v0.12.0
GEN_API_REF_DOCS_VERSION ?= e327d0730470cbd61b06300f81c5fcf91c23c113

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

build: ## Build manager binary
	go build $(GO_STATIC_FLAGS) -o $(BUILD_DIR)/bin/manager main.go

KUBEBUILDER_ASSETS?="$(shell $(ENVTEST) --arch=$(ENVTEST_ARCH) use -i $(ENVTEST_KUBERNETES_VERSION) --bin-dir=$(ENVTEST_ASSETS_DIR) -p path)"
test: install-envtest test-api ## Run all tests
	HTTPS_PROXY="" HTTP_PROXY="" \
	KUBEBUILDER_ASSETS=$(KUBEBUILDER_ASSETS) \
	GIT_CONFIG_GLOBAL=/dev/null \
	go test $(GO_STATIC_FLAGS) \
	  ./... \
	  $(GO_TEST_ARGS) \
	  -coverprofile cover.out

test-ctrl: install-envtest test-api ## Run controller tests
	HTTPS_PROXY="" HTTP_PROXY="" \
	KUBEBUILDER_ASSETS=$(KUBEBUILDER_ASSETS) \
	GIT_CONFIG_GLOBAL=/dev/null \
	go test $(GO_STATIC_FLAGS) \
	  -run "^$(GO_TEST_PREFIX).*" \
	  -v ./internal/controller \
	  -coverprofile cover.out

test-api: ## Run api tests
	cd api; go test $(GO_TEST_ARGS) ./... -coverprofile cover.out

run: generate fmt vet manifests  ## Run against the configured Kubernetes cluster in ~/.kube/config
	@mkdir -p $(PWD)/bin/data
	go run $(GO_STATIC_FLAGS) ./main.go --storage-adv-addr=:0 --storage-path=$(PWD)/bin/data

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
	$(GEN_CRD_API_REFERENCE_DOCS) -api-dir=./api/v1beta2 -config=./hack/api-docs/config.json -template-dir=./hack/api-docs/template -out-file=./docs/api/v1beta2/source.md
	$(GEN_CRD_API_REFERENCE_DOCS) -api-dir=./api/v1 -config=./hack/api-docs/config.json -template-dir=./hack/api-docs/template -out-file=./docs/api/v1/source.md

tidy:  ## Run go mod tidy
	cd api; rm -f go.sum; go mod tidy -compat=1.20
	rm -f go.sum; go mod tidy -compat=1.20

fmt:  ## Run go fmt against code
	go fmt ./...
	cd api; go fmt ./...

vet:  ## Run go vet against code
	go vet ./...
	cd api; go vet ./...

generate: controller-gen  ## Generate API code
	cd api; $(CONTROLLER_GEN) object:headerFile="../hack/boilerplate.go.txt" paths="./..."

docker-build:  ## Build the Docker image
	docker buildx build \
		--platform=$(BUILD_PLATFORMS) \
		-t $(IMG):$(TAG) \
		$(BUILD_ARGS) .

docker-push:  ## Push Docker image
	docker push $(IMG):$(TAG)

# Find or download controller-gen
CONTROLLER_GEN = $(GOBIN)/controller-gen
.PHONY: controller-gen
controller-gen: ## Download controller-gen locally if necessary.
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION))

# Find or download gen-crd-api-reference-docs
GEN_CRD_API_REFERENCE_DOCS = $(GOBIN)/gen-crd-api-reference-docs
.PHONY: gen-crd-api-reference-docs
gen-crd-api-reference-docs: ## Download gen-crd-api-reference-docs locally if necessary
	$(call go-install-tool,$(GEN_CRD_API_REFERENCE_DOCS),github.com/ahmetb/gen-crd-api-reference-docs@$(GEN_API_REF_DOCS_VERSION))

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

.PHONY: help
help:  ## Display this help menu
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

e2e:
	./hack/ci/e2e.sh

verify: fmt vet manifests api-docs tidy
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

# Build fuzzers used by oss-fuzz.
fuzz-build:
	rm -rf $(shell pwd)/build/fuzz/
	mkdir -p $(shell pwd)/build/fuzz/out/

	docker build . --tag local-fuzzing:latest -f tests/fuzz/Dockerfile.builder
	docker run --rm \
		-e FUZZING_LANGUAGE=go -e SANITIZER=address \
		-e CIFUZZ_DEBUG='True' -e OSS_FUZZ_PROJECT_NAME=fluxcd \
		-v "$(shell pwd)/build/fuzz/out":/out \
		local-fuzzing:latest

# Run each fuzzer once to ensure they will work when executed by oss-fuzz.
fuzz-smoketest: fuzz-build
	docker run --rm \
		-v "$(shell pwd)/build/fuzz/out":/out \
		-v "$(shell pwd)/tests/fuzz/oss_fuzz_run.sh":/runner.sh \
		local-fuzzing:latest \
		bash -c "/runner.sh"

# Run fuzz tests for the duration set in FUZZ_TIME.
fuzz-native: 
	KUBEBUILDER_ASSETS=$(KUBEBUILDER_ASSETS) \
	FUZZ_TIME=$(FUZZ_TIME) \
		./tests/fuzz/native_go_run.sh
