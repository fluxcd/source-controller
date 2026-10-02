# Sigstore test harness
# Usage:
#   make -f hack/sigstore-test/Makefile up           # create cluster + registry
#   make -f hack/sigstore-test/Makefile sigstore      # install sigstore stack
#   make -f hack/sigstore-test/Makefile build         # build and load source-controller
#   make -f hack/sigstore-test/Makefile cosign        # fetch cosign v2 and v3 binaries
#   make -f hack/sigstore-test/Makefile test          # run signing/verification tests
#   make -f hack/sigstore-test/Makefile all           # do everything
#   make -f hack/sigstore-test/Makefile down          # tear down
#
# kind-cluster.yaml is committed with the default cluster name
# (sigstore-test) and registry ports (5555, 5557). To target a different
# cluster name or ports, render an override out-of-tree first:
#
#   make -f hack/sigstore-test/Makefile kind-config \
#       CLUSTER_NAME=foo KIND_CONFIG_PATH=/tmp/foo.yaml
#   KIND_CONFIG_PATH=/tmp/foo.yaml make -f hack/sigstore-test/Makefile up

SCRIPT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

.PHONY: all kind-config up registries sigstore tsa down build cosign test

all: up registries sigstore tsa cosign build test

# Optional: re-render kind-cluster.yaml from the template. Only needed when
# overriding CLUSTER_NAME / REG_LOCALHOST_PORT / REG2_LOCALHOST_PORT.
kind-config:
	bash $(SCRIPT_DIR)/render-kind-config.sh

up:
	bash $(SCRIPT_DIR)/kind-up.sh

registries:
	bash $(SCRIPT_DIR)/registries-up.sh

sigstore:
	bash $(SCRIPT_DIR)/setup-sigstore.sh

tsa:
	bash $(SCRIPT_DIR)/setup-tsa.sh

down:
	bash $(SCRIPT_DIR)/kind-down.sh

build:
	bash $(SCRIPT_DIR)/build-and-load.sh

cosign:
	bash $(SCRIPT_DIR)/fetch-cosign.sh

test:
	bash $(SCRIPT_DIR)/test-signing.sh
