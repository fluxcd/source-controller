# Sigstore test harness for PR #2003 validation
# Usage:
#   make -f hack/sigstore-test/Makefile up           # create cluster + registry
#   make -f hack/sigstore-test/Makefile sigstore      # install sigstore stack
#   make -f hack/sigstore-test/Makefile build         # build and load source-controller
#   make -f hack/sigstore-test/Makefile cosign        # fetch cosign v2 and v3 binaries
#   make -f hack/sigstore-test/Makefile test          # run signing/verification tests
#   make -f hack/sigstore-test/Makefile all           # do everything
#   make -f hack/sigstore-test/Makefile down          # tear down

SCRIPT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

.PHONY: all up sigstore down build cosign test

all: up sigstore cosign build test

up:
	bash $(SCRIPT_DIR)/kind-up.sh

sigstore:
	bash $(SCRIPT_DIR)/setup-sigstore.sh

down:
	bash $(SCRIPT_DIR)/kind-down.sh

build:
	bash $(SCRIPT_DIR)/build-and-load.sh

cosign:
	bash $(SCRIPT_DIR)/fetch-cosign.sh

test:
	bash $(SCRIPT_DIR)/test-signing.sh
