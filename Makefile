# vuln-tracker
#
# `make test` is the whole test suite: the unit tests and the envtest layer,
# which runs the process against a real API server. It downloads the control
# plane binaries itself, so it needs nothing but a Go toolchain. Without them
# (a bare `go test ./...`) the envtest layer skips and says so.

SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

# Kubernetes version of the control plane binaries envtest runs against.
ENVTEST_K8S_VERSION ?= 1.34.x
# Where setup-envtest keeps the downloaded control plane binaries.
ENVTEST_DIR ?= $(CURDIR)/bin/envtest

GO ?= go
# setup-envtest and golangci-lint are pinned by the tool directives in go.mod.
SETUP_ENVTEST ?= $(GO) tool setup-envtest
GOLANGCI_LINT ?= $(GO) tool golangci-lint

IMAGE ?= ghcr.io/yuanying/vuln-tracker:dev

##@ General

.PHONY: help
help: ## Show this help.
	@awk 'BEGIN {FS = ":.*##"} \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } \
		/^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

##@ Development

.PHONY: build
build: ## Build the vuln-tracker binary into bin/.
	$(GO) build -o bin/vuln-tracker ./cmd/vuln-tracker

.PHONY: vet
vet: fmt-check ## Run go vet over every package.
	$(GO) vet ./...

.PHONY: lint
lint: ## Run golangci-lint over every package.
	$(GOLANGCI_LINT) run ./...

.PHONY: lint-fix
lint-fix: ## Run golangci-lint and apply the fixes it can make itself.
	$(GOLANGCI_LINT) run --fix ./...

.PHONY: fmt
fmt: ## Format the source tree.
	$(GO) fmt ./...

.PHONY: fmt-check
fmt-check: ## Fail if anything in the tree is not gofmt'd.
	@unformatted="$$(gofmt -l . | grep -v '^bin/' || true)"; \
	if [ -n "$$unformatted" ]; then \
		echo "not gofmt'd, run \`make fmt\`:"; \
		echo "$$unformatted" | sed 's/^/  /'; \
		exit 1; \
	fi

.PHONY: manifests-check
manifests-check: ## Fail if config/ does not build with kustomize.
	kubectl kustomize config >/dev/null

##@ Test

.PHONY: envtest-bin
envtest-bin: ## Download the control plane binaries envtest needs.
	@mkdir -p $(ENVTEST_DIR)
	$(SETUP_ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(ENVTEST_DIR) -p path

.PHONY: test
test: envtest-bin ## Run every test, the envtest layer included.
	KUBEBUILDER_ASSETS="$$($(SETUP_ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(ENVTEST_DIR) -p path)" \
		$(GO) test -race -count=1 -timeout 10m ./...

##@ Image

.PHONY: image
image: ## Build the container image locally.
	docker build -t $(IMAGE) .

##@ Release

# What the weekly release workflow asks before it releases anything (ADR 0010).
# Run on a checkout with its tags to see what the next run would do; the
# workflow passes `-github-output` through RELEASE_PLAN_ARGS.
.PHONY: release-plan
release-plan: ## Say whether the weekly run would release the next patch version, and why.
	$(GO) run ./hack/release-plan $(RELEASE_PLAN_ARGS)

##@ Housekeeping

.PHONY: tidy
tidy: ## Tidy go.mod and go.sum.
	$(GO) mod tidy

.PHONY: clean
clean: ## Remove build and test artifacts.
	rm -rf bin
