SHELL := /bin/bash

BINARY  := mcp-cve
BIN_DIR := bin
CMD_DIR := ./cmd/cve

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

GOLANGCI_LINT_VERSION := latest
GOSEC_VERSION         := latest
GOVULNCHECK_VERSION   := latest

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help message
	@echo "Available targets:" && echo && \
	awk 'BEGIN {FS = ":.*?## "}; /^[a-zA-Z0-9_\-]+:.*?## / {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST) | sort

.PHONY: generate frontend
generate: ## Generate the frontend bundle (npm install + build via esbuild)
	@command -v esbuild >/dev/null 2>&1 || npm --prefix web install
	go generate ./internal/frontend/...

frontend: generate ## Alias for generate

.PHONY: build
build: generate ## Build the binary into bin/mcp-cve
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BIN_DIR)/$(BINARY) $(CMD_DIR)

.PHONY: run
run: ## Run the server locally with stub auth (use ARGS="--flag=value" for extra flags)
	go run $(CMD_DIR) --auth-stub --db-dsn data/cve.db $(ARGS)

.PHONY: test
test: ## Run all tests
	go test ./...

.PHONY: test-race
test-race: ## Run all tests with the race detector
	go test -race ./...

.PHONY: fmt
fmt: ## Format all Go code
	go fmt ./...

.PHONY: vet
vet: ## Run go vet
	go vet ./...

# Where `go install` puts tool binaries. Resolving each tool through `command
# -v` with this as the fallback keeps these targets working on machines that
# haven't added GOPATH/bin to PATH.
GOPATH_BIN := $(shell go env GOPATH)/bin
tool = $$(command -v $(1) 2>/dev/null || echo $(GOPATH_BIN)/$(1))

# Tools must be built with a toolchain at least as new as this module's `go`
# directive. Derive the version from go.mod rather than the installed Go.
MODULE_GO_VERSION := $(shell go list -m -f '{{.GoVersion}}')
TOOL_GOTOOLCHAIN  := GOTOOLCHAIN=go$(MODULE_GO_VERSION)$(if $(word 3,$(subst ., ,$(MODULE_GO_VERSION))),,.0)

.PHONY: lint
lint: ## Run golangci-lint (auto-installed if missing)
	@command -v golangci-lint >/dev/null 2>&1 || \
		$(TOOL_GOTOOLCHAIN) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	$(call tool,golangci-lint) run ./...

.PHONY: gosec
gosec: ## Run gosec security scanner (auto-installed if missing)
	@command -v gosec >/dev/null 2>&1 || \
		$(TOOL_GOTOOLCHAIN) go install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)
	$(call tool,gosec) ./...

.PHONY: govulncheck
govulncheck: ## Run govulncheck dependency vulnerability scan (auto-installed if missing)
	@command -v govulncheck >/dev/null 2>&1 || \
		$(TOOL_GOTOOLCHAIN) go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	$(call tool,govulncheck) ./...

.PHONY: security
security: gosec govulncheck ## Run all security and vulnerability checks

.PHONY: tidy
tidy: ## Tidy go.mod/go.sum
	go mod tidy

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BIN_DIR)
	rm -f internal/frontend/static/js/app.bundle.js

.PHONY: docker
docker: ## Build the Docker image locally
	docker build -t $(BINARY):$(VERSION) .
