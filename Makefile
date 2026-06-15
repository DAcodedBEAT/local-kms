.DEFAULT_GOAL := help
SHELL := bash

BINARY      := local-kms
RECOVERY    := recovery
PKG_MAIN    := ./cmd/local-kms
PKG_RECOV   := ./cmd/recovery
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GIT_COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS     := -s -w -X 'main.Version=$(VERSION)' -X 'main.GitCommit=$(GIT_COMMIT)'

IMAGE       ?= local-kms
COMPOSE     := docker compose
COMPOSE_TEST := $(COMPOSE) -f docker-compose.test.yml

.PHONY: help
help: ## Show this help
	@awk 'BEGIN{FS=":.*##"; printf "Usage: make <target>\n\nTargets:\n"} \
	  /^[a-zA-Z0-9_.-]+:.*##/ {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

## ---- Build ----
.PHONY: build
build: ## Build the local-kms binary
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG_MAIN)

.PHONY: build-recovery
build-recovery: ## Build the recovery utility
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(RECOVERY) $(PKG_RECOV)

.PHONY: docker-build
docker-build: ## Build the production Docker image (tag: local-kms:dev)
	docker build \
	  --build-arg VERSION=$(VERSION) \
	  --build-arg GIT_COMMIT=$(GIT_COMMIT) \
	  -t $(IMAGE):dev .

## ---- Dev ----
.PHONY: dev
dev: ## Start local-kms in dev mode with live reload
	$(COMPOSE) up

.PHONY: dev-down
dev-down: ## Stop dev environment
	$(COMPOSE) down

## ---- Quality ----
.PHONY: fmt
fmt: ## Format Go sources (gofmt + goimports)
	gofmt -s -w .
	go tool goimports -w .

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: vuln
vuln: ## Run govulncheck
	go tool govulncheck ./...

.PHONY: lint
lint: ## Run golangci-lint (installs locally if missing via official action in CI)
	@if command -v golangci-lint >/dev/null 2>&1; then \
	  golangci-lint run --timeout=5m; \
	else \
	  echo "golangci-lint not installed. Install: https://golangci-lint.run/usage/install/"; \
	  exit 1; \
	fi

.PHONY: tidy
tidy: ## Tidy go.mod
	go mod tidy

## ---- Tests ----
.PHONY: test
test: ## Run functional tests via docker compose
	$(COMPOSE_TEST) up --build --abort-on-container-exit --remove-orphans --exit-code-from test
	$(COMPOSE_TEST) down --remove-orphans

.PHONY: test-down
test-down: ## Stop test environment
	$(COMPOSE_TEST) down --remove-orphans

## ---- Cleanup ----
.PHONY: clean
clean: ## Remove containers, volumes, built binaries
	-$(COMPOSE) down --volumes --remove-orphans
	-$(COMPOSE_TEST) down --volumes --remove-orphans
	rm -f $(BINARY) $(RECOVERY)
