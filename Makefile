.PHONY: help build build-recovery dev dev-down test test-down clean

help:
	@echo "Local KMS - Available Commands"
	@echo ""
	@echo "Development:"
	@echo "  make dev             Start KMS in development mode (with live reload)"
	@echo "  make dev-down        Stop development environment"
	@echo ""
	@echo "Testing:"
	@echo "  make test            Run functional tests in Docker"
	@echo "  make test-down       Stop test environment"
	@echo ""
	@echo "Building:"
	@echo "  make build           Build the KMS binary"
	@echo "  make build-recovery  Build the recovery utility (for corruption recovery)"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean           Remove containers, volumes, and binaries"
	@echo ""

build:
	go build -o local-kms ./cmd/local-kms

build-recovery:
	go build -o recovery ./cmd/recovery

dev:
	docker-compose up

dev-down:
	docker-compose down

test:
	@./run-tests.sh

test-down:
	docker-compose -f docker-compose.test.yml down --remove-orphans

clean:
	docker-compose down --volumes --remove-orphans
	docker-compose -f docker-compose.test.yml down --volumes --remove-orphans
	rm -f local-kms recovery
