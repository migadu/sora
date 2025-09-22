.PHONY: all clean build sora sora-admin install test test-integration test-integration-imap test-integration-lmtp test-integration-pop3

# Binary names - can be overridden by environment variables
SORA_BINARY ?= sora
SORA_ADMIN_BINARY ?= sora-admin
SORA_LINUX_BINARY ?= sora-linux-amd64
SORA_ADMIN_LINUX_BINARY ?= sora-admin-linux-amd64
SORA_FREEBSD_BINARY ?= sora-freebsd-amd64
SORA_ADMIN_FREEBSD_BINARY ?= sora-admin-freebsd-amd64

# ====================================================================================
# Version Information
# You can override these variables during the build, e.g., make build VERSION=v1.0.0
# ====================================================================================
VERSION ?= $(shell git describe --tags --always --dirty --match='v*')
COMMIT ?= $(shell git rev-parse --short HEAD)
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Go linker flags to inject version info
LDFLAGS_VARS = -X 'main.version=${VERSION}' -X 'main.commit=${COMMIT}' -X 'main.date=${DATE}'
LDFLAGS = -ldflags="${LDFLAGS_VARS}"

# Default target
all: build

# Build both executables
build: sora sora-admin

# Build the main sora server
sora:
	go build $(LDFLAGS) -o $(SORA_BINARY) ./cmd/sora

# Build the sora-admin tool
sora-admin:
	go build $(LDFLAGS) -o $(SORA_ADMIN_BINARY) ./cmd/sora-admin

# Install both executables to GOPATH/bin
install:
	go install ./cmd/sora
	go install ./cmd/sora-admin

# Clean build artifacts
clean:
	rm -f $(SORA_BINARY) $(SORA_ADMIN_BINARY) $(SORA_LINUX_BINARY) $(SORA_ADMIN_LINUX_BINARY) $(SORA_FREEBSD_BINARY) $(SORA_ADMIN_FREEBSD_BINARY)

# Run tests
test:
	go test ./...

# Run integration tests (requires PostgreSQL)
test-integration:
	./run_integration_tests.sh

# Run IMAP integration tests only
test-integration-imap:
	./run_integration_tests.sh --protocol imap

# Run LMTP integration tests only  
test-integration-lmtp:
	./run_integration_tests.sh --protocol lmtp

# Run POP3 integration tests only
test-integration-pop3:
	./run_integration_tests.sh --protocol pop3

# Cross-compile with musl libc for Linux
build-linux-musl:
	CC=x86_64-linux-musl-gcc CXX=x86_64-linux-musl-g++ GOARCH=amd64 GOOS=linux go build -ldflags="${LDFLAGS_VARS} -extldflags -static" -o $(SORA_LINUX_BINARY) ./cmd/sora
	CC=x86_64-linux-musl-gcc CXX=x86_64-linux-musl-g++ GOARCH=amd64 GOOS=linux go build -ldflags="${LDFLAGS_VARS} -extldflags -static" -o $(SORA_ADMIN_LINUX_BINARY) ./cmd/sora-admin

# Cross-compile for FreeBSD
build-freebsd:
	GOARCH=amd64 GOOS=freebsd go build $(LDFLAGS) -o $(SORA_FREEBSD_BINARY) ./cmd/sora
	GOARCH=amd64 GOOS=freebsd go build $(LDFLAGS) -o $(SORA_ADMIN_FREEBSD_BINARY) ./cmd/sora-admin

# Help target
help:
	@echo "Available targets:"
	@echo "  all          - Build both sora and sora-admin (default)"
	@echo "  build        - Build both executables"
	@echo "  sora         - Build only the main sora server"
	@echo "  sora-admin   - Build only the sora-admin tool for account management"
	@echo "  install      - Install both executables to GOPATH/bin"
	@echo "  clean        - Remove build artifacts"
	@echo "  test         - Run unit tests"
	@echo "  test-integration - Run all integration tests (requires PostgreSQL)"
	@echo "  test-integration-imap - Run IMAP integration tests only"
	@echo "  test-integration-lmtp - Run LMTP integration tests only"
	@echo "  test-integration-pop3 - Run POP3 integration tests only"
	@echo "  build-linux-musl - Cross-compile static binaries for Linux with musl"
	@echo "  build-freebsd - Cross-compile binaries for FreeBSD"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Environment variables:"
	@echo "  SORA_BINARY              - Name for sora binary (default: sora)"
	@echo "  SORA_ADMIN_BINARY        - Name for sora-admin binary (default: sora-admin)"
	@echo "  SORA_LINUX_BINARY        - Name for Linux sora binary (default: sora-linux-amd64)"
	@echo "  SORA_ADMIN_LINUX_BINARY  - Name for Linux sora-admin binary (default: sora-admin-linux-amd64)"
	@echo "  SORA_FREEBSD_BINARY      - Name for FreeBSD sora binary (default: sora-freebsd-amd64)"
	@echo "  SORA_ADMIN_FREEBSD_BINARY - Name for FreeBSD sora-admin binary (default: sora-admin-freebsd-amd64)"
	@echo ""
	@echo "Example usage:"
	@echo "  make build                      # Use default names"
	@echo "  SORA_BINARY=mysora make build   # Custom binary name"
