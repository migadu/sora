.PHONY: all clean build sora sora-admin install test

# Binary names - can be overridden by environment variables
SORA_BINARY ?= sora
SORA_ADMIN_BINARY ?= sora-admin
SORA_LINUX_BINARY ?= sora-linux-amd64
SORA_ADMIN_LINUX_BINARY ?= sora-admin-linux-amd64
SORA_FREEBSD_BINARY ?= sora-freebsd-amd64
SORA_ADMIN_FREEBSD_BINARY ?= sora-admin-freebsd-amd64

# Default target
all: build

# Build both executables
build: sora sora-admin

# Build the main sora server
sora:
	go build -o $(SORA_BINARY) ./cmd/sora

# Build the sora-admin tool
sora-admin:
	go build -o $(SORA_ADMIN_BINARY) ./cmd/sora-admin

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

# Build with version and build info
build-release:
	go build -ldflags "-X main.version=$(shell git describe --tags --always --dirty)" -o $(SORA_BINARY) ./cmd/sora
	go build -ldflags "-X main.version=$(shell git describe --tags --always --dirty)" -o $(SORA_ADMIN_BINARY) ./cmd/sora-admin

# Cross-compile with musl libc for Linux
build-linux-musl:
	CC=x86_64-linux-musl-gcc CXX=x86_64-linux-musl-g++ GOARCH=amd64 GOOS=linux CGO_ENABLED=1 go build -ldflags "-linkmode external -extldflags -static" -o $(SORA_LINUX_BINARY) ./cmd/sora
	CC=x86_64-linux-musl-gcc CXX=x86_64-linux-musl-g++ GOARCH=amd64 GOOS=linux CGO_ENABLED=1 go build -ldflags "-linkmode external -extldflags -static" -o $(SORA_ADMIN_LINUX_BINARY) ./cmd/sora-admin

# Cross-compile for FreeBSD
build-freebsd:
	GOARCH=amd64 GOOS=freebsd CGO_ENABLED=0 go build -o $(SORA_FREEBSD_BINARY) ./cmd/sora
	GOARCH=amd64 GOOS=freebsd CGO_ENABLED=0 go build -o $(SORA_ADMIN_FREEBSD_BINARY) ./cmd/sora-admin

# Help target
help:
	@echo "Available targets:"
	@echo "  all          - Build both sora and sora-admin (default)"
	@echo "  build        - Build both executables"
	@echo "  sora         - Build only the main sora server"
	@echo "  sora-admin   - Build only the sora-admin tool for account management"
	@echo "  install      - Install both executables to GOPATH/bin"
	@echo "  clean        - Remove build artifacts"
	@echo "  test         - Run tests"
	@echo "  build-release - Build with version information"
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
