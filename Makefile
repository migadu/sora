.PHONY: all clean build sora sora-admin install test

# Default target
all: build

# Build both executables
build: sora sora-admin

# Build the main sora server
sora:
	go build -o sora ./cmd/sora

# Build the sora-admin tool
sora-admin:
	go build -o sora-admin ./cmd/sora-admin

# Install both executables to GOPATH/bin
install:
	go install ./cmd/sora
	go install ./cmd/sora-admin

# Clean build artifacts
clean:
	rm -f sora sora-admin

# Run tests
test:
	go test ./...

# Build with version and build info
build-release:
	go build -ldflags "-X main.version=$(shell git describe --tags --always --dirty)" -o sora ./cmd/sora
	go build -ldflags "-X main.version=$(shell git describe --tags --always --dirty)" -o sora-admin ./cmd/sora-admin

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
	@echo "  help         - Show this help message"
