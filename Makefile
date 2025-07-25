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

# Cross-compile with musl libc for Linux
build-linux-musl:
	CC=x86_64-linux-musl-gcc CXX=x86_64-linux-musl-g++ GOARCH=amd64 GOOS=linux CGO_ENABLED=1 go build -ldflags "-linkmode external -extldflags -static" -o sora-linux-amd64 ./cmd/sora
	CC=x86_64-linux-musl-gcc CXX=x86_64-linux-musl-g++ GOARCH=amd64 GOOS=linux CGO_ENABLED=1 go build -ldflags "-linkmode external -extldflags -static" -o sora-admin-linux-amd64 ./cmd/sora-admin

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
	@echo "  help         - Show this help message"
