.PHONY: all clean build sora sora-admin install tests tests-race reset-test-db build-test-sora-admin \
	integration-tests integration-tests-imap integration-tests-lmtp integration-tests-pop3 \
	integration-tests-managesieve integration-tests-imapproxy integration-tests-lmtpproxy \
	integration-tests-pop3proxy integration-tests-managesieveproxy integration-tests-userapiproxy \
	integration-tests-connection-limits integration-tests-lmtp-connection-limits \
	integration-tests-pop3-connection-limits integration-tests-managesieve-connection-limits \
	integration-tests-proxy-connection-limits integration-tests-adminapi integration-tests-userapi \
	integration-tests-config integration-tests-sora-admin integration-tests-relay \
	performance-tests performance-tests-short

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

# Build sora-admin for integration tests (some tests exec the binary directly)
build-test-sora-admin:
	go build $(LDFLAGS) -o integration_tests/sora-admin ./cmd/sora-admin

# Clean build artifacts
clean:
	rm -f $(SORA_BINARY) $(SORA_ADMIN_BINARY) $(SORA_LINUX_BINARY) $(SORA_ADMIN_LINUX_BINARY) $(SORA_FREEBSD_BINARY) $(SORA_ADMIN_FREEBSD_BINARY) integration_tests/sora-admin

# Run tests with verbose output
tests:
	go test -v ./...

# Run tests with race detector
tests-race:
	go test -v -race ./...

# Helper variables for integration tests
# Timeout set to 20m to accommodate long-running tests like slowloris (takes ~7 minutes)
TEST_TIMEOUT = 20m
TEST_FLAGS = -v -tags=integration -count=1 -timeout=$(TEST_TIMEOUT)
DB_NAME = sora_mail_db
DB_USER = postgres
DB_HOST = localhost
DB_PORT = 5432

# Reset test database to clean state
reset-test-db:
	@psql -h $(DB_HOST) -p $(DB_PORT) -U $(DB_USER) -d $(DB_NAME) -c "SET session_replication_role = replica; \
		TRUNCATE TABLE vacation_responses CASCADE; \
		TRUNCATE TABLE sieve_scripts CASCADE; \
		TRUNCATE TABLE pending_uploads CASCADE; \
		TRUNCATE TABLE message_contents CASCADE; \
		TRUNCATE TABLE message_sequences CASCADE; \
		TRUNCATE TABLE messages CASCADE; \
		TRUNCATE TABLE mailbox_stats CASCADE; \
		TRUNCATE TABLE mailbox_acls CASCADE; \
		TRUNCATE TABLE mailboxes CASCADE; \
		TRUNCATE TABLE credentials CASCADE; \
		TRUNCATE TABLE accounts CASCADE; \
		TRUNCATE TABLE metadata CASCADE; \
		TRUNCATE TABLE health_status CASCADE; \
		TRUNCATE TABLE cache_metrics CASCADE; \
		SET session_replication_role = DEFAULT;" > /dev/null 2>&1 || true

# Run all integration tests (requires PostgreSQL)
integration-tests: integration-tests-imap integration-tests-lmtp integration-tests-pop3 \
	integration-tests-managesieve integration-tests-imapproxy integration-tests-lmtpproxy \
	integration-tests-pop3proxy integration-tests-managesieveproxy integration-tests-userapiproxy \
	integration-tests-connection-limits integration-tests-lmtp-connection-limits \
	integration-tests-pop3-connection-limits integration-tests-managesieve-connection-limits \
	integration-tests-proxy-connection-limits integration-tests-adminapi integration-tests-userapi \
	integration-tests-config integration-tests-sora-admin integration-tests-relay

# Run integration tests in quick mode (skip long-running tests like slowloris)
integration-tests-quick: integration-tests-imap-quick integration-tests-lmtp integration-tests-pop3 \
	integration-tests-managesieve integration-tests-imapproxy integration-tests-lmtpproxy \
	integration-tests-pop3proxy integration-tests-managesieveproxy integration-tests-userapiproxy \
	integration-tests-connection-limits integration-tests-lmtp-connection-limits \
	integration-tests-pop3-connection-limits integration-tests-managesieve-connection-limits \
	integration-tests-proxy-connection-limits integration-tests-adminapi integration-tests-userapi \
	integration-tests-config integration-tests-sora-admin integration-tests-relay

# Core protocol integration tests
integration-tests-imap: reset-test-db build-test-sora-admin
	@echo "Running IMAP integration tests..."
	@cd integration_tests/imap && go test $(TEST_FLAGS) .

integration-tests-imap-quick: reset-test-db build-test-sora-admin
	@echo "Running IMAP integration tests (quick mode, skipping long tests)..."
	@cd integration_tests/imap && go test -short $(TEST_FLAGS) .

integration-tests-lmtp: reset-test-db
	@echo "Running LMTP integration tests..."
	@cd integration_tests/lmtp && go test $(TEST_FLAGS) .

integration-tests-pop3: reset-test-db
	@echo "Running POP3 integration tests..."
	@cd integration_tests/pop3 && go test $(TEST_FLAGS) .

integration-tests-managesieve: reset-test-db
	@echo "Running ManageSieve integration tests..."
	@cd integration_tests/managesieve && go test $(TEST_FLAGS) .

# Proxy integration tests
integration-tests-imapproxy: reset-test-db
	@echo "Running IMAP proxy integration tests..."
	@cd integration_tests/imapproxy && go test $(TEST_FLAGS) .

integration-tests-lmtpproxy: reset-test-db
	@echo "Running LMTP proxy integration tests..."
	@cd integration_tests/lmtpproxy && go test $(TEST_FLAGS) .

integration-tests-pop3proxy: reset-test-db
	@echo "Running POP3 proxy integration tests..."
	@cd integration_tests/pop3proxy && go test $(TEST_FLAGS) .

integration-tests-managesieveproxy: reset-test-db
	@echo "Running ManageSieve proxy integration tests..."
	@cd integration_tests/managesieveproxy && go test $(TEST_FLAGS) .

integration-tests-userapiproxy: reset-test-db
	@echo "Running User API proxy integration tests..."
	@cd integration_tests/userapiproxy && go test $(TEST_FLAGS) .

# Connection limit integration tests
integration-tests-connection-limits: reset-test-db
	@echo "Running connection limits integration tests..."
	@cd integration_tests/connection_limits && go test $(TEST_FLAGS) .

integration-tests-lmtp-connection-limits: reset-test-db
	@echo "Running LMTP connection limits integration tests..."
	@cd integration_tests/lmtp_connection_limits && go test $(TEST_FLAGS) .

integration-tests-pop3-connection-limits: reset-test-db
	@echo "Running POP3 connection limits integration tests..."
	@cd integration_tests/pop3_connection_limits && go test $(TEST_FLAGS) .

integration-tests-managesieve-connection-limits: reset-test-db
	@echo "Running ManageSieve connection limits integration tests..."
	@cd integration_tests/managesieve_connection_limits && go test $(TEST_FLAGS) .

integration-tests-proxy-connection-limits: reset-test-db
	@echo "Running proxy connection limits integration tests..."
	@cd integration_tests/proxy_connection_limits && go test $(TEST_FLAGS) .

# HTTP API integration tests
integration-tests-adminapi: reset-test-db
	@echo "Running Admin API integration tests..."
	@cd integration_tests/adminapi && go test $(TEST_FLAGS) .

integration-tests-userapi: reset-test-db
	@echo "Running User API integration tests..."
	@cd integration_tests/userapi && go test $(TEST_FLAGS) .

# Configuration and admin tool tests
integration-tests-config: reset-test-db
	@echo "Running configuration integration tests..."
	@cd integration_tests/config && go test $(TEST_FLAGS) .

integration-tests-sora-admin: reset-test-db
	@echo "Running sora-admin integration tests..."
	@cd cmd/sora-admin && go test $(TEST_FLAGS) .

integration-tests-relay:
	@echo "Running relay integration tests..."
	@cd integration_tests/relay && go test $(TEST_FLAGS) .

# Performance tests
performance-tests:
	@echo "Running search performance tests..."
	@echo "Basic search functionality tests..."
	@go test -v ./db -run "TestSearchConstants|TestSearchCriteriaValidation" -timeout 30s
	@echo ""
	@echo "Search validation tests..."
	@go test -v ./db -run "TestValidate" -timeout 30s
	@echo ""
	@echo "Basic search performance tests..."
	@go test -v ./db -run "TestSearchPerformanceBasic" -timeout 60s
	@echo ""
	@echo "Comprehensive performance tests (with large datasets)..."
	@go test -v ./db -run "TestSearchPerformance" -timeout 10m
	@echo ""
	@echo "Search benchmarks..."
	@go test -v ./db -bench "BenchmarkSearchOperations" -benchtime=5s -timeout 5m

performance-tests-short:
	@echo "Running quick performance validation tests..."
	@go test -v ./db -run "TestSearchPerformance" -short -timeout 2m

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
	@echo ""
	@echo "Build targets:"
	@echo "  all          - Build both sora and sora-admin (default)"
	@echo "  build        - Build both executables"
	@echo "  sora         - Build only the main sora server"
	@echo "  sora-admin   - Build only the sora-admin tool"
	@echo "  install      - Install both executables to GOPATH/bin"
	@echo "  clean        - Remove build artifacts"
	@echo ""
	@echo "Test targets:"
	@echo "  tests                   - Run unit tests"
	@echo "  tests-race              - Run unit tests with race detector"
	@echo "  performance-tests       - Run comprehensive search performance tests"
	@echo "  performance-tests-short - Run quick performance validation tests"
	@echo "  integration-tests       - Run all integration tests (requires PostgreSQL)"
	@echo "  integration-tests-quick - Run integration tests, skip long tests (e.g., slowloris)"
	@echo ""
	@echo "Core protocol integration tests:"
	@echo "  integration-tests-imap          - IMAP protocol tests (includes long tests)"
	@echo "  integration-tests-imap-quick    - IMAP protocol tests (quick, skip long tests)"
	@echo "  integration-tests-lmtp          - LMTP delivery tests"
	@echo "  integration-tests-pop3          - POP3 protocol tests"
	@echo "  integration-tests-managesieve   - ManageSieve tests"
	@echo ""
	@echo "Proxy integration tests:"
	@echo "  integration-tests-imapproxy         - IMAP proxy tests"
	@echo "  integration-tests-lmtpproxy         - LMTP proxy tests"
	@echo "  integration-tests-pop3proxy         - POP3 proxy tests"
	@echo "  integration-tests-managesieveproxy  - ManageSieve proxy tests"
	@echo "  integration-tests-userapiproxy      - User API proxy tests"
	@echo ""
	@echo "Connection limit tests:"
	@echo "  integration-tests-connection-limits               - IMAP connection limits"
	@echo "  integration-tests-lmtp-connection-limits          - LMTP connection limits"
	@echo "  integration-tests-pop3-connection-limits          - POP3 connection limits"
	@echo "  integration-tests-managesieve-connection-limits   - ManageSieve connection limits"
	@echo "  integration-tests-proxy-connection-limits         - Proxy connection limits"
	@echo ""
	@echo "HTTP API tests:"
	@echo "  integration-tests-adminapi      - Admin API tests"
	@echo "  integration-tests-userapi       - User API tests"
	@echo ""
	@echo "Other integration tests:"
	@echo "  integration-tests-config        - Configuration tests"
	@echo "  integration-tests-sora-admin    - Import/export tests"
	@echo "  integration-tests-relay         - Relay (SMTP/HTTP) tests"
	@echo ""
	@echo "Cross-compilation targets:"
	@echo "  build-linux-musl - Cross-compile static binaries for Linux with musl"
	@echo "  build-freebsd    - Cross-compile binaries for FreeBSD"
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
	@echo "  make build                              # Build with default names"
	@echo "  make integration-tests                  # Run all integration tests"
	@echo "  make integration-tests-imap             # Run only IMAP tests"
	@echo "  SORA_BINARY=mysora make build           # Custom binary name"
