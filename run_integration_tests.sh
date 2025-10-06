#!/bin/bash

# SORA Integration Test Runner
# ===========================
# This script runs integration tests for all SORA protocols.
# It starts local servers and tests them as clients.

set -e

# Detect OS and set appropriate timeout command
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    if command -v gtimeout >/dev/null 2>&1; then
        TIMEOUT_CMD="gtimeout"
    else
        echo "Warning: gtimeout not found. Install with: brew install coreutils"
        echo "Falling back to running tests without timeout..."
        TIMEOUT_CMD=""
    fi
else
    # Linux and others
    TIMEOUT_CMD="timeout"
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DB_NAME="sora_mail_db"
DB_USER="postgres"
DB_HOST="localhost"
DB_PORT="5432"

print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    SORA Integration Tests                    ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_section() {
    echo -e "${YELLOW}=== $1 ===${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

check_prerequisites() {
    print_section "Checking Prerequisites"
    
    # Check if Go is installed
    if ! command -v go &> /dev/null; then
        print_error "Go is not installed or not in PATH"
        exit 1
    fi
    print_success "Go is installed: $(go version)"
    
    # Check if PostgreSQL is running
    if ! pg_isready -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" &> /dev/null; then
        print_error "PostgreSQL is not running or not accessible"
        print_info "Please ensure PostgreSQL is running on $DB_HOST:$DB_PORT"
        print_info "You can start it with: brew services start postgresql (on macOS)"
        exit 1
    fi
    print_success "PostgreSQL is running and accessible"
    
    # Check if test database exists
    if ! psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -lqt | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
        print_info "Test database $DB_NAME does not exist, creating it..."
        createdb -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$DB_NAME"
        print_success "Created test database: $DB_NAME"
    else
        print_success "Test database exists: $DB_NAME"
    fi
    
    # Run database migrations if needed
    if [ -f "db/schema.sql" ]; then
        print_info "Applying database schema..."
        psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f db/schema.sql &> /dev/null || true
        print_success "Database schema applied"
    fi
    
    echo
}

run_test_suite() {
    local test_path="$1"
    local test_name="$2"
    
    print_section "Running $test_name Tests"
    
    if [ ! -d "$test_path" ]; then
        print_error "Test directory $test_path does not exist"
        return 1
    fi
    
    # Change to test directory and run tests
    cd "$test_path"
    
    # Set timeout for tests (10 minutes)
    timeout_duration="10m"
    # Use -count=1 to disable test caching to ensure tests actually run
    if [ -n "$TIMEOUT_CMD" ]; then
        test_cmd="$TIMEOUT_CMD $timeout_duration go test -v -tags=integration -count=1 -timeout=\"$timeout_duration\" ."
    else
        test_cmd="go test -v -tags=integration -count=1 -timeout=\"$timeout_duration\" ."
    fi
    
    if [ "$VERBOSE" = true ]; then
        print_info "Note: Some tests (like IDLE) may take up to 20 seconds to complete"
        print_info "Running command: $test_cmd"
        print_info "Working directory: $(pwd)"
    fi
    
    if eval "$test_cmd"; then
        print_success "$test_name tests passed"
        cd - > /dev/null
        return 0
    else
        exit_code=$?
        print_error "$test_name tests failed (exit code: $exit_code)"
        cd - > /dev/null
        return $exit_code
    fi
}

cleanup() {
    print_section "Cleanup"
    # Kill any remaining test processes
    pkill -f "sora.*test" 2>/dev/null || true
    print_info "Cleanup completed"
}

main() {
    # Trap to ensure cleanup on exit
    trap cleanup EXIT
    
    print_banner
    
    # Parse command line arguments
    SKIP_DB_CHECK=false
    SCOPES=()
    VERBOSE=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --skip-db-check)
                SKIP_DB_CHECK=true
                shift
                ;;
            --scope)
                SCOPES+=("$2")
                shift 2
                ;;
            --verbose|-v)
                VERBOSE=true
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --skip-db-check    Skip database connectivity checks"
                echo "  --scope SCOPE      Run tests for specific scope"
                echo "  --verbose, -v      Enable verbose output"
                echo "  --help, -h         Show this help message"
                echo ""
                echo "Available scopes:"
                echo "  Core: imap, lmtp, pop3, managesieve, httpapi, config"
                echo "  Admin: sora-admin (importer/exporter tests)"
                echo "  Proxy: imapproxy, lmtpproxy, pop3proxy, managesieveproxy"
                echo "  Limits: connection_limits, lmtp_connection_limits, pop3_connection_limits,"
                echo "          managesieve_connection_limits, proxy_connection_limits"
                echo ""
                echo "Examples:"
                echo "  $0                          # Run all integration tests"
                echo "  $0 --scope imap             # Run only IMAP tests"
                echo "  $0 --scope sora-admin       # Run only importer/exporter tests"
                echo "  $0 --scope httpapi          # Run only HTTP API tests"
                echo "  $0 --scope connection_limits     # Run only connection limit tests"
                echo "  $0 --verbose                # Run with verbose output"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done

    # Set default scopes if none specified
    if [ ${#SCOPES[@]} -eq 0 ]; then
        SCOPES=(
            "imap" "lmtp" "pop3" "managesieve"
            "imapproxy" "lmtpproxy" "pop3proxy" "managesieveproxy"
            "connection_limits" "lmtp_connection_limits" "pop3_connection_limits"
            "managesieve_connection_limits" "proxy_connection_limits"
            "httpapi" "config"
            "sora-admin"
        )
    fi
    
    # Check prerequisites unless skipped
    if [ "$SKIP_DB_CHECK" = false ]; then
        check_prerequisites
    fi
    
    # Store original directory
    ORIGINAL_DIR=$(pwd)

    # Run tests for each scope
    overall_result=0
    for scope in "${SCOPES[@]}"; do
        # Special handling for sora-admin tests
        if [ "$scope" = "sora-admin" ]; then
            test_path="$ORIGINAL_DIR/cmd/sora-admin"
        else
            test_path="$ORIGINAL_DIR/integration_tests/$scope"
        fi

        if run_test_suite "$test_path" "$scope"; then
            print_success "$scope integration tests completed successfully"
        else
            print_error "$scope integration tests failed"
            overall_result=1
        fi
        echo
    done
    
    # Print final results
    print_section "Final Results"
    if [ $overall_result -eq 0 ]; then
        print_success "All integration tests passed!"
        echo -e "${GREEN}"
        echo "╔══════════════════════════════════════════════════════════════╗"
        echo "║                      ALL TESTS PASSED                        ║"
        echo "╚══════════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
    else
        print_error "Some integration tests failed"
        echo -e "${RED}"
        echo "╔══════════════════════════════════════════════════════════════╗"
        echo "║                      TESTS FAILED                            ║"
        echo "╚══════════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        exit 1
    fi
}

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi