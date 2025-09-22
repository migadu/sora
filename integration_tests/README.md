# SORA Integration Tests

This directory contains comprehensive integration tests for the SORA mail server protocols. These tests start actual server instances locally and test them as clients, providing end-to-end validation of protocol implementations.

## Overview

The integration tests are organized by protocol:

- **`imap/`** - IMAP4rev1 protocol tests
- **`lmtp/`** - LMTP (Local Mail Transfer Protocol) tests  
- **`pop3/`** - POP3 protocol tests
- **`common/`** - Shared test utilities and server setup helpers

## Prerequisites

### Required Software

1. **Go 1.23.1+** - For running the tests
2. **PostgreSQL** - Database backend
   - Must be running locally on `localhost:5432`
   - Default user: `postgres` (no password)
   - Database: `sora_mail_db`

### Database Setup

1. **Install PostgreSQL** (if not already installed):
   ```bash
   # macOS
   brew install postgresql
   brew services start postgresql
   
   # Ubuntu/Debian
   sudo apt-get install postgresql postgresql-contrib
   sudo systemctl start postgresql
   ```

2. **Create test database**:
   ```bash
   createdb sora_mail_db
   ```

3. **Apply schema** (if needed):
   ```bash
   psql sora_mail_db -f db/schema.sql
   ```

## Running Tests

### Quick Start

Run all integration tests:
```bash
./run_integration_tests.sh
```

### Run Specific Protocol Tests

```bash
# IMAP only
./run_integration_tests.sh --protocol imap

# LMTP only  
./run_integration_tests.sh --protocol lmtp

# POP3 only
./run_integration_tests.sh --protocol pop3
```

### Manual Test Execution

You can also run tests manually for individual protocols:

```bash
# IMAP tests
cd integration_tests/imap
go test -v -tags=integration

# LMTP tests
cd integration_tests/lmtp  
go test -v -tags=integration

# POP3 tests
cd integration_tests/pop3
go test -v -tags=integration
```

### Skip Database Checks

If you have a custom database setup:
```bash
./run_integration_tests.sh --skip-db-check
```

### Environment Variables

- `SKIP_INTEGRATION_TESTS=1` - Skip all integration tests
- `DB_HOST` - Database host (default: localhost)
- `DB_PORT` - Database port (default: 5432)
- `DB_USER` - Database user (default: postgres)
- `DB_NAME` - Database name (default: sora_mail_db)

## Test Architecture

### Common Test Utilities (`common/testutil.go`)

The common package provides shared functionality:

- **`SetupTestDatabase()`** - Creates database connections
- **`CreateTestAccount()`** - Creates unique test accounts per test
- **`SetupIMAPServer()`** - Starts IMAP server on random port
- **`SetupLMTPServer()`** - Starts LMTP server on random port  
- **`SetupPOP3Server()`** - Starts POP3 server on random port
- **`SkipIfDatabaseUnavailable()`** - Graceful skipping when DB unavailable

### Test Isolation

Each test:
- Uses unique email addresses (includes test name + timestamp)
- Runs on random available ports to avoid conflicts
- Cleans up resources automatically via `t.Cleanup()`
- Can run concurrently with other tests

### Server Lifecycle

1. **Setup**: Start server with minimal dependencies
2. **Test**: Connect as client and issue protocol commands
3. **Cleanup**: Gracefully shutdown server and close connections

## Test Coverage

### IMAP Tests (`imap/imap_test.go`)

- ✅ **Basic Authentication** - Login/logout with valid credentials
- ✅ **Invalid Authentication** - Wrong password and non-existent users
- ✅ **Mailbox Operations** - LIST, CREATE, DELETE mailboxes
- ✅ **Multiple Connections** - Concurrent client connections
- ✅ **IDLE Command** - Long-running IDLE connections
- ✅ **Capabilities** - CAPABILITY command and required features
- ✅ **Connection Reuse** - Multiple operations on same connection

### LMTP Tests (`lmtp/lmtp_test.go`)

- ✅ **Basic Connection** - Server startup and client connection
- ✅ **LHLO Command** - LMTP handshake and capabilities
- ✅ **Simple Delivery** - End-to-end message delivery
- ✅ **Invalid Recipients** - Rejection of unknown recipients
- ✅ **Multiple Recipients** - Single message to multiple recipients
- ✅ **RSET Command** - Transaction reset functionality

### POP3 Tests (`pop3/pop3_test.go`)

- ✅ **Basic Connection** - Server startup and client connection
- ✅ **USER/PASS Authentication** - Standard POP3 authentication
- ✅ **Invalid Authentication** - Wrong credentials handling
- ✅ **STAT Command** - Mailbox statistics
- ✅ **LIST Command** - Message listing
- ✅ **CAPA Command** - Server capabilities
- ✅ **NOOP Command** - No-operation keepalive
- ✅ **Multiple Connections** - Concurrent client support
- ✅ **QUIT Command** - Graceful session termination

## Extending Tests

### Adding New Test Cases

1. **Choose appropriate protocol directory** (`imap/`, `lmtp/`, `pop3/`)
2. **Use test build tag**: `//go:build integration`
3. **Use common utilities** for server setup:
   ```go
   func TestMyNewFeature(t *testing.T) {
       common.SkipIfDatabaseUnavailable(t)
       
       server, account := common.SetupIMAPServer(t)
       defer server.Close()
       
       // Your test code here
   }
   ```

### Adding New Protocol Support

1. **Create new directory** under `integration_tests/`
2. **Add server setup function** to `common/testutil.go`
3. **Create client utilities** for the protocol
4. **Add test cases** following existing patterns
5. **Update test runner script** to include new protocol

### Protocol Client Implementations

Each protocol directory includes simple client implementations:

- **IMAP**: Uses `github.com/emersion/go-imap/v2` library
- **LMTP**: Custom TCP client with SMTP-like commands
- **POP3**: Custom TCP client with POP3 commands

These clients are intentionally simple to focus on testing server behavior rather than client sophistication.

## Troubleshooting

### Common Issues

1. **Database Connection Failed**
   ```
   Failed to set up test database: connection refused
   ```
   - Ensure PostgreSQL is running: `brew services start postgresql`
   - Check connection: `pg_isready -h localhost -p 5432 -U postgres`

2. **Permission Denied**
   ```
   permission denied for database sora_mail_db
   ```
   - Create database: `createdb sora_mail_db`
   - Check user permissions in PostgreSQL

3. **Port Already in Use**
   ```
   listen tcp 127.0.0.1:1143: bind: address already in use
   ```
   - Tests use random ports, but ensure no other SORA instances are running
   - Kill processes: `pkill -f sora`

4. **Test Timeouts**
   ```
   test timed out after 10m0s
   ```
   - Check database performance
   - Ensure sufficient system resources
   - Look for deadlocks in test logs

### Debug Mode

Enable verbose logging in tests:
```go
// In common/testutil.go, change:
LogQueries: true, // Enable SQL logging
```

### Test Data Cleanup

Tests create unique accounts per run, but don't automatically clean up the database. To reset:
```bash
./reset-db.sh
```

## Performance Considerations

- Tests run with minimal S3 storage (mock objects)
- Database connections use small connection pools
- Servers start with debugging disabled for performance
- Random ports prevent conflicts but may affect timing

## Security Testing

These integration tests focus on basic protocol compliance rather than security testing. For security-focused testing:

- Use dedicated security testing tools
- Test with real TLS certificates
- Validate authentication edge cases
- Test rate limiting and connection limits

## CI/CD Integration

To integrate with continuous integration:

```yaml
# Example GitHub Actions step
- name: Run Integration Tests
  run: |
    # Start PostgreSQL service
    sudo systemctl start postgresql
    sudo -u postgres createdb sora_mail_db
    
    # Run tests
    ./run_integration_tests.sh
  env:
    SKIP_INTEGRATION_TESTS: false
```

The test runner returns appropriate exit codes for CI systems:
- `0` - All tests passed
- `1` - One or more tests failed