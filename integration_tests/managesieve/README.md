# ManageSieve Integration Tests

This directory contains integration tests for the ManageSieve protocol implementation in Sora.

## Overview

ManageSieve is a protocol for managing Sieve email filtering scripts on a mail server. These integration tests verify that the Sora ManageSieve server correctly implements the protocol specifications and can handle various client operations.

## Test Coverage

The test suite includes the following test scenarios:

### Basic Functionality Tests
- **TestManageSieveBasicConnection**: Tests basic server connection and greeting
- **TestManageSieveAuthentication**: Tests user authentication with PLAIN SASL mechanism
- **TestManageSieveScriptOperations**: Tests script management operations (PUTSCRIPT, GETSCRIPT, LISTSCRIPTS)

### Server Behavior Tests
- **TestManageSieveMultipleConnections**: Tests handling of concurrent client connections
- **TestManageSieveConnectionTimeout**: Tests server behavior with idle connections
- **TestManageSieveTLS**: Tests TLS/STARTTLS functionality (currently skipped)

## Running Tests

### Prerequisites
- PostgreSQL database running locally
- Go development environment
- Sora test database schema applied

### Using the Test Runner Script

The easiest way to run tests is using the provided test runner script:

```bash
# Run all tests
./test_managesieve.sh

# Run specific test categories
./test_managesieve.sh --basic      # Basic connection tests
./test_managesieve.sh --auth       # Authentication tests
./test_managesieve.sh --script-ops # Script operations tests
./test_managesieve.sh --multiple   # Multiple connections tests
./test_managesieve.sh --timeout    # Connection timeout tests

# Run with verbose output
./test_managesieve.sh --verbose
```

### Running Tests Directly

You can also run the tests directly using Go:

```bash
cd integration_tests/managesieve

# Run all tests
go test -v -tags=integration .

# Run specific test
go test -v -tags=integration -run TestManageSieveBasicConnection .
```

## Test Implementation Details

### Authentication Testing
The tests use PLAIN SASL authentication mechanism, which is the most common authentication method for ManageSieve. The authentication credentials are base64 encoded in the format: `\0username\0password`.

### Script Testing
The script operations tests use a simple Sieve script that demonstrates basic filtering capabilities:
- File messages containing "test" in the subject into a "Test" folder
- Uses common Sieve extensions like "fileinto" and "reject"

### Connection Management
The server properly handles:
- Multiple concurrent connections
- Connection cleanup on client disconnect
- Authentication state management per connection

## Integration with Common Test Utilities

These tests use the common test utilities from `../common/testutil.go`:
- `SetupManageSieveServer()`: Creates a test ManageSieve server instance
- `SetupTestDatabase()`: Initializes test database connection
- `CreateTestAccount()`: Creates test user accounts for authentication

## Protocol Compliance

The tests verify compliance with ManageSieve protocol specifications:
- Proper greeting messages
- CAPABILITY command support
- AUTHENTICATE command with SASL mechanisms
- Script management commands (PUTSCRIPT, GETSCRIPT, LISTSCRIPTS)
- Proper response formatting and status codes

## Configurable Sieve Extensions

The ManageSieve server supports configurable Sieve extensions through the `SupportedExtensions` configuration option. The following extensions are supported by the underlying go-sieve library:

### Core Extensions (RFC 5228)
- **envelope** - Test envelope information (sender/recipient addresses)
- **fileinto** - File messages into specified mailboxes  
- **redirect** - Redirect messages to other email addresses
- **encoded-character** - Support for encoded characters in strings

### Extended Extensions
- **imap4flags** (RFC 5232) - Set IMAP flags on messages
- **variables** (RFC 5229) - Variable support for dynamic script behavior
- **relational** (RFC 5231) - Relational comparisons (greater than, less than)
- **vacation** (RFC 5230) - Automatic vacation/out-of-office responses
- **copy** (RFC 3894) - Copy messages while performing other actions

### Configuration

Configure supported extensions in the ManageSieve server options:

```go
managesieve.ManageSieveServerOptions{
    SupportedExtensions: []string{"fileinto", "vacation", "envelope", "variables"},
    // ... other options
}
```

If no extensions are configured, the default extensions are: `["fileinto", "vacation"]`

### Testing

The integration tests verify that:
- Only configured extensions are advertised in CAPABILITY responses
- Scripts using configured extensions are accepted
- Scripts using non-configured extensions are rejected
- Default extensions work when no configuration is provided

## Future Enhancements

Potential areas for test expansion:
- TLS/STARTTLS functionality testing
- Additional SASL authentication mechanisms
- More complex Sieve script scenarios
- Error handling and edge cases
- Performance and load testing
- PROXY protocol support testing