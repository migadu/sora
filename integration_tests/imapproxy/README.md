# IMAP Proxy Integration Tests

This directory contains integration tests for the IMAP proxy functionality in Sora.

## Test Coverage

The tests cover the following scenarios:

1. **PROXY Protocol Mode** (`TestIMAPProxyWithPROXYProtocol`)
   - Tests IMAP proxy using PROXY protocol for backend communication
   - Sends PROXY protocol headers to preserve client IP information
   - Verifies login, mailbox selection, and listing work through the proxy
   - Ensures logs show proper PROXY protocol information

2. **ID Command Mode (Dovecot Compatibility)** (`TestIMAPProxyWithIDCommand`)
   - Tests IMAP proxy using ID command forwarding for Dovecot compatibility
   - Uses IMAP ID command to forward client information instead of PROXY protocol
   - Validates that the proxy correctly handles client identification

3. **Multiple Backend Servers** (`TestIMAPProxyMultipleBackends`)
   - Tests load balancing across multiple backend IMAP servers
   - Verifies connections to different backends work correctly

4. **Authentication** (`TestIMAPProxyAuthentication`)
   - Tests various authentication scenarios through the proxy
   - Validates proper error handling for invalid credentials

5. **Connection Limits** (`TestIMAPProxyConnectionLimits`)
   - Tests connection limiting functionality
   - Verifies proxy properly handles connection throttling

## Key Features Tested

- **PROXY Protocol Support**: The proxy sends PROXY protocol headers to backend servers to preserve client IP
- **ID Command Forwarding**: For Dovecot compatibility, uses IMAP ID command to forward client information
- **Load Balancing**: Connections are distributed across multiple backend servers
- **Authentication Passthrough**: User credentials are properly forwarded to backends
- **Session Management**: Proper handling of IMAP sessions through the proxy
- **Error Handling**: Appropriate error responses for various failure scenarios

## Two Communication Modes

### 1. PROXY Protocol Mode
This mode is ideal for backends that support PROXY protocol (like Sora itself):
- `RemoteUseProxyProtocol: true`
- `RemoteUseIDCommand: false`
- Real client IP is preserved in PROXY protocol headers
- More efficient and reliable for IP preservation

### 2. ID Command Mode (Dovecot Compatibility)
This mode is designed for Dovecot backends that don't support PROXY protocol:
- `RemoteUseProxyProtocol: false`  
- `RemoteUseIDCommand: true`
- Client information forwarded via IMAP ID command
- Compatible with Dovecot's proxy implementation

## Running the Tests

### Individual Test Execution

```bash
# Run all IMAP proxy tests
go test -v -tags=integration

# Run specific test
go test -v -tags=integration -run TestIMAPProxyWithPROXYProtocol
go test -v -tags=integration -run TestIMAPProxyWithIDCommand
```

### Using the Test Script

```bash
# Run all IMAP proxy tests
./test_imap_proxy.sh

# Run specific test categories
./test_imap_proxy.sh --proxy-protocol
./test_imap_proxy.sh --id-command
./test_imap_proxy.sh --multiple-backends
./test_imap_proxy.sh --authentication
./test_imap_proxy.sh --connection-limits
```

### Using the Main Integration Test Runner

```bash
# Run all integration tests including IMAP proxy
./run_integration_tests.sh

# Run only IMAP proxy tests
./run_integration_tests.sh --protocol imapproxy
```

## Prerequisites

- PostgreSQL database running and accessible
- Go development environment
- Sora dependencies installed (`go mod tidy`)

## Test Architecture

Each test follows this pattern:

1. **Setup**: Create backend IMAP server(s) with test accounts
2. **Proxy Creation**: Start IMAP proxy pointing to backend(s)
3. **Testing**: Connect through proxy and verify functionality
4. **Cleanup**: Properly shut down proxy and backend servers

## Log Verification

The tests verify that proper PROXY protocol information appears in logs:

- Backend servers should log connections with PROXY protocol information
- Real client IP addresses should be preserved and logged
- Proxy IP addresses should be distinguished from client IPs

## Configuration

The tests use these key proxy configuration options:

- `RemoteUseProxyProtocol: true` - Enables PROXY protocol to backends
- `RemoteUseIDCommand: true/false` - Controls ID command forwarding
- `EnableAffinity: true` - Enables session affinity for load balancing
- `TrustedProxies` - Defines trusted proxy networks