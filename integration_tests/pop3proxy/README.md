# POP3 Proxy Integration Tests

This directory contains integration tests for the POP3 proxy functionality in Sora.

## Test Coverage

The tests cover the following scenarios:

1. **PROXY Protocol Mode** (`TestPOP3ProxyWithPROXYProtocol`)
   - Tests POP3 proxy using PROXY protocol for backend communication
   - Sends PROXY protocol headers to preserve client IP information
   - Verifies login, basic POP3 operations work through the proxy
   - Ensures logs show proper PROXY protocol information

2. **XCLIENT Command Mode** (`TestPOP3ProxyWithXCLIENT`)
   - Tests POP3 proxy using XCLIENT command for parameter forwarding
   - Uses POP3 XCLIENT command to forward client information instead of PROXY protocol
   - Validates that the proxy correctly handles client identification

3. **Multiple Backend Servers** (`TestPOP3ProxyMultipleBackends`)
   - Tests load balancing across multiple backend POP3 servers
   - Verifies connections to different backends work correctly

4. **Authentication** (`TestPOP3ProxyAuthentication`)
   - Tests various authentication scenarios (valid/invalid credentials)
   - Validates proper error handling for authentication failures

## Key Features Tested

- **PROXY Protocol Support**: The proxy sends PROXY protocol headers to backend servers to preserve client IP
- **XCLIENT Command Forwarding**: Uses POP3 XCLIENT command to forward client information
- **Load Balancing**: Connections are distributed across multiple backend servers
- **Authentication Passthrough**: User credentials are properly forwarded to backends
- **Session Management**: Proper handling of POP3 sessions through the proxy
- **Error Handling**: Appropriate error responses for various failure scenarios

## Two Communication Modes

### 1. PROXY Protocol Mode
This mode is ideal for backends that support PROXY protocol (like Sora itself):
- `RemoteUseProxyProtocol: true`
- `RemoteUseXCLIENT: false`
- Real client IP is preserved in PROXY protocol headers
- More efficient and reliable for IP preservation

### 2. XCLIENT Command Mode
This mode is designed for backends that support XCLIENT command:
- `RemoteUseProxyProtocol: false`  
- `RemoteUseXCLIENT: true`
- Client information forwarded via POP3 XCLIENT command
- Compatible with POP3 servers that implement XCLIENT extension

## Running the Tests

### Individual Test Execution

```bash
# Run all POP3 proxy tests
go test -v -tags=integration

# Run specific test
go test -v -tags=integration -run TestPOP3ProxyWithPROXYProtocol
go test -v -tags=integration -run TestPOP3ProxyWithXCLIENT
```

### Using the Test Script

```bash
# Run all POP3 proxy tests
./test_pop3_proxy.sh

# Run specific test categories
./test_pop3_proxy.sh --proxy-protocol
./test_pop3_proxy.sh --xclient
./test_pop3_proxy.sh --multiple-backends
./test_pop3_proxy.sh --authentication
```

### Using the Main Integration Test Runner

```bash
# Run all integration tests including POP3 proxy
./run_integration_tests.sh

# Run only POP3 proxy tests
./run_integration_tests.sh --protocol pop3proxy
```

## Prerequisites

- PostgreSQL database running and accessible
- Go development environment
- Sora dependencies installed (`go mod tidy`)

## Test Architecture

Each test follows this pattern:

1. **Setup**: Create backend POP3 server(s) with test accounts
2. **Proxy Creation**: Start POP3 proxy pointing to backend(s)
3. **Testing**: Connect through proxy and verify functionality
4. **Cleanup**: Properly shut down proxy and backend servers

## Log Verification

The tests verify that proper protocol information appears in logs:

### PROXY Protocol Mode Logs:
- `[PROXY] Sent PROXY v2 header to backend`
- `[PROXY] Parsed PROXY v2: client=127.0.0.1:port -> server=127.0.0.1:port`
- `POP3 remote=127.0.0.1 proxy=127.0.0.1` - proper proxy logging

### XCLIENT Command Mode Logs:
- `CLIENT COMMAND: XCLIENT ADDR=127.0.0.1 PORT=...`
- `[XCLIENT] Updated client IP from forwarding parameters`
- `[POP3 Proxy] XCLIENT forwarding completed successfully`

Both modes correctly preserve client IP information and show proper protocol-specific logging.

## Tested POP3 Operations

The tests verify these core POP3 operations work through the proxy:

1. **Connection & Greeting**: Initial connection and server greeting
2. **Authentication**: USER and PASS commands with proper credential forwarding
3. **STAT**: Get mailbox statistics (message count, total size)
4. **LIST**: List messages in mailbox
5. **QUIT**: Proper session termination

## Configuration

The tests use these key proxy configuration options:

- `RemoteUseProxyProtocol: true/false` - Controls PROXY protocol usage
- `RemoteUseXCLIENT: true/false` - Controls XCLIENT command usage
- `EnableAffinity: true` - Enables session affinity for load balancing
- `TrustedProxies` - Defines trusted proxy networks for parameter forwarding
- `MasterSASLUsername/Password` - Master credentials for backend authentication