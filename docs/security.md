# Security Guide

Securing your mail server is critical. Sora provides several features to help you build a secure and robust email service.

## Transport Layer Security (TLS)

Always use TLS to encrypt communications between clients, proxies, and servers.

*   **Enabling TLS**: In each server's configuration section (e.g., `[servers.imap]`), set `tls = true` and provide the paths to your certificate and key files:
    ```toml
    [servers.imap]
    addr = ":993" # Standard IMAPS port
    tls = true
    tls_cert_file = "/path/to/your/fullchain.pem"
    tls_key_file = "/path/to/your/privkey.pem"
    ```
    It is highly recommended that `tls_cert_file` contains the full certificate chain.

*   **STARTTLS**: For protocols that support opportunistic encryption (LMTP, ManageSieve), you can enable `tls_use_starttls = true`.

*   **Client Certificates**: Sora can be configured to verify client certificates for mutual TLS (`tls_verify = true`), but this is typically disabled (`false`) for general-purpose mail servers.

## Authentication

*   **Password Schemes**: Sora supports modern and legacy password hashing schemes. The default and recommended scheme is `bcrypt`. Support for various Dovecot schemes (`SSHA512`, `SHA512-CRYPT`, etc.) is included for easier migration. This is configured in the `sora-admin` tool or via the API when creating/updating credentials, not in `config.toml`.

*   **Master Users**: The `master_username` and `master_password` settings in the protocol server sections allow a special user to log in as any other user. This is primarily intended for proxy-to-backend authentication and administrative access. **Protect these credentials carefully.**

## Authentication Rate Limiting

To protect against brute-force password attacks, Sora has a built-in rate limiter. You can enable it in each protocol's configuration:

```toml
[servers.imap.auth_rate_limit]
enabled = true
max_attempts_per_ip = 10
max_attempts_per_username = 5
ip_window_duration = "15m"
fast_block_threshold = 10
fast_block_duration = "5m"
```

This system tracks failed login attempts per IP and per username, introducing progressive delays and temporary blocks to thwart attackers.

**Security Note**: The rate limiter implements a "fail-closed" security policy. If the database becomes unavailable, authentication attempts will be denied to prevent attackers from bypassing rate limiting by causing database errors. The rate limiter will automatically retry database access after the configured `db_error_threshold` period (default: 1 minute).

## PROXY Protocol

When running Sora behind a load balancer or proxy, the server will only see the proxy's IP address. The PROXY protocol solves this by prepending a header to the connection that contains the real client IP.

*   **WARNING**: Only enable this if you are certain your proxy is sending this header. An attacker who can connect directly to the port could spoof their IP address if this is misconfigured.
*   **Configuration**:
    ```toml
    [servers.imap.proxy_protocol]
    enabled = true
    trusted_proxies = ["127.0.0.1/32", "10.0.0.0/8"] # List of trusted proxy IPs/CIDRs
    ```

## Client-Side S3 Encryption

For an additional layer of security, you can have Sora encrypt message bodies *before* they are uploaded to S3.

```toml
[s3]
encrypt = true
encryption_key = "YOUR-SECRET-32-BYTE-HEX-ENCODED-KEY-HERE"
```

**CRITICAL**: If you enable this, you **must** back up the `encryption_key`. If this key is lost, all encrypted message data will be permanently unrecoverable.

## Resource Limits and DoS Protection

Sora includes built-in protections against resource exhaustion attacks:

### Search Result Limits

To prevent memory exhaustion from large search operations:
- **MaxSearchResults**: Limited to 1,000 messages per search (down from 5,000)
- **MaxComplexSortResults**: Limited to 500 messages for expensive JSONB-based sorts

These limits are enforced at the database layer and cannot be bypassed by clients. For mailboxes with more messages, clients should use more specific search criteria or implement pagination.

### Search Rate Limiting

Sora includes per-user search rate limiting to prevent DoS attacks via excessive search queries:

```toml
[servers.imap]
search_rate_limit_per_min = 10  # Maximum searches per minute (0 = disabled)
search_rate_limit_window = "1m" # Time window for rate limiting
```

When a user exceeds the limit, they receive a clear error message indicating how long to wait before trying again. The rate limiter:
- Tracks searches per user (not per IP)
- Uses a sliding time window
- Automatically cleans up inactive user tracking
- Is disabled by default (set `search_rate_limit_per_min` to enable)

### Session Memory Limits

Each IMAP and POP3 session has a configurable memory limit to prevent memory exhaustion attacks:

```toml
[servers.imap]
session_memory_limit = "100mb"  # Maximum memory per session (default: 100mb, 0 = unlimited)

[servers.pop3]
session_memory_limit = "100mb"  # Maximum memory per session (default: 100mb, 0 = unlimited)
```

The session memory tracker:
- **IMAP**: Monitors memory usage for FETCH and SEARCH operations
- **POP3**: Monitors memory usage for RETR and TOP operations
- Enforces limits before allocating large message bodies
- Automatically frees memory when operations complete
- Logs peak memory usage on session close
- Exports Prometheus metrics for monitoring

When a session exceeds its memory limit, the operation fails gracefully with a clear error message, protecting the server from out-of-memory conditions.

### Message Size Limits

To prevent memory exhaustion from oversized messages:

**IMAP APPEND**: Configurable via `append_limit` (default: 25MB)
```toml
[servers.imap]
append_limit = "25mb"  # Maximum size for IMAP APPEND operations
```

**LMTP Delivery**: Configurable via `max_message_size` (default: 50MB)
```toml
[servers.lmtp]
max_message_size = "50mb"  # Maximum size for incoming messages
```

When a message exceeds the configured limit:
- **IMAP**: Returns `[TOOBIG]` response code (RFC 7889)
- **LMTP**: Returns 552 error code (message size exceeds limit)

**Security Note**: LMTP's `max_message_size` is critical for preventing memory exhaustion attacks. The limit is enforced before loading the message into memory using `io.LimitReader`, protecting against attempts to send multi-GB emails that could OOM the server.

### Connection Limits

Each protocol server supports configurable connection limits:
```toml
[servers.imap]
max_connections = 1000          # Total connections
max_connections_per_ip = 10     # Per IP address
```

These limits prevent connection exhaustion attacks and ensure fair resource allocation across users.

### Command Timeout and Slowloris Protection

All protocol servers (IMAP, POP3, ManageSieve, LMTP) and their proxy variants implement multi-layered timeout protection to defend against various denial-of-service attacks:

#### Three-Layer Timeout Protection

1. **Idle Timeout** (`command_timeout`): Closes connections that have no activity for the specified duration
   - Default: `"5m"` (5 minutes)
   - Protects against: Clients that connect but never send commands
   - Triggered when: No read or write operations occur within the timeout period

2. **Absolute Session Timeout** (`absolute_session_timeout`): Enforces maximum total connection duration
   - Default: `"30m"` (30 minutes)
   - Protects against: Connections that stay open indefinitely by sending minimal activity
   - Triggered when: Total session duration exceeds the limit, regardless of activity

3. **Minimum Throughput Enforcement** (`min_bytes_per_minute`): Closes connections transferring data too slowly
   - Default: `1024` bytes/minute (1 KB/min)
   - Protects against: Slowloris attacks where attackers send data byte-by-byte to tie up connections
   - Triggered when: Average data transfer rate falls below the threshold over a 1-minute window

#### Configuration Example

```toml
[servers.imap]
start = true
addr = ":143"
command_timeout = "5m"              # Close after 5 minutes of inactivity
absolute_session_timeout = "30m"    # Maximum 30-minute sessions
min_bytes_per_minute = 1024         # Require at least 1KB/min throughput

[servers.imap_proxy]
start = true
addr = ":1143"
remote_addrs = ["backend1:143", "backend2:143"]
command_timeout = "10m"             # Longer than backend timeouts
absolute_session_timeout = "30m"
min_bytes_per_minute = 1024
```

#### Important Considerations

- **Set to `0`**: Uses default values (5m idle, 30m session, 1024 bytes/min)
- **Set to `-1`**: Disables that specific protection (not recommended for production)
- **Proxy timeout coordination**: When using proxies with backends that have PROXY protocol enabled, ensure the proxy's `command_timeout` is **longer** than the backend's `proxy_protocol_timeout` (typically 5s) to prevent the proxy from timing out while waiting for backend PROXY protocol negotiation

#### Monitoring

All timeout events are logged with detailed information and exported as Prometheus metrics:

```
command_timeouts_total{protocol="imap", reason="idle"}
command_timeouts_total{protocol="imap", reason="session_max"}
command_timeouts_total{protocol="imap", reason="slow_throughput"}
```

Monitor these metrics to:
- Detect potential attack patterns (sudden spikes in timeouts)
- Tune timeout values for your workload
- Identify misbehaving clients
