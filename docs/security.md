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

### Connection Limits

Each protocol server supports configurable connection limits:
```toml
[servers.imap]
max_connections = 1000          # Total connections
max_connections_per_ip = 10     # Per IP address
```

These limits prevent connection exhaustion attacks and ensure fair resource allocation across users.
