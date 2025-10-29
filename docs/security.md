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

## Cluster-Wide Rate Limiting

When cluster mode is enabled, Sora can synchronize authentication rate limiting across all nodes using the gossip protocol.

### Benefits

- **3x Better Protection**: Distributed attacks hitting different nodes are detected and blocked cluster-wide
- **Fast Synchronization**: Rate limit state propagated in 50-200ms via gossip
- **Low Overhead**: <200KB memory, <15 KB/s bandwidth per protocol
- **Eventually Consistent**: All nodes converge to the same blocked IP list

### Configuration

```toml
[cluster]
enabled = true
bind_addr = "0.0.0.0"
bind_port = 7946
node_id = "node-1"
peers = ["node-2:7946", "node-3:7946"]
secret_key = "base64-encoded-32-byte-key"  # Generate: openssl rand -base64 32

# Cluster-wide rate limiting (enabled by default when cluster is enabled)
[cluster.rate_limit_sync]
enabled = true              # Enable cluster-wide rate limiting
sync_blocks = true          # Sync IP blocks across nodes
sync_failure_counts = true  # Sync progressive delays across nodes
```

### How It Works

1. Node 1 detects authentication failure from IP `192.0.2.1`
2. After threshold failures, Node 1 blocks the IP locally
3. Node 1 broadcasts BLOCK_IP event via gossip (50-200ms)
4. Node 2 and Node 3 receive the event and block the IP locally
5. Future attempts from `192.0.2.1` to any node are rejected

### Security Guarantees

- **Encrypted Communication**: All gossip messages encrypted with AES-256
- **Replay Protection**: Events older than 5 minutes automatically rejected
- **Authentication**: Only nodes with correct `secret_key` can participate
- **Fail-Safe**: If gossip fails, per-node rate limiting still works

## TLS Certificate Management

Sora supports both manual certificate management and automatic Let's Encrypt integration.

### Let's Encrypt Integration

Automatic certificate issuance and renewal with cluster coordination:

```toml
[tls]
enabled = true
provider = "letsencrypt"

[tls.letsencrypt]
email = "admin@example.com"
domains = ["mail.example.com", "imap.example.com"]
storage_provider = "s3"      # Store certificates in S3
renew_before = "720h"        # Optional: renew 30 days before expiry (default)

[tls.letsencrypt.s3]
bucket = "sora-tls-certificates"
region = "us-east-1"
```

### Security Features

- **Automatic Renewal**: Certificates renewed 30 days before expiry
- **Hot Reload**: No server restart required for certificate updates
- **S3 Storage**: Certificates encrypted at rest with AES-256
- **Cluster Coordination**: Leader-only renewal prevents duplicate requests
- **HTTP-01 Challenges**: All nodes can respond to Let's Encrypt challenges
- **Graceful Failover**: 5-10 second recovery if leader fails

### Requirements

- Port 80 must be accessible from the internet for HTTP-01 challenges
- DNS A records must point to server public IPs
- S3 bucket with appropriate IAM permissions
- In cluster mode, all nodes must have network access to S3

### Monitoring

Monitor certificate expiration:
```bash
echo | openssl s_client -connect mail.example.com:993 -servername mail.example.com 2>/dev/null | \
  openssl x509 -noout -dates
```

Check renewal logs:
```bash
journalctl -u sora | grep -i "certificate\|renewal"
```

## Shared Mailbox Security (ACL)

Sora implements RFC 4314 Access Control Lists (ACL) with strict security boundaries.

### Same-Domain Enforcement

ACL entries are restricted to the same domain:
- Users in `example.com` can only grant access to other `example.com` users
- Cross-domain access is blocked at both database and application layers
- Domain extracted from primary credential, not from alias/credential

### Permission Model

11 standard ACL rights (lrswipkxtea):
- `l` (lookup) - Mailbox visible in LIST/LSUB
- `r` (read) - SELECT, FETCH, SEARCH, COPY source
- `s` (seen) - Keep \Seen flag across sessions
- `w` (write) - STORE flags (except \Seen, \Deleted)
- `i` (insert) - APPEND, COPY into mailbox
- `p` (post) - Send mail to submission address
- `k` (create) - CREATE child mailboxes
- `x` (delete) - DELETE mailbox
- `t` (delete-msg) - STORE \Deleted flag
- `e` (expunge) - EXPUNGE messages
- `a` (admin) - SETACL/DELETEACL/GETACL/LISTRIGHTS

### Security Guarantees

- **Owner Protection**: Owner always has full rights (cannot be locked out)
- **Admin Required**: Modifying ACLs requires `a` (admin) right
- **Visibility Control**: Mailbox invisible without `l` (lookup) right
- **Operation Enforcement**: Every operation checks required permissions
- **Database Validation**: Foreign key constraints prevent orphaned ACLs

### Configuration

```toml
[shared_mailboxes]
enabled = true
namespace_prefix = "Shared/"
allow_user_create = true          # Or false for admin-only
default_rights = "lrswipkxtea"    # Full rights for creators
```

### IMAP ACL Commands

```
# Check your rights
A001 MYRIGHTS "Shared/TeamInbox"

# List all ACL entries
A002 GETACL "Shared/TeamInbox"

# Grant read-write access
A003 SETACL "Shared/TeamInbox" user2@example.com lrswi

# Revoke access
A004 DELETEACL "Shared/TeamInbox" user2@example.com
```

## JA4 TLS Fingerprinting

Sora can identify TLS clients using JA4 fingerprints and selectively disable problematic capabilities.

### Use Case

Some email clients have bugs with specific IMAP extensions (e.g., iOS Mail with IDLE). JA4 fingerprinting allows you to work around these bugs without affecting other clients.

### Configuration

```toml
[[servers]]
type = "imap"
addr = ":993"
tls = true
# ... other settings ...

# Disable IDLE for iOS Mail clients
[[servers.client_filters]]
ja4_fingerprint = "^t13d1516h2_.*"
disable_caps = ["IDLE"]
reason = "iOS Mail client with known IDLE issues"
```

### Security Considerations

- **Non-blocking**: Fingerprint capture doesn't delay TLS handshake
- **Standard Format**: Uses industry-standard JA4 format
- **Regex Matching**: Flexible pattern-based client detection
- **Per-Client Filtering**: Only affects matched clients, others unaffected

### Limitations

- Only works with TLS connections (plaintext connections not fingerprinted)
- Fingerprints can change with client updates
- Requires regular testing with actual client devices

## API Security

The HTTP API provides comprehensive administration capabilities and must be properly secured.

### Authentication

Use a strong random API key:
```bash
# Generate a secure API key
openssl rand -hex 32
```

Configure in `config.toml`:
```toml
[[servers]]
type = "http_api"
start = true
addr = ":8080"
api_key = "your-secure-random-api-key"
allowed_hosts = ["127.0.0.1", "10.0.0.0/8"]  # IP/CIDR restrictions
```

### Best Practices

1. **Strong API Key**: Use a random 32-byte key
2. **Host Restrictions**: Limit access to trusted IPs/networks
3. **TLS**: Always use TLS in production (configure `tls_cert_file` and `tls_key_file`)
4. **Rotate Keys**: Periodically rotate API keys
5. **Monitor Access**: Log and monitor API access patterns
6. **Least Privilege**: Use separate API keys for different services if possible

### Security Features

- **Bearer Token Authentication**: Standard OAuth 2.0 style
- **CIDR Support**: Fine-grained IP access control
- **Secure Error Handling**: No information leakage in error messages
- **Request Logging**: Comprehensive audit trail
- **Rate Limiting**: Can be added at reverse proxy level

## Cluster Security

When running in cluster mode, secure the gossip protocol communication.

### Encryption

All cluster communication is encrypted with AES-256:
```toml
[cluster]
secret_key = "base64-encoded-32-byte-key"
```

Generate a secure key:
```bash
openssl rand -base64 32
```

### Network Isolation

- Bind gossip to private network: `bind_addr = "10.0.0.1"`
- Use firewall rules to restrict port 7946 to cluster nodes only
- Do not expose gossip port to the internet

### Best Practices

1. **Strong Secret Key**: Use a random 32-byte key
2. **Private Network**: Run gossip on private network only
3. **Firewall Rules**: Restrict port 7946 to cluster nodes
4. **Key Rotation**: Rotate secret key periodically (requires cluster restart)
5. **Monitor Health**: Track gossip health and node membership changes

## Security Checklist

### Before Production Deployment

- [ ] Enable TLS on all public-facing servers
- [ ] Configure authentication rate limiting
- [ ] Set strong API keys for HTTP API
- [ ] Enable PROXY protocol only from trusted proxies
- [ ] Configure connection limits (per-protocol, per-IP)
- [ ] Set session memory limits
- [ ] Enable cluster-wide rate limiting (if using cluster mode)
- [ ] Use strong secret key for cluster (if using cluster mode)
- [ ] Restrict HTTP API to trusted IPs
- [ ] Configure Let's Encrypt or provide TLS certificates
- [ ] Enable S3 encryption for message bodies (optional)
- [ ] Set appropriate file permissions on config files (chmod 600)
- [ ] Configure timeout protection on all protocols
- [ ] Review and tune search rate limits
- [ ] Monitor authentication failures and blocked IPs
- [ ] Set up alerting for security events

### Regular Maintenance

- [ ] Monitor authentication failure rates
- [ ] Review blocked IPs and user accounts
- [ ] Check TLS certificate expiration (if not using Let's Encrypt)
- [ ] Rotate API keys periodically
- [ ] Update Sora to latest security patches
- [ ] Review and audit access logs
- [ ] Test failover and recovery procedures
- [ ] Monitor cluster health and gossip connectivity
- [ ] Review and tune rate limiting thresholds

## Incident Response

### Suspected Brute-Force Attack

1. Check blocked IPs: `psql -c "SELECT ip, blocked_until FROM auth_attempts WHERE blocked_until > now()"`
2. Review auth statistics: `./sora-admin stats auth --config config.toml`
3. Increase rate limit sensitivity if needed
4. Consider blocking entire IP ranges at firewall level

### Suspected DoS Attack

1. Check connection counts: `./sora-admin connections list --config config.toml`
2. Review timeout metrics in logs and Prometheus
3. Kick connections if needed: `./sora-admin connections kick --config config.toml --protocol imap`
4. Adjust timeout values and connection limits as needed
5. Enable or tighten rate limiting

### Certificate Compromise

1. If using Let's Encrypt: Revoke certificate via ACME
2. Rotate to new certificate immediately
3. Review logs for suspicious access during compromise window
4. Notify affected users if necessary

### API Key Compromise

1. Generate new API key: `openssl rand -hex 32`
2. Update config and restart Sora
3. Review API access logs for suspicious activity
4. Audit what operations were performed with compromised key

### Cluster Secret Compromise

1. Generate new secret key: `openssl rand -base64 32`
2. Update config on all nodes
3. Restart entire cluster in coordinated fashion
4. Review cluster communication logs for suspicious activity

## Additional Resources

- **Let's Encrypt Documentation**: https://letsencrypt.org/docs/
- **RFC 4314 (IMAP ACL)**: https://tools.ietf.org/html/rfc4314
- **JA4 Fingerprinting**: https://github.com/FoxIO-LLC/ja4
- **Prometheus Security**: https://prometheus.io/docs/operating/security/
- **PostgreSQL Security**: https://www.postgresql.org/docs/current/security.html
