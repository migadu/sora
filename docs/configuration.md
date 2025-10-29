# Configuration Guide

Sora is configured using a single TOML file, typically named `config.toml`. You can start by copying the provided `config.toml.example` and modifying it for your environment.

This guide explains the most important configuration sections. For a complete list of all options and their default values, please refer to the heavily commented `config.toml.example` file.

## Minimal Configuration (Single Node)

For a simple, single-node setup, you only need to configure a few key areas. This example assumes PostgreSQL and Sora are running on the same host.

```toml
# config.toml

# Log to standard output
log_output = "stdout"

# --- Database ---
# All reads and writes go to the same database instance.
[database.write]
hosts = ["localhost"]
user = "sora_user"
password = "db_password"
name = "sora_mail_db"

# --- S3 Storage ---
# Configure your S3-compatible storage endpoint.
[s3]
endpoint = "s3.us-east-1.amazonaws.com"
access_key = "YOUR_S3_ACCESS_KEY"
secret_key = "YOUR_S3_SECRET_KEY"
bucket = "your-sora-mail-bucket"

# --- Protocol Servers ---
# Enable the servers you need.
[servers.imap]
start = true
addr = ":143"

[servers.lmtp]
start = true
addr = ":24"

[servers.pop3]
start = true
addr = ":110"

[servers.managesieve]
start = true
addr = ":4190"
```

## Section-by-Section Breakdown

### `[database]`

This section configures Sora's connection to PostgreSQL. For resilience and scalability, Sora supports splitting database traffic between a primary write instance and one or more read replicas.

*   `[database.write]`: Configures the primary database endpoint. All `INSERT`, `UPDATE`, and `DELETE` operations go here. In a simple setup, it also handles `SELECT` queries.
*   `[database.read]`: (Optional) Configures one or more read-replica database endpoints. If specified, Sora will load-balance all `SELECT` queries across these hosts, reducing the load on the primary database.

Each section allows you to configure hosts, port, user, password, database name, and connection pool settings (`max_conns`, `min_conns`, etc.).

### `[s3]`

This section is for your S3-compatible object storage, where message bodies are stored.

*   `endpoint`: The URL of your S3 provider (e.g., `s3.amazonaws.com` or a local MinIO `minio.example.com:9000`).
*   `access_key` & `secret_key`: Your S3 credentials.
*   `bucket`: The name of the S3 bucket to use.
*   `encrypt`: Set to `true` to enable client-side encryption. If enabled, you **must** provide a secure 32-byte `encryption_key`. **Losing this key means losing access to all your email bodies.**

### `[local_cache]` and `[uploader]`

These two components work together to provide high-performance mail delivery and access.

*   `[local_cache]`: Configures the local filesystem cache for message bodies.
    *   `path`: The directory to store cached files. Use a fast disk (SSD) for best performance.
    *   `capacity`: The maximum size of the cache (e.g., `"10gb"`).
    *   `enable_warmup`: If `true`, Sora will proactively fetch recent messages for a user's `INBOX` upon login, making the initial client experience much faster.
*   `[uploader]`: Configures the background service that moves messages to S3.
    *   `path`: A temporary staging directory where incoming messages are stored before being uploaded.
    *   `concurrency`: The number of parallel workers uploading to S3.

### `[cleanup]`

This configures the background janitorial service.

*   `grace_period`: How long to wait before permanently deleting a message that a user has expunged (e.g., `"14d"`). This acts as a recovery window.
*   `max_age_restriction`: Automatically expunge messages older than this duration (e.g., `"365d"`). Leave empty to disable.

### `[servers.*]`

Each protocol (IMAP, LMTP, POP3, ManageSieve) has its own configuration table.

*   `start`: A boolean to enable or disable the server.
*   `addr`: The listen address and port (e.g., `":143"`).
*   `tls`: Set to `true` to enable TLS (e.g., for IMAPS on port 993). You must also provide `tls_cert_file` and `tls_key_file`.
*   `max_connections`: Limits the total concurrent connections to this server.
*   `auth_rate_limit`: Contains settings to enable and configure brute-force authentication protection.
*   `proxy_protocol`: Contains settings to enable PROXY protocol, which is essential for seeing real client IPs when Sora is behind a load balancer. **Only enable this if you are behind a trusted proxy.**

#### Command Timeout and DoS Protection

All protocol servers support multi-layered timeout protection to defend against various denial-of-service attacks:

*   `command_timeout`: Maximum idle time before closing an inactive connection (default: `"5m"`). This protects against clients that connect but never send commands.
*   `absolute_session_timeout`: Maximum total session duration regardless of activity (default: `"30m"`). This ensures connections don't stay open indefinitely.
*   `min_bytes_per_minute`: Minimum data throughput required (default: `1024` bytes/min). This protects against slowloris attacks where clients send data extremely slowly to tie up connections. Set to `0` to use the default; set to `-1` to disable throughput checking.

Example:
```toml
[servers.imap]
start = true
addr = ":143"
command_timeout = "5m"              # Close after 5 minutes of inactivity
absolute_session_timeout = "30m"    # Maximum session duration
min_bytes_per_minute = 1024         # Require at least 1KB/min throughput
```

### `[servers.*_proxy]`

Sora can also act as a proxy to load balance connections to other Sora backend servers.

*   `start`: Enables the proxy server.
*   `addr`: The public-facing address the proxy listens on.
*   `remote_addrs`: A list of backend Sora server addresses.
*   `enable_affinity`: Enables sticky sessions, ensuring a user is consistently routed to the same backend server.
*   `prelookup`: An advanced feature for database-driven user routing. When enabled, the proxy queries a database to determine which backend server a user should be routed to. This is powerful for sharded or geo-distributed architectures.

#### Proxy Timeout Protection

Proxy servers also support the same multi-layered timeout protection as direct protocol servers:

*   `command_timeout`: Maximum idle time before closing an inactive connection (default: `"5m"`).
*   `absolute_session_timeout`: Maximum total session duration (default: `"30m"`).
*   `min_bytes_per_minute`: Minimum throughput to prevent slowloris attacks (default: `1024` bytes/min).

**Important:** When configuring timeout values for proxies, ensure the proxy's `command_timeout` is **longer** than any backend timeout values (including `proxy_protocol_timeout` if PROXY protocol is enabled on backends). This prevents the proxy from timing out while waiting for backend responses.

Example:
```toml
[servers.imap_proxy]
start = true
addr = ":1143"
remote_addrs = ["backend1:143", "backend2:143"]
command_timeout = "10m"             # Longer than backend timeouts
absolute_session_timeout = "30m"
min_bytes_per_minute = 1024
```

### `[servers.metrics]` and `[servers.http_api]`

*   `[servers.metrics]`: Enable and configure the Prometheus metrics endpoint.
*   `[servers.http_api]`: Enable and configure the administrative REST API. Requires setting a secure `api_key`.

### `[cluster]`

Enables gossip-based clustering for TLS certificate management, rate limiting synchronization, and connection tracking.

*   `enabled`: Set to `true` to enable cluster mode.
*   `addr`: **REQUIRED** - Specific IP address (with optional port) to bind for cluster communication. **MUST** be a real IP address reachable from other cluster nodes. **CANNOT** use `0.0.0.0`, `localhost`, `127.0.0.1`, `::`, or `::1`. Examples: `"10.10.10.40:7946"` or `"10.10.10.40"` (uses `port` field if port not specified).
*   `port`: Port for gossip protocol (default: `7946`). Only used if `addr` does not include a port.
*   `node_id`: Unique identifier for this node (e.g., `"node-1"`).
*   `peers`: List of other cluster nodes (e.g., `["10.10.10.41:7946", "10.10.10.42:7946"]`). **Do NOT include this node's address** - only list OTHER nodes in the cluster.
*   `secret_key`: 32-byte base64-encoded key for encrypting cluster communication. Generate with: `openssl rand -base64 32`

Example:
```toml
[cluster]
enabled = true
addr = "10.10.10.40:7946"  # Node 1 - MUST be specific IP reachable from peers
node_id = "node-1"
peers = ["10.10.10.41:7946", "10.10.10.42:7946"]  # List OTHER nodes, not this node
secret_key = "your-base64-encoded-secret-key"
```

**CRITICAL:** The `addr` field must be a specific IP address that other cluster nodes can reach. The gossip protocol uses this address for both binding the listener and advertising to peers. Using `0.0.0.0` or `localhost` will prevent other nodes from connecting to this node.

#### Cluster-Wide Rate Limiting

When cluster mode is enabled, rate limiting can be synchronized across all nodes:

```toml
[cluster.rate_limit_sync]
enabled = true              # Enable cluster-wide rate limiting
sync_blocks = true          # Sync IP blocks across nodes
sync_failure_counts = true  # Sync progressive delays across nodes
```

This provides 3x better protection against distributed attacks by sharing authentication failure state across all nodes with 50-200ms latency.

### `[tls]`

Configures TLS certificate management, including Let's Encrypt integration for automatic certificate issuance and renewal.

#### File-Based Certificates

Use static certificate files:
```toml
[tls]
enabled = true
provider = "file"

# Then configure per-server:
[[servers]]
type = "imap"
addr = ":993"
tls = true
tls_cert_file = "/path/to/cert.pem"
tls_key_file = "/path/to/key.pem"
```

#### Let's Encrypt with Automatic Renewal

Enable automatic certificate issuance and renewal:
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

**Features:**
- Automatic certificate issuance on first connection
- Automatic renewal (default: 30 days before expiry)
- Hot reload without restart
- Cluster coordination (leader-only renewal)
- S3-backed storage for cluster-wide sharing
- HTTP-01 challenge support (requires port 80)

**Requirements:**
- Port 80 must be accessible from the internet for HTTP-01 challenges
- DNS A records must point to server public IPs
- In cluster mode, all nodes can respond to challenges

### `[shared_mailboxes]`

Enables RFC 4314 shared mailboxes with Access Control Lists (ACL).

```toml
[shared_mailboxes]
enabled = true
namespace_prefix = "Shared/"      # Prefix for shared mailboxes
allow_user_create = true          # Allow users to create shared mailboxes
default_rights = "lrswipkxtea"    # Full rights for creators
```

**ACL Rights:**
- `l` - lookup: Mailbox visible in LIST/LSUB
- `r` - read: SELECT, FETCH, SEARCH, COPY source
- `s` - seen: Keep \Seen flag across sessions
- `w` - write: STORE flags (except \Seen, \Deleted)
- `i` - insert: APPEND, COPY into mailbox
- `p` - post: Send mail to submission address
- `k` - create: CREATE child mailboxes
- `x` - delete: DELETE mailbox
- `t` - delete-msg: STORE \Deleted flag
- `e` - expunge: EXPUNGE messages
- `a` - admin: SETACL/DELETEACL/GETACL/LISTRIGHTS

**IMAP ACL Commands:**
- `MYRIGHTS <mailbox>` - Show your rights
- `GETACL <mailbox>` - List all ACL entries
- `SETACL <mailbox> <user> <rights>` - Grant/modify access
- `DELETEACL <mailbox> <user>` - Revoke access
- `LISTRIGHTS <mailbox> <user>` - Show available rights

### `[relay]` and `[relay_queue]`

Configures external mail relay with disk-based queue for reliable delivery.

```toml
[relay]
type = "smtp"
smtp_host = "smtp.example.com:587"
smtp_username = "relay@example.com"
smtp_password = "relay-password"
smtp_tls = true
smtp_tls_verify = true
smtp_use_starttls = true

[relay_queue]
enabled = true
path = "/var/spool/sora/relay"
worker_interval = "1m"          # How often to process queue
batch_size = 100                # Messages per batch
max_attempts = 10               # Maximum retry attempts
retry_backoff = ["1m", "5m", "15m", "1h", "6h", "24h"]  # Exponential backoff
```

**Features:**
- Disk-based persistence (three-state queue: pending, processing, failed)
- Exponential backoff retry (max 10 attempts over ~32 hours)
- Background worker processing
- Prometheus metrics integration

### JA4 TLS Fingerprinting

Filter IMAP capabilities based on TLS client fingerprints to work around client-specific bugs.

```toml
[[servers]]
type = "imap"
# ... other settings ...

# Disable IDLE for iOS Mail clients
[[servers.client_filters]]
ja4_fingerprint = "^t13d1516h2_.*"
disable_caps = ["IDLE"]
reason = "iOS Mail client with known IDLE issues"
```

**Features:**
- Non-blocking capture during TLS handshake
- Standard JA4 format (industry-standard)
- Regex pattern matching
- Per-client capability filtering

## Configuration Best Practices

### Security

1. **Use strong passwords:** Generate random passwords for database and S3 credentials.
2. **Enable TLS:** Use Let's Encrypt for automatic certificate management, or provide your own certificates.
3. **Rate limiting:** Enable authentication rate limiting on all protocol servers.
4. **API authentication:** Use a strong random API key for the HTTP API.
5. **Cluster encryption:** Use a strong secret key for cluster communication.
6. **Host restrictions:** Limit HTTP API access to specific IPs/CIDRs.

### Performance

1. **Connection pooling:** Tune `max_conns` and `min_conns` based on your load.
2. **Read replicas:** Configure `database.read` for read-heavy workloads.
3. **Cache size:** Set `local_cache.capacity` to ~10-20% of your working set.
4. **Uploader concurrency:** Increase `uploader.concurrency` for high-volume deployments.
5. **Background workers:** Adjust cleanup and relay queue intervals based on load.

### High Availability

1. **Cluster mode:** Enable clustering for coordinated TLS renewal and rate limiting.
2. **Multiple nodes:** Run 3+ nodes for quorum and redundancy.
3. **Read replicas:** Use PostgreSQL read replicas to scale read operations.
4. **Proxy mode:** Use IMAP/POP3/LMTP proxies for load balancing.
5. **Health checks:** Enable health monitoring and integrate with load balancers.

### Monitoring

1. **Prometheus metrics:** Enable the metrics server and configure Prometheus scraping.
2. **Health checks:** Use `sora-admin health` or the HTTP API for health monitoring.
3. **Log aggregation:** Configure structured logging and aggregate with your logging system.
4. **Alert on failures:** Monitor authentication failures, connection limits, circuit breaker trips.

## Example Configurations

### Standalone Server

Simple single-node setup for small deployments:

```toml
log_output = "stdout"

[database]
host = "localhost"
port = 5432
dbname = "sora_mail_db"
user = "sora"
password = "secure-password"
max_conns = 50

[s3]
endpoint = "s3.amazonaws.com"
region = "us-east-1"
bucket = "sora-messages"
access_key = "your-access-key"
secret_key = "your-secret-key"

[[servers]]
type = "imap"
start = true
addr = ":993"
tls = true
tls_cert_file = "/etc/sora/cert.pem"
tls_key_file = "/etc/sora/key.pem"

[[servers]]
type = "lmtp"
start = true
addr = ":24"
```

### Clustered Deployment with Let's Encrypt

High-availability setup with automatic TLS:

```toml
log_output = "stdout"

[database]
host = "postgres-primary.internal"
port = 5432
dbname = "sora_mail_db"
user = "sora"
password = "secure-password"
max_conns = 100

[[database.read_endpoints]]
host = "postgres-replica-1.internal"
port = 5432

[[database.read_endpoints]]
host = "postgres-replica-2.internal"
port = 5432

[s3]
endpoint = "s3.amazonaws.com"
region = "us-east-1"
bucket = "sora-production-messages"
access_key = "your-access-key"
secret_key = "your-secret-key"

[cluster]
enabled = true
addr = "10.0.1.10:7946"  # Node 1 - MUST be specific IP reachable from peers
node_id = "node-1"  # Unique per node
peers = ["10.0.1.11:7946", "10.0.1.12:7946"]  # List OTHER nodes, not this node
secret_key = "base64-encoded-secret-key"

[cluster.rate_limit_sync]
enabled = true
sync_blocks = true
sync_failure_counts = true

[tls]
enabled = true
provider = "letsencrypt"

[tls.letsencrypt]
email = "ops@example.com"
domains = ["mail.example.com", "imap.example.com"]
storage_provider = "s3"
renew_before = "720h"

[tls.letsencrypt.s3]
bucket = "sora-tls-certificates"
region = "us-east-1"

[shared_mailboxes]
enabled = true
namespace_prefix = "Shared/"
allow_user_create = true

[[servers]]
type = "imap"
start = true
addr = ":993"
max_connections = 5000
max_connections_per_ip = 50

[servers.imap.auth_rate_limit]
enabled = true
max_attempts_per_ip = 10
fast_block_threshold = 5

[[servers]]
type = "http_api"
start = true
addr = ":8080"
api_key = "your-secure-api-key"
allowed_hosts = ["10.0.0.0/8", "172.16.0.0/12"]
```

### Proxy Setup

Frontend proxy with backend servers:

**Proxy configuration:**
```toml
[[servers]]
type = "imap_proxy"
start = true
addr = ":993"
remote_addrs = ["backend1.internal:143", "backend2.internal:143", "backend3.internal:143"]
tls = true
tls_cert_file = "/etc/sora/cert.pem"
tls_key_file = "/etc/sora/key.pem"
enable_affinity = true

[[servers]]
type = "lmtp_proxy"
start = true
addr = ":24"
remote_addrs = ["backend1.internal:24", "backend2.internal:24", "backend3.internal:24"]
```

**Backend configuration:**
```toml
[database]
host = "postgres-primary.internal"
# ... database config ...

[s3]
# ... S3 config ...

[[servers]]
type = "imap"
start = true
addr = ":143"
proxy_protocol = true  # Important: receive real client IPs from proxy

[[servers]]
type = "lmtp"
start = true
addr = ":24"
```

## Reference

For a complete list of all configuration options with detailed comments and examples, see `config.toml.example` in the repository root.
