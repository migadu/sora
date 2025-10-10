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

