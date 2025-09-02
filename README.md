# SORA — Mail Server

**Sora** is a robust, cloud-native email server built for scalability and resilience.  
It provides enterprise-grade email infrastructure with modern storage backends, comprehensive monitoring, and advanced proxy capabilities.

---

## Features

### Core Protocols
- **IMAP4rev1** server with IDLE, ESEARCH, and other extensions
- **LMTP** for reliable message delivery
- **POP3** with SASL authentication
- **ManageSieve** for script management
- **SIEVE** filtering with vacation responses

### Storage Architecture
- **PostgreSQL** for metadata with full-text search (pg_trgm)
- **S3-compatible** object storage for message bodies with deduplication
- **Local cache** for frequently accessed messages
- **Configurable retention** with grace periods and ephemeral storage

### Production Features
- **Connection pooling** with read/write separation
- **Circuit breakers** for external service failures
- **Health monitoring** with component status tracking
- **Rate limiting** for authentication attempts with IP blocking
- **Connection limits** per protocol and per IP
- **Graceful degradation** strategies under load
- **Background workers** with distributed task processing

### Proxy Mode 
- **Multi-backend support** for horizontal scaling
- **Load balancing** across backend servers
- **Server affinity** for consistent user routing
- **Health-based routing** with automatic failover
- **Protocol support**: IMAP, POP3, ManageSieve, LMTP

---

## Use Cases

Sora is designed for:

- **Production email infrastructure** at scale
- **Multi-tenant email hosting** with proxy load balancing
- **Cloud-native deployments** with Kubernetes/containers
- **High-availability setups** with multiple backend servers
- **Custom email solutions** with modern storage backends

---

## Status: BETA

Sora has evolved from alpha to production-ready with comprehensive resilience features, monitoring, and horizontal scaling capabilities. 

---

## Requirements

- Go 1.23+
- PostgreSQL 14+ with pg_trgm extension
- S3-compatible object storage (MinIO, AWS S3, etc.)

---

## Getting Started

1.  **Clone the repository:**
```bash
git clone https://github.com/yourname/sora.git
cd sora
```

2.  **Create and edit your configuration file:**
Copy the example configuration and then edit `config.toml` with your specific settings (database credentials, S3 details, server preferences, etc.).
```bash
cp config.toml.example config.toml
nano config.toml # Or your preferred editor
```
Refer to the comments within `config.toml.example` for guidance on each option.

3.  **Build the executables:**
```bash
make build
```
This creates two executables:
- `sora` - The main email server (from `cmd/sora`)
- `sora-admin` - Administrative tool for account management (from `cmd/sora-admin`)

4.  **Create accounts:**
Before running the server, create email accounts using the admin tool:
```bash
./sora-admin create-account --email user@example.com --password secretpassword
```

5.  **Run Sora:**
Start the email server:
```bash
./sora -config config.toml
```

---

## Configuration

See `config.toml.example` for comprehensive documentation of all configuration options.

### Key Configuration Areas

#### Database Configuration
```toml
[database]
# Connection pooling with separate read/write endpoints
max_conns = 100           # Maximum connections in pool
min_conns = 10            # Minimum idle connections
max_conn_lifetime = "1h"  # Connection lifetime

# Optional read replicas for scaling
[[database.read_endpoints]]
host = "replica1.example.com"
port = "5432"
```

#### Proxy Mode Configuration
```toml
[servers.imap_proxy]
enabled = true
listen = ":1143"          # Proxy listen port
backends = [              # Backend servers to proxy to
    "backend1.example.com:143",
    "backend2.example.com:143",
]
strategy = "round-robin"  # or "least-connections", "ip-hash"
```

#### Production Resilience
```toml
[servers.imap]
max_connections = 1000       # Total connection limit
max_connections_per_ip = 10  # Per-IP limit

[servers.imap.auth_rate_limit]
enabled = true
max_failures_per_ip = 5      # Block after 5 failures
max_failures_per_user = 10   # Per-user limit
failure_window = "15m"       # Time window for failures
block_duration = "1h"        # How long to block
```

#### Health Monitoring
```toml
[health]
enabled = true
check_interval = "30s"       # How often to check health
database_timeout = "5s"      # Database health check timeout
s3_timeout = "10s"          # S3 health check timeout
```

### Message Expunge Behavior

Sora implements a two-phase deletion process for expunged messages:

1. When messages are expunged (via IMAP EXPUNGE command), they are marked with an `expunged_at` timestamp but not immediately deleted
2. A background cleanup worker permanently deletes messages after a configurable grace period

Configure this behavior in your `config.toml`:

```toml
[cleanup]
# Time duration for which deleted items are kept before being permanently removed
# Examples: "14d" (14 days), "30d" (30 days), "7d" (7 days), "24h" (24 hours)
grace_period = "14d"

# How often the cleanup process should run to remove old items  
# Examples: "1h" (hourly), "24h" (daily), "6h" (every 6 hours)
wake_interval = "1h"

# Maximum age restriction for messages - enables ephemeral storage
# Messages older than this will be automatically expunged
# Leave empty for no restriction (messages can stay forever)
# Examples: "30d" (30 days), "90d" (90 days), "365d" (1 year)
max_age_restriction = "" # Empty means no restriction
```

This allows for:
- Recovery of accidentally expunged messages within the grace period
- Compliance with retention policies
- Reduced load on the storage backend by batching deletions
- **Ephemeral storage**: With `max_age_restriction` set, old messages are automatically expunged, ensuring storage doesn't grow indefinitely

### Ephemeral Storage Mode

When `max_age_restriction` is configured, Sora operates in ephemeral storage mode:

1. Messages older than the specified age are automatically marked as expunged during cleanup runs
2. These auto-expunged messages then enter the grace period before permanent deletion
3. This ensures that storage usage remains bounded over time

Example configuration for 90-day ephemeral storage:

```toml
[cleanup]
grace_period = "7d"           # Keep expunged messages for 7 days
wake_interval = "6h"          # Run cleanup every 6 hours
max_age_restriction = "90d"   # Auto-expunge messages older than 90 days
```

In this example:
- Messages older than 90 days are automatically expunged
- Expunged messages are kept for another 7 days before permanent deletion
- Total maximum message lifetime: 97 days

## Admin Tool

The `sora-admin` tool provides comprehensive administrative functions for managing accounts, monitoring connections, and system health.

### Creating Accounts

Create new email accounts:

```bash
# Basic account creation
./sora-admin create-account --email user@example.com --password secretpassword

# Create account with specific hash type
./sora-admin create-account --email user@example.com --password secretpassword --hash ssha512

# Create account and mark as primary identity
./sora-admin create-account --email user@example.com --password secretpassword --primary

# Use custom database connection (overriding config file)
./sora-admin create-account --email user@example.com --password secretpassword \
  --dbhost localhost --dbport 5432 --dbuser postgres --dbname sora_db
```

### Updating Accounts

Update existing account passwords:

```bash
# Basic password update
./sora-admin update-account --email user@example.com --password newpassword

# Update password with specific hash type
./sora-admin update-account --email user@example.com --password newpassword --hash ssha512

# Use custom database connection (overriding config file)  
./sora-admin update-account --email user@example.com --password newpassword \
  --dbhost localhost --dbport 5432 --dbuser postgres --dbname sora_db
```

### Available Hash Types

- `bcrypt` (default) - bcrypt hash with salt
- `ssha512` - Salted SHA512 hash
- `sha512` - SHA512 hash without salt

### Monitoring Commands

```bash
# View active connections
./sora-admin connections         # List all active connections
./sora-admin connections --user user@example.com  # User-specific

# Check system health
./sora-admin health-status       # Overall health check
./sora-admin health-status --detailed  # Component details

# Connection statistics
./sora-admin connection-stats    # Connection metrics by protocol/server

# Terminate connections
./sora-admin terminate-connections --user user@example.com
./sora-admin terminate-connections --protocol imap
./sora-admin terminate-connections --server backend1.example.com
```

### Import/Export Operations

```bash
# Import maildir format
./sora-admin import-maildir --email user@example.com --path /path/to/maildir

# Export to maildir format
./sora-admin export-maildir --email user@example.com --path /path/to/export
```

### Help

Get help for any command:

```bash
./sora-admin help
./sora-admin create-account --help
./sora-admin update-account --help
./sora-admin health-status --help
```

## Operational Guide

### Running in Production

#### Standalone Mode
```bash
# Run with specific config
./sora -config /etc/sora/config.toml

# Override specific settings
./sora -config config.toml -masterpassword "secret" -dbhost prod-db.example.com
```

#### Proxy Mode for Horizontal Scaling
```bash
# Run proxy on load balancer
./sora -config proxy-config.toml  # Enable proxy sections, disable backend sections

# Run backend servers
./sora -config backend1-config.toml  # Port 143, proxy disabled
./sora -config backend2-config.toml  # Port 143, proxy disabled
```

### Monitoring and Health Checks

Sora provides comprehensive health monitoring:

1. **Database Health**: Checks write/read pool connectivity
2. **S3 Health**: Validates object storage accessibility  
3. **Circuit Breaker Status**: Monitors service resilience
4. **Connection Metrics**: Tracks active connections per protocol

Access health status via:
```bash
./sora-admin health-status
```

### Performance Tuning

#### Database Connection Pools
```toml
[database]
max_conns = 100          # Adjust based on concurrent users
min_conns = 10           # Maintain minimum ready connections
max_conn_lifetime = "1h" # Refresh connections periodically
```

#### Rate Limiting
```toml
[servers.imap.auth_rate_limit]
max_failures_per_ip = 5    # Stricter for public-facing
failure_window = "15m"      # Shorter window = more forgiving
block_duration = "1h"       # Longer = better protection
```

#### Background Workers
```toml
[upload]
workers = 10              # Parallel S3 uploads
batch_size = 100         # Messages per batch

[cleanup]
wake_interval = "1h"     # Cleanup frequency
grace_period = "7d"      # Recovery window
```

### Troubleshooting

#### Connection Issues
```bash
# Check active connections
./sora-admin connections

# View connection limits
grep "max_connections" config.toml

# Terminate stuck connections
./sora-admin terminate-connections --protocol imap
```

#### Performance Issues
```bash
# Check health status
./sora-admin health-status --detailed

# Monitor database connections
./sora-admin connection-stats

# Review circuit breaker status in logs
grep "circuit breaker" /var/log/sora.log
```

#### Authentication Failures
```bash
# Check rate limiting
grep "rate limit" /var/log/sora.log

# View blocked IPs (in database)
psql -c "SELECT * FROM auth_attempts WHERE blocked_until > now()"
```
