# SORA — Mail Server

**Sora** is a cloud-native email server built for scalability and resilience.  
It provides enterprise-grade email infrastructure with modern storage backends, comprehensive monitoring, clustering capabilities, and advanced proxy features.

---

## Features

### Core Protocols
- **IMAP4rev1** server with IDLE, ESEARCH, ACL, and other extensions
- **LMTP** for reliable message delivery with SIEVE filtering
- **POP3** with SASL authentication
- **ManageSieve** for script management
- **SIEVE** filtering with vacation responses
- **HTTP API** for administration and monitoring

### Storage Architecture
- **PostgreSQL** for metadata with full-text search (pg_trgm)
- **S3-compatible** object storage for message bodies with content deduplication
- **Local cache** for frequently accessed messages, providing read-level deduplication
- **Configurable retention** with grace periods and ephemeral storage

### Shared Mailboxes (RFC 4314)
- **Access Control Lists (ACL)** with 11 standard rights (lrswipkxtea)
- **IMAP ACL commands**: MYRIGHTS, GETACL, SETACL, DELETEACL, LISTRIGHTS
- **Same-domain enforcement** for security
- **Configurable namespace** for shared mailboxes

### Clustering Features
- **Gossip-based coordination** using HashiCorp memberlist
- **Let's Encrypt integration** with automatic certificate renewal
- **S3-backed certificate storage** for cluster-wide sharing
- **Cluster-wide rate limiting** with 50-200ms synchronization
- **Hot reload** for TLS certificates without restart
- **Leader election** for certificate management
- **Connection tracking** across cluster nodes

### Production Features
- **Connection pooling** with read/write separation
- **Circuit breakers** for external service failures
- **Health monitoring** with component status tracking (26 Prometheus metrics)
- **Rate limiting** with cluster-wide synchronization and IP blocking
- **Connection limits** per protocol, per IP, and per user
- **Graceful degradation** strategies under load
- **Background workers** with distributed task processing
- **Relay queue** with disk persistence and exponential backoff retry
- **JA4 TLS fingerprinting** for client detection and capability filtering

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
- **High-availability setups** with clustered nodes
- **Custom email solutions** with modern storage backends
- **Collaborative email** with shared mailboxes and ACL

---

## Requirements

- Go 1.23+
- PostgreSQL 14+ with pg_trgm extension
- S3-compatible object storage (MinIO, AWS S3, etc.)
- Port 7946 (for cluster gossip protocol, optional)
- Port 80 (for Let's Encrypt HTTP-01 challenges, optional)

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
./sora-admin accounts create --config config.toml --email user@example.com --password secretpassword
```

5.  **Run Sora:**
Start the email server:
```bash
./sora --config config.toml
```

---

## Configuration

See `config.toml.example` for comprehensive documentation of all configuration options.

### Key Configuration Areas

#### Database Configuration
```toml
[database]
host = "localhost"
port = 5432
dbname = "sora_mail_db"
user = "postgres"
password = "your-password"

# Connection pooling with separate read/write endpoints
max_conns = 100           # Maximum connections in pool
min_conns = 10            # Minimum idle connections
max_conn_lifetime = "1h"  # Connection lifetime
max_conn_idle_time = "30m" # Maximum idle time

# Optional read replicas for scaling
[[database.read_endpoints]]
host = "replica1.example.com"
port = 5432
```

#### S3 Storage Configuration
```toml
[s3]
endpoint = "s3.amazonaws.com"
region = "us-east-1"
bucket = "sora-messages"
access_key = "your-access-key"
secret_key = "your-secret-key"
use_ssl = true
```

#### Server Configuration
```toml
[[servers]]
type = "imap"
start = true
addr = ":143"
tls = false

[[servers]]
type = "imap"
start = true
addr = ":993"
tls = true
tls_cert_file = "/path/to/cert.pem"
tls_key_file = "/path/to/key.pem"

max_connections = 1000       # Total connection limit
max_connections_per_ip = 10  # Per-IP limit
```

#### Cluster Configuration
```toml
[cluster]
enabled = true
addr = "10.10.10.40:7946"  # MUST be specific IP reachable from other nodes (NOT 0.0.0.0 or localhost)
node_id = "node-1"
peers = ["10.10.10.41:7946", "10.10.10.42:7946"]  # List OTHER nodes, not this node
secret_key = "base64-encoded-32-byte-key"  # Generate: openssl rand -base64 32

# Cluster-wide rate limiting (enabled by default when cluster is enabled)
[cluster.rate_limit_sync]
enabled = true              # Cluster-wide rate limiting
sync_blocks = true          # Sync IP blocks across nodes
sync_failure_counts = true  # Sync progressive delays
```

#### TLS with Let's Encrypt
```toml
[tls]
enabled = true
provider = "letsencrypt"

[tls.letsencrypt]
email = "admin@example.com"
domains = ["mail.example.com", "imap.example.com"]
storage_provider = "s3"
renew_before = "720h"  # Optional: customize renewal window (default: 30 days)

[tls.letsencrypt.s3]
bucket = "sora-tls-certificates"
region = "us-east-1"
```

#### Shared Mailboxes
```toml
[shared_mailboxes]
enabled = true
namespace_prefix = "Shared/"
allow_user_create = true          # Allow users to create shared mailboxes
default_rights = "lrswipkxtea"    # Full rights for creators
```

#### HTTP API
```toml
[[servers]]
type = "http_api"
start = true
addr = ":8080"
api_key = "your-secure-api-key-here"
allowed_hosts = ["127.0.0.1", "10.0.0.0/8"]  # Optional IP/CIDR restrictions
```

#### Proxy Mode Configuration
```toml
[[servers]]
type = "imap_proxy"
start = true
addr = ":1143"            # Proxy listen port
remote_addrs = [          # Backend servers to proxy to
    "backend1.example.com:143",
    "backend2.example.com:143",
]
```

#### Rate Limiting
```toml
[servers.imap.auth_rate_limit]
enabled = true
max_attempts_per_ip = 10       # Max failed attempts per IP
max_attempts_per_username = 5  # Max failed attempts per username
ip_window_duration = "15m"     # Time window for IP-based limiting
username_window_duration = "30m" # Time window for username-based limiting
progressive_delay_enabled = true
progressive_delay_min = "1s"
progressive_delay_max = "30s"
```

#### Relay Queue
```toml
[relay]
type = "smtp"
smtp_host = "smtp.example.com:587"
tls = false
tls_verify = true
tls_use_starttls = true

[relay.queue]
path = "/var/spool/sora/relay"
worker_interval = "1m"
batch_size = 100
max_attempts = 10
retry_backoff = ["1m", "5m", "15m", "1h", "6h", "24h"]
```

#### Health Monitoring
```toml
[health]
enabled = true
check_interval = "30s"       # How often to check health
database_timeout = "5s"      # Database health check timeout
s3_timeout = "10s"           # S3 health check timeout
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

### JA4 TLS Fingerprinting

Filter IMAP capabilities based on TLS client fingerprints:

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

---

## Admin Tool

The `sora-admin` tool provides comprehensive administrative functions for managing accounts, monitoring connections, and system health.

### Account Management

Create new email accounts:

```bash
# Basic account creation
./sora-admin accounts create --config config.toml --email user@example.com --password secretpassword

# Create account with specific hash type
./sora-admin accounts create --config config.toml --email user@example.com --password secretpassword --hash ssha512

# Update existing account password
./sora-admin accounts update --config config.toml --email user@example.com --password newpassword

# List all accounts
./sora-admin accounts list --config config.toml

# Delete account (soft delete)
./sora-admin accounts delete --config config.toml --email user@example.com

# Restore deleted account
./sora-admin accounts restore --config config.toml --email user@example.com
```

### Credential Management

Manage multiple credentials per account:

```bash
# Add additional credential (alias)
./sora-admin accounts credentials add --config config.toml \
  --email user@example.com --alias alias@example.com --password aliaspass

# List credentials for an account
./sora-admin accounts credentials list --config config.toml --email user@example.com

# Show specific credential
./sora-admin credentials show --config config.toml --email alias@example.com

# Delete credential
./sora-admin credentials delete --config config.toml --email alias@example.com
```

### Monitoring Commands

```bash
# View connection statistics
./sora-admin stats connection --config config.toml
./sora-admin stats connection --config config.toml --user user@example.com

# View cache performance metrics
./sora-admin cache metrics --config config.toml
./sora-admin cache stats --config config.toml

# Purge cache
./sora-admin cache purge --config config.toml

# Check system health
./sora-admin health --config config.toml
./sora-admin health --config config.toml --detailed

# View authentication statistics
./sora-admin stats auth --config config.toml --window 24h

# Kick connections
./sora-admin connections kick --config config.toml --user user@example.com
./sora-admin connections kick --config config.toml --protocol imap
./sora-admin connections kick --config config.toml --server backend1.example.com

# List active connections
./sora-admin connections list --config config.toml
```

### Import/Export Operations

```bash
# Import maildir format
./sora-admin import-maildir --config config.toml --email user@example.com --path /path/to/maildir

# Import with Dovecot UID preservation
./sora-admin import-maildir --config config.toml --email user@example.com \
  --path /path/to/maildir --preserve-uids

# Import with SIEVE scripts
./sora-admin import-maildir --config config.toml --email user@example.com \
  --path /path/to/maildir --sieve-path /path/to/sieve

# Export to maildir format
./sora-admin export-maildir --config config.toml --email user@example.com --path /path/to/export
```

### Available Hash Types

- `bcrypt` (default) - bcrypt hash with salt
- `ssha512` - Salted SHA512 hash
- `sha512` - SHA512 hash without salt

### Help

Get help for any command:

```bash
./sora-admin help
./sora-admin accounts --help
./sora-admin health --help

# Show version information
./sora-admin version
```

---

## HTTP API

Sora provides a comprehensive REST API for administration and monitoring:

```bash
# Set your API key
export API_KEY="your-api-key"
export BASE_URL="http://localhost:8080/admin"

# List accounts
curl -H "Authorization: Bearer $API_KEY" $BASE_URL/accounts

# Create account
curl -X POST -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"secret"}' \
  $BASE_URL/accounts

# Get health status
curl -H "Authorization: Bearer $API_KEY" $BASE_URL/health/overview

# Get connection statistics
curl -H "Authorization: Bearer $API_KEY" $BASE_URL/connections/stats

# Kick user connections
curl -X POST -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com"}' \
  $BASE_URL/connections/kick

# Get cache metrics
curl -H "Authorization: Bearer $API_KEY" $BASE_URL/cache/metrics

# View upload queue status
curl -H "Authorization: Bearer $API_KEY" $BASE_URL/uploader/status
```

See `docs/admin-api.md` for complete API documentation.

---

## Operational Guide

### Running in Production

#### Standalone Mode
```bash
# Run with specific config
./sora --config /etc/sora/config.toml

# Override specific settings via environment or flags
./sora --config config.toml
```

#### Cluster Mode with Multiple Nodes
```bash
# Node 1 (leader will be automatically elected)
./sora --config node1-config.toml

# Node 2
./sora --config node2-config.toml

# Node 3
./sora --config node3-config.toml

# All nodes will gossip on port 7946 and automatically coordinate
# Leader handles TLS certificate renewal
# All nodes share rate limiting state
# Connection tracking synchronized across cluster
```

#### Proxy Mode for Horizontal Scaling
```bash
# Run proxy on load balancer
./sora --config proxy-config.toml  # Enable proxy sections, disable backend sections

# Run backend servers
./sora --config backend1-config.toml  # Port 143, proxy disabled
./sora --config backend2-config.toml  # Port 143, proxy disabled
```

### Monitoring and Health Checks

Sora provides comprehensive health monitoring:

1. **Database Health**: Checks write/read pool connectivity
2. **S3 Health**: Validates object storage accessibility  
3. **Circuit Breaker Status**: Monitors service resilience
4. **Connection Metrics**: Tracks active connections per protocol
5. **Cluster Health**: Monitors gossip protocol and node status
6. **TLS Certificate Status**: Tracks certificate expiration

Access health status via:
```bash
./sora-admin health --config config.toml
```

Or via HTTP API:
```bash
curl -H "Authorization: Bearer $API_KEY" http://localhost:8080/adnin/health/overview
```

### Prometheus Metrics

Sora exposes 26 comprehensive Prometheus metrics at `/metrics`:

- **Connection metrics**: Total, current, authenticated, duration
- **Database metrics**: Query counts, duration, account/mailbox totals
- **Storage metrics**: S3 operations, duration, upload attempts
- **Cache metrics**: Hit/miss ratios, size, object count
- **Protocol metrics**: LMTP relay, IMAP IDLE, ManageSieve scripts
- **Worker metrics**: Upload worker jobs and duration
- **Health metrics**: Component status, health checks
- **Memory metrics**: Session peak memory, limit exceeded events

Configure Prometheus to scrape:
```yaml
scrape_configs:
  - job_name: 'sora'
    static_configs:
      - targets: ['localhost:8080']
```

### Performance Tuning

#### Database Connection Pools
```toml
[database]
max_conns = 100          # Adjust based on concurrent users
min_conns = 10           # Maintain minimum ready connections
max_conn_lifetime = "1h" # Refresh connections periodically
max_conn_idle_time = "30m" # Close idle connections
```

#### Rate Limiting
```toml
[servers.imap.auth_rate_limit]
max_attempts_per_ip = 10    # Adjust based on security needs
ip_window_duration = "15m"   # Shorter window = more forgiving
```

#### Background Workers
```toml
[upload]
workers = 10              # Parallel S3 uploads
batch_size = 100         # Messages per batch

[cleanup]
wake_interval = "1h"     # Cleanup frequency
grace_period = "7d"      # Recovery window

[relay_queue]
worker_interval = "1m"   # How often to process relay queue
batch_size = 100         # Messages per batch
```

### Cluster Operations

#### Checking Cluster Status
```bash
# View cluster health
./sora-admin health --config config.toml | grep -i cluster

# Monitor gossip logs
journalctl -u sora -f | grep -i "cluster\|gossip"

# Check TLS certificate status
echo | openssl s_client -connect mail.example.com:993 -servername mail.example.com 2>/dev/null | \
  openssl x509 -noout -dates

# Monitor rate limiting synchronization
journalctl -u sora -f | grep -i "rate limit\|cluster-limiter"
```

#### Leader Election
- Leader is automatically elected (lexicographically smallest node ID)
- Leader handles TLS certificate renewal
- If leader fails, new leader is elected within 5-10 seconds
- All nodes can respond to HTTP-01 challenges

### Troubleshooting

#### Connection Issues
```bash
# Check active connections
./sora-admin connections list --config config.toml

# View connection statistics
./sora-admin stats connection --config config.toml

# Kick stuck connections
./sora-admin connections kick --config config.toml --user user@example.com
```

#### Performance Issues
```bash
# Check health status
./sora-admin health --config config.toml

# Monitor cache performance
./sora-admin cache metrics --config config.toml

# Review database connection pool
grep "database" /var/log/sora.log | grep -i "pool\|connection"

# Check circuit breaker status
grep "circuit breaker" /var/log/sora.log
```


#### Cluster Issues
```bash
# Check cluster membership
./sora-admin health --config config.toml | grep -i member

# Verify gossip connectivity (port 7946)
nc -zv node-2 7946

# Check TLS certificate renewal
grep "certificate\|renewal" /var/log/sora.log

# Monitor rate limit synchronization
grep "cluster.*rate limit" /var/log/sora.log
```

---

## Documentation

- **docs/architecture.md** - Detailed architecture guide
- **docs/configuration.md** - Configuration reference
- **docs/deployment.md** - Deployment guide
- **docs/security.md** - Security features and best practices
- **docs/admin-api.md** - HTTP API documentation
- **docs/admin-cli.md** - CLI tool reference
- **CLAUDE.md** - Developer guide for AI assistants

---

## Development

### Building from Source
```bash
# Install dependencies
go mod download

# Build server and admin tool
make build

# Run tests
make test

# Run integration tests (requires PostgreSQL)
make test-integration

# Run specific test scope
./run_integration_tests.sh --scope imap
```

### Project Structure
- `cmd/sora/` - Main server application
- `cmd/sora-admin/` - Administrative CLI tool
- `server/` - Protocol implementations (IMAP, LMTP, POP3, ManageSieve, HTTP API)
- `db/` - Database layer and operations
- `storage/` - S3 storage abstraction
- `cache/` - Local filesystem cache
- `cluster/` - Gossip-based cluster coordination
- `tlsmanager/` - TLS certificate management
- `pkg/metrics/` - Prometheus metrics
- `integration_tests/` - Comprehensive integration test suite
