# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Sora is a production-ready, cloud-native email server written in Go. It provides enterprise-grade email infrastructure with modern storage backends, comprehensive monitoring, proxy capabilities, horizontal scaling support, and advanced security features.

**Key Technologies:**
- Language: Go 1.23+
- Database: PostgreSQL 14+ (with pg_trgm extension for full-text search)
- Object Storage: S3-compatible storage for message bodies
- Clustering: HashiCorp memberlist (gossip protocol) for cluster coordination
- Protocols: IMAP4rev1, LMTP, POP3, ManageSieve, SIEVE, HTTP API

**Status:** PRODUCTION READY with comprehensive resilience, security, and clustering features

## Common Development Commands

### Building
```bash
make build              # Build both sora and sora-admin
make sora              # Build only the server
make sora-admin        # Build only the admin tool
```

### Testing
```bash
# Unit tests
make test              # Run all unit tests
go test ./...          # Alternative: direct Go command
go test -short ./db    # Run unit tests without database integration

# Integration tests (requires PostgreSQL)
make test-integration                    # Run all integration tests
./run_integration_tests.sh              # Same as above
./run_integration_tests.sh --scope imap # Run specific protocol tests
./run_integration_tests.sh --scope sora-admin  # Run importer/exporter tests
./run_integration_tests.sh --verbose    # Verbose output

# Run specific integration test
go test -v -tags=integration ./integration_tests/imap -run TestIDLE
go test -v -tags=integration ./cmd/sora-admin -run TestImportExportCycle

# Database integration tests (in db/ directory)
go test ./db                             # Run all db tests including integration
go test -run "TestAuth" ./db             # Run specific test category
go test -run "TestMessage" ./db          # Message operation tests
```

### Development Workflow
```bash
./reset-db.sh          # Reset development database (drops and recreates sora_mail_db)
./start-dev.sh         # Run server with race detection enabled

# Account management (note: use 'accounts' subcommand)
./sora-admin accounts create --config config.toml --email user@example.com --password pass
./sora-admin accounts update --config config.toml --email user@example.com --password newpass

# Import/Export maildir
./sora-admin import-maildir --config config.toml --email user@example.com --path /path/to/maildir
./sora-admin export-maildir --config config.toml --email user@example.com --path /path/to/export

# Monitoring and health
./sora-admin health --config config.toml                      # Check system health
./sora-admin stats connection --config config.toml            # View connection statistics
./sora-admin cache metrics --config config.toml               # View cache performance
./sora-admin connections kick --config config.toml --user user@example.com  # Kick user connections
```

## Architecture Overview

### Core Design Principles
- **Separation of Storage**: Message metadata in PostgreSQL, bodies in S3
- **Content Deduplication**: Using BLAKE3 hashes for message bodies
- **Background Processing**: Async S3 uploads and cleanup workers with distributed task processing
- **Multi-Protocol**: Single server supports IMAP, LMTP, POP3, ManageSieve, and HTTP API
- **Horizontal Scaling**: Proxy mode for load balancing across multiple backends
- **Cluster Coordination**: Gossip-based clustering for TLS certificate management and rate limiting
- **Resilience**: Connection pooling, circuit breakers, health monitoring, rate limiting

### Key Components

1. **cmd/sora/** - Main server application
   - Entry point: main.go
   - Protocol listeners with TLS support
   - Configuration management
   - Health monitoring and metrics collection
   - Cluster coordination and gossip protocol integration

2. **cmd/sora-admin/** - Administrative CLI tool
   - Account management with bcrypt/SSHA512 password hashing
   - **Import/Export**: Maildir format support with SQLite caching
     - `importer.go` - Import maildir to S3 with Dovecot UID preservation
     - `exporter.go` - Export from S3 to maildir
     - SQLite database (`sora-maildir.db`) caches S3 upload state for fast incremental imports
   - Connection monitoring and management
   - Health status reporting
   - Cache statistics

3. **db/** - Database layer (PostgreSQL)
   - Core operations: accounts.go, mailbox.go, message.go
   - IMAP operations: append.go, fetch.go, expunge.go, move.go, search.go
   - **ACL operations**: acl.go (shared mailbox access control)
   - Search functionality with PostgreSQL full-text search (pg_trgm)
   - Background workers: cleaner.go (expunge cleanup), upload_worker.go (S3 uploads)
   - Connection pooling with read/write separation
   - Retry logic and resilience wrappers

4. **server/** - Protocol implementations
   - server/imap/ - IMAP4rev1 with IDLE, ESEARCH, ACL, and other extensions
   - server/lmtp/ - Mail delivery with SIEVE script execution
   - server/pop3/ - POP3 with SASL authentication
   - server/managesieve/ - SIEVE script management
   - server/sieveengine/ - SIEVE script interpreter
   - **server/httpapi/** - REST API for administration and monitoring
   - **server/uploader/** - Background S3 upload worker
   - **server/cleaner/** - Background message cleanup worker
   - **server/relayqueue/** - Disk-based relay queue with retry logic
   - Each protocol has proxy variants in `*proxy/` subdirectories for horizontal scaling

5. **storage/** - S3 abstraction for message body storage
   - Circuit breaker for resilience
   - Retry logic for transient failures
   - Health monitoring

6. **cache/** - Local filesystem cache for frequently accessed objects
   - Provides read-level deduplication
   - Metrics tracking (hit/miss ratios)

7. **cluster/** - Cluster coordination using HashiCorp memberlist
   - Gossip protocol for node discovery and health
   - Leader election for TLS certificate management
   - Cluster-wide rate limiting synchronization
   - Connection tracking across cluster nodes

8. **tlsmanager/** - TLS certificate management
   - Let's Encrypt autocert with automatic renewal
   - S3-backed certificate storage for clusters
   - HTTP-01 challenge handling
   - Hot reload without server restart
   - Cluster-aware certificate issuance (leader-only)

9. **pkg/metrics/** - Prometheus metrics
   - Connection, database, storage, cache, and protocol metrics
   - Health status and component monitoring
   - Background worker statistics
   - Metrics collector for periodic gauge updates

10. **integration_tests/** - Comprehensive integration test suite
    - Organized by protocol: imap/, lmtp/, pop3/, managesieve/
    - Proxy tests: imapproxy/, lmtpproxy/, pop3proxy/, managesieveproxy/
    - Connection limits: connection_limits/, *_connection_limits/
    - HTTP API tests: httpapi/
    - Configuration tests: config/
    - ACL and shared mailbox tests: imap/acl_test.go, imap/shared_mailbox_test.go
    - Admin tool tests in cmd/sora-admin/*_test.go

### Message Flow

#### Incoming Message (LMTP)
1. Message arrives via LMTP
2. SIEVE scripts executed for filtering/vacation responses
3. Message metadata stored in PostgreSQL
4. Message body queued for S3 upload (background worker)
5. Background worker uploads to S3 with retry logic
6. Local cache maintains frequently accessed messages
7. Optional: Queue for external relay with disk-based persistence

#### Message Retrieval (IMAP/POP3)
1. Client requests message
2. Check local cache first (fast path)
3. If cache miss, fetch from S3
4. Store in local cache for future access
5. Return to client

#### Two-Phase Deletion
1. EXPUNGE command marks messages with `expunged_at` timestamp
2. Background cleanup worker runs periodically (configurable interval)
3. Messages older than grace period are permanently deleted from PostgreSQL and S3
4. Optional: `max_age_restriction` enables ephemeral storage (auto-expunge old messages)

### Proxy Mode Architecture

Sora supports horizontal scaling through proxy mode:

1. **Frontend Proxy**: Load balances across multiple backend servers
2. **Backend Servers**: Handle actual protocol operations
3. **Server Affinity**: Consistent user routing to same backend
4. **Health-Based Routing**: Automatic failover to healthy backends
5. **Connection Tracking**: Cluster-wide connection monitoring via gossip
6. **Supported Protocols**: IMAP, POP3, ManageSieve, LMTP

Configuration example:
```toml
[servers.imap_proxy]
start = true
addr = ":1143"
remote_addrs = ["backend1:143", "backend2:143"]
```

### Cluster Features

Sora includes comprehensive clustering capabilities:

#### 1. Gossip-Based Coordination
- **Protocol**: HashiCorp memberlist for node discovery and health monitoring
- **Encryption**: AES-256 encryption of cluster communication
- **Leader Election**: Deterministic leader selection (lexicographically smallest node ID)
- **Failure Detection**: 3-second timeout with automatic re-election

#### 2. TLS Certificate Management
- **Let's Encrypt Integration**: Automatic certificate issuance and renewal
- **S3 Storage**: Shared certificate storage across cluster
- **Cluster Coordination**: Leader-only certificate requests prevent duplicates
- **HTTP-01 Challenges**: All nodes can respond to ACME challenges
- **Hot Reload**: Certificates updated without restart (via GetCertificate callback)
- **Automatic Renewal**: Configurable renewal window (default: 30 days before expiry)
- **Graceful Failover**: 5-10 second recovery on leader failure

#### 3. Cluster-Wide Rate Limiting
- **Gossip Synchronization**: Real-time auth failure propagation (50-200ms latency)
- **IP Blocking**: Fast IP blocks synchronized across all nodes
- **Progressive Delays**: Failure counts shared for coordinated rate limiting
- **Attack Protection**: 3x better protection against distributed attacks
- **Low Overhead**: <200KB memory, <15 KB/s bandwidth per protocol

#### 4. Connection Tracking
- **Proxy Mode**: Gossip-based cluster-wide connection tracking
- **Connection Limits**: Per-user connection limits enforced cluster-wide
- **Kick Mechanism**: Cluster-wide user connection termination
- **Eventually Consistent**: Connection counts converge via gossip

### Resilience Features

1. **Connection Pooling**: Separate read/write pools with configurable limits
2. **Circuit Breakers**: Protect against cascading failures in S3 and external services
3. **Rate Limiting**: 
   - Per-IP and per-username authentication rate limiting
   - Progressive delays before fast IP blocking
   - Cluster-wide synchronization in cluster mode
4. **Health Monitoring**: Component-level health checks (database, S3, circuit breakers, cluster)
5. **Graceful Degradation**: Fallback strategies under load
6. **Connection Limits**: Per-protocol and per-IP limits to prevent resource exhaustion
7. **Retry Logic**: Exponential backoff for transient failures
8. **Distributed Task Processing**: Background workers for uploads, cleanup, and relay

### Shared Mailboxes and ACL (RFC 4314)

Sora implements comprehensive shared mailbox support with Access Control Lists:

#### Features
- **Shared Mailboxes**: Mailboxes accessible to multiple users (configurable namespace prefix)
- **11 ACL Rights**: Full RFC 4314 implementation (lrswipkxtea)
- **IMAP ACL Commands**: MYRIGHTS, GETACL, SETACL, DELETEACL, LISTRIGHTS
- **Same-Domain Enforcement**: Security boundary preventing cross-domain access
- **Database Schema**: Dedicated `mailbox_acls` table with foreign key constraints
- **Permission Checks**: Enforced on SELECT, DELETE, RENAME, and mailbox listing

#### ACL Rights
```
l - lookup      : Mailbox visible in LIST/LSUB
r - read        : SELECT, FETCH, SEARCH, COPY source
s - seen        : Keep \Seen flag across sessions
w - write       : STORE flags (except \Seen, \Deleted)
i - insert      : APPEND, COPY into mailbox
p - post        : Send mail to submission address (LMTP)
k - create      : CREATE child mailboxes
x - delete      : DELETE mailbox
t - delete-msg  : STORE \Deleted flag
e - expunge     : EXPUNGE messages
a - admin       : SETACL/DELETEACL/GETACL/LISTRIGHTS
```

#### Configuration
```toml
[shared_mailboxes]
enabled = true
namespace_prefix = "Shared/"
allow_user_create = true
default_rights = "lrswipkxtea"
```

### Import/Export SQLite Caching

The import/export tools use a local SQLite database (`sora-maildir.db`) to track which messages have been uploaded to S3:

- **Schema**: Messages table with `s3_uploaded` and `s3_uploaded_at` columns
- **First Import**: Scans maildir, uploads all messages, marks as `s3_uploaded = 1`
- **Re-Import**: Skips messages already marked as uploaded (13x faster - just SQLite check)
- **Incremental Import**: Only processes new messages (not in SQLite cache)
- **Migration**: Automatically adds columns to existing databases, marks old messages as uploaded

This enables fast re-runs and true incremental imports without re-checking PostgreSQL or S3.

### HTTP API

Sora provides a comprehensive REST API for administration and monitoring:

#### Features
- **Account Management**: Create, read, update, delete accounts and credentials
- **Connection Monitoring**: List active connections, kick users, view statistics
- **Cache Management**: View stats, metrics, and purge cache
- **Health Monitoring**: System health overview and component-level checks
- **Upload Queue**: Monitor S3 upload status and failed uploads
- **Authentication**: Bearer token (API key) authentication
- **Authorization**: Host-based access control with CIDR support

#### Configuration
```toml
[servers.http_api]
start = true
addr = ":8080"
api_key = "your-secure-api-key-here"
allowed_hosts = ["127.0.0.1", "10.0.0.0/8"]
```

#### Example Usage
```bash
# List accounts
curl -H "Authorization: Bearer $API_KEY" \
  http://localhost:8080/api/v1/accounts

# Get health status
curl -H "Authorization: Bearer $API_KEY" \
  http://localhost:8080/api/v1/health/overview

# Kick user connections
curl -X POST -H "Authorization: Bearer $API_KEY" \
  http://localhost:8080/api/v1/connections/kick \
  -d '{"email": "user@example.com"}'
```

### JA4 TLS Fingerprinting

Sora supports JA4 TLS fingerprinting for client identification and capability filtering:

#### Features
- **Non-blocking Capture**: Uses Go's `GetConfigForClient` callback during TLS handshake
- **Standard JA4 Format**: Industry-standard three-part fingerprint (JA4_a, JA4_b, JA4_c)
- **Pattern Matching**: Regex-based client detection
- **Capability Filtering**: Disable problematic capabilities for specific clients (e.g., IDLE for iOS)

#### Configuration
```toml
[[server.client_filters]]
ja4_fingerprint = "^t13d1516h2_.*"
disable_caps = ["IDLE"]
reason = "iOS Mail client with known IDLE issues"
```

### Relay Queue

Disk-based relay queue for reliable message forwarding:

#### Features
- **Disk Persistence**: Three-state queue (pending/, processing/, failed/)
- **Retry Logic**: Exponential backoff (1m, 5m, 15m, 1h, 6h, 24h)
- **Max Attempts**: Configurable maximum retry count (default: 10 over ~32 hours)
- **Background Worker**: Processes queue at configurable intervals
- **Batch Processing**: Configurable batch size for efficient processing
- **Metrics**: Prometheus integration for queue depth and delivery statistics

#### Configuration
```toml
[relay]
type = "smtp"
smtp_host = "smtp.example.com:587"

[relay_queue]
enabled = true
path = "/var/spool/sora/relay"
worker_interval = "1m"
batch_size = 100
max_attempts = 10
```

### Prometheus Metrics

Comprehensive monitoring with 26 Prometheus metrics:

#### Metric Categories
- **Connections** (5): Total, current, authenticated, duration, auth attempts
- **Database** (3): Query counts, duration, accounts/mailboxes totals
- **Storage** (4): S3 operations, duration, upload attempts
- **Cache** (4): Operations, hit/miss ratios, size, object count
- **Protocols** (4): LMTP relay, IMAP IDLE, ManageSieve scripts
- **Workers** (2): Upload worker jobs and duration
- **Health** (3): Component status, health checks, check duration
- **Memory** (2): Session peak memory, limit exceeded events

#### Metrics Collector
- Runs every 60 seconds to update gauge metrics from database
- Tracks account counts, mailbox counts, cache statistics
- Uses resilient wrapper for database operations

## Database Schema

The PostgreSQL schema (db/schema.sql) includes:
- **accounts**: Email accounts with bcrypt/SSHA512 password hashing
- **credentials**: Multiple credentials per account (primary + aliases)
- **mailboxes**: Hierarchical mailbox structure with subscriptions
- **mailbox_acls**: Access control lists for shared mailboxes (RFC 4314)
- **messages**: Message metadata with full-text search indexing
- **message_flags**: User-defined IMAP flags
- **sieve_scripts**: Per-account SIEVE filtering scripts
- **vacation_tracking**: Vacation response tracking to prevent loops
- **s3_upload_queue**: Queued messages for background S3 upload
- **auth_attempts**: Rate limiting and IP blocking data

## Important Considerations

1. **Status**: Production-ready - actively used in production environments
2. **Logging**: Uses custom `logger` package, not standard `log`
3. **Testing**: Integration tests require PostgreSQL; use `-tags=integration` build tag
4. **Configuration**: Always copy config.toml.example and modify for your environment
5. **Dependencies**: Some forked dependencies (see go.mod replace directives)
6. **SQLite Migration**: Import/export tools automatically migrate old SQLite databases
7. **Cluster Mode**: When enabled, requires gossip port (7946) accessibility between nodes
8. **TLS Certificates**: Let's Encrypt requires port 80 for HTTP-01 challenges
9. **Shared Mailboxes**: Enabled via configuration, requires database migration to version 6
10. **Connection Tracking**: Proxy uses gossip, backends use local tracking

## Common Development Tasks

### Adding a New IMAP Command
1. Create handler in server/imap/cmd_*.go
2. Register command in server/imap/server.go command map
3. Add database operations in db/ if needed
4. Add integration test in integration_tests/imap/
5. Update capability list if adding extension

### Modifying Message Storage
1. Update db/message.go for metadata changes
2. Update db/schema.sql if adding/changing columns
3. Modify storage/storage.go for S3 operations
4. Consider impact on cache/cache.go
5. Update background workers if needed (upload_worker.go, cleaner.go)

### Adding a New Protocol or Proxy
1. Create server/*protocol*/ directory
2. Implement protocol handler following existing patterns (see server/pop3/ for reference)
3. Create server/*protocol*proxy/ for proxy variant
4. Add configuration in config/config.go
5. Register in cmd/sora/main.go
6. Add integration tests in integration_tests/*protocol*/
7. Update run_integration_tests.sh with new scope

### Working with Shared Mailboxes and ACL

1. **Enable Feature**: Set `[shared_mailboxes] enabled = true` in config
2. **Database Migration**: Ensure migration 000006 is applied
3. **Create Shared Mailbox**: Use "Shared/" prefix (or configured prefix)
4. **Grant Access**: Use IMAP ACL commands or database functions
   - Via IMAP: `SETACL "Shared/TeamInbox" user@example.com lrwi`
   - Via code: `db.GrantMailboxAccess(ctx, ownerID, granteeID, mailbox, rights)`
5. **Testing**: Use integration_tests/imap/acl_test.go as reference

### Setting Up Cluster Mode

1. **Configuration**: Enable cluster in config.toml
   ```toml
   [cluster]
   enabled = true
   bind_addr = "0.0.0.0"
   bind_port = 7946
   node_id = "node-1"
   peers = ["node-2:7946", "node-3:7946"]
   secret_key = "base64-encoded-32-byte-key"
   ```
2. **TLS Certificates**: Configure Let's Encrypt with S3 storage
3. **Port Access**: Ensure port 7946 (gossip) accessible between nodes
4. **Port 80**: Must be accessible from internet for HTTP-01 challenges
5. **S3 Bucket**: Create bucket for certificate storage
6. **Testing**: Verify leader election and certificate renewal

### Running Integration Tests

Integration tests are organized by scope and run via `./run_integration_tests.sh`:

```bash
# Available scopes
./run_integration_tests.sh --scope imap                    # IMAP protocol tests
./run_integration_tests.sh --scope lmtp                    # LMTP delivery tests
./run_integration_tests.sh --scope pop3                    # POP3 protocol tests
./run_integration_tests.sh --scope managesieve             # ManageSieve tests
./run_integration_tests.sh --scope sora-admin              # Import/export tests
./run_integration_tests.sh --scope imapproxy               # IMAP proxy tests
./run_integration_tests.sh --scope connection_limits       # Connection limit tests
./run_integration_tests.sh --scope httpapi                 # HTTP API tests
./run_integration_tests.sh --scope config                  # Configuration tests
```

All integration tests use the `-tags=integration` build tag and require:
- PostgreSQL running on localhost:5432
- Database named `sora_mail_db`
- User `postgres` with no password (or configure via environment)
- `pg_trgm` extension installed in the database

The test runner (`run_integration_tests.sh`) automatically checks prerequisites and applies schema.

### Working with Import/Export

The import/export functionality has special considerations:

1. **SQLite Cache**: Located at `{maildir}/sora-maildir.db`
   - Tracks which files have been uploaded to S3
   - Automatically created on first import
   - Automatically migrated when schema changes

2. **Migration**: When running with new version
   - Old databases automatically get `s3_uploaded` columns added
   - Existing messages marked as `s3_uploaded = 1` (assumes already on S3)
   - No data loss, preserves all existing message records

3. **Dovecot Compatibility**: Import supports Dovecot maildir
   - Preserves UIDs from `dovecot-uidlist` files (use `--preserve-uids` flag)
   - Reads Dovecot keywords from mailbox metadata
   - Can import Sieve scripts (use `--sieve-path` flag)

4. **Testing**: Integration tests verify
   - Initial import creates cache correctly
   - Re-import skips everything (fast path)
   - Incremental import only processes new files
   - SQLite migration preserves data and marks correctly
   - Tests located in `cmd/sora-admin/*_test.go`

### Database Testing

The `db/` directory contains both unit tests and integration tests:

**Unit Tests** (fast, no database required):
```bash
go test -short ./db     # Skip integration tests
```

**Integration Tests** (require PostgreSQL):
```bash
go test ./db                        # All tests including integration
go test -run "TestAuth" ./db        # Authentication tests
go test -run "TestMessage" ./db     # Message operation tests
go test -run "TestMailbox" ./db     # Mailbox management tests
go test -run "TestSearch" ./db      # Search functionality tests
go test -run "TestACL" ./db         # ACL and shared mailbox tests
```

**Test Infrastructure**:
- Tests use `config-test.toml` for database connection (defaults: localhost:5432, user: postgres, db: sora_mail_db)
- Helper utilities in `testutils/` package for database setup and cleanup
- Tests automatically check for database availability and skip if unavailable
- See `db/README_TESTING.md` for detailed testing guide

### Working with HTTP API

1. **Enable API**: Configure in config.toml
2. **Generate API Key**: Use strong random key
3. **Restrict Access**: Configure allowed_hosts with IP/CIDR
4. **Test Endpoints**: Use curl or integration tests
5. **Monitor**: Check logs for authentication and errors

Example development workflow:
```bash
# Start server with API enabled
./start-dev.sh

# Test API (in another terminal)
export API_KEY="your-api-key"
curl -H "Authorization: Bearer $API_KEY" \
  http://localhost:8080/api/v1/health/overview

# Run integration tests
go test -v -tags=integration ./integration_tests/httpapi
```

### Monitoring Cluster Health

```bash
# Check cluster status
./sora-admin health --config config.toml | grep -i cluster

# View cluster members
journalctl -u sora -f | grep -i "cluster\|gossip"

# Check TLS certificate status
echo | openssl s_client -connect mail.example.com:993 \
  -servername mail.example.com 2>/dev/null | openssl x509 -noout -dates

# Monitor rate limiting sync
journalctl -u sora -f | grep -i "rate limit\|cluster-limiter"

# View connection tracking
./sora-admin connections --config config.toml
```

### Adding Prometheus Metrics

1. **Define Metric**: Add to pkg/metrics/metrics.go
   ```go
   MyMetric = promauto.NewCounterVec(prometheus.CounterOpts{
       Name: "sora_my_metric_total",
       Help: "Description",
   }, []string{"label1", "label2"})
   ```
2. **Instrument Code**: Add metric.Inc() or metric.Set() calls
3. **Test**: Verify metric appears in /metrics endpoint
4. **Document**: Update Prometheus documentation

### Logging Conventions

The codebase uses a custom logger package (`github.com/migadu/sora/logger`):

```go
// Use logger, not log package
logger.Info("Starting server")
logger.Infof("Listening on %s", addr)
logger.Error("Failed to connect", err)
```

Do not use the standard `log` package - use `logger` instead.

## Recent Major Updates

### ACL and Shared Mailboxes (2025)
- Complete RFC 4314 implementation with 11 ACL rights
- IMAP ACL commands (MYRIGHTS, GETACL, SETACL, DELETEACL, LISTRIGHTS)
- Same-domain enforcement for security
- Database migration to version 6
- Comprehensive integration tests

### Cluster Features (2025)
- Gossip-based coordination using HashiCorp memberlist
- Let's Encrypt integration with automatic renewal
- S3-backed certificate storage
- Cluster-wide rate limiting synchronization
- Leader-only certificate issuance
- Hot reload without restart

### HTTP API (2025)
- Full REST API with 25+ endpoints
- Account and credential management
- Connection monitoring and control
- Cache and health monitoring
- Bearer token authentication
- Host-based access control

### Relay Queue (2025)
- Disk-based persistence with retry logic
- Exponential backoff (max 10 attempts over ~32 hours)
- Background worker processing
- Prometheus metrics integration
- Three-state queue (pending/processing/failed)

### Prometheus Metrics (2025)
- 26 comprehensive metrics covering all subsystems
- Metrics collector for periodic gauge updates
- Connection, database, storage, cache, protocol metrics
- Health monitoring and worker statistics

### JA4 Fingerprinting (2025)
- TLS client fingerprinting using exaring/ja4plus
- Non-blocking capture during TLS handshake
- Pattern-based client detection
- Capability filtering (e.g., disable IDLE for iOS)

### Connection Tracking (2025)
- Proxy: Gossip-based cluster-wide tracking
- Backend: Local tracking (currently disabled, infrastructure ready)
- Per-user connection limits
- Cluster-wide kick mechanism

## Related Documentation

### Main Documentation
- **README.md** - Project overview and quick start
- **docs/architecture.md** - Detailed architecture guide
- **docs/configuration.md** - Configuration reference
- **docs/deployment.md** - Deployment guide
- **docs/security.md** - Security features and best practices
- **docs/admin-api.md** - HTTP API documentation
- **docs/admin-cli.md** - CLI tool reference
- **docs/user-api.md** - User-facing API documentation

### Feature Documentation
- **ACL_IMPLEMENTATION_COMPLETE.md** - Shared mailboxes and ACL guide (2000+ lines)
- **TLS_COMPLETE_FEATURE_SUMMARY.md** - TLS features overview
- **TLS_AUTOCERT_GUIDE.md** - Let's Encrypt setup guide (500+ lines)
- **CLUSTER_TLS_INTEGRATION.md** - Cluster integration details (500+ lines)
- **CLUSTER_RATE_LIMITING_IMPLEMENTATION.md** - Rate limiting guide (1500+ lines)
- **HTTP_API_SUMMARY.md** - HTTP API implementation summary
- **RELAY_QUEUE_INTEGRATION_STATUS.md** - Relay queue status
- **PROMETHEUS_METRICS_COMPLETE.md** - Metrics implementation
- **JA4_IMPLEMENTATION_FINAL.md** - JA4 fingerprinting guide
- **CONNECTION_TRACKING_REVIEW.md** - Connection tracking analysis

### Development Documentation
- **DATABASE_TESTING_GUIDE.md** - Database testing guide
- **db/README_TESTING.md** - Detailed testing guide for db/ package
- **GRACEFUL_FAILOVER_GUIDE.md** - Cluster failover scenarios (500+ lines)
- **HTTP01_CLUSTER_ROUTING.md** - HTTP-01 challenge routing (500+ lines)

### Review Documents
- **WORKER_REVIEW.md** - Background workers analysis
- **RELAY_OPERATIONS_REVIEW.md** - Relay operations review
- **BACKEND_CONNECTION_TRACKING_IMPLEMENTATION.md** - Connection tracking implementation
- **MANAGESIEVE_EXTENSION_
