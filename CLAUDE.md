# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Sora is a production-ready, cloud-native email server written in Go. It provides enterprise-grade email infrastructure with modern storage backends, comprehensive monitoring, proxy capabilities, and horizontal scaling support.

**Key Technologies:**
- Language: Go 1.23+
- Database: PostgreSQL 14+ (with pg_trgm extension for full-text search)
- Object Storage: S3-compatible storage for message bodies
- Protocols: IMAP4rev1, LMTP, POP3, ManageSieve, SIEVE

**Status:** BETA (production-ready with comprehensive resilience features)

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
./sora-admin accounts create --email user@example.com --password pass
./sora-admin accounts update --email user@example.com --password newpass

# Import/Export maildir
./sora-admin import-maildir --email user@example.com --path /path/to/maildir
./sora-admin export-maildir --email user@example.com --path /path/to/export

# Monitoring and health
./sora-admin health                      # Check system health
./sora-admin stats connection            # View connection statistics
./sora-admin cache metrics               # View cache performance
./sora-admin connections kick --user user@example.com  # Kick user connections
```

## Architecture Overview

### Core Design Principles
- **Separation of Storage**: Message metadata in PostgreSQL, bodies in S3
- **Content Deduplication**: Using BLAKE3 hashes for message bodies
- **Background Processing**: Async S3 uploads and cleanup workers with distributed task processing
- **Multi-Protocol**: Single server supports IMAP, LMTP, POP3, and ManageSieve
- **Horizontal Scaling**: Proxy mode for load balancing across multiple backends
- **Resilience**: Connection pooling, circuit breakers, health monitoring, rate limiting

### Key Components

1. **cmd/sora/** - Main server application
   - Entry point: main.go
   - Protocol listeners with TLS support
   - Configuration management
   - Health monitoring and metrics collection

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
   - Search functionality with PostgreSQL full-text search (pg_trgm)
   - Background workers: cleaner.go (expunge cleanup), upload_worker.go (S3 uploads)
   - Connection pooling with read/write separation
   - Retry logic and resilience wrappers

4. **server/** - Protocol implementations
   - server/imap/ - IMAP4rev1 with IDLE, ESEARCH, and other extensions
   - server/lmtp/ - Mail delivery with SIEVE script execution
   - server/pop3/ - POP3 with SASL authentication
   - server/managesieve/ - SIEVE script management
   - server/sieveengine/ - SIEVE script interpreter
   - Each protocol has proxy variants in `*proxy/` subdirectories for horizontal scaling

5. **storage/** - S3 abstraction for message body storage
   - Circuit breaker for resilience
   - Retry logic for transient failures
   - Health monitoring

6. **cache/** - Local filesystem cache for frequently accessed objects
   - Provides read-level deduplication
   - Metrics tracking (hit/miss ratios)

7. **integration_tests/** - Comprehensive integration test suite
   - Organized by protocol: imap/, lmtp/, pop3/, managesieve/
   - Proxy tests: imapproxy/, lmtpproxy/, pop3proxy/, managesieveproxy/
   - Connection limits: connection_limits/, *_connection_limits/
   - HTTP API tests: httpapi/
   - Configuration tests: config/
   - Admin tool tests in cmd/sora-admin/*_test.go

### Message Flow

#### Incoming Message (LMTP)
1. Message arrives via LMTP
2. SIEVE scripts executed for filtering/vacation responses
3. Message metadata stored in PostgreSQL
4. Message body queued for S3 upload (background worker)
5. Background worker uploads to S3 with retry logic
6. Local cache maintains frequently accessed messages

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
5. **Supported Protocols**: IMAP, POP3, ManageSieve, LMTP

Configuration example:
```toml
[servers.imap_proxy]
start = true
addr = ":1143"
remote_addrs = ["backend1:143", "backend2:143"]
```

### Resilience Features

1. **Connection Pooling**: Separate read/write pools with configurable limits
2. **Circuit Breakers**: Protect against cascading failures in S3 and external services
3. **Rate Limiting**: Authentication attempts per IP/username with progressive delays
4. **Health Monitoring**: Component-level health checks (database, S3, circuit breakers)
5. **Graceful Degradation**: Fallback strategies under load
6. **Connection Limits**: Per-protocol and per-IP limits to prevent resource exhaustion

### Import/Export SQLite Caching

The import/export tools use a local SQLite database (`sora-maildir.db`) to track which messages have been uploaded to S3:

- **Schema**: Messages table with `s3_uploaded` and `s3_uploaded_at` columns
- **First Import**: Scans maildir, uploads all messages, marks as `s3_uploaded = 1`
- **Re-Import**: Skips messages already marked as uploaded (13x faster - just SQLite check)
- **Incremental Import**: Only processes new messages (not in SQLite cache)
- **Migration**: Automatically adds columns to existing databases, marks old messages as uploaded

This enables fast re-runs and true incremental imports without re-checking PostgreSQL or S3.

## Database Schema

The PostgreSQL schema (db/schema.sql) includes:
- **accounts**: Email accounts with bcrypt/SSHA512 password hashing
- **credentials**: Multiple credentials per account (primary + aliases)
- **mailboxes**: Hierarchical mailbox structure with subscriptions
- **messages**: Message metadata with full-text search indexing
- **message_flags**: User-defined IMAP flags
- **sieve_scripts**: Per-account SIEVE filtering scripts
- **vacation_tracking**: Vacation response tracking to prevent loops
- **s3_upload_queue**: Queued messages for background S3 upload
- **auth_attempts**: Rate limiting and IP blocking data

## Important Considerations

1. **Status**: Production-ready (BETA) - actively used in production environments
2. **Logging**: Uses custom `logger` package, not standard `log`
3. **Testing**: Integration tests require PostgreSQL; use `-tags=integration` build tag
4. **Configuration**: Always copy config.toml.example and modify for your environment
5. **Dependencies**: Some forked dependencies (see go.mod replace directives)
6. **SQLite Migration**: Import/export tools automatically migrate old SQLite databases

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
```

**Test Infrastructure**:
- Tests use `config-test.toml` for database connection (defaults: localhost:5432, user: postgres, db: sora_mail_db)
- Helper utilities in `testutils/` package for database setup and cleanup
- Tests automatically check for database availability and skip if unavailable
- See `db/README_TESTING.md` for detailed testing guide

### Logging Conventions

The codebase uses a custom logger package (`github.com/migadu/sora/logger`):

```go
// Use logger, not log package
logger.Info("Starting server")
logger.Infof("Listening on %s", addr)
logger.Error("Failed to connect", err)
```

Do not use the standard `log` package - use `logger` instead.
