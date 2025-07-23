# SORA — Hackable IMAP Server

**Sora** is a simple, minimalistic IMAP server built for composability.  
It serves as a lightweight building block for larger infrastructure systems, with an emphasis on correctness, extensibility, and simplicity.

---

## Features

- Built around the [go-imap](https://github.com/emersion/go-imap) library
- Standards-compliant **IMAP4rev1** server
- **S3-compatible** object storage for message bodies
- **PostgreSQL** for metadata and indexing
- Minimal dependencies and clean, understandable codebase
- Can be embedded as a Go module or deployed as a standalone daemon
- Fast startup and efficient resource usage
- **LMTP** support for message delivery
- **POP3** support
- **ManageSIEVE** 
- **SIEVE** scripts support
- **Configurable message expunge delay** with grace period before permanent deletion

---

## Use Cases

Sora is for:

- Custom cloud-native email infrastructure
- Research and experimentation
- Integrating with modern storage and indexing backends
- Self-hosted environments with external authentication and delivery pipelines

---

## Status: Alpha

Sora is functional, but **not yet production-ready**.  
Cross-client compatibility is still being tested. Some clients may misbehave or fail to operate correctly.

Use in test environments only. Patches and pull requests are welcome.

---

## Requirements

- Go 1.20+
- PostgreSQL compatible database
- S3-compatible object storage (e.g. MinIO, AWS S3)

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

The `sora-admin` tool provides administrative functions for managing accounts.

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

### Help

Get help for any command:

```bash
./sora-admin help
./sora-admin create-account --help
./sora-admin update-account --help
```
