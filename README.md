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
