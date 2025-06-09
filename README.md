# SORA — Hackable IMAP Server
**Status: Experimental – Not Production Ready**

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

## Status: Experimental

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

3.  **Run Sora:**
Point to your configuration file when running the application:
```bash
go run main.go -config config.toml
```
