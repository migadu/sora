# Deployment Guide

This guide covers common scenarios for deploying Sora.

## Prerequisites

Before deploying Sora, you will need:

1.  **A PostgreSQL Server**: Version 9.6 or newer. The `pg_trgm` extension must be enabled on the database (`CREATE EXTENSION IF NOT EXISTS pg_trgm;`).
2.  **S3-Compatible Object Storage**: An S3 bucket from a provider like AWS, or a self-hosted solution like MinIO.
3.  **A Mail Transfer Agent (MTA)**: Such as Postfix or Exim, to handle SMTP and deliver mail to Sora via LMTP.

## Database Migrations

Sora uses a schema for its PostgreSQL database. Before running the server for the first time, and after any upgrade, you must run the database migrations using the `sora-admin` tool.

```bash
./sora-admin -config /path/to/config.toml migrate up
```

## Scenario 1: Single-Node Deployment

This is the simplest way to run Sora, with all components on a single instance. It's suitable for smaller-scale deployments or for testing.

### Architecture

```
+--------------+      LMTP      +-----------------+
|      MTA     | -------------> |                 |
+--------------+                |   Sora Server   |      +-------------+
                                | (IMAP,POP3,LMTP)| <--> |  PostgreSQL |
+--------------+      IMAP      |                 |      +-------------+
| Email Client | <------------> |                 |
+--------------+                +-----------------+      +-------------+
                                        ^          <--> | S3 Storage  |
                                        |                +-------------+
                                        +----------------+
```

### Configuration

1.  Create a `config.toml` file. Use the minimal configuration as a starting point.
2.  Fill in your database and S3 credentials.
3.  Ensure the paths for `local_cache` and `uploader` exist and are writable by the user running Sora.

### Mail Flow

You need to configure your MTA to deliver mail to Sora's LMTP socket. For Postfix, you would add the following to `main.cf`:

```
# Deliver mail to Sora via LMTP on port 24
virtual_transport = lmtp:127.0.0.1:24
```

## Scenario 2: Scaled, High-Availability (HA) Deployment

For larger deployments, you can run multiple Sora instances in a cluster for scalability and high availability. This involves running Sora in two modes: **proxy** and **backend**.

### Architecture

```
+--------------+      LMTP      +-----------------+
|      MTA     | -------------> |                 |
+--------------+                |   Sora Proxy    |
                                | (LMTP, IMAP, etc) |
+--------------+      IMAP      |                 |
| Email Client | <------------> |                 |
+--------------+                +-------+---------+
                                        |
                  +---------------------+---------------------+
                  | (Load Balancing & User-Server Affinity) |
                  v                     v                     v
        +-----------------+   +-----------------+   +-----------------+
        |  Sora Backend 1 |   |  Sora Backend 2 |   |  Sora Backend N |
        +-----------------+   +-----------------+   +-----------------+
                 |                     |                     |
                 |                     |                     |
                 +----------+----------+----------+----------+
                            |                     |
                            v                     v
                  +-----------------+   +-----------------+
                  |  PostgreSQL     |   |   S3 Storage    |
                  |  (Write/Read_Replicas)   |   |                 |
                  +-----------------+   +-----------------+
```

### Configuration

You will have two different `config.toml` files: one for your proxy nodes and one for your backend nodes.

**Proxy `config.toml`:**
*   Enable the `*_proxy` servers (e.g., `servers.imap_proxy`, `servers.lmtp_proxy`).
*   Disable the regular protocol servers (e.g., `servers.imap.start = false`).
*   In each proxy section, define the `remote_addrs` list with the addresses of your backend nodes.
*   Enable `enable_affinity = true` to provide a better user experience.
*   Configure `master_sasl_username` and `master_sasl_password` which the proxy will use to authenticate to the backends.

**Backend `config.toml`:**
*   This configuration is similar to the single-node setup.
*   Enable the regular protocol servers (`servers.imap`, `servers.lmtp`, etc.).
*   Disable the proxy servers.
*   Configure the `master_sasl_username` and `master_sasl_password` in the `[servers.imap]` (and other protocols) section to match what the proxy is configured to use.
*   For improved performance, configure `[database.read]` to point to PostgreSQL read-replicas.

