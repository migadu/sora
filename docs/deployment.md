# Deployment Guide

This guide covers common scenarios for deploying Sora.

## Prerequisites

Before deploying Sora, you will need:

1.  **A PostgreSQL Server**: Version 9.6 or newer. The `pg_trgm` and `btree_gin` extensions must be enabled on the database (`CREATE EXTENSION IF NOT EXISTS pg_trgm; CREATE EXTENSION IF NOT EXISTS btree_gin;`). Both ship with contrib and are trusted, so the database owner can install them without superuser rights.
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


## Taking a Backend Out of Service

A backend cannot simply be stopped. Mail it accepted is uploaded to S3 only by that backend (the body waits in its local spool, and its `pending_uploads` rows are leased to its `[uploader] instance_id`), and once a stopped node's heartbeat is stale the cleaner eventually reaps those rows together with their messages. Removing it from `remote_addrs` needs every proxy reconfigured and restarted. Instead, put it in maintenance:

```bash
sora-admin backends maintenance on --host storage2.example.com --reason "disk swap" --wait
```

Within one `[backend_maintenance] poll_interval` (default 5s), every proxy:

*   routes new logins, deliveries and User API requests to other backends, including users with affinity to the backend and users whose remote-lookup route names it. Those are routed as in auth-only mode, with the proxy's own backend settings rather than the remote lookup's, and return to the backend the lookup names once maintenance ends;
*   closes IMAP sessions on the backend gradually (`kick_rate` per second per proxy), since an open session can keep APPENDing. Each session stops forwarding new commands to the backend, gets `* BYE [UNAVAILABLE]` between two responses (never inside one), and still receives the replies to the commands the backend already had, so a client never re-sends an APPEND or MOVE that went through. It ends once the backend has answered them and the client has closed its end (or 2 seconds after the backend), at most 30 seconds later;
*   drops an LMTP session's connection to the backend at its next transaction, before any recipient is accepted.

POP3 and ManageSieve sessions are left to end on their own: a POP3 session closed before its QUIT loses the deletions it made, and ManageSieve sessions are short and lose nothing. A backend in maintenance is never marked unhealthy, and if every backend of a pool is in maintenance the proxy refuses the connection rather than use one; the LMTP proxy then answers an unknown recipient with a temporary failure rather than a bounce.

The backend itself, once it has been in maintenance for its `[backend_maintenance] refuse_after` (default 30s, long enough for every proxy to have stopped routing to it), refuses new sessions with a temporary failure, however they reach it (LMTP sent to it directly, its own Admin API, a proxy on an older build): IMAP logins get `NO [UNAVAILABLE]`, POP3 logins `-ERR [SYS/TEMP]`, LMTP transactions `451 4.3.2` at `MAIL`, Admin API deliveries `503` with `Retry-After`. Sessions already under way carry on. It looks up its own maintenance on the primary database by its uploader instance id when it starts (refusing until it knows) and every 10 seconds after that, so the instance id given to `maintenance on` must be this backend's: given another live node's, that node refuses new sessions instead, and proxies match it by its addresses too. While refusing, it reports `sora_backend_maintenance_refusing` 1 and counts what it refused in `sora_backend_maintenance_sessions_refused_total{protocol}`.

`--wait` returns once nothing is pending and, by the backend's own report, it refuses new client sessions and has none open. Those are IMAP and POP3 sessions that have logged in, LMTP transactions and Admin API deliveries: what could still add an upload, or (POP3) lose its deletions if the node stopped under it. An LMTP connection that only greeted (a monitoring probe) or sits idle between transactions does not count. Every node with an uploader reports them every 10 seconds under its uploader instance id, together with the maintenance it refuses new ones for; it starts refusing before it counts, so a report of refusing with none open stays true for as long as that maintenance lasts. A report refusing for an earlier maintenance (turned off and on again since) does not count. For a backend that does not report, or that stopped reporting, `--wait` keeps waiting and says why. `backends status` shows the same without waiting. Parked uploads (out of attempts) never drain on their own: resolve them with `sora-admin uploader resolve` on that node. Before stopping the backend, also check its relay queue (`sora-admin relay stats`, on the node).

`--host` is the backend as the proxies know it, a name or an IP, without a port: one entry covers every protocol the host serves. Names and addresses match both ways: a name covers the addresses it resolves to (and the pool addresses the proxy resolved from that name, even while the name fails to resolve for the maintenance list), and a route that names the host differently (a remote-lookup route, an alias) is skipped if its name resolves to an address in maintenance. The host is also matched by the addresses its node reports for itself (those of its interfaces, less loopback and link-local, sent with its sessions report under `--instance`), so it is matched whatever address the proxies route to it by, even when `--host` is a name that resolves, where they run, to another of its addresses (a public one, where the pools list private ones) or not at all. An address that another node reports too (the bridge address every Docker host has) is not used. Only a proxy reaching the node through an address that is not its own (NAT, a load balancer) depends on the name alone; `maintenance on` and `backends status` show the addresses reported. The dial itself also refuses an address in maintenance, and the User API proxy drops its idle connections whenever the list changes. `--instance` is the backend's uploader instance id (`[uploader] instance_id`, by default its hostname), defaulting to the host. An id that no node has ever reported under is refused, with the ids that have, because nothing would ever be pending under it.

Proxies need database access to honor maintenance; one without it logs a warning at startup. A proxy reads the list before it accepts connections; if that first read fails, it refuses every backend connection until a poll succeeds, rather than risk routing to a backend in maintenance. Each proxy reports how many hosts it honors in `sora_backend_maintenance_hosts`, failed reads of the list in `sora_backend_maintenance_poll_failures_total`, and the sessions it closed in `sora_backend_maintenance_sessions_closed_total`; it also marks its pool backends in maintenance as `[maintenance]` in `sora-admin health status --backends`. `[backend_maintenance]` settings take effect on restart.

To bring the backend back: `sora-admin backends maintenance off --host storage2.example.com`. Users moved off it keep their new backend until their affinity expires, so they do not all return at once.


## Connection Poolers (PgBouncer)

Sora works behind PgBouncer in any pooling mode, including transaction pooling. Nothing session-scoped is relied on: statement and lock timeouts are applied with `SET LOCAL`, and every advisory lock is transaction-scoped (`pg_advisory_xact_lock`), held in a dedicated transaction that stays open exactly as long as the lock is needed.

Some of those locks span an S3 round trip, so they keep one pooled connection (one server connection behind the pooler) checked out while that round trip runs:

- the cleaner: two on the node running a cycle, the cycle lock for the whole cycle plus the per-batch lock during each S3 delete;
- IMAP COPY between accounts: one per copy in flight, held across the S3 existence check and copy.

An upload holds no lock across its transfer. Before writing it takes and at once releases the per-object lock in a single statement, which orders the write after any delete of the same body already under way; every later delete sees the upload's pending row and leaves the body alone. The same statement leases that row to that one upload (`pending_uploads.lease_until` and `lease_owner`, renewed while the transfer runs). The lease is exclusive: another upload of the same row is deferred while it is live, and only the owner can renew, release or finalize it. Nothing deletes a leased row but its owner's finalize, so account deletion and purge wait for it. An upload therefore uses a pooled connection only for its few short statements, and `[uploader] concurrency` is bounded by S3, not by the pool.

Size the pooler's pool for the write user with that in mind:

```
pool_size >= 2 + headroom for interactive writes, cross-account copies and short uploader statements
```

A pool sized only for short IMAP/LMTP transactions can still queue mail delivery behind the cleaner's S3 deletes, most visibly during an S3 outage when those deletes sit in retry.

Sora keeps a held lock transaction alive with a statement at least every minute, so PostgreSQL's `idle_in_transaction_session_timeout` must be well above that. A shorter setting kills the lock holder mid-transfer; the transfer is then abandoned and retried, not lost.

Session-level advisory locks (`pg_advisory_lock`) must never be introduced: through a transaction pooler the lock and its unlock land on different backends, the lock strands until the pooler retires that backend, and enough stranded locks fill PostgreSQL's shared lock table, at which point every session fails with `out of shared memory` (SQLSTATE 53200). A source-scan test (`db.TestNoSessionLevelAdvisoryLocksInProductionCode`) enforces this.
