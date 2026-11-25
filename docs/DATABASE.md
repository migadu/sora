# Sora Database

This document explains how Sora uses PostgreSQL: what it stores there, what PostgreSQL needs,
how Sora connects (write and read endpoints, pools, TLS), which queries go where, the timeouts,
how Sora reacts when the database fails, how to run it behind PgBouncer, and how schema
migrations are applied and rolled back.

It is written for operators who run the PostgreSQL behind Sora, and for contributors who change
the database code. Search, which is the heaviest user of the database, has its own document,
[SEARCH.md](SEARCH.md). Message bodies live in S3; see [STORAGE.md](STORAGE.md).

## Contents

1. [What Sora keeps in PostgreSQL](#1-what-sora-keeps-in-postgresql)
2. [Requirements](#2-requirements)
3. [Connecting: the write and read endpoints](#3-connecting-the-write-and-read-endpoints)
4. [Connection pools](#4-connection-pools)
5. [Which queries use which endpoint](#5-which-queries-use-which-endpoint)
6. [Timeouts](#6-timeouts)
7. [Failover, retries and circuit breakers](#7-failover-retries-and-circuit-breakers)
8. [PgBouncer and other connection poolers](#8-pgbouncer-and-other-connection-poolers)
9. [Migrations](#9-migrations)
10. [Maintenance](#10-maintenance)
11. [Monitoring](#11-monitoring)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. What Sora keeps in PostgreSQL

PostgreSQL is Sora's source of truth for everything except message bodies. Every account, login,
folder, message header, flag and search vector is a row in it. Message bodies are in S3, keyed
by their BLAKE3 hash.

| Table | What it holds |
|---|---|
| `accounts` | One row per account, with its deletion mark (`deleted_at`) and purge request (`purge_requested_at`). |
| `credentials` | Login addresses (the primary address and aliases) and their password hashes. |
| `mailboxes` | Folders. Deleted folders stay as tombstones until the cleaner removes them. |
| `subscriptions` | IMAP subscriptions, by folder name, per account. |
| `mailbox_acls` | Access rights to shared folders ([SHARED_MAILBOXES.md](SHARED_MAILBOXES.md)). |
| `messages` | One row per message per folder: UID, MODSEQ, dates, size, header columns, body structure, S3 location, expunge state. |
| `message_state` | Flags and keywords of each message, kept apart from `messages` so that a flag change does not rewrite the large message row. |
| `mailbox_stats` | Message count, unseen count, total size, highest MODSEQ and keyword list per folder, kept current by database triggers. |
| `messages_fts_v2` | Body search vectors. The only copy of this data; see [SEARCH.md](SEARCH.md#4-the-fts-table-and-the-fts-worker). |
| `pending_uploads` | Bodies waiting to be uploaded to S3, with the node that owns each and its upload lease. |
| `s3_body_delete_intents` | S3 deletes of message bodies that have been sent but not yet confirmed. A body with a row here is quarantined ([STORAGE.md](STORAGE.md#95-how-deletions-are-made-safe)). |
| `instance_heartbeats` | When each uploader instance was last alive. |
| `instance_sessions` | Open sessions each node reports, used to drain a backend for maintenance. |
| `backend_maintenance` | Backends taken out of rotation ([PROXY.md](PROXY.md)). |
| `sieve_scripts` | Sieve scripts per account. |
| `vacation_responses` | Which senders got a vacation reply and when. |
| `redirect_log` | Sieve redirects per account, for the redirect rate limit. |
| `redirect_deliveries` | Which redirect addresses each delivery (LMTP or Admin API) was queued for, so that a retry of the delivery is not redirected again. |
| `metadata` | IMAP METADATA entries. |
| `locks` | Named locks with an expiry, for work that must run on exactly one node (TLS certificate issuance). |
| `credential_changes` | One row for every changed or removed password, login address or account, written by database triggers. Every node reads it to drop cached logins ([AUTHENTICATION.md](AUTHENTICATION.md#121-the-credential-change-feed)). Rows are deleted 7 days after a node first saw them. |
| `database_identity` | One random UUID that names this database. Imports use it to recognise the database they resume into, and the auth cache to recognise its own entries. Backups and failover keep it. |
| `health_status` | Current health of each node's components. |
| `cache_metrics` | Hit and miss counts of each node's local cache. |
| `schema_migrations` | The schema version and its dirty flag ([section 9](#9-migrations)). |

The schema is defined by the migration files in [db/migrations/](../db/migrations/). They are the
authoritative description of every table, index, trigger and function.

---

## 2. Requirements

### PostgreSQL

Use PostgreSQL 14 or later. Every node that serves the same users (backends, API servers, proxies
that look up local users) connects to the same database, directly or through replicas and
poolers. A proxy that only routes needs no database.

Create the database with UTF-8 encoding. Sora stores folder names, subjects and addresses as
UTF-8 text.

### Extensions

The migrations need two extensions from PostgreSQL's contrib package:

| Extension | Created by | Used for |
|---|---|---|
| `pg_trgm` | the baseline | Trigram indexes the schema creates on header columns. |
| `btree_gin` | the baseline | The search index on `(account_id, text_body_tsv)`, which scopes a body search to one account. |

The migrations run `CREATE EXTENSION IF NOT EXISTS` as Sora's database user. Both extensions are
"trusted", so a user with the `CREATE` privilege on the database (for example its owner) can
create them without being a superuser. Your distribution may ship contrib as a separate package
(for example `postgresql-contrib`). If Sora's user may not create extensions, create them
yourself before the first start:

```sql
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS btree_gin;
```

### Privileges

Migrations create and alter tables, indexes, triggers and functions. The simplest setup is a
database owned by Sora's user:

```sql
CREATE ROLE sora LOGIN PASSWORD 'change-me';
CREATE DATABASE sora_mail_db OWNER sora ENCODING 'UTF8' TEMPLATE template0;
```

### Server settings

- **`max_connections`**: large enough for every Sora process, see [section 4](#4-connection-pools).
- **`idle_in_transaction_session_timeout`**: if you set it, keep it well above one minute. Some
  of Sora's transactions stay open on purpose while they hold a lock across an S3 call, and
  run a statement at least every minute to stay alive (see [section 8](#8-pgbouncer-and-other-connection-poolers)).
- **`max_locks_per_transaction`**: PostgreSQL has room for `max_locks_per_transaction` ×
  (`max_connections` + `max_prepared_transactions`) locks for the whole server, advisory locks
  included. Once they are used up, every session fails with `out of shared memory` (SQLSTATE
  `53200`). Some of Sora's transactions take many advisory locks at once:
  - The cleanup cycle locks up to 500 message bodies per batch of S3 deletes, and up to 1,000
    search rows when it sweeps orphaned search vectors.
  - An IMAP `COPY` or `MOVE` that moves messages into a mailbox of another account locks every
    distinct body it carries, and their search rows, until it commits. Such a command may carry
    at most 1,000 distinct bodies, so it takes at most about 2,000 advisory locks, plus its
    ordinary row locks. A larger command is refused with `NO [LIMIT]` and changes nothing.
    `COPY` and `MOVE` within one account have no such limit and take no advisory lock per body:
    they hold row locks on their source messages instead, which do not use the lock table.

  These numbers are per transaction. Leave room for several of them at once, and for all other
  locks.

---

## 3. Connecting: the write and read endpoints

Sora's `[database]` section has global settings and two endpoints:

- **`[database.write]`**: the primary. All writes go here, and so do reads that must see the
  latest data.
- **`[database.read]`**: optional read replicas. Most reads go here.

A minimal configuration with one PostgreSQL server:

```toml
[database.write]
hosts = ["db.example.com"]
port = 5432
user = "sora"
password = "change-me"
name = "sora_mail_db"
```

With two read replicas:

```toml
[database.write]
hosts = ["db-primary.example.com"]
port = 5432
user = "sora"
password = "change-me"
name = "sora_mail_db"

[database.read]
hosts = ["db-replica1.example.com", "db-replica2.example.com"]
port = 5432
user = "sora"
password = "change-me"
name = "sora_mail_db"
```

### Endpoint keys

`[database.write]` and `[database.read]` take the same keys. Defaults are what Sora uses when the
key is missing from the file.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `hosts` | list of strings | `["localhost"]` | Database hosts. Each entry is a name or address, optionally with a port (`"db1.example.com:5433"`). With several hosts, Sora uses one at a time and fails over to the next ([section 7](#7-failover-retries-and-circuit-breakers)). |
| `port` | integer or string | `5432` | Port for host entries written without one. |
| `user` | string | `"postgres"` | Database user. |
| `password` | string | `""` | Password. |
| `name` | string | `"sora_mail_db"` | Database name. |
| `tls` | boolean | `false` | Encrypt the connection. See [TLS](#tls) below. |
| `max_connections` | integer | `100` | Most connections in one pool. See [section 4](#4-connection-pools). |
| `min_connections` | integer | `0` | Connections opened at startup and kept open. |
| `min_idle_connections` | integer | `5` (write), `10` (read) | Idle connections the pool keeps ready. The pool opens them in the background. |
| `max_conn_lifetime` | duration | `"1h"` | A connection older than this is closed and replaced. |
| `max_conn_idle_time` | duration | `"5m"` | An idle connection above `min_idle_connections` is closed after this time. |
| `query_timeout` | duration | `"30s"` | Timeout of read queries. See [section 6](#6-timeouts). |

Always set at least `hosts`, `user` and `name`.

Durations take Go units such as `"30s"`, `"5m"`, `"1h"`, or a whole number of days such as
`"7d"`. Setting `max_connections`, `min_connections` or `min_idle_connections` to `0` (or a
duration to `""`) leaves it to the driver's default (for `max_connections`, 4 or the number of
CPUs, whichever is larger).

### Rules that are easy to miss

- **Nothing is inherited.** `[database.read]` does not copy `user`, `password` or `name` from
  `[database.write]`. Repeat them, or the read endpoint uses the defaults above.
- **An endpoint you do not write is not configured.** Without a `[database.write]` (or
  `[database.read]`) section in the file, Sora has no such endpoint. This is how a proxy-only node
  runs without a database. A node that needs a database and has none refuses to start, and
  `sora-admin config validate` refuses the file, with `[database]: server "<name>" (<type>) needs
  the database, but it is not configured in [database.write] or [database.read]`.
- **`[database.read]` alone is not enough.** The migrations and every write go to
  `[database.write]`, so a node that needs a database needs `[database.write]` hosts, a proxy
  that only checks passwords included. With `[database.read]` hosts and none in
  `[database.write]`, Sora refuses to start, and `sora-admin config validate` refuses the file,
  with `[database.write]: server "<name>" (<type>) needs the database, but [database.write] has
  no hosts; ...`. Other `sora-admin` commands stop with `[database.write] has no hosts`.
- **User name and password** may contain any characters. Sora escapes them in the connection URL.
- **IPv6 addresses** go in brackets with a port: `hosts = ["[2001:db8::10]:5432"]`.

### Global keys

These keys go directly under `[database]`:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `query_timeout` | duration | `"30s"` | Base timeout of read queries. See [section 6](#6-timeouts). |
| `search_timeout` | duration | `"1m"` | Timeout of search queries and some long reads. |
| `write_timeout` | duration | `"15s"` | Timeout of write transactions. |
| `lock_timeout` | duration | `"10s"` | How long a statement in a write transaction waits for a row lock. `"0"` turns it off. |
| `migration_timeout` | duration | `"2m"` | How long other nodes wait while one node applies migrations: three times this value. |
| `fetch_chunk_size` | integer | `5000` | Messages read per database query when a large FETCH is streamed. `0` or less means the default. |
| `debug` | boolean | `false` | Log every SQL statement and its arguments. |

`debug` logs the arguments too, which include password hashes, addresses and message text. Use it
only on a test system.

`sora-admin` uses the same defaults.

Changes to `[database]` take effect on restart. A reload (SIGHUP) reports them as changed but
requiring a restart.

### TLS

`tls = true` connects with PostgreSQL's `sslmode=require`: the connection is encrypted, but Sora
does not check the server's certificate. There is no key for a CA file.

The driver Sora uses (pgx) reads the standard libpq environment variables, and the connection
string Sora builds does not override the certificate ones. So, in Sora's environment:

- `PGSSLROOTCERT=/etc/sora/db-ca.pem` makes it verify the certificate chain against that CA
  (libpq's `verify-ca`: the host name is not checked);
- `PGSSLROOTCERT=system` makes it verify the chain against the system's CAs and check the host
  name (libpq's `verify-full`);
- `PGSSLCERT` and `PGSSLKEY` give a client certificate.

These variables apply to every connection the process makes, the write and read endpoints alike.
With `tls = false`, Sora sends `sslmode=disable`, and `PGSSLMODE` cannot turn TLS on.

---

## 4. Connection pools

Each Sora process (`sora` or `sora-admin`) keeps its own pools of connections. Size PostgreSQL,
or your pooler, for all of them together.

### Pool size

For **every host** in `hosts`, Sora opens a pool with that endpoint's settings:
`max_connections` sets the upper limit and `min_idle_connections` the idle connections kept
ready. The pools grow only as load needs, but the upper limit is what PostgreSQL must be ready
for.

**Without `[database.read]`**, each write host gets a second pool, of the same size, for
reads. Heavy writes (a large import, a burst of deliveries) then cannot starve reads of
connections. Such a host can therefore see up to 2 × `max_connections` connections from one
process. With `[database.read]`, a write host has one pool, and reads share it only when no
replica is healthy.

`sora-admin` connects to the write hosts only, and never to replicas. The import commands and
`import rekey` need at least 2 connections in the write pool: each worker holds one for its
body locks while its writes use another. They run at most half as many workers as the pool has
connections.

### Pool behaviour

- A new connection times out after 5 seconds (`connect_timeout=5`).
- Every 15 seconds the pool checks its idle connections and replaces dead ones, closes those past
  `max_conn_lifetime` or `max_conn_idle_time`, and opens connections up to
  `min_idle_connections`.
- A connection that is already closed is never handed out.
- The pools also hold some connections for a long time on purpose, see
  [section 8](#8-pgbouncer-and-other-connection-poolers).

### Mailbox-level queueing

Before it takes a connection to insert a message (delivery, `APPEND`, import), a Sora process
makes other inserts into the same mailbox wait in memory (1024 stripes, keyed by mailbox ID). Many
deliveries to one mailbox then wait in Sora, not holding connections from the pool. This applies
within one process only. The wait is measured in `sora_go_mailbox_lock_wait_seconds`.

---

## 5. Which queries use which endpoint

| Work | Endpoint |
|---|---|
| Every write and every write transaction | write |
| Advisory locks ([section 8](#8-pgbouncer-and-other-connection-poolers)) | write |
| Migrations | the first write host that connects |
| Reads: login lookups, folder lists, message lists, FETCH metadata, SEARCH, SORT, THREAD, the User API, metrics statistics, the cleaner's candidate scans | read |
| Reads in a session that has already written something | write |
| Reads that must not be fooled by a lagging replica | write |

**Sessions that have written.** An IMAP, POP3, LMTP or ManageSieve session sends all of its later
reads to the write endpoint once it has written anything (for example an IMAP `APPEND`, `STORE`,
`COPY`, `MOVE`, `EXPUNGE`, `CREATE`, `RENAME`, `DELETE` or `SETACL`). The session then sees its
own changes, even when a replica lags. This lasts until the session ends.

**Checks that never trust a replica.** Some reads always go to the write endpoint, because a
stale answer would do harm:

- Before LMTP answers "no such user" (a permanent `550` that makes the sender bounce the mail),
  it repeats the lookup on the write endpoint.
- Before IMAP or POP3 reports a message body as missing, it checks on the write endpoint whether
  the body is still waiting to be uploaded.
- The cleaner re-checks on the write endpoint before it deletes an account's search data, and
  re-validates every deletion candidate inside the deleting transaction.

**What replica lag means for users.** A new message, folder or flag change made in another
session can take as long as your replication lag to show up in a session that has not written.
Search results lag in the same way.

Without `[database.read]`, all of this goes to the write endpoint.

---

## 6. Timeouts

Sora enforces its database timeouts in the client: each operation gets a deadline, and when it
passes, the driver cancels the query in PostgreSQL. Sora does not set `statement_timeout`.

| Operation | Timeout |
|---|---|
| Reads | The read endpoint's `query_timeout` (or the write endpoint's, without a read endpoint). If that is `"0"`, `[database] query_timeout`. |
| Search queries (IMAP `SEARCH`, `SORT`, `THREAD`, multi-mailbox `ESEARCH`, User API search), each chunk of a streamed FETCH, the cleaner's large scans | `[database] search_timeout` |
| Write transactions | `[database] write_timeout` |
| Login lookups | `[database] write_timeout`, but at most 10 seconds |
| Administrative and bulk work (account and credential changes, imports, restores, FTS indexing and pruning) | 75% of `[database] search_timeout` |
| Waiting for a row lock inside a write transaction | `[database] lock_timeout` |
| Waiting for another node's migrations | 3 × `[database] migration_timeout` |

Things to know:

- **The endpoint `query_timeout` wins for reads.** Both default to 30 seconds. To change the read
  timeout, set `query_timeout` in `[database.read]` (or `[database.write]` when you have no read
  endpoint). Setting only `[database] query_timeout` changes it for a few session-level lookups,
  not for ordinary reads.
- **IMAP commands have their own limits too.** `SEARCH`, `SORT`, `THREAD` and multi-mailbox
  `ESEARCH` stop after 30 seconds by default (`timeouts.imap_command_timeouts` in an IMAP
  `[[server]]` block), before the default `search_timeout` of one minute. See
  [SEARCH.md](SEARCH.md#9-limits) and [PROTOCOLS.md](PROTOCOLS.md).
- **A timed-out operation is not retried.**
- **`lock_timeout`** is set with `SET LOCAL lock_timeout` at the start of each write transaction,
  so it works behind any pooler. A statement that waits longer for a row lock fails with SQLSTATE
  `55P03` and frees its connection, instead of holding it for the whole `write_timeout`. Keep it
  at or below `write_timeout`. IMAP answers such a failure with `NO [UNAVAILABLE]`.
- **The migration leader has no timeout.** The node applying migrations runs until they finish
  ([section 9](#9-migrations)).

What clients see when the database is slow or down depends on the protocol: IMAP answers
`NO [UNAVAILABLE] Service temporarily unavailable, please try again later`, and LMTP answers with
a temporary `451` reply so your mail transfer agent retries later. See
[PROTOCOLS.md](PROTOCOLS.md).

---

## 7. Failover, retries and circuit breakers

### Several hosts in one endpoint

`hosts` can list several hosts, for example several PgBouncer instances in front of one primary,
or several replicas. Sora treats each host separately and uses **one host at a time** per
endpoint, the "current" one. It does not spread load across them.

- At startup, Sora connects to every listed host. A host that cannot be reached, read or write,
  is retried in the background after 30 seconds, 1, 2, 5 and then every 10 minutes. If no write
  host can be reached, Sora exits with `Failed to initialize resilient database`.
- If no read host can be reached at startup, reads use the write endpoint until a replica comes
  back.
- Every 30 seconds Sora pings each host (5-second timeout). A host that fails one ping is marked
  unhealthy, and the next operation switches to the next healthy host of that endpoint. A host
  that answers again is marked healthy.
- When no read host is healthy, reads use a healthy write host, as at startup, until a replica
  answers again. When every write host is unhealthy, Sora keeps using the current one.
- On a write host, the check also runs `SELECT pg_is_in_recovery()`. A primary that has become a
  standby after a failover is marked unhealthy and its connections are dropped. The same happens
  when a write fails with SQLSTATE `25006` (read-only transaction). New connections then reach
  whatever the host name or address points to at that moment.

So point `[database.write] hosts` at a name or address that always reaches the current primary:
a DNS name your failover tooling updates, a virtual IP, or a pooler that follows the primary. You
can also list every server that may become primary. The check marks the standbys unhealthy, and
writes move to the server that answers as primary within one check interval.

### Advisory locks across a failover

Sora orders the deletion of a message body in S3 (the cleaner, account purges, `import rekey`)
against the writes that claim one (uploads, restores, imports, cross-account copies and moves)
with advisory locks on the write host ([STORAGE.md](STORAGE.md#95-how-deletions-are-made-safe)). A lock excludes only what runs on the server that holds it. So when Sora stops
writing through a server, it revokes the locks it holds there: the work they guard is cancelled
(a cleanup batch or purge runs again in a later cycle; a copy or `import rekey` fails and can be
retried). It does so when it switches to another write host, before it writes anything there, and
when it reconnects its write host because the server answered read-only or in recovery, as soon
as it has dropped the old connections. The log shows `Database: fencing advisory locks`.

Each node notices a failover by itself, at its next health check or at its first write that
fails. Until then, a node still connected to the old primary keeps its locks there, and they
exclude nothing on the new one. Your failover tooling must therefore fence the old primary before
the new one accepts writes: shut it down, or terminate every client session on it
(`pg_terminate_backend`) and refuse new ones. Making it read-only is not enough, because a session
that is already open keeps its locks.

Fencing ends the locks, but not at once the work they guard. Sora notices that the session
holding a lock is gone only at the lock's next keepalive, which runs at most a minute after the
lock's last statement (twice the 30-second keepalive interval) and gives up on a server that does
not answer after 5 seconds. Until then the guarded work goes on: an S3 delete that was already
under way, and its retries, can still remove the body of a message the new primary has just
accepted. So the new primary must not accept writes until more than 65 seconds after the old one
was fenced.

### Retries

Sora retries an operation that failed for a reason that usually passes:

- a deadlock (`40P01`) or serialization failure (`40001`);
- too many connections (`53300`);
- a connection error (class `08`);
- a network timeout on the socket.

Reads are retried up to 3 times and write transactions up to 4 times, with growing pauses
(starting at 250 ms). Other errors are not retried, and neither are timeouts. When a `COMMIT`
itself fails, Sora does not retry it: the transaction may already have been applied, and running
it again could, for example, copy messages twice. Sora logs `Write transaction commit failed,
outcome unknown`.

### Circuit breakers

If most database operations fail within a short window, Sora stops sending new ones for a while
and fails them at once. This keeps a struggling database from being flooded.

| Breaker | Opens when | Stays open |
|---|---|---|
| Reads | at least 8 reads in 15 seconds, and 60% or more of them failed | 45 seconds |
| Writes | at least 5 writes in 10 seconds, and 50% or more of them failed | 30 seconds |

After that time a few operations are let through to test the database. The breaker closes again
when they succeed. When a health check sees the database answer again, it lets test operations
through at once. Expected outcomes (user not found, folder already exists, no rows, the search
result cap) do not count as failures, nor, for writes, a deadlock or serialization failure that is
retried. Timeouts do count.

State changes are logged as `Database query circuit breaker state changed` and
`Database write circuit breaker state changed`.

---

## 8. PgBouncer and other connection poolers

Sora works behind PgBouncer in **session** or **transaction** pooling mode. It does not work in
**statement** mode, which forbids the multi-statement transactions Sora uses everywhere.

### What Sora does to be pooler-safe

- Every timeout it sets is `SET LOCAL`, scoped to one transaction. Sora keeps no session state on
  a connection: no `SET`, no `LISTEN`, no temporary tables.
- Every advisory lock is transaction-scoped (`pg_advisory_xact_lock`). A lock is held in a
  dedicated transaction that stays open exactly as long as the lock is needed, so a pooler cannot
  move it to another server connection.

### What you must set up

- **Prepared statements.** Sora's driver prepares and caches statements on each connection. In
  transaction mode PgBouncer must track them: use PgBouncer 1.21 or later with
  `max_prepared_statements` set above zero.
- **Idle transactions.** A held lock keeps its transaction open across an S3 call and runs a
  statement at least once a minute. Keep PostgreSQL's `idle_in_transaction_session_timeout` and
  PgBouncer's `idle_transaction_timeout` well above one minute, or turn them off. A shorter
  setting kills the lock holder; the guarded work is then abandoned and done again later, not
  lost.
- **Pool size for Sora's user.** See below.

### Connections held across S3 calls

These hold one server connection behind the pooler for as long as they run:

| Holder | How many |
|---|---|
| The cleanup cycle | Two on the node running the cycle: one for the whole cycle, one during each batch of S3 deletes. A third is used briefly to commit each batch's deletion intents ([STORAGE.md](STORAGE.md#95-how-deletions-are-made-safe)). |
| An account purge | One per node while it purges an account, and a second briefly for its deletion intents. |
| `sora-admin` imports and `import rekey` | Two per worker: one for the body locks, one for the writes. |
| IMAP `COPY` or `MOVE` into a folder owned by another account | One per command in progress: its own transaction, from the S3 check and copy until its rows commit. |
| Migrations | Two on the node applying them, for the whole run: the leader lock and the connection the migrations run on. |

S3 uploads hold no connection across the transfer. An upload uses the pool only for a few short
statements, so `[uploader] concurrency` is bounded by S3, not by the pool.

Size the pooler's pool for Sora's database user with this in mind:

```
pool_size >= 3 + headroom for interactive writes, cross-account copies and moves, imports, and uploader statements
```

A pool sized only for short IMAP and LMTP transactions can queue mail delivery behind the
cleaner's S3 deletes, most visibly during an S3 outage, when those deletes wait in retries.

### For contributors

Never add a session-level advisory lock (`pg_advisory_lock`). Behind a transaction pooler the
lock and its unlock land on different server connections. The lock then stays behind until the
pooler closes that connection, and enough of them fill PostgreSQL's shared lock table, after
which every session fails with `out of shared memory` (SQLSTATE `53200`). Use `AdvisoryLockTx`
([db/advisory_lock_tx.go](../db/advisory_lock_tx.go)). The test
`TestNoSessionLevelAdvisoryLocksInProductionCode` enforces this for Sora's own code.

---

## 9. Migrations

The schema lives in [db/migrations/](../db/migrations/), built into both binaries:

- **The baseline**, `000001_baseline.up.sql`, creates the complete schema in one step. A new
  installation applies only this file.
- **Numbered migrations after it** (`000002_...` onwards) change the schema, each with an `up`
  and a `down` file. The baseline has no `down` file and is never reverted.

The applied version is stored in `schema_migrations`, which also has a `dirty` flag that is set
while a migration runs.

A migration file with several statements runs as one transaction. If it fails, none of its
changes stay, but `schema_migrations` is left at that version with `dirty` set.

The baseline replaced the 75 migrations (000001 to 000077) of earlier releases. A database
built by those is moved to the baseline once, by hand:
[Moving a database to the baseline](#moving-a-database-to-the-baseline).

### How migrations are applied

There are two ways, and they do the same thing:

1. **Automatically, at startup.** Every `sora` process that opens the database applies pending
   migrations before it starts serving, through the first host of `[database.write] hosts` that
   it can connect to. If a migration fails, the node does not start.
2. **By hand**, with `sora-admin migrate up`.

When several nodes start at once, they elect one leader with a transaction-scoped advisory lock:

```mermaid
sequenceDiagram
    participant A as Node A
    participant B as Node B
    participant DB as PostgreSQL
    A->>DB: try leader lock (granted)
    B->>DB: try leader lock (refused)
    A->>DB: apply migrations, no time limit
    B->>DB: poll schema_migrations every 5 s
    A->>DB: done, version N, not dirty
    B->>DB: sees version N, starts
```

- A node that finds the schema already at or above the newest version it knows starts at once
  (`Database: migrations are up to date. Skipping migration infrastructure setup`).
- The leader logs `Database: acquired migration leader lock, proceeding with migrations`, then
  `Database: migrations are still actively running... please wait` every 30 seconds, and
  `Database: migration complete` with the version.
- The other nodes log `Database: another instance is currently running migrations. Waiting...`
  and poll every 5 seconds. If the migrations are not done after 3 × `migration_timeout`
  (6 minutes by default), they exit with `timed out waiting for another instance to complete
  migrations`. The leader carries on.
- A node that becomes leader and finds the schema dirty refuses to start with `database is in a
  dirty migration state (version N). Manual intervention required`.

A node does not refuse to start when the schema is **newer** than its binary. An older node keeps
running after a newer node migrated the database, and logs `Database: schema version is newer than
this binary's migrations; none will be applied` when it starts.

### sora-admin migrate

```sh
sora-admin migrate version --config /etc/sora/config.toml
sora-admin migrate up      --config /etc/sora/config.toml
sora-admin migrate down    --config /etc/sora/config.toml --limit 1
sora-admin migrate force   --config /etc/sora/config.toml 3
```

| Subcommand | What it does |
|---|---|
| `version` | Prints the current version and whether it is dirty (`Dirty state: no`). A plain read: safe while Sora runs. |
| `up` | Applies every pending migration. |
| `down` | Reverts the last migration, or `--limit N` of them, or with `--all` every one after the baseline. It never reverts the baseline ([Rolling back](#rolling-back)). |
| `force VERSION` | Sets the version and clears the dirty flag, without running anything. |

The tool's help asks you to stop Sora before `up`, `down` and `force`. `migrate` connects through
`[database.write]`, with the same host and port rules as the server. All options are in
[ADMIN_CLI.md](ADMIN_CLI.md).

### Before you upgrade

1. **Back up the database.** Down migrations cannot bring back data a migration removed, and the
   search vectors exist nowhere else ([section 10](#10-maintenance)).
2. **Read the new migration files.** Compare `sora-admin migrate version` with the files in
   `db/migrations/` of the new release. Read the comment at the top of each new `up` file. On a
   large database some must be prepared by hand first; see [Large databases](#large-databases)
   below.
3. **Check the extensions** the new migrations need ([section 2](#2-requirements)).
4. **Decide who applies the migrations.** On a small database, the first upgraded node can do it
   at startup. Otherwise run `sora-admin migrate up` yourself, and start the upgraded nodes
   after it finishes. They then find nothing to do. This also keeps a long migration from making
   other nodes give up after 3 × `migration_timeout`.
5. **Plan the mixed-version window.** While nodes are upgraded one by one, old and new binaries
   run against the new schema. See [OPERATIONS.md](OPERATIONS.md) for upgrade order.

### After you upgrade

1. Run `sora-admin migrate version`. It should show the newest version and `Dirty state: no`.
2. Check each node's log for `Database: migration complete` or `migrations are up to date`.
3. Run `ANALYZE` on any table or index you built by hand.
4. If you use replicas, check that they have replayed the changes before you send reads to them.
5. Watch the metrics a migration touches, for example `sora_fts_queue_depth` after a search
   change ([section 11](#11-monitoring)).

### A failed migration

When a migration fails, the version is left dirty and nodes refuse to start. Because the failed
file's changes were rolled back as a whole:

1. Read the error in the log. It names the problem, for example a missing prerequisite or
   out-of-band preparation that is not finished ([Large databases](#large-databases)).
2. Fix the cause.
3. Set the version back to the last migration that completed: `sora-admin migrate force <N-1>`,
   where N is the version shown as dirty. If the numbering has a gap, use the number of the
   previous file that exists. If the baseline itself failed on a new, empty database, drop and
   recreate the database instead.
4. Start Sora again, or run `sora-admin migrate up`.

A failed **down** migration is recorded the other way round: reverting N leaves the version at
N−1, dirty. Finish its preparation, run `sora-admin migrate force N`, and run
`migrate down` again.

Never force a version to skip a migration that refused: the migration's checks are what keep a
blocking index build away from a large table. If a migration file had a statement that cannot
run inside a transaction, check by hand what was applied before you force a version.

### Rolling back

`sora-admin migrate down` runs the `down` files. They drop the tables, columns and indexes the
`up` files created, with their data. Restore from a backup instead when you can, and never run
`down --all` on a live system: it reverts every migration after the baseline and deletes their
data. `migrate down` never reverts the baseline: `--all` stops after it, and a `--limit` that
would reach it is refused. To tear down a database completely, drop and recreate it.

Stop every binary that uses what a migration added before you revert it, and read the `down`
file first: its header comment says what reverting loses and whether it needs preparation.

### Large databases

A migration runs inside one transaction under the leader lock. A plain `CREATE INDEX` on a large
table holds a lock that blocks writes (or reads and writes) for the whole build, and
`CREATE INDEX CONCURRENTLY` cannot run inside a migration. So a migration that builds an index
on a large table, or adds a column to one, describes an out-of-band procedure in its header
comment, and is written so that once you have done the work by hand, it finds nothing left to
do.

Do the out-of-band work on the primary, over a direct connection (not through a transaction
pooler), off-peak:

- **Columns:** `SET lock_timeout = '3s'`, then the `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`
  from the file. Adding a nullable column needs only a brief exclusive lock; retry on a lock
  timeout.
- **Indexes:** `CREATE INDEX CONCURRENTLY`, with exactly the definition in the file. A migration
  recognises a prepared index by its name, so a different definition would be kept silently.
- **Replaced indexes:** drop the old one with `DROP INDEX CONCURRENTLY` only after the new one is
  valid.

When a `CREATE INDEX CONCURRENTLY` fails, it leaves an invalid index behind. Check with
`SELECT indisvalid FROM pg_index WHERE indexrelid = 'index_name'::regclass;` and drop it with
`DROP INDEX CONCURRENTLY` before you try again.

A migration that refuses to do blocking work on a large table stops startup with the version
dirty, although nothing was changed: finish the preparation, `migrate force` the previous
version, and start again ([A failed migration](#a-failed-migration)).

### Rows stored by earlier releases

Several columns were added while Sora was already in use. They are **forward-only**: new mail
fills them, and Sora never fills them for mail stored before. Nothing reads the bodies in S3
again to fill them, and there is no command to do so. A database that has always run the
baseline has no such rows.

| Column | What it holds | A row stored before the column existed |
|---|---|---|
| `messages.extra_addresses` | Every further From, To and Cc name and address, so that FROM, TO and CC searches match all of them ([SEARCH.md](SEARCH.md)). | NULL: only the first address of each field matches. [scripts/backfill_extra_addresses.sql](../scripts/backfill_extra_addresses.sql) can fill it. |
| `messages.sent_utc_offset` | The time zone of the `Date:` header, so that SENTBEFORE, SENTON and SENTSINCE match the day the header names ([SEARCH.md](SEARCH.md)). | NULL: searched by the UTC day. |
| `messages.sent_date_unknown` | TRUE for a message without a `Date:` header that parses. Its ENVELOPE date is NIL ([PROTOCOLS.md](PROTOCOLS.md)), and date searches leave it out. | NULL: the stored date is reported. |
| `messages.restored_at` | Marks the expunged row of a restored message ([STORAGE.md](STORAGE.md#92-removal-after-the-grace-period)). | NULL. |
| `messages.header_presence` | Which searchable header fields a message has, so that a search for an empty header value is exact ([SEARCH.md](SEARCH.md)). | NULL: searched without it. COPY, MOVE and restore keep NULL. |
| `messages.message_id_raw` | The full `Message-ID:` field when it is not one plain `<id@domain>`, for exact `HEADER Message-ID` searches. | NULL: searched by the normalised ID. |
| `message_state.initial_modseq` | Set by a trigger on every new flag row, so that a client is not told twice of the flags of a message it has just learnt of. | NULL: handled as before. |

**Flag rows.** Every message Sora stores gets its `message_state` row, including copies, moves,
restores and imports. A message stored by an early release may have none; it reads as having no
flags. An IMAP `STORE` or a User API flag change on such a message creates its row first. Reads
and background work do not create missing rows.

### Moving a database to the baseline

This applies once, to a database created by a release that still had migrations 000001 to
000077. The baseline is the schema those migrations produce, without objects nothing uses any
more, under version 1.

Sora cannot tell the two numberings apart, so the order matters:

- A baseline binary on a database at version 77 starts normally and changes nothing.
- A binary from before the baseline, on a database at version 1, takes it for a database that
  is behind and runs its old migrations 2 onwards against the live schema. Never start one
  after step 4 without setting the version back to 77 first.

1. **Reach version 77 with the last release that has the old migrations.** That is the commit
   before `db/migrations/000001_baseline.up.sql` was added. `sora-admin migrate version` must
   show `77` and `Dirty state: no`. A database below 77 must not be given version 1: it lacks
   part of the schema.
2. **Remove what the baseline does not have.** The old migrations leave two unused tables and
   two unused indexes behind. Drop them once nothing older than the last release runs:

   ```sql
   DROP TABLE IF EXISTS messages_fts, message_contents;
   DROP INDEX CONCURRENTLY IF EXISTS idx_messages_mailbox_common_search;
   DROP INDEX CONCURRENTLY IF EXISTS idx_messages_mailbox_modseqs;
   ```

   `messages_fts` and `message_contents` held body-search data of releases before per-account
   search (`messages_fts_v2`). Drop them only if that data was carried over or is not wanted.
3. **Compare the schema with the baseline.** Create an empty database, let the new
   `sora-admin migrate up` build it, and compare `pg_dump --schema-only --no-owner
   --no-privileges` of both. They should differ only in what you added yourself, such as
   storage options on `messages`, and in spelling that does not change behaviour: the order of
   columns in `mailboxes` and `mailbox_acls`, a comment inside `has_mailbox_right`, and the
   way the `health_status` check is printed. Anything else needs a decision before step 4.
4. **Upgrade every node to the baseline release**, then set the version, on the primary:

   ```sql
   UPDATE schema_migrations SET version = 1 WHERE version = 77 AND NOT dirty;
   ```

   It must report `UPDATE 1`. Remove older `sora` binaries that a rollback procedure could
   start.

Test and development databases are simply recreated: `make reset-test-db`.

---

## 10. Maintenance

### Backups

Back up the whole database with your usual PostgreSQL tooling (base backups with WAL archiving,
or `pg_dump`). Include `messages_fts_v2`: its vectors are the only copy of the body search data,
and Sora has no command to rebuild them from S3. A database backup alone is not a mail backup:
the bodies are in S3. See [STORAGE.md](STORAGE.md) and [OPERATIONS.md](OPERATIONS.md).

### Autovacuum on messages

Header search ([SEARCH.md](SEARCH.md#2-header-search)) is answered from the index alone, which is
fast only while the table's visibility map is current. Each new message's row is updated once
more when its body has been uploaded, which clears the page's visibility bit until the next
vacuum. On a busy server, consider vacuuming `messages` more often than PostgreSQL's default, for
example:

```sql
ALTER TABLE messages SET (autovacuum_vacuum_scale_factor = 0.01);
```

### Statistics

Run `ANALYZE` on any table you filled or indexed by hand (see [section 9](#9-migrations)).
Autovacuum keeps statistics current after that. Sora's row-count metrics read the planner's
estimates, so they lag a little behind the real counts.

### What Sora cleans up itself

The cleaner ([STORAGE.md](STORAGE.md)) deletes expunged messages after the grace period, deleted
folders, deleted accounts, expired search vectors ([SEARCH.md](SEARCH.md#6-fts-retention)),
orphaned search rows and old `health_status` rows (`[cleanup] health_status_retention`). Each node
with a local cache deletes its old `cache_metrics` rows (`[local_cache] metrics_retention`). You
do not need cron jobs for these. The steps that remove messages, mailboxes and accounts run
only once message-body deletion is turned on ([STORAGE.md](STORAGE.md#95-how-deletions-are-made-safe));
until then expunged rows and deleted accounts stay in the database.

### Deleting messages by hand

The `mailbox_stats` counters are kept by triggers on `messages` and `message_state`. A `DELETE` on
`messages` removes the message's `message_state` row by cascade before either trigger runs, so
neither can see whether a message that was still live (not expunged) was unseen: the message and
its size leave the counts, but it stays in the folder's unseen count. Sora therefore never deletes
a live message directly. Whatever it removes for good, it expunges first, holding the folder's row
lock (`SELECT 1 FROM mailboxes WHERE id = ... FOR UPDATE`), and then deletes only rows that are
expunged or in no folder. Deleting a folder works the same way: its messages are expunged before
their flag rows are detached from it.

Follow the same order in SQL of your own: expunge the messages
(`UPDATE messages SET expunged_at = now(), expunged_modseq = nextval('messages_modseq') WHERE ...`)
while holding the folder's lock, and let the cleaner delete them after the grace period, or delete
them yourself. If live messages were deleted directly, run
[`mailbox repair-unseen --apply`](ADMIN_CLI.md#mailbox-repair-unseen) to fix the counts.

### Repair commands

`sora-admin` has commands for data that older releases left inconsistent. Each one has a dry-run
mode; see [ADMIN_CLI.md](ADMIN_CLI.md):

- [`mailbox repair-unseen`](ADMIN_CLI.md#mailbox-repair-unseen) recounts unseen counters that
  are too high or too low (the cleaner already repairs counters that went below zero);
- [`mailbox repair-hierarchy`](ADMIN_CLI.md#mailbox-repair-hierarchy) repairs the parent links
  of mailboxes;
- [`messages repair-references`](ADMIN_CLI.md#messages-repair-references) fills the stored
  References of messages that have none.

---

## 11. Monitoring

| Metric | Meaning |
|---|---|
| `sora_db_queries_total{operation,status,role}` | Queries by operation, outcome and endpoint (`read` or `write`). |
| `sora_db_query_duration_seconds{operation,role}` | Query time. Search shapes have their own `operation` values ([SEARCH.md](SEARCH.md#8-how-a-search-is-run)). |
| `sora_db_transactions_total{status}` | Committed and rolled-back transactions. |
| `sora_db_transaction_duration_seconds` | Transaction time. |
| `sora_db_pool_total_conns{role}`, `sora_db_pool_idle_conns{role}`, `sora_db_pool_in_use_conns{role}` | Connections of the write and read pools, summed over hosts. |
| `sora_db_pool_exhaustion_total{role}` | Times a pool was found more than 95% in use. |
| `sora_go_mailbox_lock_wait_seconds` | Time writers waited for the in-memory mailbox lock. |
| `sora_fts_queue_depth` | Search rows waiting for the FTS worker ([SEARCH.md](SEARCH.md#12-operating-search)). |

The health checks `database` (critical) and `database_read_pool` ping the database every 30
seconds. Every 30 seconds Sora also logs `Pools health status` with the connection counts, and
`Database pool near exhaustion` when a pool is more than 95% in use. See [METRICS.md](METRICS.md).

On the PostgreSQL side, `pg_stat_activity` shows Sora's connections; the ones in state `idle in
transaction` for a long time are usually the lock holders of [section 8](#8-pgbouncer-and-other-connection-poolers).

---

## 12. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Startup fails with `[database]: server "<name>" (<type>) needs the database, but it is not configured ...` | `[database.write]` is missing. | Configure the write endpoint ([section 3](#3-connecting-the-write-and-read-endpoints)). |
| Startup fails with `Failed to initialize resilient database` | No write host could be reached. | Check the host, port, credentials and network. The line before it names the error. |
| Startup fails with `dirty migration state` | A migration failed earlier. | See [A failed migration](#a-failed-migration). |
| Nodes exit with `timed out waiting for another instance to complete migrations` | A long migration on another node. | Let it finish, then start them; for long migrations, run `sora-admin migrate up` first or raise `migration_timeout`. |
| `prepared statement ... does not exist` behind PgBouncer | Transaction pooling without prepared-statement support. | PgBouncer 1.21 or later with `max_prepared_statements` above zero. |
| `out of shared memory` (SQLSTATE `53200`) | The shared lock table is full. | Look for long-held locks in `pg_locks`; with a transaction pooler, look for session-level advisory locks left behind. |
| Writes fail with `read-only transaction` after a failover | The write host name still points at the old primary. | Point it at the new primary (DNS, virtual IP or pooler); Sora reconnects on its own. |
| Clients get `NO [UNAVAILABLE]` under load | Timeouts, lock timeouts, an open circuit breaker or an exhausted pool. | Check the circuit breaker log lines, `sora_db_pool_in_use_conns` and slow queries in PostgreSQL. |
