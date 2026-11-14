# Sora Operations

This is the operator's runbook for Sora. It covers how the `sora` process starts, what it checks
before it serves anyone, the signals it handles and what a reload changes, how it shuts down, what a
restart loses, every file it writes on local disk, logging and log rotation, the service files in
`dist/`, database migrations, upgrades and mixed-version windows, backups, and the network
connections a host must allow.

It is written for people who run Sora. You should know Linux, PostgreSQL and mail in general; you do
not need to know Sora's code. Where a detail lives in another reference document, this one links to
it: [CONFIGURATION.md](CONFIGURATION.md) for the config file, [DATABASE.md](DATABASE.md) for
PostgreSQL, [STORAGE.md](STORAGE.md) for S3, the cache and the uploader, [PROXY.md](PROXY.md) for
proxies and backend maintenance, [METRICS.md](METRICS.md) for monitoring, and
[ADMIN_CLI.md](ADMIN_CLI.md) for every `sora-admin` command.

## Table of contents

1. [Running Sora](#1-running-sora)
2. [Startup](#2-startup)
3. [Exit status](#3-exit-status)
4. [Signals](#4-signals)
5. [What a restart loses and keeps](#5-what-a-restart-loses-and-keeps)
6. [What Sora writes to local disk](#6-what-sora-writes-to-local-disk)
7. [Logging](#7-logging)
8. [Service files](#8-service-files)
9. [Node identity](#9-node-identity)
10. [Database migrations](#10-database-migrations)
11. [Upgrades and mixed-version windows](#11-upgrades-and-mixed-version-windows)
12. [Taking a backend out of service](#12-taking-a-backend-out-of-service)
13. [Backups and restores](#13-backups-and-restores)
14. [Network: listeners and outbound connections](#14-network-listeners-and-outbound-connections)
15. [Common questions](#15-common-questions)

---

## 1. Running Sora

Sora ships as two programs:

- `sora` is the server. One process runs every listener configured in its file: backends (IMAP,
  POP3, LMTP, ManageSieve), proxies, the HTTP admin and user APIs and the metrics endpoint.
- `sora-admin` is the command-line tool for operators. It reads the same config file and talks to
  PostgreSQL directly, or to the admin API for some commands ([ADMIN_CLI.md](ADMIN_CLI.md)).

### Building

`make build` builds both programs in the repository root. `make build-linux-musl` builds static
Linux binaries (`sora-linux-amd64`, `sora-admin-linux-amd64`) and `make build-freebsd` builds FreeBSD
ones (`sora-freebsd-amd64`, `sora-admin-freebsd-amd64`). The module needs Go 1.25.0 or later
(`go.mod`). The Makefile stamps the version, commit and build date into the binary from git.

### Command-line flags

`sora` has three flags:

| Flag | Default | Meaning |
|---|---|---|
| `-config PATH` (or `--config PATH`) | `config.toml` | The TOML config file. A relative path is read from the working directory. |
| `-version`, `-v` | | Print `sora version <version> (commit: <commit>, built at: <date>)` and exit with status 0. |
| `-h`, `-help` | | Print the flags and exit with status 0. |

There is no flag that only checks the config. Use `sora-admin --config PATH config validate`
([Startup](#checking-a-config-before-you-start)) for that.

If `-config` is left at its default and `config.toml` does not exist, Sora logs
`Default configuration file not found - using application defaults` and goes on with built-in
defaults. Those define no `[[server]]` block, so startup then stops with "no servers configured". If
you name a file with `-config` and it does not exist, Sora stops at once.

### Foreground process

`sora` runs in the foreground. It does not fork, does not write a pid file and does not notify
systemd of readiness. Run it under a supervisor: systemd with `Type=simple`, or `daemon(8)` on
FreeBSD ([Service files](#8-service-files)).

---

## 2. Startup

### Startup order

Sora starts in this order. A failure in any step ends the process with status 1, except where noted.

1. **Flags.** `-version` prints and exits here.
2. **Config file.** Sora reads and parses the file. Unknown keys and duplicate keys are warnings, not
   errors ([CONFIGURATION.md](CONFIGURATION.md)). These warnings go to standard error, because
   logging is not set up yet.
3. **Validation.** In this order:
   - Unknown names in `[sieve] enabled_extensions` are a warning.
   - Each `[[server]]` block is validated: a `type`, `name` and `addr`, a known `type`, and no
     `master_username` or `master_sasl_username` with an empty password.
   - `[[pool]]` blocks are validated against the proxies that use them ([PROXY.md](PROXY.md)).
   - Every `[servers] trusted_networks` entry must be an IP address or a CIDR block.
   - A listener with `proxy_protocol = true` requires a non-empty `[servers] trusted_networks`.
   - Two `[[server]]` blocks may not share a `name` or an `addr`.
   - At least one `[[server]]` block must exist.
4. **Database endpoints.** A `[database.write]` or `[database.read]` section that is not in the file
   counts as not configured. This is how a proxy-only node runs without a database.
5. **Global settings.** `bcrypt_cost` and `[sieve] max_execution_time` are applied.
6. **Logging.** The `[logging]` output opens. From here on, log lines go where `[logging] output`
   says ([Logging](#7-logging)). Sora logs `SORA application starting` with its version, commit and
   build date.
7. **Timeout scheduler** (`[timeout_scheduler] shard_count`).
8. **SIGINT and SIGTERM** are handled from this point ([Signals](#4-signals)).
9. **Services**, in this order:
   1. The node's two names are resolved and logged: `Resolved instance ID` and
      `Resolved mail hostname` ([Node identity](#9-node-identity)).
   2. Sora decides what it needs. A node with an `imap`, `pop3` or `lmtp` server needs S3 and
      PostgreSQL. A node with `managesieve`, `http_admin_api` or `http_user_api` needs PostgreSQL,
      and `http_user_api` also uses S3 to serve message bodies. A proxy needs PostgreSQL when it
      checks passwords in the database (no remote lookup, or
      `[server.remote_lookup] lookup_local_users = true`). A database that is needed but not
      configured stops startup.
   3. **S3**, when needed: `[s3] access_key`, `secret_key`, `bucket` and `endpoint` must be set. Sora
      does not contact S3 here and does not create the bucket. With `[s3] encrypt = true` the
      encryption key is checked (64 hex characters).
   4. **PostgreSQL**, when needed: Sora connects to every write host, applies pending migrations
      through the first one it can reach ([Database migrations](#10-database-migrations)), and
      connects to the read hosts. A failed migration stops startup. Hosts that fail, read or write,
      are retried later; if no write host can be reached, Sora logs
      `Failed to initialize resilient database` and exits with status 1.
   5. The **auth cache** opens, if `[auth_cache] enabled = true`. If it fails, Sora logs an error and
      runs without it.
   6. On a node with S3 (a backend): the **local cache**, the **FTS worker**, the **cleaner**, the
      **purge worker** and the **uploader** start.
   7. The **relay queue** and its worker start, if `[relay] type` is set. A type other than `smtp`
      or `http` stops startup with `unsupported [relay] type`.
   8. The **cluster** joins, if `[cluster] enabled = true`, and with it the affinity manager (with
      `[cluster.affinity] enabled = true`) and its optional SQLite file.
   9. The **TLS manager** starts, if `[tls] enabled = true`: it loads certificate files, or sets up
      Let's Encrypt ([TLS.md](TLS.md)).
   10. Health checks, the metrics collector and the spam-training client start.
10. **SIGHUP** reloads the config from this point. An earlier SIGHUP does not end the process,
    and the log file can be reopened at any time.
11. **Listeners.** Backend maintenance is loaded (on nodes with proxies and a database), the
    HTTP-01 listener on port 80 starts (Let's Encrypt only), and every `[[server]]` starts. Each logs
    a line when it listens, for example `IMAP server listening with TLS name=imaps addr=:993` or
    `lmtp server listening name=lmtp addr=127.0.0.1:24 tls=false`.

A listener that fails to start (for example, the address is already in use) ends the whole process
with status 1. It does not leave the other listeners running.

### Messages that stop startup

Errors from steps 2 to 9 are written by Sora's error handler, in this form:

```
[ERROR] 2026/01/15 10:00:00 ERROR: invalid configuration - <what>: <why>
[ERROR] 2026/01/15 10:00:00 FATAL: operation '<what>' failed: <why>
```

Before step 6 they go to standard error. From step 6 on they go to the `[logging]` output. With
`output` set to a file, a node that fails to start under systemd may therefore show nothing in the
journal: look in the log file.

| Message contains | Cause | Fix |
|---|---|---|
| `configuration file '...' not found` | The file named with `-config` does not exist. | Check the path. |
| `failed to parse configuration file` | TOML syntax error. The message points at the line. | Fix the syntax. |
| `invalid configuration - servers: no servers configured` | No `[[server]]` block. | Add one with `type`, `name` and `addr`. |
| `server address is required` (or the name or type) | A `[[server]]` block lacks `addr`, `name` or `type`. | Add the missing key. |
| `invalid server type` | `type` is misspelled. | Use one of the types in [CONFIGURATION.md](CONFIGURATION.md). |
| `master_username is set but master_password is empty` | A master user without a password would let anyone in. | Set the password or remove the user. |
| `proxy_protocol is enabled on server(s) ... but [servers] trusted_networks is empty` | PROXY protocol without trusted senders. | Set `[servers] trusted_networks`. |
| `duplicate server name` / `duplicate server address` | Two blocks share a `name` or `addr`. | Make them unique. |
| `database is required for configured servers but not configured` | No `[database.write]` section (step 4). | Configure `[database.write]`. |
| `missing required S3 credentials` / `S3 endpoint not specified` | A backend without `[s3]` settings. | Set `[s3]`. |
| `Failed to initialize resilient database` | No write host reachable, or migrations failed. The line before it says why. | See [Database migrations](#10-database-migrations) and [DATABASE.md](DATABASE.md). |
| `FATAL: operation 'initialize cache' failed` | `[local_cache] path` cannot be created. | Fix the path or its permissions. |
| `FATAL: operation 'create upload worker' failed` | `[uploader] path` cannot be created. | Fix the path or its permissions. |
| `FATAL: operation 'initialize TLS manager' failed` | Certificate files unreadable, or a Let's Encrypt setting is missing. | See [TLS.md](TLS.md). |
| `FATAL: operation 'server operation' failed` | A listener could not start or failed later, for example `address already in use`. | Free the port, or check privileges for ports below 1024. |

### Warnings worth reading at startup

Sora starts despite these, but each one points at something to fix:

- `Mail hostname is not fully qualified`: the host has a short name ([Node identity](#9-node-identity)).
- `Instance ID could not be derived from the host - using the fallback identity`.
- `plaintext authentication is allowed without TLS on a publicly reachable address`: a client-facing
  listener without TLS on a public address.
- `metrics endpoint is served without access control on a publicly reachable address`.
- `trusted_networks includes whole private ranges`.
- `Cannot create certificate fallback directory - degrading to S3-only` (Let's Encrypt).
- `Backend maintenance is not honored on this node` (a proxy without a database).
- `HTTP Admin API server enabled but no API key configured - skipping` and the same for the user API
  without `jwt_secret`: that listener does not start, and the others do.

### Checking a config before you start

`sora-admin --config PATH config validate` parses the file, prints unknown and duplicate keys,
validates every `[[server]]` block and checks for duplicate names and addresses. It connects to
nothing and exits with status 0 when the file is valid. It does not run every check `sora` runs at
startup: it skips the `[[pool]]` checks, the `proxy_protocol`/`trusted_networks` check and the
database and S3 checks. `sora-admin --config PATH config dump` prints the parsed config with secrets
masked.

---

## 3. Exit status

| Status | When |
|---|---|
| 0 | `-version` or `-help`; or a shutdown after SIGINT or SIGTERM. |
| 1 | Any startup failure from [Startup](#2-startup); or a listener that fails while Sora runs. |
| 2 | An unknown flag; or a Go panic. |

A status of 1 after a runtime listener failure skips the shutdown steps in
[SIGINT and SIGTERM](#sigint-and-sigterm): sessions are cut and workers are not stopped. The
uploader's spool and the relay queue are on disk, so nothing queued is lost
([What a restart loses and keeps](#5-what-a-restart-loses-and-keeps)).

---

## 4. Signals

Sora handles SIGINT, SIGTERM and SIGHUP.

| Signal | Handled from | Effect |
|---|---|---|
| SIGINT, SIGTERM | Step 8 of [Startup](#startup-order) | Graceful shutdown. |
| SIGHUP | Step 10 of [Startup](#startup-order), after all services are up | Reopen the log file, then reload the config. |

Before step 10, a SIGHUP does not end the process, and the log file can be reopened at any time.

### SIGHUP

`systemctl reload sora` and `service sora reload` send SIGHUP. Sora then does three things, in order.

**1. Reopen the log file.** When `[logging] output` is a file path, Sora opens the same path again and
closes the old descriptor. A rotation tool can move the file aside and then send SIGHUP, and Sora
goes on writing to a new file under the old name. If the path cannot be opened, Sora keeps writing to
the old descriptor and logs `SIGHUP: log file not reopened`. With `stdout`, `stderr` or `syslog`
there is nothing to reopen.

Because SIGHUP also reloads the config, a log rotation applies any reloadable change you have saved
in the config file.

**2. Re-read the config file.** Sora logs `SIGHUP received - reloading configuration`. If the file
cannot be read or parsed, it logs `Config reload failed - keeping current config` and stops here.

**3. Apply what can be applied, report the rest.**

For each `[[server]]` that is running, Sora looks up the block with the same `name` in the new file.

- If the new block fails validation (for example a master user without a password), Sora logs
  `Skipping reload: invalid new server config` and that server keeps its settings.
- Otherwise the server applies the settings in the table below. It logs `<Protocol> config reloaded`
  with the list of what changed, for example `IMAP config reloaded name=imaps updated=[command_timeout]`.
- Every other setting that differs from the file the process **started** with is listed in
  `Config reload: server settings changed but require restart to take effect` with the server name
  and the changed keys.

New settings reach connections, logins and requests that start after the reload. Sessions that are
already open keep the settings they started with.

| `type` | Settings a SIGHUP applies |
|---|---|
| `imap` | `timeouts.command_timeout`, `timeouts.absolute_session_timeout`, `timeouts.min_bytes_per_minute`, `limits.session_memory_limit`, `master_sasl_username`, `master_sasl_password`, `master_sasl_allowed_networks` |
| `pop3` | the same as `imap` |
| `managesieve` | `timeouts.command_timeout`, `timeouts.absolute_session_timeout`, `timeouts.min_bytes_per_minute`, `max_script_size`, `master_sasl_username`, `master_sasl_password`, `master_sasl_allowed_networks` |
| `lmtp` | `max_message_size` |
| `imap_proxy` | `limits.max_auth_errors`, `auth_idle_timeout`, `timeouts.command_timeout`, `timeouts.absolute_session_timeout`, `timeouts.min_bytes_per_minute`, `master_sasl_username`, `master_sasl_password` |
| `pop3_proxy` | the same as `imap_proxy`, plus `debug` |
| `managesieve_proxy` | the same as `imap_proxy`, plus `debug` |
| `lmtp_proxy` | `timeouts.absolute_session_timeout`, `max_message_size` |
| `http_admin_api` | `api_key`, `read_only_api_key`, `allowed_hosts` |
| `http_user_api` | `jwt_secret`, `allowed_origins`, `allowed_hosts` |
| `user_api_proxy` | `jwt_secret` |
| `metrics` | nothing; changes are not reported either |

The list lives in `reloadableServerSettings` in
[cmd/sora/server_reload.go](../cmd/sora/server_reload.go). The admin API refuses a new `api_key`
shorter than 16 characters or equal to the placeholder from `config.toml.example`; it then keeps the
old key and Sora logs `Failed to reload server config`.

A reload never starts or stops a listener, and Sora reports added and removed blocks:

- A `[[server]]` block added to the file is not started.
- A block removed from the file keeps running.
- A block whose `name` changed counts as both: the old one keeps running, the new one does not start.

Outside the `[[server]]` blocks, nothing is applied by a reload. Sora reports every section that
changed, each with a line `Config reload: <section> changed but requires restart to take effect`:

- `[logging]` (`level`, `output` and `format`)
- `[cleanup]`
- `[shared_mailboxes]`
- `[sieve]`
- `[backend_maintenance]`
- `[metadata]`
- `[servers] trusted_networks` (logged as a warning: until a restart, the networks Sora started with
  stay trusted and added ones are not)
- `[database]`, `[s3]`, `[local_cache]`, `[uploader]`, `[relay]`, `[cluster]`, `[tls]`,
  `[auth_cache]`, `[[pool]]`, `[spam_training]`, `[timeout_scheduler]` and `bcrypt_cost`

TLS certificates are never reloaded by SIGHUP. Certificate files (`[tls] cert_file`/`key_file` and
per-server `tls_cert_file`/`tls_key_file`) are read once, at startup, so a renewed certificate needs
a restart. Certificates from Let's Encrypt renew inside the running process
([TLS.md](TLS.md)).

The "requires restart" lines compare with the config the process started with. They repeat on every
later SIGHUP until you restart.

### SIGINT and SIGTERM

The first SIGINT or SIGTERM starts a graceful shutdown. Sora logs
`Received signal - shutting down signal=terminated` (or `interrupt`) and
`Graceful shutdown initiated`, then:

1. **Listeners close.** Every server stops accepting connections and tells its sessions to end.
   - IMAP sends `* BYE Server shutting down, please reconnect` to every open session (at most 2
     seconds for all of them), then closes its listener.
   - POP3 sends `-ERR Server shutting down, please reconnect`, and ManageSieve sends
     `BYE (TRYLATER) "Server shutting down, please reconnect"`.
   - LMTP closes its listener and its connections. An LMTP transaction cut off here gets no `250`,
     so the MTA keeps the message and tries again. A recipient check interrupted by the shutdown is
     answered `421 4.2.1 service shutting down`.
   - The proxies close their listeners and client connections.
   - The admin API, the user API and the metrics endpoint stop accepting requests and let the
     requests in progress finish, within the time that steps 2 and 3 leave.
2. Sora waits up to **10 seconds** for every listener to close. It logs `All server listeners closed`,
   or `Server shutdown timeout reached after 10 seconds`.
3. Sora logs `Waiting for active connections to finish` and waits a fixed **3 seconds**, then logs
   `Shutdown grace period complete - releasing database resources`.
4. Background workers stop, in this order: relay worker, uploader, FTS worker, purge worker, cleaner,
   metrics collector, health checks. Each logs a line such as `Uploader: worker stopped`. Uploads in
   flight are abandoned; they stay queued and run again after the restart.
5. The node leaves the cluster, if there is one (it waits up to 5 seconds for the other nodes to
   hear it). Then the local cache, the affinity manager, the auth cache and the database pools close.
6. Sora exits with status 0.

A shutdown usually takes between 3 and 15 seconds, plus up to 5 seconds to leave a cluster. The
workers in step 4 have no time limit of their own; they end quickly because every worker is told to
stop at step 1.

Sessions that are still open after step 3 end when the process exits. Clients see the connection
drop and reconnect.

A second SIGINT or SIGTERM does not speed up a shutdown: Sora ignores it. SIGKILL ends the process at
once. Under systemd, `TimeoutStopSec` decides when that happens ([Service files](#8-service-files)).

### Killed or crashed

SIGKILL, a panic or a power loss skip all of the above. Nothing that was committed is lost: message
bodies waiting for S3 are files in the uploader spool with a row in `pending_uploads`, and relay
messages are files in the relay queue. Both are picked up by the next start of the same node. A
relay message that was being sent is moved from `processing/` back to `pending/` at startup and is
sent again, so a crash can cause one duplicate redirect or vacation reply.

---

## 5. What a restart loses and keeps

A restart, planned or not, **loses**:

- **Every open session.** IMAP clients (including IDLE) get a BYE and reconnect. POP3 sessions that
  had not reached `QUIT` lose the `DELE` commands they sent: POP3 applies deletions only at `QUIT`.
  LMTP transactions without a final answer are retried by the MTA. ManageSieve sessions are short and
  lose nothing that was saved.
- **In-memory state:** login lookup caches, auth rate-limit counters and blocks, search rate limits,
  connection counts. In a cluster, the other nodes keep the per-user proxy connection counts
  ([CLUSTER.md](CLUSTER.md)).
- **Proxy affinity** held in this node's memory, unless `[cluster.affinity] cache_path` is set.
- **Uploads and relay deliveries in flight.** They are retried after the start.

A restart **keeps** everything on disk and in the shared stores:

- PostgreSQL and S3: all accounts, mailboxes, messages and scripts.
- The **uploader spool**: message bodies that were accepted but are not in S3 yet. The node uploads
  them after the restart, as long as it starts with the same `[uploader] path` and the same instance
  ID ([Node identity](#9-node-identity)).
- The **relay queue**.
- The **local cache**, the **auth cache**, the **affinity cache** file and the Let's Encrypt fallback
  directory.

This only holds if those paths survive a restart. The defaults for the spool, the cache and the auth
cache are under `/tmp/sora`, which many systems clear at boot. Always set `[uploader] path` (and the
other paths) to a directory that persists
([What Sora writes to local disk](#6-what-sora-writes-to-local-disk)).

---

## 6. What Sora writes to local disk

| What | Key | Default | Written when | Contents | Can it be lost? |
|---|---|---|---|---|---|
| Upload spool | `[uploader] path` | `/tmp/sora/uploads` | The node has an `imap`, `pop3` or `lmtp` server | One file per message body not yet in S3, at `<path>/<account_id>/<content_hash>`. Written to a `.tmp` name, synced, then renamed. | **No.** Until a body is in S3, this file is its only copy. |
| Local cache | `[local_cache] path` | `/tmp/sora/cache` | Same | Bodies in `<path>/data/`, 256 SQLite index files `cache_index_00.db` to `cache_index_ff.db` (WAL mode), and `.sora_warmup_state`, written when an IMAP server stops with cache warmup on (the default). | Yes. Sora fetches bodies from S3 again. |
| Auth cache | `[auth_cache] path` | `/tmp/sora/auth_cache.db` | `[auth_cache] enabled = true` | SQLite file (mode 0600, WAL) with addresses, account IDs and password hashes. Its parent directory is created. | Yes. It refills from the database. Treat it as secret: it holds password hashes. |
| Affinity cache | `[cluster.affinity] cache_path` | none (off) | Cluster and `[cluster.affinity]` enabled, and `cache_path` set | SQLite file (mode 0600, WAL) with user-to-backend affinity. | Yes. Users are routed afresh. |
| Relay queue | `[relay.queue] path` | `/var/spool/sora/relay` | `[relay] type` is set | `pending/`, `processing/` and `failed/` directories with outgoing Sieve redirects and vacation replies. | Losing `pending/` loses those messages. |
| Let's Encrypt fallback | `[tls.letsencrypt] fallback_dir` | `/var/lib/sora/certs` | `[tls] provider = "letsencrypt"`, unless `enable_fallback = false` | A local copy of the certificates in S3, including private keys (directory mode 0700). | Yes. It is a mirror of the S3 store. |
| Log file | `[logging] output` | none (stderr) | `output` is a file path | Log lines, mode 0644, appended. The directory must exist. | Your choice. |

`sora-admin` writes one more file: `sora-maildir.db`, a SQLite cache, in each maildir it imports
([IMPORT_EXPORT.md](IMPORT_EXPORT.md)).

Advice:

- Keep the spool on a durable disk that survives reboots, not on `tmpfs`. Watch its size: if the disk
  fills, LMTP answers `452 4.3.1` and the MTA retries. `[uploader] max_staging_size` caps the spool
  on purpose ([STORAGE.md](STORAGE.md)).
- Put the spool and the cache on the same filesystem. After an upload, Sora moves the file into the
  cache with a rename; across filesystems it has to copy it.
- Two Sora processes on one host need separate spool and cache paths, and separate
  `[uploader] instance_id` values ([Node identity](#9-node-identity)).

---

## 7. Logging

Logging is set in `[logging]`. All three keys are read once, at startup.

| Key | Values | Default |
|---|---|---|
| `output` | `stderr`, `stdout`, `syslog`, or a file path | `stderr` |
| `format` | `console` or `json` | `console` |
| `level` | `debug`, `info`, `warn` (or `warning`), `error` | `info` |

An unknown `level` is treated as `info`. Changing any of the three needs a restart.

### Formats

`console` is Go's `slog` text format: one line per event, `key=value` pairs, values with spaces
quoted.

```
time=2026-01-15T10:00:00.000Z level=INFO msg="SIGHUP received - reloading configuration" config=/etc/sora/config.toml
```

`json` writes one JSON object per line with the keys `time`, `level` and `msg` plus the event's own
keys. Use it when a log collector parses the lines.

### Outputs

- **`stderr` and `stdout`.** Under systemd both end up in the journal: `journalctl -u sora`.
- **A file path.** Sora opens the file in append mode and creates it (mode 0644, less the umask) if
  needed. It does not create the directory. If the file cannot be opened, Sora prints
  `WARNING: failed to open log file '...'. Falling back to stderr.` and logs to stderr. Sora reopens
  the file on SIGHUP, see [Rotating the log file](#rotating-the-log-file).
- **`syslog`.** Sora sends to the local syslog daemon (its Unix socket), with facility `daemon` and
  tag `sora`. There is no setting for a remote syslog server, another facility or another tag. The
  message is `<msg> key=value ...` in logfmt; `format` is ignored. The log level maps to the syslog
  severity (debug, info, warning, err). Carriage returns and line feeds inside a message are written
  as `\r` and `\n`, so a value cannot forge an extra line. If the syslog socket cannot be reached at
  startup, Sora prints `WARNING: failed to connect to syslog: ... Falling back to stderr.`

### What does not go through `[logging]`

A few things are always written to the process's standard error, whatever `output` says:

- Warnings from reading the config at startup (unknown keys, duplicate keys) and the startup errors
  that happen before logging is set up ([Startup](#messages-that-stop-startup)).
- A Go panic and its stack trace.

Under systemd these are in the journal even when Sora logs to a file. Check both when Sora does not
start.

Errors after logging is set up, and protocol traces from `debug = true` on a `[[server]]`, go to the
log file when `output` is a file path, and to standard error or standard output otherwise. They are
plain text, not `slog` lines.

### Rotating the log file

With `output` set to a file, rotate it with logrotate (Linux) or newsyslog (FreeBSD). Move the file
aside, then send SIGHUP; Sora opens a new file under the old name. A logrotate rule:

```
/var/log/sora/sora.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 sora sora
    postrotate
        systemctl reload sora.service
    endscript
}
```

`delaycompress` leaves the newest rotated file uncompressed until the next run, so lines Sora writes
between the move and the signal are not lost. Remember that SIGHUP also reloads the config
([SIGHUP](#sighup)).

With `stderr` and journald, the journal does the rotation and nothing else is needed.

---

## 8. Service files

`dist/` has a systemd unit and a FreeBSD rc.d script.

### systemd: `dist/sora.service`

The unit, abridged:

```ini
[Unit]
Description=Sora Mail Server
Documentation=https://github.com/migadu/sora
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=sora
Group=sora
ExecStart=/usr/local/bin/sora --config /etc/sora/config.toml
ExecReload=/bin/kill -HUP $MAINPID
TimeoutStopSec=30
KillMode=mixed
KillSignal=SIGTERM
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/spool/sora /var/cache/sora /var/lib/sora /var/log/sora
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

What each part means for you:

- **User `sora`.** Create a system user and group named `sora`. The config file must be readable by
  that group, and so must every certificate and key file Sora loads.
- **`ExecReload`** sends SIGHUP: `systemctl reload sora` reopens the log and reloads the config
  ([SIGHUP](#sighup)).
- **`TimeoutStopSec=30`, `KillMode=mixed`.** systemd sends SIGTERM to Sora and, if it has not exited
  after 30 seconds, SIGKILL to every process of the unit. Sora's own shutdown waits at most 10
  seconds for its listeners plus a fixed 3 seconds, then stops its workers
  ([SIGINT and SIGTERM](#sigint-and-sigterm)), so 30 seconds leaves room.
- **`Restart=on-failure`, `RestartSec=5`.** A startup failure (status 1) is retried every 5 seconds.
  That suits a database that comes up later. For a config error, it repeats the same error until
  you fix it.
- **`ProtectSystem=strict`, `ReadWritePaths`.** The whole file system is read-only for Sora except
  `/var/spool/sora`, `/var/cache/sora`, `/var/lib/sora` and `/var/log/sora`. All four must exist
  before the unit starts; systemd refuses to start it if one is missing. Every path Sora writes
  must be under one of them:
  - set `[uploader] path` to a directory under `/var/spool/sora` (for example
    `/var/spool/sora/uploads`);
  - set `[local_cache] path` to a directory under `/var/cache/sora` (for example
    `/var/cache/sora/cache`), and `[auth_cache] path` too if you use it;
  - the relay queue default, `/var/spool/sora/relay`, already fits;
  - with Let's Encrypt, the default `fallback_dir`, `/var/lib/sora/certs`, already fits.
- **`AmbientCapabilities=CAP_NET_BIND_SERVICE`** lets the `sora` user bind ports below 1024 (25, 80,
  110, 143, 993, 995 and so on).
- **`LimitNOFILE=65536`.** Each client connection uses a file descriptor, and a proxy uses two.

To add something to the unit, use a drop-in, for example `systemctl edit sora` with:

```ini
[Service]
ReadWritePaths=/srv/sora
```

`ReadWritePaths=` in a drop-in adds to the list in the unit. Run `systemctl daemon-reload` after
editing the unit file itself.

### FreeBSD: `dist/sora.rc`

The rc.d script reads these `rc.conf` variables:

| Variable | Default |
|---|---|
| `sora_enable` | `NO` |
| `sora_user`, `sora_group` | `sora` |
| `sora_config` | `/usr/local/etc/sora/config.toml` |
| `sora_logdir` | `/var/log/sora` |
| `sora_spooldir` | `/var/spool/sora` |

Before it starts Sora, it creates `sora_logdir` and `sora_spooldir` (mode 0750, owned by the user).
It does not create a cache directory. `service sora reload` sends SIGHUP.

The script runs Sora under `daemon(8)`, which detaches it and writes the pid file
`/var/run/sora.pid`. `service sora start` returns once Sora is running, `status` reports its PID,
`stop` stops it and `reload` sends it SIGHUP. Set `[logging] output` to a file such as
`/var/log/sora/sora.log`; newsyslog uses the pid file to send SIGHUP after rotating the log.

---

## 9. Node identity

Every node has two names. They answer different questions and come from different places.

**The instance ID** is an internal key. Each spooled upload is leased to the instance that accepted
it, because the body is a file on that node's disk ([STORAGE.md](STORAGE.md)). The node also reports
its sessions under this ID for backend maintenance ([PROXY.md](PROXY.md)). It comes from, in order:

1. `[uploader] instance_id`, if set;
2. the operating system's hostname;
3. the fixed string `sora-unknown-host`, if the hostname cannot be read (logged as a warning).

`[cluster] node_id` does not change it. Sora logs it at startup as
`Resolved instance ID instance_id=...`.

Changing the instance ID strands the uploads queued under the old one: no node will upload them, and
the cleaner eventually deletes them along with their messages. This also happens when you rename a
host and leave `instance_id` unset, and when a container gets a new hostname at every start. Before
you change it, drain the node: stop new mail reaching it, wait until
`sora-admin uploader status` lists no pending uploads for the old ID under
"Pending Uploads by Instance", then restart under the new ID. In containers, set
`[uploader] instance_id` explicitly and keep the spool on a persistent volume.

**The mail hostname** is public. It is the name in protocol greetings, the `by` host in the
`Received:` header of every delivery, and the domain of the `Message-ID` of vacation replies. It is
always the operating system's hostname (or `sora-unknown-host.invalid` if that cannot be read). No
config key changes it, `cluster.node_id` included. Give the host a fully qualified name, such as
`mail.example.com`; Sora warns at startup when the name has no dot.

---

## 10. Database migrations

The schema is a numbered series of SQL migrations embedded in the binary (`db/migrations/`). Sora
keeps the applied version in the `schema_migrations` table. [DATABASE.md](DATABASE.md) describes the
schema, the migrations and the PostgreSQL requirements; this section covers how they run.

### At startup

Every `sora` process that connects to PostgreSQL applies pending migrations before it serves anyone.
It does this through the first host in `[database.write] hosts` that it can reach. If a migration
fails, the process does not start.

1. The process tries to take a migration lock in PostgreSQL. Only one process can hold it.
2. It reads `schema_migrations`. If the version is at or above the newest migration in its binary,
   it logs `Database: migrations are up to date` and carries on. This is also what an **older**
   binary does against a **newer** schema: it starts without complaint.
3. The process that holds the lock applies the pending migrations. It logs
   `Database: attempting to run migrations up to latest version`, one `MIGRATE` line per step,
   `Database: migrations are still actively running... please wait` every 30 seconds, and
   `Database: migration complete version=N` at the end. There is no time limit on this.
4. A process that starts while another one migrates logs
   `Database: another instance is currently running migrations. Waiting...` and checks the version
   every 5 seconds. It gives up after three times `[database] migration_timeout` (default `2m`, so
   6 minutes), with `timed out waiting for another instance to complete migrations`, and exits with
   status 1. Under systemd it is then restarted and waits again.

If a migration failed half-way, the version is marked dirty. The next process to take the lock stops
with `database is in a dirty migration state (version N). Manual intervention required`, and Sora
does not start. To fix it:

1. Stop every Sora process.
2. Read the log for the error, and the file `db/migrations/0000NN_*.up.sql` for that version. Most
   files run as one transaction, so nothing of a failed one stays; a file with its own
   `BEGIN`/`COMMIT` or a `CREATE INDEX CONCURRENTLY` can leave part of its work behind. Check in
   PostgreSQL which of its statements took effect.
3. Fix the cause. Then either finish the migration by hand and run
   `sora-admin --config PATH migrate force N`, or undo what it did and run `migrate force` with the
   number of the migration before it. The numbers have a gap (there is no `000032`), so use the
   previous file that exists.
4. Start Sora. After forcing the previous version, it applies migration N again.

[DATABASE.md](DATABASE.md) has more on failed and long migrations.

### With `sora-admin`

`sora-admin --config PATH migrate <subcommand>` connects through `[database.write]`, with the same
host and port rules as `sora`:

| Subcommand | What it does | Sora must be stopped? |
|---|---|---|
| `version` | Prints `Current migration version` and whether it is dirty. Plain read, no lock. | No |
| `up` | Applies every pending migration. | Yes, per the tool's help |
| `down [--limit N \| --all]` | Reverts migrations, one by default. | Yes |
| `force N` | Sets the version to N and clears the dirty flag. Runs no SQL. | Yes |

`sora-admin` does not apply migrations on its own: on a new database, start `sora` once or run
`migrate up` before other `sora-admin` commands.

Notes:

- Migrations create the `pg_trgm` and `btree_gin` extensions themselves. The database owner can do
  that without superuser rights on current PostgreSQL versions, because both extensions are trusted
  ([DATABASE.md](DATABASE.md)).
- Down migrations can delete data. For example, reverting `000055` drops the `backend_maintenance`
  table, and reverting `000057` deletes vacation records the older schema cannot hold. Read the
  `.down.sql` files before you run `migrate down`.

---

## 11. Upgrades and mixed-version windows

### One node

1. Read the release notes. Back up PostgreSQL ([Backups and restores](#13-backups-and-restores)).
2. Build the new binaries and copy them into place (for example `/usr/local/bin/sora` and
   `/usr/local/bin/sora-admin`). A running process keeps using the old binary until it restarts.
3. `systemctl restart sora`. The new process applies any migrations (step 9 of
   [Startup](#startup-order)) before it opens its listeners. Clients reconnect.
4. Check: `sora --version`, the `SORA application starting` line, `Database: migration complete` or
   `Database: migrations are up to date`, and `sora-admin --config PATH migrate version`.

A large migration can take a long time on a big `messages` table, and during that time the node
serves nobody. You can apply migrations ahead of the restart with `sora-admin migrate up` while Sora
is stopped, which keeps the same downtime but separates the two steps. [DATABASE.md](DATABASE.md)
describes migrations that need special handling.

### Several nodes

All nodes share one database, so the schema changes for every node at once, while the binaries
change one node at a time. Between the first and the last restart, old and new binaries run side by
side against the new schema. This is the mixed-version window.

1. Read the release notes for anything about ordering or about the mixed window. Back up PostgreSQL.
2. Upgrade one node first. Its start applies the migrations. Nodes that start at the same moment wait
   for it ([At startup](#at-startup)).
3. Upgrade the remaining nodes one at a time. On backends behind proxies, drain each one first with
   backend maintenance ([Taking a backend out of service](#12-taking-a-backend-out-of-service)), so
   no session is cut and its spool is empty when it stops.
4. Keep the window short. A behaviour that every node has to take part in is only complete once
   every node runs the new binary.

Sora does not check that the binaries in the window are compatible with each other or with the
schema: an older binary starts against a newer schema without a warning. Whether that is safe is a
property of each release, so the release notes are the place to look.

### Rolling back

- **Binary only.** Put the old binary back and restart. The old binary starts against the newer
  schema (it sees the version as up to date). This works when the release says the new schema is
  compatible with the old binary.
- **Schema too.** Stop every node, run `sora-admin --config PATH migrate down --limit N` for the
  migrations the new release added, then start the old binary. Read the `.down.sql` files first:
  some delete data ([With `sora-admin`](#with-sora-admin)).
- **Restore.** Restore the database backup taken before the upgrade
  ([Backups and restores](#13-backups-and-restores)). Mail delivered since then is lost from the
  database.

---

## 12. Taking a backend out of service

In a proxied setup, do not stop a backend without preparing it: bodies it accepted wait in its own spool until
it uploads them, and only it can. Put it in maintenance first:

```sh
sora-admin --config /etc/sora/config.toml backends maintenance on \
  --host backend2.example.com --reason "upgrade" --wait
```

Every proxy stops routing new sessions to it within `[backend_maintenance] poll_interval` (default
`5s`), closes its IMAP sessions gradually, and the backend itself refuses new sessions after
`refuse_after` (default `30s`). `--wait` returns once nothing is pending for its instance ID and the
backend reports no open session. Then stop it, do the work, start it, and run
`sora-admin --config ... backends maintenance off --host backend2.example.com`.

Proxies need database access to honor maintenance. [PROXY.md](PROXY.md) describes the mechanism in
full, and [ADMIN_CLI.md](ADMIN_CLI.md) the flags. Before you retire a backend for good, also check its
relay queue with `sora-admin relay stats` on that node.

A single server has no proxy to move users elsewhere: restart it and clients reconnect.

---

## 13. Backups and restores

Mail lives in three places, and each needs its own plan.

| What | Where | How to protect it |
|---|---|---|
| Everything except message bodies: accounts, passwords, aliases, mailboxes, flags, Sieve scripts, ACLs, and the full-text search vectors | PostgreSQL | Regular PostgreSQL backups (dumps, or base backups with WAL archiving). The search vectors are the only copy of the indexed text; they cannot be rebuilt without fetching every body again ([SEARCH.md](SEARCH.md)). |
| Message bodies | The S3 bucket in `[s3] bucket` | Your provider's versioning, replication or a bucket copy. |
| The body encryption key | `[s3] encryption_key`, with `encrypt = true` | Keep a copy apart from the bucket. Without it every encrypted body is unreadable. |
| Bodies not yet in S3 | The upload spool on each backend (`[uploader] path`) | A backup does not help much here: keep the spool on a durable disk and keep the upload queue short. Monitor it ([METRICS.md](METRICS.md)); `sora-admin uploader status` shows it. |
| Outgoing redirects and vacation replies | The relay queue (`[relay.queue] path`) | Durable disk; include it in host backups if you rely on it. |
| Configuration and secrets | The config file, TLS keys, API keys, JWT secrets, the cluster key | Your configuration management. |

The local cache, the auth cache, the affinity cache and the Let's Encrypt fallback directory can be
rebuilt and need no backup.

### Restoring PostgreSQL to an earlier point

The cleaner deletes a body from S3 only when every message that used it was expunged more than
`[cleanup] grace_period` ago (default 14 days) ([STORAGE.md](STORAGE.md)). So a database backup that
is younger than the grace period refers only to bodies that are still in the bucket. Accounts purged
through the admin API are the exception: their bodies are deleted at once.

After such a restore:

- Messages delivered after the backup are gone from the database. Their bodies stay in the bucket,
  unused.
- Messages expunged after the backup are visible again.
- IMAP clients that synchronized after the backup point may hold UIDs that the restored database
  hands out again for new mail. Such a client may need its account removed and added again.

---

## 14. Network: listeners and outbound connections

### Listeners

Sora listens only on the `addr` of each `[[server]]` block, plus:

- TCP port **80** on all addresses, when `[tls] provider = "letsencrypt"`, for HTTP-01 challenges. The
  address is fixed.
- The cluster's gossip port (default **7946**, TCP and UDP) on `[cluster] addr`, when the cluster is
  enabled ([CLUSTER.md](CLUSTER.md)).

Conventional ports for client-facing listeners are 143 (IMAP with STARTTLS), 993 (IMAP over TLS),
110 and 995 (POP3), 4190 (ManageSieve) and 24 (LMTP, usually bound to a private or loopback address).
Ports below 1024 need root or `CAP_NET_BIND_SERVICE`.

### Outbound connections

A host running Sora must be able to reach:

| Destination | Needed when | Config | Protocol |
|---|---|---|---|
| PostgreSQL write hosts | Any node with a database ([Startup](#startup-order), step 9), and `sora-admin` | `[database.write] hosts`, `port` | PostgreSQL, TCP 5432 by default; TLS with `tls = true` |
| PostgreSQL read hosts | `[database.read]` is set | `[database.read] hosts`, `port` | Same |
| S3 endpoint | Backends (`imap`, `pop3`, `lmtp`), and `sora-admin` commands that touch bodies | `[s3] endpoint` | HTTPS, or HTTP with `disable_tls = true` or an `http://` endpoint |
| Let's Encrypt | `[tls] provider = "letsencrypt"` | fixed: `https://acme-v02.api.letsencrypt.org/directory` | HTTPS |
| Certificate store | Same | `[tls.letsencrypt.s3] endpoint` (default `s3.amazonaws.com`), `bucket` | HTTPS, or HTTP with `disable_tls = true` |
| Relay | `[relay] type = "smtp"` or `"http"` | `smtp_host`, or `http_url` | SMTP (with optional TLS or STARTTLS), or HTTP(S) ([RELAY.md](RELAY.md)) |
| Remote lookup API | Proxies with `[server.remote_lookup] enabled = true` | `url` | HTTP(S) |
| Backends | Proxies | `remote_addrs`, `[[pool]]` members, hosts named by the lookup API | The proxied protocol ([PROXY.md](PROXY.md)) |
| Cluster peers | `[cluster] enabled = true` | `peers` | Gossip, TCP and UDP, port 7946 by default |
| Spam-training endpoint | `[spam_training] enabled = true` with an `endpoint` | `endpoint` | HTTP(S) ([RELAY.md](RELAY.md)) |
| Admin API | `sora-admin` commands that use it: `connections`, `affinity`, `stats`, `auth-cache`, `affinity-cache` and `health status --backends` | `[admin_cli] addr` | HTTP(S) |

DNS must work for every host name above. Proxies also re-resolve the names in `remote_addrs`
periodically ([PROXY.md](PROXY.md)).

---

## 15. Common questions

**Do I need a cluster to run one server?** No. `[cluster]` is off by default, and a single node needs
none of what it shares. See [CLUSTER.md](CLUSTER.md) for what it adds.

**How do I check the version of a running node?** Run the same binary with `--version`, or find the
`SORA application starting` line, which has `version`, `commit` and `built`.

**I changed the config and nothing happened.** Most settings need a restart. Check the
[SIGHUP](#sighup) tables, and look for `requires restart` in the log after the reload.

**Sora does not start and the journal is empty.** With `[logging] output` set to a file, errors after
step 6 of [Startup](#startup-order) are in that file.

**Can I delete the cache directory?** Yes, with Sora stopped. Do not delete the upload spool: it holds
bodies that are not in S3 yet.

**How do I rotate the log?** See [Rotating the log file](#rotating-the-log-file).

**My certificate was renewed on disk. Do I need a restart?** Yes, for certificate files. Let's
Encrypt certificates renew inside the process.
