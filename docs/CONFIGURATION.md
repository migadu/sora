# Sora Configuration Reference

This document describes Sora's configuration file as a whole. It covers how the `sora` binary
finds and reads the file, how values are written, what happens with defaults, unknown keys and
mistakes, which checks run at startup, how `[[server]]` blocks work, and which settings a `SIGHUP`
reloads. It then lists every section and every key the file can hold, with its type and default,
in one place.

It is for operators who write or review a Sora configuration, and for contributors who add a key.
The tables here say what a key is and what Sora does when it is absent. For the full meaning of a
key, follow the link to the topic document named at the top of each section.

The keys are defined in [config/](../config/) and read in [cmd/sora/main.go](../cmd/sora/main.go).
Where this document and [config.toml.example](../config.toml.example) disagree, this document is
the reference.

## Contents

1. [How Sora reads the file](#1-how-sora-reads-the-file)
2. [Writing values](#2-writing-values)
3. [Defaults](#3-defaults)
4. [Checks at startup](#4-checks-at-startup)
5. [Server blocks](#5-server-blocks)
6. [Reloading with SIGHUP](#6-reloading-with-sighup)
7. [Map of sections](#7-map-of-sections)
8. [Global keys and sections](#8-global-keys-and-sections)
9. [Keys of a `[[server]]` block](#9-keys-of-a-server-block)
10. [Named backend pools (`[[pool]]`)](#10-named-backend-pools-pool)

---

## 1. How Sora reads the file

### Command-line flags

| Flag | Effect |
|---|---|
| `-config <path>` | The configuration file. Default `config.toml`, relative to the working directory. `--config` works too. |
| `-version`, `-v` | Prints `sora version <version> (commit: <commit>, built at: <date>)` and exits with status 0. |
| `-h` | Prints the flag list and exits. |

`make build` writes the version, commit and date into the binary. A plain `go build` does not, and
`-version` then prints `sora version dev (commit: none, built at: unknown)`.

What happens when the file is missing depends on the path:

- If you pass no `-config` and `config.toml` does not exist, Sora logs
  `Default configuration file not found - using application defaults` and goes on with the built-in
  defaults. The defaults contain no `[[server]]` block, so startup then stops with
  `no servers configured` (see [section 4](#4-checks-at-startup)).
- If you name a file with `-config` and it does not exist, Sora stops with
  `ERROR: configuration file '<path>' not found`.

### The parser

The file is TOML, read with the `github.com/BurntSushi/toml` library
([config/config.go](../config/config.go), `LoadConfigFromFile`). Sora starts from its built-in
defaults (`config.NewDefaultConfig`) and lays the file over them, so a key you leave out keeps its
default. After parsing, Sora trims leading and trailing spaces from every string value, so
`name = " imap "` is read as `imap`.

`sora-admin` reads the same file with the same loader (see [ADMIN_CLI.md](ADMIN_CLI.md)). It uses
only some sections (`[database]`, `[s3]`, `[local_cache]`, `[uploader]`, `[cleanup]`,
`[shared_mailboxes]`, `[tls]`, `[admin_cli]`, `[relay]`, `[sieve]`, `[cluster]` and the
`[[server]]` blocks), and it starts from the same built-in defaults.

### Unknown keys

A key Sora does not know is ignored, and Sora prints a warning that names it:

```
WARNING: Configuration file 'config.toml' contains unknown keys that will be ignored:
WARNING:   - servers.imap
WARNING:   - servers.imap.start
WARNING:   - servers.imap.addr
WARNING: These keys may be typos or deprecated settings. Please review your configuration.
```

An unknown table is listed together with each key in it.

The key keeps its default, so a misspelt key silently does nothing. Read these warnings after every
change. At startup they are printed to standard error, before logging is set up, so they do not
reach a log file named in `[logging] output`. On a `SIGHUP` reload they go through the logger.

### Duplicate keys

A key written twice in the same table is normally a TOML error. Sora is lenient here: it prints a
warning for each duplicate, keeps the first occurrence, comments out the others and parses the file
again.

```
WARNING: Configuration file 'config.toml' contains duplicate keys: ...
WARNING: Ignoring duplicate entries. Only the first occurrence of each key will be used.
WARNING: Please fix your configuration file to remove duplicates.
WARNING: Duplicate key 'server.addr' found at line 12 (first occurrence at line 9). Ignoring duplicate.
```

Lines printed by the standard logger start with a date and time, left out in these examples.

Each `[[server]]` or `[[pool]]` block is a new array element, so the same key in two blocks is not a
duplicate.

### Syntax errors and wrong types

Any other parse error stops startup with exit status 1. Sora adds a hint for common mistakes:

- a boolean written as `t`, `f`, `yes`, `no`, `1` or `0` (TOML wants `true` or `false`);
- other syntax errors (unbalanced brackets, unquoted strings).

A value of the wrong type for a known key (for example a string where a number is expected) is also
a parse error.

---

## 2. Writing values

### Durations

Duration keys are strings in Go duration syntax: a number and a unit, such as `"300ms"`,
`"30s"`, `"5m"`, `"2h"` or `"1h30m"`. Valid units are `ns`, `us`, `ms`, `s`, `m` and `h`. `"0"` is
zero.

Sora adds one unit: a whole number of days, written `"Nd"`, such as `"14d"` or `"30d"`
([helpers/parsers.go](../helpers/parsers.go), `ParseDuration`). Only the plain form works. `"1d12h"`
and `"1.5d"` are rejected.

What happens with a value that does not parse depends on the key. Some keys stop startup (for
example `[uploader] max_staging_size` or `[relay.queue] cleanup_interval`), and many fall back to
their default with a warning in the log. Check the log after a change.

### Sizes

Size keys are strings: a whole number and a unit, `b`, `kb`, `mb` or `gb`, in any case, with
optional space: `"512kb"`, `"25MB"`, `"1 gb"`. A plain number such as `"1048576"` is bytes. Units
are powers of 1024 (`"1kb"` is 1024 bytes). Fractions (`"1.5gb"`) and units without `b` (`"10m"`)
are rejected.

### Ports

`port` in `[database.write]` and `[database.read]`, and `remote_port` in a `[[server]]` block and in
`[server.remote_lookup]`, accept a number or a string: `5432` and `"5432"` are the same.

### Lists

Lists are TOML arrays: `trusted_networks = ["192.0.2.10/32", "192.0.2.11"]`. Networks are CIDR
blocks or bare IP addresses.

---

## 3. Defaults

A default in this document is what Sora does when the key is absent. It comes from
`config.NewDefaultConfig`, from a `Get...()` helper in [config/](../config/), or from the code that
uses the value. The values in [config.toml.example](../config.toml.example) are examples, and some of
them differ from the defaults.

Things to know:

- **Booleans default to `false`.** TOML cannot tell "absent" from "false" for most keys, so a
  boolean you leave out is `false`. A few keys default to `true` when absent:
  `remote_health_checks`, `[server.remote_lookup] remote_tls_verify`,
  `[[pool]] remote_tls_verify`, `[tls.letsencrypt] enable_fallback`, the `metrics` keys
  `enable_domain_metrics` and `hash_usernames`, `[server.lookup_cache] enabled` on the server types
  that use the cache by default, and `[admin_cli] insecure_skip_verify` (which defaults to "skip
  only for a loopback address").
- **Zero often means "use the default".** For many number keys, `0` or a negative value means the
  default, not "off". The tables say where `0` means "no limit" or "disabled" instead.
- **A table you write changes only the keys it names.** In a `[server.lookup_cache]` table, for
  example, the keys you leave out keep their defaults, and the cache stays on unless the table says
  `enabled = false`. See [9.10](#910-lookup-cache-serverlookup_cache).
- **A database endpoint you do not write means "no database".** Without a `[database.write]` (or
  `[database.read]`) section in the file, Sora has no such endpoint. This is how a proxy-only node
  runs without one. A node that needs a database and has none stops with `[database]: server
  "<name>" (<type>) needs the database, but it is not configured in [database.write] or
  [database.read]`.

---

## 4. Checks at startup

After parsing, Sora checks the configuration before it opens any listener. Each failed check below
stops startup with exit status 1. The checks on the file itself run before logging is set up, so
they write a line of the form `[ERROR] <date> <time> ERROR: invalid configuration - <what>: <reason>`
to standard error, one for each problem the file has. The `[timeout_scheduler]` check runs after it,
so its failure is an ERROR record of the `[logging]` output, in its format.

| Check | Message |
|---|---|
| A server has a type that is not in the list in [section 5](#5-server-blocks) | `invalid server type '<type>', must be one of: imap, lmtp, ...` |
| `master_username` is set and `master_password` is empty | `server "<name>": master_username is set but master_password is empty; refusing to start ...` |
| `master_sasl_username` is set and `master_sasl_password` is empty | `server "<name>": master_sasl_username is set but master_sasl_password is empty; refusing to start ...` |
| `[[pool]]` blocks are inconsistent (see [section 10](#10-named-backend-pools-pool)) | `[[pool]]: ...` |
| A server has `proxy_protocol = true` and `[servers] trusted_networks` is empty | `trusted_networks: proxy_protocol is enabled on server(s) <names> but [servers] trusted_networks is empty; ...` |
| Two servers have the same `name` | `duplicate server name '<name>' found. Each server must have a unique name` |
| Two servers have the same `addr` string | `duplicate server address '<addr>' found. Server '<a>' and '<b>' cannot bind to the same address` |
| A `[[server]]` block lacks `type`, `name` or `addr` | for example `server address is required` |
| No server is configured | `no servers configured. Please configure at least one server in a [[server]] section` |
| An IMAP, POP3 or LMTP server is configured, or an `http_user_api` server with any `[s3]` connection setting, and `[s3] bucket` or `endpoint` is empty, or `timeout` is not a duration | `[s3]: bucket is required ...`, `[s3]: endpoint is required ...` or `[s3]: invalid timeout "<value>": ...` |
| A server that needs the database is configured and there is no database endpoint (see [section 3](#3-defaults)) | `[database]: server "<name>" (<type>) needs the database, but it is not configured in [database.write] or [database.read]` |
| `[cluster] enabled = true` and `addr` is not an IP address other than `0.0.0.0` or `::`, or `secret_key` is missing or not the base64 of 32 bytes (see [CLUSTER.md](CLUSTER.md)) | `[cluster]: cluster addr '<host>' must be a specific IP address reachable from other nodes, ...`, `[cluster]: cluster secret_key is required when cluster mode is enabled ...`, `[cluster]: failed to decode cluster secret_key: ...` or `[cluster]: cluster secret_key must be 32 bytes (got <n> bytes)` |
| `[servers] trusted_networks` has an entry that is neither an IP address nor a CIDR block | names the invalid entry |
| A server's `auth_rate_limit.exempt_networks` has an entry that is neither an IP address nor a CIDR block | `server "<name>": auth_rate_limit.exempt_networks has entries that are neither an IP address nor a CIDR: [...]` |
| A server's `auth_rate_limit` has a negative count or duration, or a `delay_multiplier` that is negative, `nan` or `inf` | `server "<name>": auth_rate_limit.<key> must not be negative, got <value>` or `server "<name>": auth_rate_limit.delay_multiplier must be a finite number, got <value>` |
| An `lmtp` or `http_admin_api` server has a `limits.redirect_rate_window` of zero or less | `server "<name>": limits.redirect_rate_window must be positive, got "<value>" (set limits.redirect_rate_limit = 0 to disable the limit)` |
| A proxy server has a `remote_port` that is not a port number | `server "<name>": invalid remote_port: ...` |
| A proxy server has `remote_lookup` enabled without a `url`; with a `url` that is not an absolute `http://` or `https://` URL with a host, has `$email` or `$ip` in the host, or uses `http://` to a host other than `localhost` or a loopback address (see [PROXY.md section 4.1](PROXY.md#41-the-request)); or with a `timeout`, `remote_port`, `circuit_breaker` or `transport` value that does not parse | `server "<name>": remote_lookup.url is required when remote_lookup is enabled`, `server "<name>": remote_lookup.url must use https:// for non-loopback hosts ...` or `server "<name>": invalid remote_lookup.<key>: ...` |
| A `metrics` server's `path` does not begin with `/`, or is not a pattern Go's `http.ServeMux` accepts | `server "<name>": metrics path "<path>" must begin with '/'` or `server "<name>": invalid metrics path "<path>": ...` |
| `[relay] type` is set to something other than `"smtp"` or `"http"` | `unsupported [relay] type ...` |
| `[relay] type = "smtp"` and `smtp_host` is not a `host:port` that can be dialed, or `type = "http"` and `http_url` is not an absolute `http://` or `https://` URL with a host and, if it has one, a valid port | `[relay] type "smtp" requires smtp_host as host:port`, `[relay] smtp_host "<value>" must be host:port: ...` (or `has no host`, `has no valid host`, `has no valid port`), `[relay] type "http" requires http_url` or `[relay] http_url "<value>" ...` |
| `[relay.queue] worker_interval` is `0` or less, or `failed_retention` is negative, with `[relay]` configured | `[relay.queue]: worker_interval must be positive, got ...` or `[relay.queue]: failed_retention must not be negative, got ...` |
| `[relay.queue] circuit_breaker_timeout`, `cleanup_interval` or `failed_retention` is not a duration, with `[relay]` configured | `[relay.queue]: invalid <key> "<value>": ...` |
| An IMAP, POP3 or LMTP server is configured and `[cleanup]` has a negative `grace_period`, `max_age_restriction`, `fts_retention` or `health_status_retention`, or an `instance_liveness_threshold` of zero or less | `[cleanup]: <key> must not be negative, got "<value>"` or `[cleanup]: instance_liveness_threshold must be positive, got "<value>"` |
| An IMAP, POP3 or LMTP server is configured and `[uploader]` has a `batch_size`, `concurrency` or `max_attempts` of zero or less, or a `cleanup_grace_period` of zero or less or that is not a duration | `[uploader] <key> must be positive, got <n>`, `[uploader] cleanup_grace_period must be positive, got "<value>"` or `[uploader] cleanup_grace_period: <parse error>` |
| `[shared_mailboxes] enabled = true` and `namespace_prefix` is not a mailbox name followed by `/` (for example `""`, `"Shared"` or `"Shared//"`), or is `INBOX/` in any letter case | `[shared_mailboxes]: namespace_prefix "<value>" must be a mailbox name followed by the hierarchy delimiter "/", such as "Shared/"` or `[shared_mailboxes]: namespace_prefix "<value>" conflicts with the reserved personal INBOX` |
| `[timeout_scheduler] shard_count` is below -1 | `msg="Fatal error" operation="initialize timeout scheduler" error="invalid shard count: <n> (must be >= -1)"` |

The address check compares the strings, so `":143"` and `"0.0.0.0:143"` pass it and fail later when
the second listener cannot bind.

These conditions only log, and startup continues:

- `[sieve] enabled_extensions` names an extension the engine does not support. The name is dropped.
- `trusted_networks` is empty (an INFO line explains what that disables), or it contains a whole
  private range such as `10.0.0.0/8` (a WARN line).
- A key is set on a server type it does not apply to, for example `remote_addrs` on an `imap`
  server, or `tls_use_starttls` without `tls = true`. Sora logs `WARNING: Server <name> (type: <type>)
  has '<key>' configured, but ...`.
- IMAP, POP3 or ManageSieve (or their proxies) allow plaintext authentication on a publicly
  reachable address: `plaintext authentication is allowed without TLS on a publicly reachable
  address`. Configure TLS to clear it.
- A `metrics` server on a publicly reachable address has neither `allowed_hosts` nor `api_key`:
  `metrics endpoint is served without access control on a publicly reachable address; set
  allowed_hosts and/or api_key`.
- The host name is not fully qualified: `Mail hostname is not fully qualified`. Sora uses the host
  name in greetings and in the `Received` header.

Later steps can still fail, for example a TLS certificate that cannot be read, or a database that
cannot be reached. Those are covered in the topic documents.

`sora-admin config validate` runs every check in this list but the `[timeout_scheduler]` one,
without starting anything. See [ADMIN_CLI.md](ADMIN_CLI.md).

---

## 5. Server blocks

Every listener is one `[[server]]` block, a TOML array of tables. Each block needs three keys:

| Key | Meaning |
|---|---|
| `type` | What the listener serves. One of the types below. |
| `name` | A name, unique in the file. It appears in logs, in metric labels (`server_name`) and in the reload report. |
| `addr` | The listen address, such as `":143"` or `"192.0.2.10:993"`. |

A block that lacks any of the three stops startup ([section 4](#4-checks-at-startup)).

You can configure several servers of the same type, for example one IMAP listener on 143 with
STARTTLS and one on 993 with implicit TLS. Every block reads only the keys that apply to its type.

| `type` | Serves | Main reference |
|---|---|---|
| `imap` | IMAP to mail clients | [PROTOCOLS.md](PROTOCOLS.md) |
| `pop3` | POP3 to mail clients | [PROTOCOLS.md](PROTOCOLS.md) |
| `lmtp` | LMTP, the protocol your mail transfer agent uses to hand messages to Sora | [PROTOCOLS.md](PROTOCOLS.md) |
| `managesieve` | ManageSieve, for clients that edit Sieve filters | [PROTOCOLS.md](PROTOCOLS.md), [SIEVE.md](SIEVE.md) |
| `imap_proxy`, `pop3_proxy`, `lmtp_proxy`, `managesieve_proxy` | The same protocols, forwarded to a backend chosen per user | [PROXY.md](PROXY.md) |
| `http_admin_api` | The administration HTTP API | [ADMIN_API.md](ADMIN_API.md) |
| `http_user_api` | The user HTTP API (JWT login) | [USER_API.md](USER_API.md) |
| `user_api_proxy` | A proxy for the user HTTP API | [USER_API.md](USER_API.md) |
| `metrics` | The Prometheus metrics endpoint | [METRICS.md](METRICS.md) |

Some servers start only when a key is set. An `http_admin_api` block without `api_key`, and an
`http_user_api` or `user_api_proxy` block without `jwt_secret`, are skipped with an INFO line such as
`HTTP Admin API server enabled but no API key configured - skipping`.

The server types decide what else Sora starts:

- `imap`, `pop3` or `lmtp` start the mail storage services: the S3 client, the local cache, the
  uploader, the cleaner, the purge worker and the full-text search worker. They need `[s3]` and a
  database. An `http_user_api` server also uses the S3 client, to serve message bodies.
- Sora connects to the database when the node runs a server that reads it: an `imap`, `pop3`,
  `lmtp` or `managesieve` server, an `http_admin_api` or `http_user_api` server, or a proxy that
  checks passwords in the database (no remote lookup, or `lookup_local_users = true`). A node whose
  only servers are proxies that use remote lookup needs no database.
- Without any database endpoint, Sora logs `Database not configured - forcing proxy-only mode
  (lookup_local_users will be treated as false)`.

### The `[servers]` table

`[servers]` (plural, a plain table) is not a list of servers. It holds one key, `trusted_networks`,
that every server reads (see [8.17](#817-trusted-networks-servers)). Some configuration files
define servers as `[servers.imap]`, `[servers.pop3]` and so on, with `start = true`. Sora does not
read those tables: it warns about their keys as unknown and, without a `[[server]]` block, refuses to
start. Rewrite each one as a `[[server]]` block with `type`, `name` and `addr`.

---

## 6. Reloading with SIGHUP

`SIGHUP` does three things, in this order ([cmd/sora/main.go](../cmd/sora/main.go)):

1. It reopens the log file, when `[logging] output` is a file path, so log rotation works.
2. It reads the configuration file again. If the file does not parse, Sora logs
   `Config reload failed - keeping current config` and changes nothing.
3. It hands each running server its own `[[server]]` block from the new file, matched by `name`. The
   server applies the settings it can change at runtime. New sessions use the new values. Sessions
   that are already open keep the values they started with.

Before applying a block, Sora runs the same per-server check as at startup (type, master passwords).
A block that fails it is skipped with `Skipping reload: invalid new server config`, and that server
keeps its old settings.

Only the settings in this table reload:

| Server type | Settings applied on SIGHUP |
|---|---|
| `imap`, `pop3` | `timeouts.command_timeout`, `timeouts.absolute_session_timeout`, `timeouts.min_bytes_per_minute`, `limits.session_memory_limit`, `master_sasl_username`, `master_sasl_password`, `master_sasl_allowed_networks` |
| `managesieve` | `timeouts.command_timeout`, `timeouts.absolute_session_timeout`, `timeouts.min_bytes_per_minute`, `max_script_size`, `master_sasl_username`, `master_sasl_password`, `master_sasl_allowed_networks` |
| `lmtp` | `max_message_size` |
| `imap_proxy` | `limits.max_auth_errors`, `auth_idle_timeout`, `timeouts.command_timeout`, `timeouts.absolute_session_timeout`, `timeouts.min_bytes_per_minute`, `master_sasl_username`, `master_sasl_password` |
| `pop3_proxy`, `managesieve_proxy` | the `imap_proxy` list, plus `debug` |
| `lmtp_proxy` | `timeouts.absolute_session_timeout`, `max_message_size` |
| `http_admin_api` | `api_key`, `read_only_api_key`, `allowed_hosts` |
| `http_user_api` | `jwt_secret`, `allowed_origins`, `allowed_hosts` |
| `user_api_proxy` | `jwt_secret`, `allowed_origins` |
| `metrics` | nothing |

A server that applied a change logs it, for example `IMAP config reloaded` with the list of updated
keys. For every other setting in a server's block that differs from the value the server started
with, Sora logs:

```
Config reload: server settings changed but require restart to take effect  server=<name> fields=[...]
```

The `metrics` server does not take part in reloads, so a change to its block is not reported.

Global sections never reload. For these, Sora logs that the change needs a restart:

| Setting | Log line |
|---|---|
| `[logging] level` | `Config reload: logging.level changed but requires restart to take effect` |
| `[cleanup]` | `Config reload: [cleanup] changed but requires restart to take effect` |
| `[shared_mailboxes]` | `Config reload: [shared_mailboxes] changed but requires restart to take effect` |
| `[sieve]` | `Config reload: [sieve] changed but requires restart to take effect` |
| `[backend_maintenance]` | `Config reload: [backend_maintenance] changed but requires restart to take effect` |
| `[metadata]` | `Config reload: [metadata] changed but requires restart to take effect` |
| `[servers] trusted_networks` | WARN `Config reload: servers.trusted_networks changed but requires restart to take effect; ...` |

Every other global setting also needs a restart, and Sora reports a change to it the same way:
`[logging] output` and `format`, `[database]`, `[s3]`, `[local_cache]`, `[uploader]`, `[tls]`,
`[cluster]`, `[auth_cache]`, `[relay]`, `[spam_training]`, `[timeout_scheduler]`, `bcrypt_cost` and
the `[[pool]]` blocks.

Adding, removing or renaming a `[[server]]` block also needs a restart, and Sora reports added and
removed blocks. A new block is not started, and a running server whose block was removed or renamed
keeps running with its old settings.

The global checks of [section 4](#4-checks-at-startup) (pools, `trusted_networks` against
`proxy_protocol`, server names and addresses) do not run on a reload.

How to send the signal, and how shutdown works, is in [OPERATIONS.md](OPERATIONS.md).

---

## 7. Map of sections

| Section | What it is for | Reference |
|---|---|---|
| top-level `bcrypt_cost` | Cost of new bcrypt password hashes | [8.1](#81-top-level-keys), [AUTHENTICATION.md](AUTHENTICATION.md) |
| `[logging]` | Where logs go, format and level | [8.2](#82-logging-logging), [OPERATIONS.md](OPERATIONS.md) |
| `[database]`, `[database.write]`, `[database.read]` | PostgreSQL | [8.3](#83-database-database), [DATABASE.md](DATABASE.md) |
| `[s3]` | Object storage for message bodies | [8.4](#84-object-storage-s3), [STORAGE.md](STORAGE.md) |
| `[local_cache]` | Local disk cache of message bodies | [8.5](#85-local-cache-local_cache), [STORAGE.md](STORAGE.md) |
| `[uploader]` | Staging and upload of new bodies to S3 | [8.6](#86-uploader-uploader), [STORAGE.md](STORAGE.md) |
| `[cleanup]` | Deletion, retention and the purge worker | [8.7](#87-cleaner-cleanup), [STORAGE.md](STORAGE.md), [SEARCH.md](SEARCH.md) |
| `[metadata]` | Limits of IMAP METADATA | [8.8](#88-imap-metadata-limits-metadata), [PROTOCOLS.md](PROTOCOLS.md) |
| `[shared_mailboxes]` | Shared folders and ACLs | [8.9](#89-shared-mailboxes-shared_mailboxes), [SHARED_MAILBOXES.md](SHARED_MAILBOXES.md) |
| `[sieve]` | Sieve extensions and execution budget | [8.10](#810-sieve-sieve), [SIEVE.md](SIEVE.md) |
| `[relay]`, `[relay.queue]` | Outbound relay for redirect and vacation | [8.11](#811-relay-relay-and-relayqueue), [RELAY.md](RELAY.md) |
| `[spam_training]` | Spam filter training on moves to and from Junk | [8.12](#812-spam-training-spam_training), [RELAY.md](RELAY.md) |
| `[tls]`, `[tls.letsencrypt]`, `[tls.letsencrypt.s3]` | Shared certificates, Let's Encrypt | [8.13](#813-tls-tls), [TLS.md](TLS.md) |
| `[cluster]`, `[cluster.affinity]` | Gossip cluster | [8.14](#814-cluster-cluster), [CLUSTER.md](CLUSTER.md) |
| `[auth_cache]` | Persistent login cache for proxies | [8.15](#815-persistent-auth-cache-auth_cache), [PROXY.md](PROXY.md) |
| `[backend_maintenance]` | How proxies drain backends in maintenance | [8.16](#816-backend-maintenance-backend_maintenance), [PROXY.md](PROXY.md) |
| `[servers]` | `trusted_networks` | [8.17](#817-trusted-networks-servers), [SECURITY.md](SECURITY.md) |
| `[timeout_scheduler]` | Connection timeout checker | [8.18](#818-timeout-scheduler-timeout_scheduler) |
| `[admin_cli]` | How `sora-admin` reaches the admin API | [8.19](#819-admin-tool-admin_cli), [ADMIN_CLI.md](ADMIN_CLI.md) |
| `[[server]]` | One block per listener | [section 9](#9-keys-of-a-server-block) |
| `[[pool]]` | Named groups of backends for proxies | [section 10](#10-named-backend-pools-pool), [PROXY.md](PROXY.md) |

---

## 8. Global keys and sections

### 8.1 Top-level keys

| Key | Type | Default | Meaning |
|---|---|---|---|
| `bcrypt_cost` | integer | `12` | Cost of bcrypt hashes Sora creates. Clamped to 10..14. See [AUTHENTICATION.md](AUTHENTICATION.md). |

Write it before the first table header, or TOML puts it inside that table.

### 8.2 Logging (`[logging]`)

| Key | Type | Default | Meaning |
|---|---|---|---|
| `output` | string | `"stderr"` | `"stderr"`, `"stdout"`, `"syslog"`, or any other value, which is taken as a file path. |
| `format` | string | `"console"` | `"json"` for one JSON object per line. Any other value gives text lines (`time=... level=... msg=... key=value`). Ignored for `syslog`. |
| `level` | string | `"info"` | `"debug"`, `"info"`, `"warn"` (or `"warning"`), `"error"`. Any other value means `info`. |

Details:

- A file path is opened for appending and created with mode 0644 if missing. Its directory must
  exist. If the file cannot be opened, Sora prints a warning and logs to standard error.
- `syslog` sends to the local syslog daemon with facility `daemon` and tag `sora`. Each line is the
  message followed by `key=value` pairs. Line breaks in values are escaped. If syslog is not
  reachable, Sora logs to standard error.
- `SIGHUP` reopens the log file. It does not change `output`, `format` or `level`.
- `debug = true` in a `[[server]]` block adds that server's debug output. See
  [9.1](#91-keys-every-server-reads).

### 8.3 Database (`[database]`)

See [DATABASE.md](DATABASE.md) for the meaning of each key.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `debug` | bool | `false` | Log SQL queries. |
| `query_timeout` | duration | `"30s"` | Default timeout of a query. |
| `search_timeout` | duration | `"1m"` | Timeout of search queries. |
| `write_timeout` | duration | `"15s"` | Timeout of write operations. |
| `lock_timeout` | duration | `"10s"` | How long a write waits for a row lock. `"0"` disables it. |
| `migration_timeout` | duration | `"2m"` | While one node applies migrations at startup, the other nodes wait up to three times this value, then exit. The node applying them has no time limit. See [DATABASE.md](DATABASE.md#9-migrations). |
| `fetch_chunk_size` | integer | `5000` | Messages fetched per chunk for large result sets. |

`[database.write]` and `[database.read]` have the same keys. Without `[database.read]`, reads use the
write endpoint. `[database.read]` does not copy values from `[database.write]`: a key you leave out
there gets the built-in default in the table below (for example `user = "postgres"`), not the write
endpoint's value.

| Key | Type | Default (write / read) | Meaning |
|---|---|---|---|
| `hosts` | list of strings | `["localhost"]` | Hosts, each optionally `host:port`. |
| `port` | integer or string | `5432` | Port for hosts written without one. |
| `user` | string | `"postgres"` | |
| `password` | string | `""` | |
| `name` | string | `"sora_mail_db"` | Database name. |
| `tls` | bool | `false` | Connect with TLS. |
| `max_connections` | integer | `100` | Pool size. |
| `min_connections` | integer | `0` | Connections opened at startup. |
| `min_idle_connections` | integer | `5` / `10` | Idle connections kept open. |
| `max_conn_lifetime` | duration | `"1h"` | |
| `max_conn_idle_time` | duration | `"5m"` | |
| `query_timeout` | duration | `"30s"` | Per-endpoint query timeout. |

An endpoint you do not write is not configured. See [section 3](#3-defaults).

### 8.4 Object storage (`[s3]`)

See [STORAGE.md](STORAGE.md).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `endpoint` | string | none | S3 endpoint host. Required on nodes with IMAP, POP3 or LMTP. |
| `access_key` | string | none | Required on those nodes. |
| `secret_key` | string | none | Required on those nodes. |
| `bucket` | string | none | Required on those nodes. |
| `disable_tls` | bool | `false` | Talk plain HTTP to the endpoint. |
| `debug` | bool | `false` | Trace S3 requests. |
| `timeout` | duration | `"30s"` | Timeout of one S3 operation. |
| `encrypt` | bool | `false` | Encrypt bodies on the client before upload. |
| `encryption_key` | string | none | Key for `encrypt`. |

### 8.5 Local cache (`[local_cache]`)

See [STORAGE.md](STORAGE.md).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `path` | string | `"/tmp/sora/cache"` | Cache directory. |
| `capacity` | size | `"1gb"` | Total cache size. |
| `max_object_size` | size | `"5mb"` | Largest body cached. |
| `purge_interval` | duration | `"12h"` | How often the cache is trimmed. |
| `orphan_cleanup_age` | duration | `"30d"` | Age before an orphaned entry is removed. |
| `metrics_interval` | duration | `"5m"` | How often hit and miss counts are stored in the database. |
| `metrics_retention` | duration | `"30d"` | How long those stored counts are kept. |
| `enable_warmup` | bool | `true` | Preload recent messages when a user logs in over IMAP. |
| `warmup_message_count` | integer | `50` | Messages preloaded per mailbox. |
| `warmup_mailboxes` | list of strings | `["INBOX"]` | Mailboxes preloaded. |
| `warmup_async` | bool | `true` | Preload in the background instead of during login. |
| `warmup_timeout` | duration | `"5m"` | Time limit of one warmup. |
| `warmup_interval` | duration | `"24h"` | Shortest interval between two warmups of one user. |

### 8.6 Uploader (`[uploader]`)

See [STORAGE.md](STORAGE.md).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `path` | string | `"/tmp/sora/uploads"` | Staging directory for bodies not yet in S3. |
| `instance_id` | string | the host name | The node's upload lease identity. Changing it strands queued uploads: read [STORAGE.md](STORAGE.md) first. |
| `batch_size` | integer | `10` | Uploads leased per batch. Must be positive. |
| `concurrency` | integer | `20` | Parallel uploads. Must be positive. |
| `max_attempts` | integer | `20` | Attempts before an upload is parked. Must be positive. |
| `retry_interval` | duration | `"30s"` | Wait before retrying a failed upload. |
| `cleanup_grace_period` | duration | `"1h"` | Minimum age of a staged file before cleanup looks at it. Must be positive. |
| `max_staging_size` | size | no limit | Size of this node's staging directory above which new messages are refused. An invalid value stops startup. |

### 8.7 Cleaner (`[cleanup]`)

See [STORAGE.md](STORAGE.md) and, for `fts_retention`, [SEARCH.md](SEARCH.md).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `grace_period` | duration | `"14d"` | How long expunged messages are kept before they are deleted for good. |
| `wake_interval` | duration | `"1h"` | How often the cleaner runs. |
| `max_age_restriction` | duration | none | Expunge messages older than this. Unset means no limit. |
| `fts_retention` | duration | none | Delete search vectors of messages older than this. Unset keeps them. |
| `health_status_retention` | duration | `"30d"` | Rows of the `health_status` table not updated for this long are deleted. |
| `instance_liveness_threshold` | duration | `"7d"` | How long an uploader instance must be silent before its unuploaded messages are reaped. Must be positive. |
| `purge_poll_interval` | duration | `"30s"` | How often the purge worker looks for accounts marked for purging. |

### 8.8 IMAP METADATA limits (`[metadata]`)

| Key | Type | Default | Meaning |
|---|---|---|---|
| `max_entry_size` | integer (bytes) | `65536` | Largest value of one entry. |
| `max_entries_per_mailbox` | integer | `100` | Entries per mailbox. |
| `max_entries_per_server` | integer | `50` | Account-level entries. |
| `max_total_size` | integer (bytes) | `1048576` | All metadata of one account. |

### 8.9 Shared mailboxes (`[shared_mailboxes]`)

See [SHARED_MAILBOXES.md](SHARED_MAILBOXES.md).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | Turn on shared mailboxes and ACLs. |
| `namespace_prefix` | string | `"Shared/"` | Prefix of the shared namespace. `Shared/` covers the root `Shared` and the names under `Shared/`, not `SharedNotes`. While sharing is on, Sora refuses to start with a prefix that is not a mailbox name followed by `/` (an empty one, `Shared` or `Shared//`), or with `INBOX/`. |
| `allow_user_create` | bool | `false` | Let users create shared mailboxes. |
| `default_rights` | string | `"lrswipkxtea"` | ACL rights of the creator. |
| `allow_anyone_identifier` | bool | `false` | Allow the RFC 4314 `anyone` identifier. |

### 8.10 Sieve (`[sieve]`)

See [SIEVE.md](SIEVE.md).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled_extensions` | list of strings | the default set | Extensions scripts may use. Empty means the default set, which leaves out `editheader`. Unknown names are dropped with a warning. |
| `max_execution_time` | duration | `"2s"` | Time budget of one script run. Clamped to 100ms..60s. An invalid value means the default. |

### 8.11 Relay (`[relay]` and `[relay.queue]`)

The relay sends mail that Sieve redirects and vacation replies create. Setting `type` turns on the
relay and its disk queue. See [RELAY.md](RELAY.md).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `type` | string | none | `"smtp"` or `"http"`. Empty disables the relay. Any other value stops startup with `unsupported [relay] type ...`. |
| `smtp_host` | string | none | `host:port` of the SMTP relay. |
| `smtp_tls` | bool | — | Use TLS to the relay. Set it explicitly; `true` is recommended. |
| `smtp_tls_verify` | bool | — | Verify the relay's certificate. Set it explicitly; `true` is recommended. |
| `smtp_use_starttls` | bool | `false` | Use STARTTLS rather than implicit TLS. |
| `smtp_tls_cert_file`, `smtp_tls_key_file` | string | none | Client certificate for the relay. |
| `smtp_helo_host` | string | the host name | Name sent in EHLO. |
| `http_url` | string | none | Endpoint for `type = "http"`. |
| `auth_token` | string | none | Bearer token for `type = "http"`. |

`[relay.queue]`:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `path` | string | `"/var/spool/sora/relay"` | Queue directory. |
| `worker_interval` | duration | `"1m"` | How often the queue is processed. Must be positive. |
| `batch_size` | integer | `100` | Messages per run. |
| `concurrency` | integer | `5` | Messages sent in parallel. |
| `max_attempts` | integer | `10` | Attempts before a message moves to `failed/`. |
| `retry_backoff` | list of durations | `["1m", "5m", "15m", "1h", "6h", "24h"]` | Waits between attempts. The last one repeats. |
| `circuit_breaker_threshold` | integer | `5` | Consecutive failures that open the circuit breaker. |
| `circuit_breaker_timeout` | duration | `"30s"` | Wait before the breaker tries again. |
| `circuit_breaker_max_requests` | integer | `3` | Requests let through while it tries again. |
| `failed_retention` | duration | `"168h"` | How long failed messages are kept. `"0"` keeps them until they are deleted or requeued; a negative value is refused. |
| `cleanup_interval` | duration | `"1h"` | How often old failed messages are removed. |

### 8.12 Spam training (`[spam_training]`)

See [RELAY.md](RELAY.md). Training runs only when `enabled = true` and `endpoint` is set.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | |
| `endpoint` | string | none | HTTP endpoint that receives training submissions. |
| `auth_token` | string | none | Bearer token. |
| `timeout` | duration | `"10s"` | HTTP timeout. |
| `max_message_size` | size | `"10mb"` | Larger messages are not submitted. |

`[spam_training.circuit_breaker]`:

| Key | Type | Default |
|---|---|---|
| `threshold` | integer | `5` |
| `timeout` | duration | `"30s"` |
| `max_requests` | integer | `3` |

### 8.13 TLS (`[tls]`)

The global TLS manager supplies certificates to every listener with `tls = true` that has no
certificate files of its own. See [TLS.md](TLS.md).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | Start the TLS manager. |
| `provider` | string | none | `"file"` or `"letsencrypt"`. Required when `enabled = true`. |
| `cert_file`, `key_file` | string | none | Certificate and key for `provider = "file"`. |

`[tls.letsencrypt]`:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `email` | string | none | Required. |
| `domains` | list of strings | none | Required. Certificates are issued only for these names. |
| `default_domain` | string | the first domain | Certificate for clients that send no SNI. |
| `storage_provider` | string | none | Must be `"s3"`. |
| `renew_before` | duration | 30 days | Renewal window. |
| `enable_fallback` | bool | `true` | Mirror certificates on local disk. |
| `fallback_dir` | string | `"/var/lib/sora/certs"` | Directory of that mirror. |
| `sync_interval` | duration | `"5m"` | How often certificates are re-read from S3. `"0"` disables. |

`[tls.letsencrypt.s3]`:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `bucket` | string | none | Bucket for certificates. |
| `endpoint` | string | `"s3.amazonaws.com"` | |
| `region` | string | none | Region the requests are signed for. |
| `disable_tls` | bool | `false` | |
| `debug` | bool | `false` | |
| `access_key`, `secret_key` | string | none | Static credentials. Without them, Sora uses the AWS default credential chain (environment variables, the shared AWS config, instance roles). |
| `server_side_encryption` | string | `"AES256"` | `"AES256"`, `"aws:kms"`, or `""` to send no encryption header. |
| `server_side_encryption_kms_key_id` | string | none | Key id, required with `"aws:kms"`. |

### 8.14 Cluster (`[cluster]`)

See [CLUSTER.md](CLUSTER.md).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | Join a gossip cluster. |
| `addr` | string | none | This node's gossip address, `IP` or `IP:port`. Must be an IP other nodes reach, not `0.0.0.0`, `::` or `localhost`. |
| `port` | integer | `7946` | Gossip port when `addr` has none. |
| `node_id` | string | the host name | Node name in the cluster. |
| `peers` | list of strings | none | Other nodes to join. |
| `secret_key` | string | none | Base64 of 32 bytes. Required when `enabled = true`. |
| `max_event_queue_size` | integer | `50000` | Event queue size of the connection trackers. |

`[cluster.affinity]`:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | Share affinities across the cluster. |
| `ttl` | duration | `"24h"` | How long an affinity lasts. |
| `cleanup_interval` | duration | `"1h"` | How often expired affinities are removed. |
| `cache_path` | string | none | SQLite file that keeps affinities across restarts. Unset keeps them in memory only. |

### 8.15 Persistent auth cache (`[auth_cache]`)

A SQLite cache of credentials, used by proxies that check passwords in the database. See
[PROXY.md](PROXY.md).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | |
| `path` | string | `"/tmp/sora/auth_cache.db"` | Database file. Its directory is created. |
| `max_age` | duration | `"24h"` | Age after which an entry is fetched again. |
| `purge_unused` | duration | `"168h"` | Entries unused this long are removed. |
| `cleanup_interval` | duration | `"1h"` | How often old entries are removed. |

If the cache cannot be opened, Sora logs an error and runs without it.

### 8.16 Backend maintenance (`[backend_maintenance]`)

See [PROXY.md](PROXY.md).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `poll_interval` | duration | `"5s"` | How often proxies re-read the list of backends in maintenance. Must be positive. |
| `kick_rate` | number | `10` | IMAP sessions per second a proxy closes on a backend in maintenance. A value that is not a positive finite number means the default. |
| `refuse_after` | duration | `"30s"` | How long a backend in maintenance still accepts new sessions. `0` refuses at once. Must not be negative. |

### 8.17 Trusted networks (`[servers]`)

| Key | Type | Default | Meaning |
|---|---|---|---|
| `trusted_networks` | list of strings | empty | Hosts trusted to pass on a client's address (PROXY protocol, XCLIENT, IMAP ID) and, unless `exempt_networks` says otherwise, exempt from authentication rate limits. |

Empty trusts nobody. A listener with `proxy_protocol = true` needs a non-empty list, or Sora does not
start. An entry that is neither an IP address nor a CIDR block stops startup. An `lmtp` server has
its own default for accepting connections and keeps working with an empty list; an `lmtp_proxy`
with an empty list is reported at startup. See [SECURITY.md](SECURITY.md) and
[AUTHENTICATION.md](AUTHENTICATION.md).

### 8.18 Timeout scheduler (`[timeout_scheduler]`)

Sora checks idle, session and throughput timeouts of connections with a shared scheduler. It splits
the connections over shards, and each shard checks its connections every 100 milliseconds.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `shard_count` | integer | `0` | `0`: one shard per logical CPU. `-1`: half the logical CPUs (at least 1). A positive number: that many shards. Below `-1` stops startup. |

The startup log line `Timeout scheduler initialized` shows the mode. The default suits most
servers.

### 8.19 Admin tool (`[admin_cli]`)

Read by `sora-admin`, not by `sora`. See [ADMIN_CLI.md](ADMIN_CLI.md).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `addr` | string | none | URL of the admin API, such as `"http://127.0.0.1:8080"`. Needed by the commands that use the API. |
| `api_key` | string | none | Key of that API. |
| `insecure_skip_verify` | bool | `true` for a loopback address, else `false` | Skip TLS certificate checks towards the admin API. |
| `import_message_limit` | size | the `append_limit` of the first `imap` server in the file (`25mb` if it sets none); `50mb` with no `imap` server | Largest message the import commands accept. |

---

## 9. Keys of a `[[server]]` block

The tables give the type and default of each key and which server types read it. In the "Applies
to" column, "backends" means `imap`, `pop3`, `lmtp` and `managesieve`, and "line proxies" means
`imap_proxy`, `pop3_proxy`, `lmtp_proxy` and `managesieve_proxy`.

### 9.1 Keys every server reads

| Key | Type | Default | Applies to | Meaning |
|---|---|---|---|---|
| `type` | string | required | all | See [section 5](#5-server-blocks). |
| `name` | string | required | all | Unique name. |
| `addr` | string | required | all | Listen address. |
| `debug` | bool | `false` | backends, line proxies | Extra diagnostics for this server. Some protocols write a raw protocol trace to the log output whatever the level. See [PROTOCOLS.md](PROTOCOLS.md). |

### 9.2 TLS on the listener

See [TLS.md](TLS.md).

| Key | Type | Default | Applies to | Meaning |
|---|---|---|---|---|
| `tls` | bool | `false` | all but `metrics` | Serve TLS, with this block's certificate files or the `[tls]` manager. |
| `tls_use_starttls` | bool | `false` | backends, line proxies | Plain connection upgraded with STARTTLS instead of implicit TLS. Needs `tls = true`. |
| `tls_cert_file`, `tls_key_file` | string | none | all but `metrics` | Certificate files for this listener. |
| `tls_verify` | bool | `false` | all but `metrics` | See [TLS.md](TLS.md). |
| `tls_default_domain` | string | `[tls.letsencrypt] default_domain` | all but `metrics` | Certificate for clients that send no SNI. |
| `insecure_auth` | bool | `false` | `imap`, `pop3`, `managesieve`, `lmtp`, `imap_proxy`, `pop3_proxy`, `managesieve_proxy` | Allow password logins on a plain connection. Without `tls = true` it is always allowed. See [SECURITY.md](SECURITY.md). |

The `metrics` server always speaks plain HTTP. `tls` on it only causes a startup warning.

### 9.3 PROXY protocol on the listener

| Key | Type | Default | Applies to | Meaning |
|---|---|---|---|---|
| `proxy_protocol` | bool | `false` | backends, line proxies, `http_admin_api`, `http_user_api`, `user_api_proxy` | Expect a PROXY protocol header from hosts in `trusted_networks`. Needs a non-empty `trusted_networks`. |
| `proxy_protocol_timeout` | duration | `"5s"` | as `proxy_protocol` | Time to wait for the header. |

`proxy_protocol_trusted_proxies` is not a key: Sora warns about it as unknown.
See [SECURITY.md](SECURITY.md) and [PROXY.md](PROXY.md).

### 9.4 Connection limits

See [SECURITY.md](SECURITY.md).

| Key | Type | Default | Applies to | Meaning |
|---|---|---|---|---|
| `max_connections` | integer | `0` (no limit); `1000` on `lmtp` | all but `metrics` | Concurrent connections of this server. On `lmtp`, `0` or less means 1000. |
| `max_connections_per_ip` | integer | `0` (no limit) | `imap`, `pop3`, `managesieve`, `imap_proxy`, `pop3_proxy`, `managesieve_proxy`, `user_api_proxy` | Concurrent connections from one IP. Hosts in `trusted_networks` are not limited. |
| `max_connections_per_user` | integer | `0` (no limit) | `imap`, `pop3`, `managesieve`, `imap_proxy`, `pop3_proxy`, `managesieve_proxy` | Logged-in sessions of one user. Enforced on this server by `imap`, `pop3` and `managesieve`. Enforced across the cluster for proxies, which track connections only with `[cluster] enabled = true`; without it a proxy ignores the key, with a startup warning. Ignored by `lmtp_proxy` with a warning. |
| `max_connections_per_user_per_ip` | integer | `0` (no limit) | as `max_connections_per_user` | Logged-in sessions of one user from one IP. |
| `listen_backlog` | integer | `1024` | backends, line proxies | TCP listen backlog. `0` means 1024. The HTTP servers listen with the kernel's default backlog; on them the key is ignored, with a startup warning. |

### 9.5 Limits (`[server.limits]`)

Written as a sub-table under the block, `[server.limits]`, or inline as `limits = { ... }`. See
[SECURITY.md](SECURITY.md), [SEARCH.md](SEARCH.md) and [PROTOCOLS.md](PROTOCOLS.md).
A key set on a server type not listed under "Applies to" is ignored, with a startup warning that
names it.

| Key | Type | Default | Applies to | Meaning |
|---|---|---|---|---|
| `session_memory_limit` | size | `"100mb"` | `imap`, `pop3` | Memory one session may allocate. `"0"` means no limit. |
| `max_auth_errors` | integer | `2` | `imap_proxy`, `pop3_proxy`, `managesieve_proxy` | Protocol errors before login (unknown or malformed commands, logins refused without TLS) before the proxy disconnects. Wrong passwords do not count; the login rate limiter handles those. `0` or less means 2. |
| `search_rate_limit_per_min` | integer | `60` | `imap` | Search cost per account per window. `0` or less disables the limit. |
| `search_rate_limit_window` | duration | `"1m"` | `imap` | Window of the search rate limit. |
| `search_rate_limit_burst` | integer | `search_rate_limit_per_min` | `imap` | Searches allowed back to back. `0` or less means the default. |
| `thread_max_messages` | integer | `50000` | `imap` | Matches one THREAD command may process. `0` or less means the default. |
| `redirect_rate_limit` | integer | `100` | `lmtp`, `http_admin_api` | Sieve redirects per account per window. `0` means no limit. |
| `redirect_rate_window` | duration | `"1h"` | `lmtp`, `http_admin_api` | Window of the redirect limit. Must be positive. |
| `max_redirect_hops` | integer | `2` | `lmtp`, `http_admin_api` | Redirects of one message before further ones are suppressed. `0` means no limit. |
| `preview_s3_per_min` | integer | `300` | `imap` | S3 downloads per account per minute to answer FETCH PREVIEW. `0` or less means no limit. |
| `preview_s3_burst` | integer | `min(200, preview_s3_per_min)` | `imap` | Of those, how many may run back to back. |
| `preview_s3_node_per_min` | integer | `3000` | `imap` | The same downloads for the whole server. `0` or less means no limit. |
| `preview_s3_max_size` | size | `[local_cache] max_object_size` | `imap` | Largest message downloaded for a preview. |

### 9.6 Timeouts (`[server.timeouts]`)

See [SECURITY.md](SECURITY.md) and [PROTOCOLS.md](PROTOCOLS.md).

| Key | Type | Default | Applies to | Meaning |
|---|---|---|---|---|
| `command_timeout` | duration | `imap`, `imap_proxy`: `30m`; `pop3`, `pop3_proxy`: `10m`; `managesieve`, `managesieve_proxy`: `3m` | `imap`, `pop3`, `managesieve` and their proxies | Idle time before a connection is closed. |
| `absolute_session_timeout` | duration | `24h`; `lmtp_proxy`: `5m` | `imap`, `pop3`, `managesieve`, line proxies | Longest a session may last. |
| `min_bytes_per_minute` | integer | `0` (off) | `imap`, `pop3`, `managesieve`, `imap_proxy`, `pop3_proxy`, `managesieve_proxy` | Minimum throughput before a slow connection is closed. |

Per-command time limits are sub-tables of `[server.timeouts]`. Each value is a duration. A key left
out keeps its default. On POP3, LMTP and ManageSieve an explicit `"0"` turns that limit off.

`[server.timeouts.imap_command_timeouts]` (`imap`):

| Key | Default |
|---|---|
| `search`, `sort`, `thread`, `multi_search`, `copy`, `move` | `"30s"` |
| `store` | `"15s"` |
| `rename` | `"60s"` |
| `fetch` | `"0"` (no limit) |

`[server.timeouts.pop3_command_timeouts]` (`pop3`): `stat`, `list`, `uidl`, `dele` `"10s"`;
`retr`, `top` `"30s"`; `quit` `"15s"`.

`[server.timeouts.managesieve_command_timeouts]` (`managesieve`): `listscripts`, `getscript`,
`putscript`, `checkscript`, `setactive`, `deletescript`, `renamescript`, `havespace`, each `"10s"`.

`[server.timeouts.lmtp_command_timeouts]` (`lmtp`): `rcpt` `"10s"`, `data` `"60s"`.

### 9.7 Protocol-specific keys

See [PROTOCOLS.md](PROTOCOLS.md).

| Key | Type | Default | Applies to | Meaning |
|---|---|---|---|---|
| `append_limit` | size | `"25mb"` | `imap` | Largest message accepted by APPEND. |
| `max_message_size` | size | `"50mb"` | `lmtp`, `lmtp_proxy`, `http_admin_api` | Largest message accepted for delivery. |
| `max_script_size` | size | `"16kb"` | `managesieve` | Largest Sieve script. |
| `supported_extensions` | list of strings | the default set | `managesieve_proxy` | Sieve extensions the proxy advertises. A `managesieve` backend uses `[sieve] enabled_extensions`. |
| `enable_preview` | bool | `false` | `imap` | Advertise FETCH PREVIEW (RFC 8970). |
| `disabled_caps` | list of strings | none | `imap` | Capabilities never advertised. |
| `additional_caps` | list of strings | none | `imap`, `imap_proxy` | Extra capability names advertised as written. |
| `id_name` | string | `"Sora"` | `imap`, `imap_proxy` | `name` in the IMAP ID answer. |
| `id_version` | string | the build version | `imap`, `imap_proxy` | `version` in the IMAP ID answer. |
| `id_vendor` | string | `"Migadu-Mail GmbH"` | `imap`, `imap_proxy` | `vendor` in the IMAP ID answer. |
| `id_support_url` | string | `"https://migadu.com"` | `imap`, `imap_proxy` | `support-url` in the IMAP ID answer. |

`[[server.client_filters]]` (`imap`) turns off capabilities for matching clients. Each entry has:

| Key | Type | Meaning |
|---|---|---|
| `client_name` | string (regular expression) | Matches the client's IMAP ID name. |
| `client_version` | string (regular expression) | Matches its version. |
| `ja4_fingerprints` | list of strings (regular expressions) | Match the TLS JA4 fingerprint. |
| `disable_caps` | list of strings | Capabilities to hide. |
| `reason` | string | Free text for logs. |

### 9.8 Master credentials

See [AUTHENTICATION.md](AUTHENTICATION.md).

| Key | Type | Default | Applies to | Meaning |
|---|---|---|---|---|
| `master_username`, `master_password` | string | none | `imap`, `pop3`, `managesieve`, `imap_proxy`, `pop3_proxy`, `managesieve_proxy` | A master login. A username without a password stops startup. |
| `master_sasl_username`, `master_sasl_password` | string | none | as above | The SASL master login proxies use towards backends. A username without a password stops startup. |
| `master_sasl_allowed_networks` | list of strings | empty (any source) | `imap`, `pop3`, `managesieve` | Source networks allowed to use the SASL master login. |

### 9.9 Authentication rate limit (`[server.auth_rate_limit]`)

Applies to `imap`, `pop3`, `managesieve`, `imap_proxy`, `pop3_proxy`, `managesieve_proxy`,
`http_user_api` and `user_api_proxy`. When `enabled = true`, every key you leave
out, or set to 0, gets the default below. A negative value, or a `delay_multiplier` of `nan` or
`inf`, stops startup ([section 4](#4-checks-at-startup)). See [AUTHENTICATION.md](AUTHENTICATION.md).

| Key | Type | Default |
|---|---|---|
| `enabled` | bool | `false` |
| `max_attempts_per_ip_username` | integer | `5` |
| `ip_username_block_duration` | duration | `15m` |
| `ip_username_window_duration` | duration | `10m` |
| `max_attempts_per_ip` | integer | `50` |
| `ip_block_duration` | duration | `30m` |
| `ip_window_duration` | duration | `30m` |
| `max_attempts_per_username` | integer | `10` |
| `username_window_duration` | duration | `1h` |
| `cleanup_interval` | duration | `5m` |
| `delay_start_threshold` | integer | `2` |
| `initial_delay` | duration | `1s` |
| `max_delay` | duration | `30s` |
| `delay_multiplier` | number | `2.0` |
| `max_ip_username_entries` | integer | `100000` |
| `max_ip_entries` | integer | `50000` |
| `max_username_entries` | integer | `50000` |
| `exempt_networks` | list of strings | `[servers] trusted_networks` when absent; `[]` exempts nobody |

### 9.10 Lookup cache (`[server.lookup_cache]`)

An in-memory cache of login results. See [AUTHENTICATION.md](AUTHENTICATION.md) and
[PROXY.md](PROXY.md).

By default the cache is on for `imap`, `pop3`, `managesieve` and the line proxies, and off for
`http_user_api` and `user_api_proxy`. A table you write changes only the keys it names; the others,
`enabled` included, keep their defaults.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | see above | |
| `positive_ttl` | duration | `"5m"` | How long a successful lookup is kept. |
| `negative_ttl` | duration | `"1m"` | How long a failed lookup is kept. |
| `max_size` | integer | `10000`; `50000` on line proxies | Entries kept. |
| `cleanup_interval` | duration | `"5m"` | How often expired entries are removed. |
| `positive_revalidation_window` | duration | `"30s"` | How soon a cached success is checked again when a different password arrives. Not used by `lmtp_proxy`. |

### 9.11 Proxy keys

Read by the line proxies and `user_api_proxy`. See [PROXY.md](PROXY.md).

| Key | Type | Default | Applies to | Meaning |
|---|---|---|---|---|
| `remote_addrs` | list of strings | none | proxies | Backends. Not allowed together with `[[pool]]` blocks. |
| `remote_port` | integer or string | none | proxies | Port for backends written without one. |
| `remote_tls` | bool | `false` | proxies | TLS to the backends (HTTPS for `user_api_proxy`). |
| `remote_tls_use_starttls` | bool | `false` | line proxies | STARTTLS to the backends. Needs `remote_tls`. |
| `remote_tls_verify` | bool | `false` | proxies | Verify backend certificates. |
| `remote_tls_ca_file` | string | none | proxies | CA file for backend certificates. |
| `remote_use_proxy_protocol` | bool | `false` | proxies | Send a PROXY protocol header to the backends. |
| `remote_use_id_command` | bool | `false` | `imap_proxy` | Forward the client's address with IMAP ID. |
| `remote_use_xclient` | bool | `false` | `pop3_proxy`, `lmtp_proxy` | Forward the client's address with XCLIENT. |
| `remote_use_utf8` | bool | `false` | `pop3_proxy` | Offer POP3 UTF8 and pass it to the backends. Only for Sora backends. |
| `connect_timeout` | duration | `"30s"` | proxies | Time to connect to a backend. |
| `auth_idle_timeout` | duration | `"2m"` | `imap`, `pop3`, `managesieve`, line proxies | Idle time allowed before login. |
| `enable_affinity` | bool | `false` | proxies | Prefer the backend a user used last. |
| `remote_health_checks` | bool | `true` | proxies | Check backend health. |
| `remote_dns_refresh` | duration | `"5m"` | proxies | How often backend host names are resolved again. `"0"` keeps the startup addresses. |

### 9.12 Remote lookup (`[server.remote_lookup]`)

Asks an HTTP API which backend serves a user, or checks the password there. Applies to the line
proxies and `user_api_proxy`. See [PROXY.md](PROXY.md).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | |
| `url` | string | none | Lookup endpoint. Required when enabled. |
| `timeout` | duration | `"5s"` | HTTP timeout. |
| `auth_token` | string | none | Bearer token. |
| `lookup_local_users` | bool | `false` | Look in the local database when the API does not know the user. Needs a database. |
| `user_not_found_response` | string | `"reject"` | LMTP answer for an unknown user: `"reject"` (550) or `"tempfail"`. Other values mean `"reject"`. |
| `restrict_to_pool` | bool | `false` | Refuse a backend address from the API that is not one of this proxy's own backends (`remote_addrs` or `[[pool]]` members). |
| `remote_tls` | bool | `false` | TLS to backends the API names. |
| `remote_tls_use_starttls` | bool | `false` | STARTTLS to those backends. Needs `remote_tls`. |
| `remote_tls_verify` | bool | `true` | Verify their certificates. |
| `remote_port` | integer or string | none | Port for backends the API names without one. |
| `remote_use_proxy_protocol` | bool | `false` | |
| `remote_use_id_command` | bool | `false` | IMAP only. |
| `remote_use_xclient` | bool | `false` | POP3 and LMTP only. |
| `remote_use_utf8` | bool | `false` | POP3 only. |

`[server.remote_lookup.circuit_breaker]`:

| Key | Type | Default |
|---|---|---|
| `max_requests` | integer | `3` |
| `interval` | duration | `"0s"` (counts never reset while closed) |
| `timeout` | duration | `"30s"` |
| `failure_ratio` | number | `0.6` (a value outside 0..1 means the default) |
| `min_requests` | integer | `3` |

`[server.remote_lookup.transport]`:

| Key | Type | Default |
|---|---|---|
| `max_idle_conns` | integer | `100` |
| `max_idle_conns_per_host` | integer | `100` |
| `max_conns_per_host` | integer | `0` (no limit) |
| `idle_conn_timeout` | duration | `"90s"` |
| `dial_timeout` | duration | `"10s"` |
| `tls_handshake_timeout` | duration | `"10s"` |
| `expect_continue_timeout` | duration | `"1s"` |
| `keep_alive` | duration | `"30s"` |

### 9.13 HTTP API keys

See [ADMIN_API.md](ADMIN_API.md) and [USER_API.md](USER_API.md).
A key set on a server type not listed under "Applies to" is ignored, with a startup warning that
names it.

| Key | Type | Default | Applies to | Meaning |
|---|---|---|---|---|
| `api_key` | string | none | `http_admin_api`, `metrics` | Bearer token. Required for `http_admin_api` (without it the server is skipped). Optional for `metrics`. |
| `read_only_api_key` | string | none | `http_admin_api` | Optional second key, accepted for `GET` requests only. Same rules as `api_key`; must differ from it. See [ADMIN_API.md](ADMIN_API.md#3-authentication-and-access-control). |
| `allowed_hosts` | list of strings | empty (any host) | `http_admin_api`, `http_user_api`, `metrics` | IPs or CIDR blocks allowed to connect. |
| `jwt_secret` | string | none | `http_user_api`, `user_api_proxy` | Key that signs and checks JWTs. Without it the server is skipped. |
| `token_duration` | duration | `"24h"` | `http_user_api` | Token lifetime. Must not be negative. |
| `token_issuer` | string | `"sora-mail-api"` | `http_user_api` | JWT issuer. |
| `allowed_origins` | list of strings | none | `http_user_api`, `user_api_proxy` | CORS origins. The proxy uses them for the errors it answers itself. |

### 9.14 Metrics server keys

See [METRICS.md](METRICS.md).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `path` | string | `"/metrics"` | URL path of the metrics. Must begin with `/`. |
| `allowed_hosts` | list of strings | empty (any host) | IPs or CIDR blocks allowed to scrape, matched against the TCP peer. |
| `api_key` | string | none | Require `Authorization: Bearer <key>`. |
| `enable_domain_metrics` | bool | `true` | Per-domain counters. |
| `enable_user_metrics` | bool | `false` | Per-user counters for heavy users. |
| `user_metrics_threshold` | integer | `1000` | Commands plus connections after which a user gets its own series. |
| `max_tracked_users` | integer | `1000` | Users with their own series. |
| `hash_usernames` | bool | `true` | Replace user names by a short SHA-256 prefix in labels. |

These five metric settings are global: if several `metrics` blocks exist, the last one read wins.
`path` and these five settings are read from `metrics` blocks only; on another server type they are
ignored, with a startup warning that names them.

---

## 10. Named backend pools (`[[pool]]`)

A `[[pool]]` block names a group of backends that every proxy on the node can route into. Each block
carries its own backend settings: nothing is inherited from the `[[server]]` that dials it. See
[PROXY.md](PROXY.md).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `name` | string | required | Unique, without spaces. |
| `backends` | list of strings | required | Backend hosts. A host without a port gets the dialing proxy's `remote_port`. |
| `default` | bool | `false` | Route users the lookup answers without a pool into this pool. At most one. |
| `remote_tls` | bool | `false` | |
| `remote_tls_use_starttls` | bool | `false` | Needs `remote_tls`. |
| `remote_tls_verify` | bool | `true` | |
| `remote_tls_ca_file` | string | none | Needs `remote_tls`. |
| `remote_use_proxy_protocol` | bool | `false` | |
| `remote_use_id_command` | bool | `false` | IMAP only. |
| `remote_use_xclient` | bool | `false` | POP3 and LMTP only. |
| `remote_use_utf8` | bool | `false` | POP3 only, Sora backends only. |

At startup Sora checks the pools as a whole (`Config.ValidatePools` in
[config/pools.go](../config/pools.go)) and stops with a `[[pool]]` error when:

- a pool has no name, a name with spaces, a name used twice, or no backends;
- a backend appears twice, or in two pools (a backend without a port clashes with any entry for the
  same host);
- `remote_tls_use_starttls` or `remote_tls_ca_file` is set without `remote_tls`;
- more than one pool has `default = true`;
- a proxy server also has `remote_addrs`;
- a pool backend has no port and a proxy server has no `remote_port`;
- there is no default pool and a proxy has no remote lookup, or has `lookup_local_users = true`.
