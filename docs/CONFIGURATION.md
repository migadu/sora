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

A key Sora does not know is ignored, and Sora logs a warning that names it (console format):

```
level=WARN msg="Configuration file 'config.toml': unknown key 'servers.imap' will be ignored (a typo or a deprecated setting?)"
level=WARN msg="Configuration file 'config.toml': unknown key 'servers.imap.start' will be ignored (a typo or a deprecated setting?)"
level=WARN msg="Configuration file 'config.toml': unknown key 'servers.imap.addr' will be ignored (a typo or a deprecated setting?)"
```

An unknown table is listed together with each key in it. An unknown key inside a
`[server.auth_rate_limit]` or `[server.lookup_cache]` table is reported as
`Unknown key 'auth_rate_limit.<key>' will be ignored` (or `lookup_cache.<key>`).

The key keeps its default, so a misspelt key silently does nothing. Read these warnings after every
change. At startup the file is read before logging is set up, so Sora holds them and writes them to
the `[logging]` output once it is open, at its level, also when a check in
[section 4](#4-checks-at-startup) then stops startup. Only a file that cannot be read or parsed stops
startup before logging is set up; what Sora held is then written to standard error with the error.
On a `SIGHUP` reload they go through the logger.

### Duplicate keys

A key written twice in the same table is normally a TOML error. Sora is lenient here: it keeps the
first occurrence, ignores the others and parses the file again. It logs one warning for the file and
one for each duplicate, held and written like the unknown-key warnings above:

```
level=WARN msg="Configuration file 'config.toml' contains duplicate keys, only the first occurrence of each is used; please remove the duplicates: ..."
level=WARN msg="Duplicate key 'server.addr' found at line 12 (first occurrence at line 9). Ignoring duplicate."
```

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

Size keys are strings: a whole number and a unit, `b`, `kb`, `mb`, `gb` or `tb`, in any case, with
optional space: `"512kb"`, `"25MB"`, `"1 gb"`. A plain number such as `"1048576"` is bytes. Units
are powers of 1024 (`"1kb"` is 1024 bytes). Fractions (`"1.5gb"`) and units without `b` (`"10m"`)
are rejected.

The durations in `[server.auth_rate_limit]` are parsed the same way as every other duration, so
`"1d"` works there too. Unlike most duration keys, a value there that is not a duration (a bare
number such as `900`, or a string that does not parse) is a parse error and stops startup.

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

- **Booleans default to `false`.** A boolean you leave out is `false`, except for these keys,
  which are `true` when absent:
  - in a `[[server]]` block: `enabled`, `remote_health_checks`, the `metrics` keys
    `enable_domain_metrics` and `hash_usernames`, `[server.remote_lookup] remote_tls_verify`, and
    `[server.lookup_cache] enabled` on the server types that use the cache by default;
  - `[[pool]] remote_tls_verify`;
  - `[relay] smtp_tls` and `smtp_tls_verify`;
  - `[tls.letsencrypt] enable_fallback`;
  - `[cluster.affinity] enabled`, and `enabled`, `sync_blocks` and `sync_failure_counts` in
    `[cluster.rate_limit_sync]`;
  - `[local_cache] enable_warmup` and `warmup_async`.

  `[admin_cli] insecure_skip_verify` defaults to "skip only for a loopback address".
- **Zero often means "use the default".** For many number keys, `0` or a negative value means the
  default, not "off". The tables say where `0` means "no limit" or "disabled" instead.
- **A table you write changes only the keys it names.** In a `[server.lookup_cache]` table, for
  example, the keys you leave out keep their defaults, and the cache stays on unless the table says
  `enabled = false`. See [9.10](#910-lookup-cache-serverlookup_cache).
- **A database endpoint you do not write means "no database".** Without a `[database.write]` (or
  `[database.read]`) section in the file, Sora has no such endpoint. This is how a proxy-only node
  runs without one. A node that needs a database and has none stops with `[database]: server
  "<name>" (<type>) needs the database, but it is not configured in [database.write] or
  [database.read]`. `[database.read]` alone is not enough: the migrations and every write go to
  `[database.write]`.

---

## 4. Checks at startup

After parsing, Sora checks the configuration before it opens any listener. Each failed check below
stops startup with exit status 1, after Sora has reported every problem the file has. It sets up
logging from `[logging]` first, so each problem is an ERROR record of that output (standard error,
syslog, a log file, ...), in its format and after the warnings held about the file. With the
console format:

```
time=2026-01-15T10:00:00.000+01:00 level=ERROR msg="Invalid configuration" field=<what> error=<reason>
```

The Message column is the `error` value, in some rows after the `field` value (`[s3]: ...`). A file
that cannot be read or parsed has no `[logging]` to follow: that error goes to standard error
([OPERATIONS.md](OPERATIONS.md#messages-that-stop-startup)).

| Check | Message |
|---|---|
| A server has a type that is not in the list in [section 5](#5-server-blocks) | `invalid server type '<type>', must be one of: imap, lmtp, ...` |
| `master_username` is set and `master_password` is empty | `server "<name>": master_username is set but master_password is empty; refusing to start ...` |
| `master_sasl_username` is set and `master_sasl_password` is empty | `server "<name>": master_sasl_username is set but master_sasl_password is empty; refusing to start ...` |
| An `imap`, `pop3` or `managesieve` server's `master_sasl_allowed_networks` has an entry that is neither an IP address nor a CIDR block | `server "<name>": invalid master_sasl_allowed_networks: invalid trusted network '<entry>': not a valid IP address or CIDR` |
| `[[pool]]` blocks are inconsistent (see [section 10](#10-named-backend-pools-pool)) | `[[pool]]: ...` |
| A proxy server (a type ending in `_proxy`) has no `remote_addrs` and the file has no `[[pool]]` blocks | `server '<name>': remote_addrs is required unless the file declares [[pool]] blocks` |
| A proxy server has a `remote_addrs` entry without a host: empty, only spaces, or a port alone such as `":143"` | `server "<name>": remote_addrs #<n>: empty backend address` |
| A proxy server has a `remote_addrs` entry with whitespace inside it (`"192.0.2.10 :143"`; spaces at the ends are trimmed) | `server "<name>": remote_addrs #<n>: backend address "<entry>" contains whitespace` |
| A server has `proxy_protocol = true` and `[servers] trusted_networks` is empty | `trusted_networks: proxy_protocol is enabled on server(s) <names> but [servers] trusted_networks is empty; ...` |
| Two servers have the same `name` | `duplicate server name '<name>' found. Each server must have a unique name` |
| Two servers have the same `addr` string | `duplicate server address '<addr>' found. Server '<a>' and '<b>' cannot bind to the same address` |
| A `[[server]]` block without `enabled = false` lacks `type`, `name` or `addr` | `server type is required`, `server name is required (type "<type>", addr "<addr>")` or `server address is required; set enabled = false to keep a [[server]] block without starting it` |
| An `imap` server's `disabled_caps` leaves neither IMAP4rev1 nor IMAP4rev2 (for example `IMAP4rev1` together with `IMAP4rev2`, `IDLE` or `MOVE`, which IMAP4rev2 includes) | `server "<name>": disabled_caps leaves neither IMAP4rev1 nor IMAP4rev2 enabled; ...` |
| `[s3] body_deletion_protocol` is set to something other than `"paused"` or `"global-hash-v1"`, on a node that connects to S3 | `[s3]: invalid body_deletion_protocol "<value>": expected paused or global-hash-v1` |
| No server is configured | `no servers configured. Please configure at least one server in a [[server]] section` |
| An IMAP, POP3 or LMTP server is configured, or an `http_user_api` server with any `[s3]` connection setting, and `[s3] bucket` or `endpoint` is empty, `timeout` is not a duration, only one of `access_key` and `secret_key` is set, or `encrypt = true` and `encryption_key` is missing or not the hex encoding of 32 bytes | `[s3]: bucket is required ...`, `[s3]: endpoint is required ...`, `[s3]: invalid timeout "<value>": ...`, `[s3]: access_key and secret_key must be set together; ...`, `[s3]: encryption_key is required when encrypt = true`, `[s3]: encryption_key must be 64 hex characters (a 32-byte key)` or `[s3]: encryption_key must be 32 bytes (64 hex characters), got <n> bytes` |
| A server that needs the database is configured and there is no database endpoint (see [section 3](#3-defaults)) | `[database]: server "<name>" (<type>) needs the database, but it is not configured in [database.write] or [database.read]` |
| A server that needs the database is configured and `[database.read]` has hosts but `[database.write]` has none | `[database.write]: server "<name>" (<type>) needs the database, but [database.write] has no hosts; ...` |
| A server that needs the database is configured and `[database] migration_timeout` is not a duration, or a `[database.write]` or `[database.read]` endpoint with hosts has a `max_conn_lifetime` or `max_conn_idle_time` that is not a duration, a `port` that is not a number from 1 to 65535 (used by every host entry without a port of its own), or a host entry whose own port is not one | `[database]: invalid migration_timeout "<value>": ...`, `[database.write]: invalid max_conn_lifetime "<value>": ...` (likewise `max_conn_idle_time`, and `[database.read]`), `[database.write]: port number <n> is out of the valid range (1-65535)`, `[database.write]: invalid string for port: "<value>"` or `[database.write]: invalid port "<port>" in host "<host>" (must be 1-65535)` |
| `[cluster] enabled = true` and `addr` is not an IP address other than `0.0.0.0` or `::`, the port (in `addr` or `port`) is above 65535 or negative, or `secret_key` is missing or not the base64 of 32 bytes (see [CLUSTER.md](CLUSTER.md)) | `[cluster]: cluster addr '<host>' must be a specific IP address reachable from other nodes, ...`, `[cluster]: cluster port <n> is not a valid port (0 to 65535)`, `[cluster]: cluster secret_key is required when cluster mode is enabled ...`, `[cluster]: failed to decode cluster secret_key: ...` or `[cluster]: cluster secret_key must be 32 bytes (got <n> bytes)` |
| `[tls] enabled = true` and `provider` is neither `"file"` nor `"letsencrypt"`; `provider = "file"` without `cert_file` or `key_file`; or `provider = "letsencrypt"` without a `[tls.letsencrypt]` table, `email` or `domains`, with a `storage_provider` other than `"s3"`, a `renew_before` or `sync_interval` that is not a duration, only one of `[tls.letsencrypt.s3] access_key` and `secret_key`, or a `server_side_encryption` and `server_side_encryption_kms_key_id` the store cannot be asked for (see [TLS.md](TLS.md)) | `[tls]: unknown TLS provider: <value> (must be 'file' or 'letsencrypt')`, `[tls]: cert_file and key_file are required for provider='file'`, `[tls]: letsencrypt configuration is required for provider='letsencrypt'`, `[tls]: letsencrypt.email is required`, `[tls]: letsencrypt.domains is required and must not be empty`, `[tls]: only storage_provider='s3' is currently supported for Let's Encrypt`, `[tls]: invalid renew_before duration "<value>": ...` (likewise `sync_interval`) or `[tls]: letsencrypt.s3: ...` |
| `[servers] trusted_networks` has an entry that is neither an IP address nor a CIDR block | names the invalid entry |
| A server's `auth_rate_limit.exempt_networks` has an entry that is neither an IP address nor a CIDR block | `server "<name>": auth_rate_limit.exempt_networks has entries that are neither an IP address nor a CIDR: [...]` |
| An `imap` server's `client_filters` entry has a `client_name`, `client_version` or `ja4_fingerprints` pattern that is not a valid regular expression | `server "<name>": client_filters #<n>: <key> "<pattern>": error parsing regexp: ...` |
| An `imap` server's `client_filters` entry has none of `client_name`, `client_version` and `ja4_fingerprints` (empty ones count as unset), or an empty `ja4_fingerprints` pattern | `server "<name>": client_filters #<n>: none of client_name, client_version and ja4_fingerprints is set, so it matches no client` or `server "<name>": client_filters #<n>: ja4_fingerprints "": an empty pattern matches every TLS fingerprint` |
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
| An IMAP, POP3 or LMTP server is configured and `[uploader]` has a `batch_size`, `concurrency` or `max_attempts` of zero or less, a `cleanup_grace_period` of zero or less or that is not a duration, a `retry_interval` of zero or less, or a `max_staging_size` that is not a size | `[uploader] <key> must be positive, got <n>`, `[uploader] cleanup_grace_period must be positive, got "<value>"`, `[uploader] cleanup_grace_period: <parse error>`, `[uploader] retry_interval must be positive, got "<value>"` or `[uploader] max_staging_size: <parse error>` |
| An IMAP, POP3 or LMTP server is configured and `[local_cache]` has a `purge_interval` or `metrics_interval` of zero or less | `[local_cache]: <key> must be positive, got "<value>"` |
| `[auth_cache] enabled = true` and `cleanup_interval` is zero or less | `[auth_cache]: cleanup_interval must be positive, got "<value>"` |
| `[cluster]` and `[cluster.affinity]` are enabled and `[cluster.affinity] cleanup_interval` is negative | `[cluster.affinity]: cleanup_interval must not be negative, got "<value>"` |
| `[shared_mailboxes] enabled = true` and `namespace_prefix` is not a mailbox name followed by `/` (for example `""`, `"Shared"` or `"Shared//"`), or is `INBOX/` in any letter case | `[shared_mailboxes]: namespace_prefix "<value>" must be a mailbox name followed by the hierarchy delimiter "/", such as "Shared/"` or `[shared_mailboxes]: namespace_prefix "<value>" conflicts with the reserved personal INBOX` |
| `[timeout_scheduler] shard_count` is below -1 | `[timeout_scheduler]: shard_count must be >= -1, got <n>` |

The address check compares the strings, so `":143"` and `"0.0.0.0:143"` pass it and fail later when
the second listener cannot bind.

These conditions only log, and startup continues:

- `[sieve] enabled_extensions`, or a `managesieve_proxy`'s `supported_extensions`, names an
  extension the engine does not support. The name is dropped.
- `trusted_networks` is empty (an INFO line explains what that disables), or it contains a whole
  private range such as `10.0.0.0/8` (a WARN line).
- A key is set on a server type it does not apply to, for example `remote_addrs` on an `imap`
  server, or `tls_use_starttls` without `tls = true`. Sora logs `WARNING: Server <name> (type: <type>)
  has '<key>' configured, but ...`.
- A key is set where it has no effect: `tls_verify` without `tls = true`; `remote_tls_use_starttls`
  without `remote_tls` (the backend leg is then plaintext); `timeouts.scheduler_shard_count` (see
  [9.6](#96-timeouts-servertimeouts)); and `remote_skip_forwarding_with_proxy_protocol` without
  `remote_use_proxy_protocol` and the forwarding command of the same leg, or on a `[[server]]` block
  in a file with `[[pool]]` blocks.
- A `[[server]]` block has `enabled = false`: `Server block has enabled = false - not starting it`
  (INFO).
- An `imap` or `pop3` server's `session_memory_limit` is below the `max_message_size` of an `lmtp`
  server: a delivered message larger than the limit is stored but can never be fetched there.
- IMAP, POP3 or ManageSieve (or their proxies) allow plaintext authentication on a publicly
  reachable address: `plaintext authentication is allowed without TLS on a publicly reachable
  address`. Configure TLS to clear it.
- A `metrics` server on a publicly reachable address has neither `allowed_hosts` nor `api_key`:
  `metrics endpoint is served without access control on a publicly reachable address; set
  allowed_hosts and/or api_key`.
- The host name is not fully qualified: `Mail hostname is not fully qualified`. Sora uses the host
  name in greetings and in the `Received` header.
- A setting has no effect on this node: `enable_affinity` on a proxy without `[cluster]` and
  `[cluster.affinity]` enabled, `max_connections_per_user` or `max_connections_per_user_per_ip` on an
  IMAP, POP3 or ManageSieve proxy without `[cluster]`, an `http_user_api` server without `[s3]` (it
  serves no message bodies), an `http_admin_api` server without an `imap`, `pop3` or `lmtp` server
  (`POST /admin/mail/deliver` answers 503), and a proxy on a node without a database (backend
  maintenance is not honored).
- `[relay]` relays to a host other than a loopback address in plaintext or without verifying its
  certificate.
- A value does not parse, and Sora uses the default instead: a size, timeout or duration of a
  `[[server]]` block (with its `limits`, `timeouts` and `lookup_cache` tables) or of
  `[cluster.affinity]`, `[backend_maintenance]`, `[relay.queue]`, `[local_cache]`, `[cleanup]`,
  `[uploader]`, `[auth_cache]` or `[database]`, where the part of the node that reads it runs. The
  `[database]` timeouts are logged at each query. A `[spam_training]` value that does not parse
  leaves spam training out, and a `max_message_size` above 2147483647 bytes is lowered to that.
- A server, the cluster, the TLS manager or the cleaner works differently from what a setting
  says: an `imap`, `pop3` or `managesieve` server has `master_sasl_password` without
  `master_sasl_allowed_networks`; an `imap` server's `append_limit` is above 2147483647 bytes
  (lowered to that) or above its `session_memory_limit` (which then is its `APPENDLIMIT`), its
  `command_timeout` is 35 minutes or more (the IMAP library closes idle sessions at 35 minutes), or
  `disabled_caps` or a `client_filters` entry names a capability it cannot withdraw; an
  `http_user_api` server's `token_duration` is above 7 days (lowered to that); an `http_admin_api`
  or `http_user_api` server's `allowed_hosts` has an entry that is not an IP address or CIDR; a
  server with `tls = true` sets `tls_cert_file` or `tls_key_file` while `[tls]` is enabled (the
  `[tls]` certificate is used); `[tls.letsencrypt]` has `enable_fallback = false`; `[cluster]`
  `addr` has a port and `port` is also set, `addr` is a loopback address, or `peers` names this node
  or leaves no other node to join; `[cleanup]` `wake_interval` is below 1 minute or
  `purge_poll_interval` below 5 seconds (raised to that).

Later steps can still fail, for example a TLS certificate that cannot be read, or a database that
cannot be reached. Those are covered in the topic documents.

`sora-admin config validate` runs every validation check in the table without starting
anything, and reports the warnings above that follow from the file alone as `[WARN]` lines without
changing its success exit status. The ones that depend on the host are reported only at startup:
plaintext authentication and metrics on a publicly reachable address, the host name, and a `peers`
entry that names this node by host name. See [ADMIN_CLI.md](ADMIN_CLI.md).

---

## 5. Server blocks

Every listener is one `[[server]]` block, a TOML array of tables. Each block needs three keys:

| Key | Meaning |
|---|---|
| `type` | What the listener serves. One of the types below. |
| `name` | A name, unique in the file. It appears in logs, in metric labels (`server_name`) and in the reload report. |
| `addr` | The listen address, such as `":143"` or `"192.0.2.10:993"`. |

A block that lacks any of the three stops startup ([section 4](#4-checks-at-startup)).

To keep a block in the file without starting it, add `enabled = false`. Sora then skips the block
completely: it does not check it, start it, count it, or compare it with the other blocks for
duplicate names and addresses. A block without `enabled`, or with `enabled = true`, starts.

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
  `lmtp` or `managesieve` server, an `http_admin_api` or `http_user_api` server, an `imap_proxy`,
  `pop3_proxy`, `managesieve_proxy` or `lmtp_proxy` that looks users up in the database (no remote
  lookup, or `lookup_local_users = true`), or a `user_api_proxy` with
  `[server.remote_lookup] lookup_local_users = true`. A node whose only servers are proxies that use
  remote lookup alone, or a `user_api_proxy` without `lookup_local_users`, needs no database.
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

`SIGHUP` does these things, in this order ([cmd/sora/main.go](../cmd/sora/main.go),
[cmd/sora/server_reload.go](../cmd/sora/server_reload.go)):

1. It reopens the log file, when `[logging] output` is a file path, so log rotation works.
2. It reads the configuration file again. If the file does not parse, Sora logs
   `Config reload failed - keeping current config` and changes nothing.
3. It reports which global settings changed and need a restart, and runs the startup checks on the
   new file (see below).
4. It hands each running server its own `[[server]]` block from the new file, matched by `name`. The
   server applies the settings it can change at runtime. New sessions use the new values. Sessions
   that are already open keep the values they started with.

A `SIGHUP` that arrives while Sora is still starting only reopens the log file at once. Sora logs
`SIGHUP received during start-up - log file reopened; the configuration is reloaded once the servers
have started` and reloads the configuration when the servers are up.

Before applying a block, Sora runs the same per-server check as at startup (type, name, address,
master passwords, `master_sasl_allowed_networks` and the other checks of a single block). A block
that fails it is skipped with `Skipping reload: invalid new server config`, and that server keeps its
old settings. If the new file has two blocks with the same `name`, the running server of that name
is not reloaded, and Sora logs
`Skipping reload: duplicate server name in config; a restart will refuse to start with it`.

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

The `metrics` server does not reload, and neither does a server that startup skipped (such as an
`http_admin_api` block without `api_key`): every change to their blocks is reported as needing a
restart.

Other changes to the `[[server]]` blocks also need a restart:

| Change | What Sora does |
|---|---|
| A block is added, or its `enabled = false` is removed | It is not started. Sora logs `Config reload: server added or enabled but not running; it is not started until restart`. |
| A block is removed, renamed or set to `enabled = false` | Its server keeps running with its old settings. Sora logs `Config reload: server removed or set to enabled = false, but it keeps running until a restart`. |
| A block's `type` changes | The running server keeps its old type and settings. Sora logs `Config reload: server type changed; keeping running server until restart` (WARN). |

No global setting reloads. Sora compares every global key of the new file with the running
configuration and logs the names (never the values) of the ones that changed in one line:

```
Config reload: global settings changed but require restart to take effect  fields=[logging.level cleanup.grace_period ...]
```

This covers every section, `bcrypt_cost` and the `[[pool]]` blocks, except `[admin_cli]`:
`sora-admin` reads that table each time it runs, and `sora` does not use it. A change to
`[servers] trusted_networks` is also logged on its own at WARN, with the old and new lists, because
until the restart the networks the servers started with stay trusted:
`Config reload: servers.trusted_networks changed but requires restart to take effect; ...`.

A reload also runs the checks of [section 4](#4-checks-at-startup), the ones
`sora-admin config validate` runs, on the new file. For each problem it logs an error, for example
`Config reload: [cluster] is invalid and the server will not start with this config`, with the
reason in `error`. A file the next restart would refuse is caught this way at the reload. Sora still
applies each valid `[[server]]` block as above, and repeats the `session_memory_limit` warning of
section 4 for the new file.

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
| `[cluster]`, `[cluster.affinity]`, `[cluster.rate_limit_sync]` | Gossip cluster | [8.14](#814-cluster-cluster), [CLUSTER.md](CLUSTER.md) |
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
| `endpoint` | string | none | S3 endpoint, a host (`"s3.example.com"`, `"minio.example.com:9000"`) or a URL with `https://` or `http://`. Required on a node that connects to S3: one with an `imap`, `pop3` or `lmtp` server, or an `http_user_api` server with any `[s3]` connection setting. |
| `bucket` | string | none | Bucket of the message bodies. Required on those nodes. Sora does not create it. |
| `access_key`, `secret_key` | string | none | Static credentials. Set both or neither. Without them, Sora uses the AWS default credential chain (environment variables, the shared AWS files, web identity, container or instance role). |
| `region` | string | `AWS_REGION` or the shared AWS config, else `"us-east-1"` | Region the requests are signed for. AWS refuses a signature for another region than the bucket's. |
| `disable_tls` | bool | `false` | Talk plain HTTP to an endpoint written without a scheme. |
| `debug` | bool | `false` | Log every S3 request and response. |
| `timeout` | duration | `"30s"` | Time limit of one S3 operation, body transfer included. |
| `encrypt` | bool | `false` | Encrypt bodies on the client before upload. |
| `encryption_key` | string | none | Key for `encrypt`: 64 hex characters (32 bytes), for example from `openssl rand -hex 32`. Required with `encrypt = true`. |
| `body_deletion_protocol` | string | `"paused"` | `"paused"` (or unset) keeps the deletion of message bodies from S3, and the retirement of their references, switched off; delivery, reads and uploads work as usual. Set `"global-hash-v1"` only once the [fleet cutover](OPERATIONS.md#upgrading-the-s3-message-body-lock-protocol) is complete. Any other value stops startup. |

### 8.5 Local cache (`[local_cache]`)

See [STORAGE.md](STORAGE.md).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `path` | string | `"/var/cache/sora/cache"` | Cache directory. |
| `capacity` | size | `"1gb"` | Total cache size. |
| `max_object_size` | size | `"5mb"` | Largest body cached. |
| `purge_interval` | duration | `"12h"` | How often the cache is trimmed. Must be positive. |
| `orphan_cleanup_age` | duration | `"30d"` | Age before an orphaned entry is removed. |
| `metrics_interval` | duration | `"5m"` | How often hit and miss counts are stored in the database. Must be positive. |
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
| `path` | string | `"/var/spool/sora/uploads"` | Staging directory for bodies not yet in S3. |
| `instance_id` | string | the host name | The node's upload lease identity. Changing it strands queued uploads: read [STORAGE.md](STORAGE.md) first. |
| `batch_size` | integer | `10` | Uploads leased per batch. Must be positive. |
| `concurrency` | integer | `20` | Parallel uploads. Must be positive. |
| `max_attempts` | integer | `20` | Attempts before an upload is parked. Must be positive. |
| `retry_interval` | duration | `"30s"` | Wait before retrying a failed upload. Must be positive. |
| `cleanup_grace_period` | duration | `"1h"` | Minimum age of a staged file before cleanup looks at it. Must be positive. |
| `max_staging_size` | size | no limit | Size of this node's staging directory above which new messages are refused. An invalid value stops startup. |

Earlier releases defaulted `path` to `/tmp/sora/uploads`. When `path` is left at the new default and
the old directory still holds staged bodies, startup stops with `Invalid configuration` for
`uploader path`. Drain or move the old spool first: see
[OPERATIONS.md](OPERATIONS.md#moving-off-the-old-tmpsora-defaults).

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
| `enabled` | bool | `false` | Turn on shared mailboxes and ACLs. Off, a node serves every mailbox to its owner only, whatever its ACL says. Use the same value on every node. |
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
| `smtp_tls` | bool | `true` | Use TLS to the relay. `false` relays in plaintext; startup warns unless `smtp_host` is a loopback address. |
| `smtp_tls_verify` | bool | `true` | Verify the relay's certificate and host name. `false` is warned about at startup unless `smtp_host` is a loopback address. |
| `smtp_use_starttls` | bool | `false` | Use STARTTLS (ports 25 and 587) rather than implicit TLS (port 465). Ignored with `smtp_tls = false`. |
| `smtp_tls_cert_file`, `smtp_tls_key_file` | string | none | Client certificate for the relay. |
| `smtp_helo_host` | string | the host name, else `"localhost"` | Name sent in EHLO. Set it to the host's fully qualified name. |
| `http_url` | string | none | Endpoint for `type = "http"`: an absolute `http://` or `https://` URL. Startup warns about `http://` to a host other than a loopback address. |
| `auth_token` | string | none | Bearer token for `type = "http"`. |

To relay through a local mail transfer agent on port 25 without TLS, set `smtp_tls = false`: the
default is implicit TLS.

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
| `max_message_size` | size | `"10mb"` | Larger messages are not submitted. The size is the stored size, attachments included. |
| `workers` | integer | `4` | Workers that fetch and submit training messages, for the whole process. `0` or less means the default. |
| `queue_size` | integer | `1000` | Messages waiting for a worker. A message moved while the queue is full is not submitted. `0` or less means the default. |

A `timeout`, `max_message_size` or circuit breaker `timeout` that does not parse makes Sora start
without spam training, with a warning.

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
| `domains` | list of strings | none | Required. Certificates are issued only for these names. Sora reads each name in lowercase, as an A-label (`xn--...`) and without a trailing dot, and drops duplicates. A name no certificate can be issued for (an IP address, a single label, an invalid label) is dropped with a warning. |
| `default_domain` | string | the first domain | Certificate for clients that send no SNI. An invalid name is ignored with a warning. |
| `storage_provider` | string | none | Must be `"s3"`. |
| `renew_before` | duration | 30 days | Renewal window, such as `"720h"` or `"30d"`. |
| `enable_fallback` | bool | `true` | Mirror certificates on local disk. |
| `fallback_dir` | string | `"/var/lib/sora/certs"` | Directory of that mirror. |
| `sync_interval` | duration | `"5m"` | How often certificates are re-read from S3. `"0"` disables. |

`[tls.letsencrypt.s3]`:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `bucket` | string | none | Bucket for certificates. |
| `endpoint` | string | `"s3.amazonaws.com"` | |
| `region` | string | `AWS_REGION` or the shared AWS config, else `"us-east-1"` | Region the requests are signed for. |
| `disable_tls` | bool | `false` | |
| `debug` | bool | `false` | |
| `access_key`, `secret_key` | string | none | Static credentials. Set both or neither: one alone stops startup (`letsencrypt.s3: access_key and secret_key must be set together; ...`). Without them, Sora uses the AWS default credential chain (environment variables, the shared AWS config, instance roles). |
| `server_side_encryption` | string | `"AES256"` | `"AES256"`, `"aws:kms"`, or `""` to send no encryption header. |
| `server_side_encryption_kms_key_id` | string | none | Key id, required with `"aws:kms"`. |

### 8.14 Cluster (`[cluster]`)

See [CLUSTER.md](CLUSTER.md).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | Join a gossip cluster. |
| `addr` | string | none | This node's gossip address, `IP` or `IP:port`. Must be an IP other nodes reach, not `0.0.0.0`, `::` or `localhost`. |
| `port` | integer | `7946` | Gossip port when `addr` has none. |
| `node_id` | string | the host name | Node name in the cluster. It is used only inside the cluster: it changes neither the host name in greetings and `Received` headers nor `[uploader] instance_id`. |
| `peers` | list of strings | none | Other nodes to join. |
| `secret_key` | string | none | Base64 of 32 bytes. Required when `enabled = true`. |
| `max_event_queue_size` | integer | `50000` | Event queue size of the connection trackers. |

`[cluster.affinity]`:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | Keep and share affinities across the cluster. With `false`, or without `[cluster] enabled = true`, a proxy's `enable_affinity` has no effect: users are routed by consistent hash, and startup and `sora-admin config validate` warn. |
| `ttl` | duration | `"24h"` | How long an affinity lasts. |
| `cleanup_interval` | duration | `"1h"` | How often expired affinities are removed. `0` means `1h`; a negative value stops startup. |
| `cache_path` | string | none | SQLite file that keeps affinities across restarts: a path or an SQLite `file:` URI; an in-memory database is refused. Unset keeps them in memory only. If the file cannot be opened, Sora logs an error and runs without it. |

`[cluster.rate_limit_sync]`, for the `imap_proxy`, `pop3_proxy` and `managesieve_proxy` listeners with
`auth_rate_limit` enabled ([CLUSTER.md](CLUSTER.md#66-authentication-rate-limits-imap-pop3-and-managesieve-proxies)):

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `true` | Share the rate limiters with the proxies of the same protocol on every node, this one included. The name statistics are always shared while it is on. |
| `sync_blocks` | bool | `true` | Share Tier 2 IP blocks. |
| `sync_failure_counts` | bool | `true` | Share Tier 2 failure counts and progressive delays, from `delay_start_threshold` on, and the successful logins that clear them. |

### 8.15 Persistent auth cache (`[auth_cache]`)

A SQLite cache of credentials, used by proxies that check passwords in the database. See
[PROXY.md](PROXY.md).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | |
| `path` | string | `"/var/cache/sora/auth_cache.db"` | Database file: a path or an SQLite `file:` URI. An in-memory or temporary database (`":memory:"`, `mode=memory`, `vfs=memdb`) is refused. The directory of a plain path is created. |
| `max_age` | duration | `"24h"` | Age after which an entry is fetched again. A value above 7 days (the retention of the credential change feed) is lowered to 7 days, with a warning. |
| `purge_unused` | duration | `"168h"` | Entries unused this long are removed. |
| `cleanup_interval` | duration | `"1h"` | How often old entries are removed. Must be positive. |

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
| `enabled` | bool | `true` | all | `false` keeps the block in the file without checking or starting it. See [section 5](#5-server-blocks). |
| `debug` | bool | `false` | `imap`, `lmtp`, line proxies | Extra diagnostics for this server. Some protocols write a raw protocol trace to the log output whatever the level. On the other server types (`pop3` and `managesieve` included) it is ignored, with a startup warning. See [PROTOCOLS.md](PROTOCOLS.md). |

### 9.2 TLS on the listener

See [TLS.md](TLS.md).

| Key | Type | Default | Applies to | Meaning |
|---|---|---|---|---|
| `tls` | bool | `false` | all but `metrics` | Serve TLS, with this block's certificate files or the `[tls]` manager. |
| `tls_use_starttls` | bool | `false` | backends, line proxies | Plain connection upgraded with STARTTLS instead of implicit TLS. Needs `tls = true`. |
| `tls_cert_file`, `tls_key_file` | string | none | all but `metrics` | Certificate files for this listener. |
| `tls_verify` | bool | `false` | all but `metrics` | See [TLS.md](TLS.md). |
| `tls_default_domain` | string | `[tls.letsencrypt] default_domain` | all but `metrics` | Certificate for clients that send no SNI. |
| `insecure_auth` | bool | `false` | `imap`, `pop3`, `managesieve`, `imap_proxy`, `pop3_proxy`, `managesieve_proxy` | Allow password logins on a plain connection. Without `tls = true` it is always allowed. LMTP has no login and the HTTP servers do not use the key; on the other server types it is ignored, with a startup warning. See [SECURITY.md](SECURITY.md). |

The `metrics` server always speaks plain HTTP. `tls`, `tls_cert_file`, `tls_key_file`,
`tls_verify` and `tls_default_domain` on it only cause a startup warning that names them.

### 9.3 PROXY protocol on the listener

| Key | Type | Default | Applies to | Meaning |
|---|---|---|---|---|
| `proxy_protocol` | bool | `false` | backends, line proxies, `http_admin_api`, `http_user_api`, `user_api_proxy` | Expect a PROXY protocol header from hosts in `trusted_networks`. Needs a non-empty `trusted_networks`. |
| `proxy_protocol_timeout` | duration | `"5s"` | as `proxy_protocol` | Time to wait for the header. |

The `metrics` server reads no PROXY header; on it both keys are ignored, with a startup warning
that names them. `proxy_protocol_trusted_proxies` is not a key: Sora warns about it as unknown.
See [SECURITY.md](SECURITY.md) and [PROXY.md](PROXY.md).

### 9.4 Connection limits

See [SECURITY.md](SECURITY.md).

| Key | Type | Default | Applies to | Meaning |
|---|---|---|---|---|
| `max_connections` | integer | `0` (no limit); `1000` on `lmtp` | all but `metrics` | Concurrent connections of this server. On `lmtp`, `0` or less means 1000. |
| `max_connections_per_ip` | integer | `0` (no limit) | `imap`, `pop3`, `managesieve`, `imap_proxy`, `pop3_proxy`, `managesieve_proxy`, `user_api_proxy` | Concurrent connections from one client IP: with `proxy_protocol`, the client the header names. A client whose own IP is in `trusted_networks` is not limited. With `[cluster] enabled = true`, `imap_proxy`, `pop3_proxy` and `managesieve_proxy` count the IP's connections on every node ([CLUSTER.md](CLUSTER.md#65-per-ip-connection-counts-imap-pop3-and-managesieve-proxies)). |
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
| `session_memory_limit` | size | `"100mb"` | `imap`, `pop3` | Memory one session may allocate. `"0"` means no limit. A message that can never fit it is refused (IMAP `NO [LIMIT]`, POP3 `-ERR [SYS/PERM]`); start-up and a reload warn when it is below the `max_message_size` of an `lmtp` server in the same file. |
| `max_auth_errors` | integer | `2` | `imap_proxy`, `pop3_proxy`, `managesieve_proxy` | Protocol errors before login (unknown or malformed commands, logins refused without TLS) before the proxy disconnects. Wrong passwords do not count; the login rate limiter handles those. `0` or less means 2. |
| `search_rate_limit_per_min` | integer | `60` | `imap` | Search cost per account per window. `0` or less disables the limit. |
| `search_rate_limit_window` | duration | `"1m"` | `imap` | Window of the search rate limit. |
| `search_rate_limit_burst` | integer | `search_rate_limit_per_min` | `imap` | Searches allowed back to back. `0` or less means the default. |
| `thread_max_messages` | integer | `50000` | `imap` | Matches one THREAD command may process. `0` or less means the default. |
| `redirect_rate_limit` | integer | `100` | `lmtp`, `http_admin_api` | Sieve redirects per account per window. `0` means no limit. |
| `redirect_rate_window` | duration | `"1h"` | `lmtp`, `http_admin_api` | Window of the redirect limit. Must be positive. The cleaner keeps redirect records for the longest window or `[cleanup] grace_period`, whichever is longer ([STORAGE.md](STORAGE.md#11-the-cleanup-cycle)). |
| `max_redirect_hops` | integer | `2` | `lmtp`, `http_admin_api` | Redirects of one message before further ones are suppressed. `0` means no limit. |
| `preview_s3_per_min` | integer | `300` | `imap` | S3 downloads per account per minute to answer FETCH PREVIEW. `0` or less means no limit. |
| `preview_s3_burst` | integer | `min(200, preview_s3_per_min)` | `imap` | Of those, how many may run back to back. |
| `preview_s3_node_per_min` | integer | `3000` | `imap` | The same downloads for the whole server. `0` or less means no limit. |
| `preview_s3_max_size` | size | `[local_cache] max_object_size` | `imap` | Largest message downloaded for a preview. |

### 9.6 Timeouts (`[server.timeouts]`)

See [SECURITY.md](SECURITY.md) and [PROTOCOLS.md](PROTOCOLS.md).
A key or per-command table set on a server type not listed for it is ignored, with a startup
warning that names it.

| Key | Type | Default | Applies to | Meaning |
|---|---|---|---|---|
| `command_timeout` | duration | `imap`, `imap_proxy`: `30m`; `pop3`, `pop3_proxy`: `10m`; `managesieve`, `managesieve_proxy`: `3m`; `lmtp`: `5m` | `imap`, `pop3`, `managesieve` and their proxies, `lmtp` | Idle time before a connection is closed. |
| `absolute_session_timeout` | duration | `24h`; `lmtp_proxy`: `5m` | `imap`, `pop3`, `managesieve`, line proxies | Longest a session may last. |
| `min_bytes_per_minute` | integer | `0` (off) | `imap`, `pop3`, `managesieve`, `imap_proxy`, `pop3_proxy`, `managesieve_proxy` | Minimum throughput before a slow connection is closed. |
| `scheduler_shard_count` | integer | `0` | none | Accepted but has no effect, with a startup warning: all servers share one timeout scheduler, sized by [`[timeout_scheduler] shard_count`](#818-timeout-scheduler-timeout_scheduler). |

An `imap` server's `command_timeout` of 35 minutes or more is capped, with a startup warning: the
IMAP library closes an idle logged-in connection at 35 minutes itself, without a `BYE`. A
duration that does not parse means the default, with a startup warning.

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
A key set on a server type not listed under "Applies to" is ignored, with a startup warning that
names it. The same holds for `[[server.client_filters]]`.

| Key | Type | Default | Applies to | Meaning |
|---|---|---|---|---|
| `append_limit` | size | `"25mb"` | `imap` | Largest message accepted by APPEND. |
| `max_message_size` | size | `"50mb"` | `lmtp`, `lmtp_proxy`, `http_admin_api` | Largest message accepted for delivery. `0` also means 50 MiB. |
| `max_script_size` | size | `"16kb"` | `managesieve` | Largest Sieve script. |
| `supported_extensions` | list of strings | the default set | `managesieve_proxy` | Sieve extensions the proxy advertises. A `managesieve` backend uses `[sieve] enabled_extensions`. |
| `enable_preview` | bool | `false` | `imap` | Advertise FETCH PREVIEW (RFC 8970). |
| `disabled_caps` | list of strings | none | `imap` | Capabilities never advertised. Capabilities that depend on a removed one are removed too (for example QRESYNC with CONDSTORE); see [PROTOCOLS.md](PROTOCOLS.md#6-controlling-imap-capabilities). |
| `additional_caps` | list of strings | none | `imap`, `imap_proxy` | Extra capability names advertised as written. |
| `id_name` | string | `"Sora"` | `imap`, `imap_proxy` | `name` in the IMAP ID answer. |
| `id_version` | string | `imap`: the build version; `imap_proxy`: `"1.0"` | `imap`, `imap_proxy` | `version` in the IMAP ID answer. |
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
A key set on a server type not listed under "Applies to" is ignored, with a startup warning that
names it.

| Key | Type | Default | Applies to | Meaning |
|---|---|---|---|---|
| `master_username`, `master_password` | string | none | `imap`, `pop3`, `managesieve`, `imap_proxy`, `pop3_proxy`, `managesieve_proxy` | A master login. A username without a password stops startup. |
| `master_sasl_username`, `master_sasl_password` | string | none | as above | The SASL master login proxies use towards backends. A username without a password stops startup. |
| `master_sasl_allowed_networks` | list of strings | empty (any source) | `imap`, `pop3`, `managesieve` | Source networks allowed to use a master login on this backend: both the SASL master login and the `user@domain@master_username` form. It is matched against the real TCP peer, never an address forwarded with PROXY, XCLIENT or ID, so list the proxy hosts. An entry that is not an IP address or CIDR block stops startup. Proxies do not read it. |

### 9.9 Authentication rate limit (`[server.auth_rate_limit]`)

Applies to `imap`, `pop3`, `managesieve`, `imap_proxy`, `pop3_proxy`, `managesieve_proxy`,
`http_user_api` and `user_api_proxy`; on another server type the table is ignored, with a startup
warning. When `enabled = true`, every key you leave
out, or set to 0, gets the default below. A negative value, a `delay_multiplier` of `nan` or
`inf`, or an `exempt_networks` entry that is not an IP address or CIDR block stops startup
([section 4](#4-checks-at-startup)). See [AUTHENTICATION.md](AUTHENTICATION.md).

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

Without a `[server.lookup_cache]` table, the cache is on for `imap`, `pop3`, `managesieve` and the
line proxies, and off for `user_api_proxy`. A table you write starts from the defaults and changes
only the keys it names, so a table without `enabled` turns the cache on, `user_api_proxy`
included. The `http_user_api` backend always reads its credential hash and token epoch from the
primary. It keeps no login cache, like the `lmtp`, `metrics` and `http_admin_api` servers; on these
types the table is ignored, with a startup warning.

A proxy whose `[server.remote_lookup] url` contains `$ip` never uses the cache, whatever the table
says: the lookup's answer may then depend on the client's address, and the cache is keyed by user.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | see above | |
| `positive_ttl` | duration | `"5m"` | How long a successful lookup is kept. |
| `negative_ttl` | duration | `"1m"` | How long a failed lookup is kept. |
| `max_size` | integer | `50000` | Entries kept. `0` or less means the default. When the cache is full, the entry closest to expiry makes room. |
| `cleanup_interval` | duration | `"5m"` | How often expired entries are removed. |
| `positive_revalidation_window` | duration | `"30s"` | Revalidation age for successful credential entries; line proxies apply it when a different password arrives. Not used by `lmtp_proxy` or `user_api_proxy`, which cache routes and warn at startup when it is set. |

### 9.11 Proxy keys

Read by the line proxies and `user_api_proxy`. See [PROXY.md](PROXY.md).
A key set on a server type not listed under "Applies to" is ignored, with a startup warning that
names it.

| Key | Type | Default | Applies to | Meaning |
|---|---|---|---|---|
| `remote_addrs` | list of strings | none | proxies | Backends. Required unless the file has `[[pool]]` blocks, and not allowed together with them. An entry without a host (`""`, `":143"`), or one with whitespace inside it, is refused. |
| `remote_port` | integer or string | none | proxies | Port for backends written without one (`remote_addrs` entries and `[[pool]]` members). |
| `remote_tls` | bool | `false` | proxies | TLS to the backends (HTTPS for `user_api_proxy`). |
| `remote_tls_use_starttls` | bool | `false` | line proxies | STARTTLS to the backends. Needs `remote_tls`; without it the key is ignored with a warning and the backend leg is plaintext. |
| `remote_tls_verify` | bool | `false` | proxies | Verify backend certificates. |
| `remote_tls_ca_file` | string | none | proxies | PEM file of CA certificates for backend certificates (private CA, self-signed backends); without it, the system roots. Used only for backends in no `[[pool]]`. |
| `remote_use_proxy_protocol` | bool | `false` | proxies | Send a PROXY protocol header to the backends. |
| `remote_use_id_command` | bool | `false` | `imap_proxy` | Forward the client's address with IMAP ID. |
| `remote_use_xclient` | bool | `false` | `pop3_proxy`, `lmtp_proxy` | Forward the client's address with XCLIENT. |
| `remote_skip_forwarding_with_proxy_protocol` | bool | `false` | `imap_proxy`, `pop3_proxy` | Leave out the configured ID or XCLIENT command on a backend connection that starts with a PROXY header. Has an effect only together with `remote_use_proxy_protocol` and that forwarding command, and not on a `[[server]]` block when the file has `[[pool]]` blocks (the pool's or the lookup's own setting applies there). See [PROXY.md](PROXY.md#88-leaving-out-id-and-xclient-next-to-proxy). |
| `remote_use_utf8` | bool | `false` | `pop3_proxy` | Offer POP3 UTF8 and pass it to the backends. Only for Sora backends. |
| `connect_timeout` | duration | `"30s"` | proxies | Time to connect to a backend. |
| `auth_idle_timeout` | duration | `"2m"` | `imap`, `pop3`, `managesieve`, line proxies | Idle time allowed before login. |
| `enable_affinity` | bool | `false` | proxies | Prefer the backend a user used last. |
| `remote_health_checks` | bool | `true` | proxies | Check backend health. |
| `remote_dns_refresh` | duration | `"5m"` | proxies | How often backend host names are resolved again. `"0"` keeps the startup addresses. |

### 9.12 Remote lookup (`[server.remote_lookup]`)

Asks an HTTP API which backend serves a user, or checks the password there. Applies to the line
proxies and `user_api_proxy`; on another server type the table is ignored, with a startup warning.
A key that only some of them read says which; on the others it is ignored, with a startup warning
that names it. See [PROXY.md](PROXY.md).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | |
| `url` | string | none | Lookup endpoint. Required when enabled. `$email` is replaced by the URL-encoded address and `$ip` by the client's address, in the path or query only. `https://` is required unless the host is `localhost` or a loopback address. |
| `timeout` | duration | `"5s"` | HTTP timeout. |
| `auth_token` | string | none | Bearer token. |
| `lookup_local_users` | bool | `false` | Look in the local database when the API does not know the user. Needs a database. |
| `user_not_found_response` | string | `"reject"` | `lmtp_proxy` only. LMTP answer for an unknown user: `"reject"` (550) or `"tempfail"`. Other values mean `"reject"`. |
| `restrict_to_pool` | bool | `false` | Refuse a backend address from the API that is not one of this proxy's own backends (`remote_addrs` or `[[pool]]` members). |
| `remote_tls` | bool | `false` | TLS to backends the API names. Line proxies only: `user_api_proxy` dials them with the `[[server]]` block's own `remote_tls`, `remote_tls_verify` and `remote_use_proxy_protocol`. |
| `remote_tls_use_starttls` | bool | `false` | STARTTLS to those backends. Needs `remote_tls`. Line proxies only. |
| `remote_tls_verify` | bool | `true` | Verify their certificates. Line proxies only. |
| `remote_port` | integer or string | see below | Port for backends the API names without one. |
| `remote_use_proxy_protocol` | bool | `false` | Line proxies only. |
| `remote_use_id_command` | bool | `false` | IMAP only. |
| `remote_skip_forwarding_with_proxy_protocol` | bool | `false` | IMAP and POP3 only. As the `[[server]]` key of the same name, for backends the API names. |
| `remote_use_xclient` | bool | `false` | POP3 and LMTP only. |
| `remote_use_utf8` | bool | `false` | POP3 only. |

A backend the API names without a port is dialed at the first of these that is set: this table's
`remote_port`; the `[[server]]` block's `remote_port`; with `remote_tls` and without
`remote_tls_use_starttls`, 993 for IMAP and 995 for POP3; the protocol's standard port (IMAP 143,
POP3 110, ManageSieve 4190, LMTP 24; for `user_api_proxy`, the port of the scheme).

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
| `remote_skip_forwarding_with_proxy_protocol` | bool | `false` | IMAP and POP3 only. Leave out ID or XCLIENT on a connection to this pool that starts with a PROXY header. Needs `remote_use_proxy_protocol` and `remote_use_id_command` or `remote_use_xclient`; without them it is warned about. |

At startup Sora checks the pools as a whole (`Config.ValidatePools` in
[config/pools.go](../config/pools.go)) and stops with a `[[pool]]` error when:

- a pool has no name, a name with spaces, a name used twice, or no backends;
- a backend is empty or has spaces inside it (the ends are trimmed);
- a backend appears twice, or in two pools, in whatever letter case or IP spelling. A backend
  without a port clashes with any entry for the same host; entries with explicit, different ports
  may share a host (for example one pool per protocol on one machine);
- `remote_tls_use_starttls` or `remote_tls_ca_file` is set without `remote_tls`;
- more than one pool has `default = true`;
- a proxy server also has `remote_addrs`;
- a pool backend has no port and a proxy server has no `remote_port`;
- there is no default pool and a proxy has no remote lookup, or has `lookup_local_users = true`.

Only enabled `[[server]]` blocks take part in these checks.
