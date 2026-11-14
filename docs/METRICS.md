# Sora Metrics and Health Reference

This document covers how you watch a running Sora node. It describes the Prometheus metrics endpoint
and how to secure it, lists every metric Sora registers with its type, labels and meaning, explains
the built-in health checks and where their results show up, and ends with the metrics and log lines
worth alerting on.

It is for operators who build dashboards and alerts, and for contributors who add a metric. Every
metric here was found in the code: the definitions are in [pkg/metrics/](../pkg/metrics/) and one in
[db/db.go](../db/db.go).

## Contents

1. [The metrics server](#1-the-metrics-server)
2. [Reading the metrics](#2-reading-the-metrics)
3. [Metric reference](#3-metric-reference)
4. [The periodic collector](#4-the-periodic-collector)
5. [Health checks](#5-health-checks)
6. [Circuit breakers](#6-circuit-breakers)
7. [What to alert on](#7-what-to-alert-on)
8. [Log lines worth watching](#8-log-lines-worth-watching)

---

## 1. The metrics server

Metrics are served by a `[[server]]` block of type `metrics`. Without one, Sora still counts
internally but nothing can scrape the numbers.

```toml
[[server]]
type = "metrics"
name = "metrics"
addr = "10.0.0.5:9090"            # a private address, not ":9090"
path = "/metrics"
allowed_hosts = ["10.0.0.20"]     # your Prometheus servers
api_key = "a-long-random-token"   # optional bearer token
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| `addr` | string | required | Listen address. |
| `path` | string | — | URL path, such as `"/metrics"`. Only this exact path serves metrics. |
| `allowed_hosts` | list of strings | empty (any host) | IP addresses or CIDR blocks allowed to scrape. Other peers get `403 forbidden`. |
| `api_key` | string | none | When set, every request needs `Authorization: Bearer <key>`. Without the header the answer is `401 unauthorized`; with a wrong key, `403 forbidden`. |
| `enable_domain_metrics` | bool | `true` | Count activity per mail domain (see [3.18](#318-domain-and-user-metrics)). |
| `enable_user_metrics` | bool | `false` | Give heavy users their own series (see [3.18](#318-domain-and-user-metrics)). |
| `user_metrics_threshold` | integer | `1000` | Commands plus connections after which a user gets its own series. |
| `max_tracked_users` | integer | `1000` | How many users may get their own series. |
| `hash_usernames` | bool | `true` | Put a 16-character SHA-256 prefix of the user name in labels instead of the name. |

How access control works ([cmd/sora/metrics_access.go](../cmd/sora/metrics_access.go)):

- `allowed_hosts` is matched against the TCP peer address. `X-Forwarded-For` and similar headers are
  ignored, and the metrics listener does not read the PROXY protocol.
- `allowed_hosts` is checked first, then `api_key`. With both set, a scrape must come from an allowed
  host and carry the token. The token is compared in constant time.
- With neither set, anyone who reaches the port can read the metrics. Sora logs a warning at
  startup when such a listener is on a publicly reachable address.

The endpoint always speaks plain HTTP. A `tls = true` in the block is ignored with a startup
warning. If the token has to cross a network you do not trust, put a TLS-terminating proxy in front.

Treat the endpoint as sensitive. With domain metrics on, it shows which domains are active. With
user metrics on, it can show user names, and with `hash_usernames = false` it shows them in clear
text.

The five `enable_*`, `user_metrics_threshold`, `max_tracked_users` and `hash_usernames` settings
apply to the whole process. With several `metrics` blocks, the last one in the file wins.

The metrics server is not reloaded by `SIGHUP`: restart Sora to change it. See
[CONFIGURATION.md](CONFIGURATION.md#6-reloading-with-sighup).

### Prometheus scrape configuration

```yaml
scrape_configs:
  - job_name: sora
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/sora-metrics.token
    static_configs:
      - targets: ["10.0.0.5:9090", "10.0.0.6:9090"]
```

Scrape every node: each node counts only its own work.

---

## 2. Reading the metrics

- **Names.** Every Sora metric starts with `sora_`. The endpoint also serves the standard Go runtime
  and process metrics of the Prometheus client library (`go_*`, `process_*`) and its own handler
  metrics (`promhttp_metric_handler_*`).
- **Per node.** Each node keeps its own counters. Use the `instance` label Prometheus adds to tell
  nodes apart.
- **Cluster-wide gauges.** A few gauges are read from the shared database, so every node reports
  the same value: `sora_accounts_total`, `sora_mailboxes_total`, `sora_fts_rows_total`,
  `sora_fts_queue_depth`, `sora_account_purges_pending`,
  `sora_account_purge_oldest_pending_seconds`, and `sora_queue_depth` for
  `s3_upload_pending` and `s3_upload_failed`. Aggregate them with `max()`, not `sum()`.
- **Series appear on first use.** A labelled series exists only after its first event, so a
  counter for an error that has not happened yet is absent, not zero. Write alerts that tolerate
  missing series.
- **Common labels.**
  - `protocol` names the server type: `imap`, `pop3`, `lmtp`, `managesieve`, `imap_proxy`,
    `pop3_proxy`, `lmtp_proxy`, `managesieve_proxy`, `userapi`, `userapi_proxy`. The proxy
    routing metrics use the backend protocol instead (`imap`, `pop3`, ...), and a few metrics
    add other values (see each table).
  - `server_name` is the `name` of the `[[server]]` block.
  - `hostname` is the node's host name. It is empty on the `userapi_proxy` connection metrics.
  - `role` is `read` or `write`, for the two database pools.

Types: a **counter** only goes up (use `rate()` or `increase()`), a **gauge** goes up and down, a
**histogram** exposes `_bucket`, `_sum` and `_count` series (use `histogram_quantile()`).

---

## 3. Metric reference

### 3.1 Connections and sessions

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `sora_connections_total` | counter | `protocol`, `server_name`, `hostname` | Connections accepted. Protocols: `imap`, `pop3`, `lmtp`, `managesieve`, the four `*_proxy` types, and `userapi_proxy` (requests). |
| `sora_connections_current` | gauge | `protocol`, `server_name`, `hostname` | Connections open now. Same protocols. |
| `sora_authenticated_connections_current` | gauge | `protocol`, `server_name`, `hostname` | Logged-in sessions now, on `imap`, `pop3` and `managesieve` backends. |
| `sora_connection_duration_seconds` | histogram | `protocol`, `server_name`, `hostname` | Length of finished connections on `imap`, `pop3`, `lmtp` and `managesieve` backends. Buckets from 5 ms to 24 h. |
| `sora_connection_timeouts_total` | counter | `protocol`, `server_name`, `hostname`, `reason` | Connections closed by a timeout. `reason`: `idle`, `slow_throughput`, `session_max`, `tls_on_plain_port`, `plain_text_on_tls_port`. |

### 3.2 Authentication and rate limiting

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `sora_authentication_attempts_total` | counter | `protocol`, `server_name`, `hostname`, `result` | Login attempts. `result`: `success`, `failure`; `rate_limited` on `pop3`; `unavailable` on the IMAP, POP3 and ManageSieve proxies (the remote lookup service was temporarily unavailable). |
| `sora_password_verification_attempts_total` | counter | `hash_type`, `result` | Password hash checks. `hash_type`: `bcrypt`, `blf_crypt`, `ssha512`, `sha512`, `unknown`. `result`: `success`, `failure`. |
| `sora_auth_rate_limiter_ip_username_entries` | gauge | `protocol`, `server_name`, `hostname` | Tracked IP-and-user pairs in the login rate limiter. `protocol`: `imap`, `pop3`, `managesieve`, `imap_proxy`, `pop3_proxy`, `managesieve_proxy`, `userapi`. |
| `sora_auth_rate_limiter_ip_entries` | gauge | same | Tracked IPs with failures. |
| `sora_auth_rate_limiter_username_entries` | gauge | same | Tracked user names with failures. |
| `sora_auth_rate_limiter_blocked_ips` | gauge | same | IPs blocked now. |
| `sora_auth_delay_queue_depth` | gauge | `protocol` | Logins waiting in a progressive delay now. |
| `sora_auth_delay_rejections_total` | counter | `protocol` | Logins refused because too many from the same IP were already waiting. |
| `sora_auth_delay_completed_total` | counter | `protocol` | Delays that ran to the end. |
| `sora_auth_delay_cancelled_total` | counter | `protocol` | Delays cut short, for example by a disconnect. |

The `sora_auth_delay_*` metrics only exist while `[server.auth_rate_limit]` is enabled. Their
`protocol` is the server type that delayed the login, as in the rate limiter metrics; every login
method of a server (LOGIN, AUTHENTICATE, master user) counts under it. Per-address detail is in
the log and in `GET /admin/auth/blocked`. See [AUTHENTICATION.md](AUTHENTICATION.md).

### 3.3 Commands and protocol errors

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `sora_commands_total` | counter | `protocol`, `command`, `status` | Commands handled by `imap`, `pop3`, `lmtp` and `managesieve` backends. `status` on IMAP: `success`, `client_error`, `server_error`. On the others: `success`, `failure`. |
| `sora_command_duration_seconds` | histogram | `protocol`, `command` | Time per command. Buckets from 1 ms to 300 s. |
| `sora_command_timeout_threshold_seconds` | gauge | `protocol` | The idle timeout (`command_timeout`) in force for `imap`, `pop3` and `managesieve`. |
| `sora_protocol_errors_total` | counter | `protocol`, `command`, `error_type`, `severity` | Classified command errors. Mostly IMAP; the proxies count `rate_limited` logins here too. `severity`: `client_error`, `server_error`, or `server_limit` (a search the server refused as too costly). |
| `sora_critical_operation_duration_seconds` | histogram | `operation` | Time of selected slow operations: `pop3_authentication`, `pop3_retrieve`, `managesieve_authentication`, `managesieve_putscript`, `managesieve_setactive`. |

IMAP `error_type` values: `auth_failed`, `server_bug`, `mailbox_not_found`, `not_found`,
`message_too_big`, `service_unavailable`, `invalid_command`, `timeout`, `network_error`,
`network_timeout`, `permission_denied`, `rate_limited`, `invalid_address`, `empty_message`,
`criteria_rejected`, `unknown`. A client that disconnects in the middle of a command is not counted.
Each counted IMAP error is also logged at WARN as `protocol error` with the same labels.

### 3.4 Messages and throughput

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `sora_messages_throughput_total` | counter | `protocol`, `operation`, `status` | Messages handled. `imap`: `fetched`, `appended`. `pop3`: `retrieved`, `deleted`. `lmtp` and `http_delivery` (the admin API's delivery endpoint): `received`, `delivered`. `status` is `success`, and for LMTP deliveries also `failure`, `timeout`, `shutdown`. |
| `sora_bytes_throughput_total` | counter | `protocol`, `direction` | Bytes moved. `direction`: `in`, `out`. Counted by `pop3`, `lmtp`, `http_delivery` and the four proxies. |
| `sora_message_size_bytes` | histogram | `protocol` | Size of delivered messages, for `lmtp` and `http_delivery`. Buckets from 1 KB to 100 MB. |

### 3.5 IMAP

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `sora_imap_idle_connections_current` | gauge | none | IMAP sessions in IDLE now, for the whole process. |
| `sora_imap_notify_sessions_current` | gauge | none | Sessions with an active NOTIFY watch. |
| `sora_imap_notify_events_sent_total` | counter | `type` | NOTIFY updates sent. `type`: `status`, `list`, `fetch`. |
| `sora_imap_notify_overflow_total` | counter | none | NOTIFY watches dropped with NOTIFICATIONOVERFLOW. |
| `sora_imap_search_refused_total` | counter | `reason` | SEARCH, SORT, THREAD and ESEARCH refused with `NO [LIMIT]`. `reason`: `result_cap` (too many matches), `rate_limit` (the account's search rate limit). See [SEARCH.md](SEARCH.md). |
| `sora_imap_preview_total` | counter | `source` | FETCH PREVIEW answers by source: `loaded`, `memo`, `local`, `storage` (an S3 download), `nil` (answered NIL), and the empty answers `unavailable`, `too_large`, `limited`, `error`. |
| `sora_warmup_operations_total` | counter | `server_name`, `state` | Cache warmups at login. `state`: `enqueued`, `dropped`, `started`, `completed`, `cancelled`, `error`. |

### 3.6 Delivery, Sieve and the relay

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `sora_sieve_executions_total` | counter | `protocol`, `result` | Sieve runs at delivery. `protocol`: `lmtp`, `http_delivery`. `result`: `success`, `failure`. |
| `sora_lmtp_external_relay_total` | counter | `result` | Sends by the relay handler, SMTP or HTTP, despite the name. `result`: `success`, `failure`, `circuit_breaker_open`. |
| `sora_relay_queue_depth` | gauge | `state` | Messages in the relay queue on this node. `state`: `pending`, `processing`, `failed`. |
| `sora_relay_delivery_total` | counter | `type`, `result` | Relay attempts. `type`: `redirect`, `vacation`. `result`: `success`, `temporary_failure`, `permanent_failure`, `circuit_breaker_blocked`, `no_handler`. |
| `sora_relay_delivery_duration_seconds` | histogram | `type`, `result` | Time of a relay attempt (`success`, `temporary_failure`, `permanent_failure`). |
| `sora_relay_queue_age_seconds` | histogram | `type` | Age of a message when the worker picks it up. Buckets from 1 s to 1 day. |
| `sora_relay_queue_operations_total` | counter | `operation`, `result` | Queue file operations. `operation`: `enqueue`, `acquire`, `mark_success`, `mark_failure`, `mark_permanent_failure`, `release`. `result`: `success`, `error`. |
| `sora_relay_queue_operation_duration_seconds` | histogram | `operation` | Time of those operations. |

See [RELAY.md](RELAY.md) and [SIEVE.md](SIEVE.md).

### 3.7 ManageSieve

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `sora_managesieve_scripts_uploaded_total` | counter | none | Scripts stored with PUTSCRIPT. |
| `sora_managesieve_scripts_activated_total` | counter | none | Scripts activated with SETACTIVE. |

### 3.8 Proxies and routing

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `sora_proxy_backend_connections_total` | counter | `protocol`, `result` | Connections a proxy opened to a backend. `protocol`: `imap`, `pop3`, `lmtp`, `managesieve`. `result`: `success`, `failure`. |
| `sora_proxy_routing_method_total` | counter | `protocol`, `method` | How the backend was chosen: `remotelookup`, `affinity`, `affinity_cross_protocol`, `consistent_hash`, `roundrobin`. |
| `sora_proxy_pool_route_total` | counter | `protocol`, `pool`, `result` | Routing into named pools. `protocol` adds `userapi`. `pool` is the pool name, or `unknown` for a name the proxy does not have. `result`: `routed`, `unknown_pool`, `no_default`, `ambiguous_pool`. |
| `sora_remote_lookup_result_total` | counter | `protocol`, `result` | Remote lookup outcomes: `success`, `user_not_found_fallback` (tried the local database), `user_not_found_rejected`, on LMTP `user_not_found_reject` or `user_not_found_tempfail`, `transient_error_rejected`, `shutdown`. |
| `sora_remote_lookup_duration_seconds` | histogram | `protocol`, `result` | Time of a remote lookup call. Recorded by the LMTP proxy only. `result`: `success`, `user_not_found`, `transient_error`, `shutdown`. Buckets from 1 ms to 5 s. |

See [PROXY.md](PROXY.md).

### 3.9 Backend maintenance

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `sora_backend_maintenance_hosts` | gauge | none | Backends in maintenance, as this proxy last read the list. |
| `sora_backend_maintenance_poll_failures_total` | counter | none | Failed reads of that list. Until a first read succeeds, the proxy dials no backend. |
| `sora_backend_maintenance_sessions_closed_total` | counter | `proxy` | Sessions a proxy closed because their backend is in maintenance. |
| `sora_backend_maintenance_refusing` | gauge | none | On a backend: `1` while it refuses new sessions because it is in maintenance (or does not know yet), else `0`. |
| `sora_backend_maintenance_sessions_refused_total` | counter | `protocol` | New sessions a backend refused for maintenance. `protocol`: `imap`, `pop3`, `lmtp`, `http_delivery`. |

### 3.10 Cluster state

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `sora_connection_tracker_users` | gauge | `protocol`, `server_name`, `hostname` | Users in the connection tracker. `protocol`: `imap`, `pop3`, `managesieve` on backends; `imap_proxy`, `pop3_proxy`, `managesieve_proxy`, `lmtp_proxy` on proxies. |
| `sora_connection_tracker_instance_ids` | gauge | same | Instance entries across all tracked users. |
| `sora_connection_tracker_ips` | gauge | same | Client IPs across all tracked users. |
| `sora_connection_tracker_broadcast_queue_size` | gauge | same | Gossip messages waiting to be sent. |
| `sora_affinity_manager_entries` | gauge | none | User-to-backend affinities held. |
| `sora_affinity_manager_broadcast_queue_size` | gauge | none | Affinity gossip messages waiting. |

See [CLUSTER.md](CLUSTER.md).

### 3.11 Database

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `sora_db_queries_total` | counter | `operation`, `status`, `role` | Instrumented queries. `operation` is a fixed name per query, such as `auth_get_credential`, `mailbox_get_by_name`, `mailbox_summary`, `message_insert`, `message_expunge`, `flags_set`, `search_thread` or one of the `search_messages_*` variants. `status` is mostly `success` or `error`. |
| `sora_db_query_duration_seconds` | histogram | `operation`, `role` | Time of those queries. Buckets from 1 ms to 60 s. |
| `sora_db_transactions_total` | counter | `status` | Transactions ended. `status`: `commit`, `rollback`. |
| `sora_db_transaction_duration_seconds` | histogram | none | Transaction duration. |
| `sora_db_pool_total_conns` | gauge | `role` | Connections in the pool, refreshed every 15 s and every 30 s. |
| `sora_db_pool_idle_conns` | gauge | `role` | Idle connections. |
| `sora_db_pool_in_use_conns` | gauge | `role` | Connections in use. |
| `sora_db_pool_exhaustion_total` | counter | `role` | Times a pool check (every 30 s) found a pool more than 95% in use. |
| `sora_message_fetch_chunked_total` | counter | `type` | Large message lists read in chunks. `type`: `uid_set`, `seq_set`, `all_messages`. |
| `sora_message_fetch_chunks` | histogram | `type` | Chunks per chunked read. |
| `sora_large_body_storage_skipped_total` | counter | none | Message texts cut to 64 KB before full-text indexing because they were larger. |
| `sora_go_mailbox_lock_wait_seconds` | histogram | none | Time a message insert waited for Sora's in-memory per-mailbox lock before taking a database connection. |
| `sora_mailbox_lock_duration_seconds` | histogram | `protocol`, `lock_type`, `result` | Time to take a session's internal lock. `protocol`: `imap`, `pop3`, `lmtp`, `managesieve`. `lock_type`: `read`, `write`. `result`: `success`, `timeout`. |
| `sora_mailbox_lock_timeouts_total` | counter | `protocol`, `lock_type` | Times that lock could not be taken in time. |

See [DATABASE.md](DATABASE.md).

### 3.12 Object storage

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `sora_s3_operations_total` | counter | `operation`, `status` | S3 operations, counted once after retries settle. `operation`: `GET`, `PUT`, `COPY`, `DELETE`, `DELETE_BULK`, `STAT`. `status`: `success`, `not_found`, `canceled`, `error`. Only `error` means an infrastructure failure. |
| `sora_s3_operation_duration_seconds` | histogram | `operation` | Time of each S3 attempt (`GET`, `PUT`, `DELETE`, `DELETE_BULK`). Buckets from 10 ms to 10 s. |
| `sora_s3_upload_attempts_total` | counter | `result` | Upload attempts by the uploader. `result`: `success`, `failure`. |
| `sora_storage_errors_total` | counter | `operation`, `error_type` | Failed S3 PUT attempts by cause: `timeout`, `canceled`, `access_denied`, `not_found`, `throttled`, `network_error`, `encryption_error`, `unknown`. |

See [STORAGE.md](STORAGE.md).

### 3.13 Caches

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `sora_cache_operations_total` | counter | `operation`, `result` | Reads of the local body cache (`operation="get"`, `result` `hit`, `miss`, `error`). |
| `sora_cache_size_bytes` | gauge | none | Size of the local body cache. |
| `sora_cache_objects_total` | gauge | none | Objects in the local body cache. |
| `sora_lookup_cache_hits_total` | counter | none | Hits of the in-memory login lookup caches, all servers together. |
| `sora_lookup_cache_misses_total` | counter | none | Misses of those caches. |
| `sora_lookup_cache_entries_total` | gauge | per server | Entries in one server's lookup cache. |
| `sora_lookup_cache_hit_rate` | gauge | per server | Hit rate of one server's lookup cache, in percent (0..100). |
| `sora_lookup_cache_shared_fetches_total` | counter | none | Lookups whose result was shared by concurrent requests for the same user, so one database or API call served several logins. |
| `sora_auth_cache_operations_total` | counter | `result` | Reads of the persistent `[auth_cache]`. `result`: `hit`, `miss`, `error`. |
| `sora_auth_cache_entries_total` | gauge | none | Entries in that cache. |

### 3.14 Upload queue and background workers

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `sora_queue_depth` | gauge | `queue_type` | `s3_upload`: uploads in the batch this node leased last. `s3_upload_pending`: uploads not yet in S3, all nodes together. `s3_upload_failed`: uploads that used up `[uploader] max_attempts` (parked), all nodes together. The last two are refreshed every 5 minutes. |
| `sora_queue_processing_lag_seconds` | gauge | `queue_type` | `s3_upload`: age of this node's oldest upload not yet in S3, `0` when there is none. Refreshed every 5 minutes. |
| `sora_upload_worker_jobs_total` | counter | `result` | Upload jobs. `result`: `success`, `failure`, and `cleanup` (staged files removed). |
| `sora_upload_worker_duration_seconds` | histogram | none | Time of an upload job. |
| `sora_fts_queue_depth` | gauge | none | Rows waiting for full-text indexing (no search vector yet). |
| `sora_fts_rows_total` | gauge | none | Rows in the full-text table, a PostgreSQL planner estimate. |
| `sora_fts_rows_indexed_total` | counter | none | Rows this node's FTS worker gave a search vector. |
| `sora_account_purges_pending` | gauge | none | Accounts marked for purging and not finished yet. |
| `sora_account_purge_oldest_pending_seconds` | gauge | none | Age of the oldest pending purge request, `0` when there is none. |
| `sora_account_purges_total` | counter | `result` | Purge attempts by this node's purge worker. `result`: `success`, `failure`. |
| `sora_accounts_total` | gauge | none | Accounts, a planner estimate (includes accounts pending purge). |
| `sora_mailboxes_total` | gauge | none | Mailboxes, a planner estimate. |

See [STORAGE.md](STORAGE.md) and [SEARCH.md](SEARCH.md).

### 3.15 Timeout scheduler

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `sora_timeout_scheduler_connections_total` | gauge | `shard` | Connections a scheduler shard watches. |
| `sora_timeout_scheduler_check_duration_seconds` | histogram | `shard` | Time of one check pass of a shard (every 100 ms). |

### 3.16 Session memory

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `sora_session_memory_peak_bytes` | histogram | `protocol`, `server_name`, `hostname` | Peak memory a finished session allocated, for `imap` and `pop3`. Buckets from 1 KB to 100 MB. |
| `sora_session_memory_limit_exceeded_total` | counter | `protocol`, `server_name`, `hostname` | Commands stopped because the session hit `session_memory_limit`. |

### 3.17 Health checks

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `sora_component_health_status` | gauge | `component`, `hostname` | Latest status of a check: `3` healthy, `2` degraded, `1` unhealthy. |
| `sora_component_health_checks_total` | counter | `component`, `hostname`, `status` | Checks run, by resulting status. |
| `sora_component_health_check_duration_seconds` | histogram | `component`, `hostname` | Time of a check. |

A check's series appear after its first run, one interval after startup. See
[section 5](#5-health-checks).

### 3.18 Domain and user metrics

These carry a mail domain or a user in their labels, so they can create many series. Domain metrics
are on by default; user metrics are off unless a `metrics` server turns them on.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `sora_domain_connections_total` | counter | `protocol`, `domain` | Logins per domain. |
| `sora_domain_commands_total` | counter | `protocol`, `domain`, `command` | Selected commands per domain: IMAP `SELECT`, `SEARCH`, `APPEND`, `EXPUNGE`; POP3 `RETR`; ManageSieve `PUTSCRIPT`. |
| `sora_domain_bytes_total` | counter | `protocol`, `domain`, `direction` | Bytes per domain. |
| `sora_domain_messages_total` | counter | `protocol`, `domain`, `operation` | Messages per domain: `fetched`, `appended`, `deleted`, `delivered`. |
| `sora_top_user_connections_total` | counter | `protocol`, `user_hash` | Connections of a heavy user, counted from the moment it was promoted. |
| `sora_top_user_commands_total` | counter | `protocol`, `user_hash`, `command` | Commands of a heavy user (`command="total"`). |
| `sora_heavy_user_operations_total` | counter | `protocol`, `user_hash`, `operation_type` | Activity of a heavy user. `operation_type`: `command`, `connection`. |

`enable_domain_metrics` turns the `sora_domain_*` series on or off. `enable_user_metrics = true`
counts each user's commands and connections in memory and gives a user its own series once that sum
reaches `user_metrics_threshold` (default 1000), up to `max_tracked_users` users (default 1000).
`user_hash` is a hash of the user name, or the user name itself with `hash_usernames = false`.

### 3.19 Process metrics

The Prometheus client library adds the Go runtime metrics (`go_goroutines`, `go_memstats_*`, ...),
the process metrics (`process_cpu_seconds_total`, `process_resident_memory_bytes`,
`process_open_fds`, ...) and `promhttp_metric_handler_requests_total`.

---

## 4. The periodic collector

On every node with a database connection, a collector runs every 60 seconds
([pkg/metrics/collector.go](../pkg/metrics/collector.go)). It reads from the database and sets:

- `sora_accounts_total` and `sora_mailboxes_total`, from PostgreSQL's row estimates (exact counts
  only while a table has never been analysed);
- `sora_fts_rows_total` (estimate) and `sora_fts_queue_depth` (an exact count of rows without a
  search vector);
- on nodes with a local cache, `sora_cache_objects_total` and `sora_cache_size_bytes`.

Each run logs `MetricsCollector: updated DB metrics` at INFO, with the counts and the total number of
messages. A failed run logs `MetricsCollector: error collecting metrics` and leaves the gauges as
they were.

Other gauges are refreshed by the component that owns them: database pools every 15 and 30 seconds,
the upload queue every 5 minutes, the purge gauges on every purge poll (`[cleanup]
purge_poll_interval`, 30 seconds by default), the relay queue on every worker run.

---

## 5. Health checks

Every node runs a set of health checks in the background ([pkg/health/](../pkg/health/)). Each check
runs on its own interval, the first time one interval after startup.

### The checks

| Component | Runs on | Interval | Timeout | Critical | What it does |
|---|---|---|---|---|---|
| `database` | nodes with a database | 30 s | 10 s | yes | Pings the write pool. |
| `database_read_pool` | nodes with a database | 30 s | 10 s | no | Pings the read pool. |
| `database_failover` | nodes with IMAP, POP3 or LMTP | 45 s | 5 s | yes | Runs `SELECT 1` through the retrying database layer. |
| `s3_storage` | nodes with IMAP, POP3 or LMTP | 60 s | 15 s | yes | Lists one object in the bucket. |
| `cache` | nodes with IMAP, POP3 or LMTP | 30 s | 5 s | no | Reads the local cache statistics. |
| `relay_queue` | nodes with `[relay]` | 60 s | 5 s | no | Fails when more than 1000 messages are pending or more than 100 are processing. |
| `circuit_breaker_smtp_relay`, `circuit_breaker_http_relay` | nodes with `[relay]` | 15 s | 5 s | no | Fails while the relay's circuit breaker is open, or when more than half its recent requests failed. |

Sora also runs `remotelookup_http_<server name>` and a circuit breaker check for each proxy with a
remote lookup. They go unhealthy when the lookup API is down.

### How a status is decided

- A passing check is **healthy**. If at least half of the last 10 runs failed, it stays
  **degraded** until the failures age out.
- A failing check is **degraded** after one failure, and **unhealthy** after 3 failures in a row,
  or when at least half of the last 10 runs failed.
- A check that has never passed is unhealthy from its first failure.
- A check that panics is unhealthy.

The node also keeps an overall status: unhealthy when a critical check is unhealthy, degraded when
any check is degraded, and healthy otherwise. A non-critical check that is unhealthy does not change
it. The overall status is only logged, not exported.

Every failed run logs `Health check failed` at WARN, with `check`, `error`, `status`,
`failure_rate` and `consecutive_failures`. A change of status logs `Health: Check status changed`,
and a change of the overall status `Health: Overall system status changed`.

### Where the results show up

1. **Metrics.** `sora_component_health_status{component="..."}` on each node's metrics endpoint.
   This is the most current view.
2. **The `health_status` table.** On a node with a database, Sora keeps a row per component and
   node (keyed by the host name) with the check's current status.
3. **The admin API**, which reads that table (see [ADMIN_API.md](ADMIN_API.md)):
   - `GET /admin/health/overview` (optional `?hostname=`) counts components by status. It reports
     `unhealthy` when any row is unhealthy, critical or not, and `unreachable` when there are no
     rows.
   - `GET /admin/health/servers/{hostname}` lists the rows of one node.
   - `GET /admin/health/servers/{hostname}/components/{component}` returns one row.
   - `GET /admin/proxy/backends` shows the backend health each proxy on that node sees.
4. **`sora-admin health status`**, which reads the same table, or with `--backends` asks the admin
   API (see [ADMIN_CLI.md](ADMIN_CLI.md)).

Use the metrics for alerting and the table for an overview across nodes.

---

## 6. Circuit breakers

Sora wraps its calls to S3, PostgreSQL, the relay, the remote lookup API and the spam training
endpoint in circuit breakers. A breaker that sees too many failures opens and fails calls at once
for a while, then lets a few through to test the service again.

You can see breaker state in these ways:

- the health checks `circuit_breaker_smtp_relay` and `circuit_breaker_http_relay`
  (`sora_component_health_status`);
- `sora_lmtp_external_relay_total{result="circuit_breaker_open"}` and
  `sora_relay_delivery_total{result="circuit_breaker_blocked"}` for the relay;
- the log lines in [section 8](#8-log-lines-worth-watching), which name the breaker and the old and
  new state (`CLOSED`, `OPEN`, `HALF_OPEN`).

---

## 7. What to alert on

These rules use real metric and label names. Thresholds marked "example" depend on your traffic:
start from what your graphs show on a normal day.

| What | Expression | Why |
|---|---|---|
| A node is not scraped | `up{job="sora"} == 0` | Nothing below works without it. |
| A critical component is down | `sora_component_health_status{component=~"database\|database_failover\|s3_storage"} <= 1` for 2m | The node cannot store or read mail. |
| A component is degraded | `sora_component_health_status < 3` for 15m | Intermittent failures. |
| Uploads are parked | `max(sora_queue_depth{queue_type="s3_upload_failed"}) > 0` for 10m | These bodies exist only on the node that staged them. Run `sora-admin uploader resolve --dry-run` on each node. |
| Uploads are not reaching S3 | `max by (instance) (sora_queue_processing_lag_seconds{queue_type="s3_upload"}) > 3600` for 15m | Transient S3 errors do not count toward `max_attempts`, so a stalled queue never shows up as parked. |
| S3 errors | `sum by (instance) (rate(sora_s3_operations_total{status="error"}[5m])) / sum by (instance) (rate(sora_s3_operations_total[5m])) > 0.05` | More than 5% of S3 operations fail (example). |
| Database pool near its limit | `increase(sora_db_pool_exhaustion_total[15m]) > 0` | A pool was more than 95% in use. |
| Search indexing falls behind | `max(sora_fts_queue_depth) > 50000` for 30m (example) | New mail is missing from search results. |
| Account purges are stuck | `max(sora_account_purge_oldest_pending_seconds) > 3600` | No node with object storage is picking up purge requests. |
| Relay queue backs up | `max by (instance) (sora_relay_queue_depth{state="pending"}) > 1000` for 15m | Redirects and vacation replies wait. Same limit as the `relay_queue` health check. |
| Relay failures | `sum by (instance) (rate(sora_relay_delivery_total{result=~"temporary_failure\|permanent_failure"}[15m])) > 0` | The relay is refusing mail. |
| Delivery failures | `sum by (instance) (rate(sora_messages_throughput_total{protocol="lmtp",operation="delivered",status!="success"}[5m])) > 0` for 10m | LMTP deliveries fail or time out. |
| IMAP server errors | `sum by (instance, command) (rate(sora_commands_total{protocol="imap",status="server_error"}[5m])) > 0.1` (example) | Commands fail on the server side. |
| Proxies cannot reach backends | `sum by (instance, protocol) (rate(sora_proxy_backend_connections_total{result="failure"}[5m])) > 0` for 5m | A backend is down or unreachable. |
| Remote lookup failures | `sum by (instance, protocol) (rate(sora_remote_lookup_result_total{result="transient_error_rejected"}[5m])) > 0` | Logins are refused because the lookup API fails. |
| Pool routing errors | `sum by (instance, protocol, result) (increase(sora_proxy_pool_route_total{result!="routed"}[10m])) > 0` | The lookup API names a pool the proxy does not know, or no default pool exists. |
| Maintenance list unreadable | `increase(sora_backend_maintenance_poll_failures_total[10m]) > 0` | Until a first read succeeds the proxy dials no backend. |
| Login failure spike | `sum by (instance, protocol) (rate(sora_authentication_attempts_total{result="failure"}[5m])) > 5` (example) | Password guessing, or a broken password store. |

Useful graphs, not alerts:

- Query latency: `histogram_quantile(0.99, sum by (le, operation) (rate(sora_db_query_duration_seconds_bucket[5m])))`.
- S3 latency: `histogram_quantile(0.99, sum by (le, operation) (rate(sora_s3_operation_duration_seconds_bucket[5m])))`.
- Open connections against your `max_connections`: `sum by (instance, server_name) (sora_connections_current)`.
- Body cache hit ratio: `rate(sora_cache_operations_total{result="hit"}[5m]) / rate(sora_cache_operations_total{result=~"hit|miss"}[5m])`.
- Timeouts by reason: `sum by (protocol, reason) (rate(sora_connection_timeouts_total[5m]))`.

---

## 8. Log lines worth watching

Sora logs through `[logging]` ([CONFIGURATION.md](CONFIGURATION.md#82-logging-logging)). These
messages point at trouble that a metric shows late or not at all.

| Message | Level | Meaning |
|---|---|---|
| `UploaderMonitor: ALERT - uploads have failed and need attention` | WARN | Parked uploads exist. Logged every 5 minutes while they do, followed by `UploaderMonitor: Stuck upload` lines. |
| `UploaderMonitor: ALERT - pending uploads are not reaching S3` | WARN | This node's oldest pending upload is over an hour old. Logged at most once an hour. |
| `Cleanup: Upload instance is gone - reaping its unuploaded messages as they pass the grace period` | WARN | Messages staged on a node that stopped reporting are being deleted. |
| `Cleanup: Upload instance never reported liveness - ...` | WARN | Pending uploads belong to an instance id that never ran the uploader. |
| `Health check failed` | WARN | A health check failed (see [section 5](#5-health-checks)). |
| `Database pool near exhaustion` | WARN | A database pool is more than 95% in use. |
| `Database query circuit breaker state changed`, `Database write circuit breaker state changed` | INFO | A database breaker opened or closed. |
| `S3 GET circuit breaker changed`, `S3 PUT circuit breaker changed`, `S3 DELETE circuit breaker changed` | INFO | An S3 breaker opened or closed. |
| `Cleanup: Skipping failed upload cleanup - S3 is unhealthy (circuit breaker open). ...` | WARN | The cleaner holds back while S3 is failing. |
| `remotelookup: Circuit breaker state changed`, `remotelookup: Circuit breaker is open` | WARN | The lookup API is failing. |
| `SMTP Relay: Circuit breaker is OPEN - skipping delivery`, `HTTP Relay: Circuit breaker is OPEN - skipping delivery` | WARN | The relay is failing. |
| `command failed` | WARN | An IMAP command ended with a server error. |
| `protocol error` | WARN | A classified IMAP error, with `error_type` and `severity`. |
| `Connection closed - timeout` | INFO | A connection hit a timeout, with `reason`. |
| `Connection limiter: Maximum total connections reached`, `Connection limiter: Maximum connections per IP reached` | INFO | A connection limit refused a client. There is no metric for this. |
| `Connection tracker: Maximum connections per user reached` | INFO | A per-user limit refused a login. |
| `Config reload: ... requires restart to take effect` | INFO, WARN | A `SIGHUP` found changes it cannot apply. |
| `Config reload failed - keeping current config` | ERROR | The file did not parse on `SIGHUP`. |
| `MetricsCollector: error collecting metrics` | ERROR | The database gauges are stale. |
