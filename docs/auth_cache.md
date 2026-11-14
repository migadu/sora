# Authentication Cache

## Overview

The authentication cache (`authcache`) is a persistent, SQLite-backed credential cache that eliminates the **thundering herd problem** when proxy servers restart. After a restart, thousands of mail clients reconnect simultaneously, each requiring authentication against the PostgreSQL database. Without caching, this creates a massive spike in database load.

The auth cache stores successful authentication lookups (address → account\_id, password\_hash) on local disk. On subsequent authentication attempts, credentials are verified locally against the cached hash (~0.1ms) instead of making a network round-trip to PostgreSQL (~10–50ms).

```
┌──────────────┐    cache hit     ┌─────────────┐
│  Proxy Auth  │ ───────────────► │  SQLite DB   │  ~0.1ms local
│  Request     │                  │  (local disk)│
│              │    cache miss    └─────────────┘
│              │ ───────────────► ┌─────────────┐
│              │                  │  PostgreSQL  │  ~10-50ms network
└──────────────┘                  │  (remote)    │
                                  └─────────────┘
```

## Scope

The auth cache applies **only to proxy servers** that authenticate users against the PostgreSQL database:

| Server Type | Uses Auth Cache | Thundering Herd Protection |
|---|---|---|
| IMAP proxy | ✅ Yes | Auth cache |
| POP3 proxy | ✅ Yes | Auth cache |
| ManageSieve proxy | ✅ Yes | Auth cache |
| LMTP proxy | — | No user authentication |
| IMAP backend | ❌ No | Startup throttle (30s) |
| POP3 backend | ❌ No | Startup throttle (30s) |
| ManageSieve backend | ❌ No | Startup throttle (30s) |

**Backend servers** do not use the auth cache. They have direct database access with connection pooling and use a startup throttle mechanism (30-second grace period with ~200 connections/second ramp-up) to spread reconnection load after restart.

**Remote lookup** authentication (where a proxy routes to a remote backend for auth) is handled separately and does **not** use the auth cache. The cache is only populated from successful PostgreSQL lookups.

## Configuration

Add an `[auth_cache]` section to `config.toml`:

```toml
[auth_cache]
enabled = true
path = "/var/cache/sora/auth/auth_cache.db"
max_age = "24h"            # entries older than this are considered stale
cleanup_interval = "1h"    # Run cleanup every hour
purge_unused = "168h"      # 7 days - entries unused for this long are removed
```

### Parameters

| Parameter | Default | Description |
|---|---|---|
| `enabled` | `false` | Enable the persistent auth cache |
| `path` | `/var/cache/sora/auth_cache.db` | Path to the SQLite database file |
| `max_age` | `24h` | Maximum age before an entry is considered expired |
| `cleanup_interval` | `1h` | How often the cleanup loop runs to purge stale entries |
| `purge_unused` | `168h` (7 days) | Entries unused for this duration are removed |

The `[auth_cache]` is a **global configuration** — when enabled, it applies to all proxy servers automatically. There is no per-proxy cache configuration.

## Authentication Flow

When a proxy server authenticates a user against the database, the following steps occur:

```
1. Check auth cache (SQLite)
   ├── Cache HIT + password matches → return success (no DB needed)
   ├── Cache HIT + password mismatch → invalidate entry, go to step 2
   └── Cache MISS → go to step 2

2. Fetch credentials from PostgreSQL
   ├── User not found → return error
   └── Credentials returned → go to step 3

3. Verify password against DB hash
   ├── Password mismatch → return error
   └── Password matches → go to step 4

4. Cache successful authentication (async)
   └── Store address, account_id, password_hash in SQLite

5. Rehash if needed (async, if bcrypt cost is outdated)
   └── Update DB and cache with new hash
```

### Key behaviors

- **Cache miss**: Falls through to PostgreSQL transparently.
- **Password changed**: If the cached hash doesn't match the supplied password, the stale entry is invalidated and authentication falls through to PostgreSQL. If the new password is correct against the DB, the cache is updated with the fresh hash.
- **Wrong password**: If both cache and DB reject the password, the caller sees a normal authentication failure. The stale cache entry is cleared (conservative approach).
- **Cache errors**: Any SQLite error is logged and authentication proceeds to PostgreSQL. The cache never causes authentication to fail.

## Rate Limiting

The auth cache does **not** interfere with auth rate limiting. Rate limiting is handled by the proxy server layer (`authLimiter`), which records success/failure **after** the authentication method returns. The cache is transparent to the rate limiter:

- Cache hit → success → rate limiter records success
- Cache miss → DB success → rate limiter records success
- Cache miss → DB failure → rate limiter records failure

## Database Schema

```sql
CREATE TABLE auth_cache (
    address TEXT PRIMARY KEY,       -- Normalized email (lowercase, trimmed)
    account_id INTEGER NOT NULL,    -- Account ID from PostgreSQL
    password_hash TEXT NOT NULL,    -- Full hashed password (bcrypt/SSHA512/etc)
    cached_at INTEGER NOT NULL,     -- Unix timestamp when cached
    last_used INTEGER NOT NULL,     -- Unix timestamp of last successful use
    hit_count INTEGER DEFAULT 0     -- Lifetime hit count for this entry
);
```

SQLite is configured with:
- **WAL mode** for concurrent read/write access
- **busy\_timeout = 5000ms** to handle lock contention
- **synchronous = NORMAL** for performance (acceptable for a cache)

## Corruption Recovery

If the SQLite database is corrupted (e.g., due to disk failure or unclean shutdown), the cache automatically:

1. Detects corruption on startup via an integrity check
2. Removes the corrupted database files (`.db`, `-wal`, `-shm`, `-journal`)
3. Creates a fresh database
4. Logs a warning and continues normally

The cache is strictly optional — if initialization fails entirely, the server continues without caching.

## Monitoring

### Prometheus Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `sora_auth_cache_operations_total` | Counter | `result` (hit/miss/error) | Total cache operations |
| `sora_auth_cache_entries_total` | Gauge | — | Current number of cached entries |

### Admin API

```
GET /admin/auth-cache/stats
```

Returns:
```json
{
  "enabled": true,
  "total_entries": 1523,
  "session_hits": 45230,
  "session_misses": 1523,
  "hit_rate_percent": 96.74,
  "lifetime_hit_count": 892451
}
```

### CLI

```bash
sora-admin --config config.toml auth-cache status
```

```
Auth Cache Status
==================

Status: ENABLED

  Cached entries:      1523
  Session hits:        45230
  Session misses:      1523
  Hit rate:            96.7%
  Lifetime hits:       892451
```

## Performance Impact

### Before (all DB authentication)

```
1000 concurrent reconnections = 1000 PostgreSQL queries
Each query: ~10-50ms (network + DB)
Total load spike: 10-50 seconds of sustained DB pressure
```

### After (with auth cache)

```
~950 cache hits (0.1ms each) = ~100ms total
~50 cache misses (DB queries) = ~500-2500ms
Total load spike: ~600-2600ms (4-20x improvement)
```

The cache is most effective immediately after a restart, when the hit rate is highest (all recently-active users are cached). Over time, as new users authenticate, the cache naturally fills with their credentials.

## File Layout

```
authcache/
├── authcache.go          # Core cache implementation
└── authcache_test.go     # 19 unit tests (race-safe)
```

Integration points:
- `config/config.go` — `AuthCacheConfig` struct
- `pkg/resilient/authentication.go` — `AuthenticateWithRetry()` integration
- `pkg/resilient/database.go` — `SetAuthCache()` / `authCache` field
- `pkg/metrics/metrics.go` — Prometheus counters and gauge
- `cmd/sora/main.go` — Initialization and lifecycle management
- `server/adminapi/server.go` — `/admin/auth-cache/stats` endpoint
- `cmd/sora-admin/auth_cache.go` — CLI `auth-cache status` command
