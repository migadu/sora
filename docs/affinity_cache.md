# Affinity Cache

## Overview

The affinity cache (`affinitycache`) is a persistent, SQLite-backed store for user-to-backend affinity mappings. It ensures that when a proxy server restarts, users are immediately routed back to the same backend they were using before the restart — without waiting for gossip protocol convergence from peer cluster nodes.

Without persistence, a restarted proxy has an empty affinity map. All users are re-routed via consistent-hash or round-robin, which may land them on different backends than before. This causes unnecessary cache misses on the new backend and potential session disruption.

```
Restart WITHOUT affinity cache:
  1. Proxy restarts → affinity map is empty
  2. Users reconnect → routed to random backends (cache cold)
  3. Gossip syncs affinities from peers (50-200ms per event, minutes for full convergence)
  4. Eventually consistent, but users already experienced backend churn

Restart WITH affinity cache:
  1. Proxy restarts → loads affinity map from SQLite (~10ms for 10k entries)
  2. Users reconnect → routed to same backends as before (cache warm)
  3. Gossip syncs any updates that happened while proxy was down
  4. Immediate consistency for cached entries, eventual for new ones
```

## Scope

The affinity cache is only meaningful when **cluster mode** and **server affinity** are both enabled. It persists the in-memory affinity map that the `AffinityManager` maintains via gossip protocol.

| Condition | Affinity Cache Used |
|---|---|
| Cluster enabled + affinity enabled + cache\_path set | ✅ Yes |
| Cluster enabled + affinity enabled + cache\_path empty | ❌ No (in-memory only) |
| Cluster enabled + affinity disabled | ❌ No (no affinity manager) |
| Cluster disabled | ❌ No (no affinity manager) |

The cache is **strictly optional**. If it fails to initialize, the proxy continues with in-memory-only affinity (rebuilt from gossip). If writes fail, errors are logged but operations continue normally.

## Configuration

Add a `cache_path` to the `[cluster.affinity]` section in `config.toml`:

```toml
[cluster.affinity]
enabled = true
ttl = "24h"
cleanup_interval = "1h"
cache_path = "/var/cache/sora/affinity_cache.db"
```

### Parameters

| Parameter | Default | Description |
|---|---|---|
| `enabled` | `true` | Enable cluster-wide server affinity. `false` runs no affinity manager: no proxy on the node keeps affinity and no cache is opened |
| `ttl` | `24h` | How long an affinity mapping persists before expiring |
| `cleanup_interval` | `1h` | How often expired affinities are cleaned up |
| `cache_path` | `""` (disabled) | Path to SQLite database for persistent affinity. Empty = in-memory only |

## How It Works

### Startup

1. `AffinityManager` is created with in-memory map
2. If `cache_path` is configured, `affinitycache.New()` opens (or creates) the SQLite database
3. `LoadPersistedAffinities()` loads all non-expired entries into the in-memory map
4. Gossip protocol begins syncing with cluster peers
5. Gossip events only overwrite in-memory entries if they are **newer** (last-write-wins)

### Runtime

Every affinity change is written through to SQLite asynchronously:

```
SetBackend(user, backend, protocol)
  ├── Update in-memory map (synchronous, under lock)
  ├── Queue gossip broadcast to cluster (synchronous)
  └── Persist to SQLite (async goroutine, non-blocking)

DeleteBackend(user, protocol)
  ├── Remove from in-memory map (synchronous, under lock)
  ├── Queue gossip broadcast to cluster (synchronous)
  └── Delete from SQLite (async goroutine, non-blocking)

HandleClusterEvent(gossip data)
  ├── Apply to in-memory map if newer (synchronous, under lock)
  └── Persist to SQLite (async goroutine, non-blocking)
```

All SQLite writes use fire-and-forget goroutines with a 2-second timeout. A `sync.WaitGroup` tracks pending writes to ensure they complete during graceful shutdown.

### Cleanup

During the periodic cleanup cycle (default: every hour):

1. Expired entries are removed from the in-memory map
2. Expired entries are removed from SQLite (async)
3. Prometheus metrics are updated

## Database Schema

```sql
CREATE TABLE affinity (
    key TEXT PRIMARY KEY,           -- "username:protocol" composite key
    username TEXT NOT NULL,         -- Email address
    protocol TEXT NOT NULL,         -- "imap", "pop3", "managesieve", "lmtp"
    backend TEXT NOT NULL,          -- Backend server address (e.g., "192.168.1.10:143")
    assigned_at INTEGER NOT NULL,   -- Unix timestamp when affinity was set
    expires_at INTEGER NOT NULL,    -- Unix timestamp when affinity expires
    node_id TEXT NOT NULL           -- Cluster node that assigned this affinity
);

CREATE INDEX idx_affinity_expires ON affinity(expires_at);
```

SQLite is configured with:
- **WAL mode** for concurrent read/write access
- **busy\_timeout = 5000ms** to handle lock contention
- **synchronous = NORMAL** for performance (acceptable for a cache)

## Corruption Recovery

If the SQLite database is corrupted (e.g., due to disk failure or unclean shutdown), the cache automatically:

1. Detects corruption on startup via schema creation and integrity check
2. Removes the corrupted database files (`.db`, `-wal`, `-shm`, `-journal`)
3. Creates a fresh, empty database
4. Logs a warning and continues normally

The server never fails to start due to affinity cache issues. A corrupted or missing cache simply means affinities will be rebuilt from gossip (slightly slower convergence, but correct).

## Graceful Shutdown

On server shutdown:

1. `AffinityManager.Stop()` is called via `defer` in `main()`
2. Background cleanup and broadcast goroutines are stopped
3. `wg.Wait()` blocks until all pending async SQLite writes complete
4. The SQLite database is closed cleanly

This ensures no data is lost during shutdown and the WAL is properly checkpointed.

## Monitoring

### Admin API

```
GET /admin/affinity/stats
```

Returns:
```json
{
  "stats": {
    "enabled": true,
    "total_entries": 847,
    "ttl": "1h0m0s",
    "cleanup_interval": "10m0s",
    "by_protocol": {
      "imap": 512,
      "pop3": 234,
      "managesieve": 101
    },
    "memory_usage": {
      "affinity_entries": 847,
      "broadcast_queue": 3,
      "broadcast_queue_max": 5000,
      "queue_utilization": 0.06
    }
  }
}
```

### CLI

```bash
sora-admin --config config.toml affinity-cache status
```

```
Affinity Cache Status
=====================

Status: ENABLED

  Cached entries:      847
  TTL:                 1h0m0s
  Cleanup interval:    10m0s

  Entries by protocol:
    imap        : 512
    pop3        : 234
    managesieve : 101

  Memory / Queue Info:
    Broadcast queue:   3 / 5000 (0.1%)
```

### Prometheus Metrics

| Metric | Type | Description |
|---|---|---|
| `sora_affinity_manager_entries` | Gauge | Current number of in-memory affinity entries |
| `sora_affinity_manager_broadcast_queue` | Gauge | Current broadcast queue size |

## Relationship to Auth Cache

The affinity cache and auth cache are independent systems that solve different problems:

| | Auth Cache | Affinity Cache |
|---|---|---|
| **Problem** | Thundering herd on DB for authentication | Loss of user-to-backend routing on restart |
| **Storage** | SQLite | SQLite |
| **Data** | Credentials (address → account\_id, hash) | Routing (user:protocol → backend) |
| **Source of truth** | PostgreSQL database | Gossip protocol (cluster) |
| **Write pattern** | On successful DB auth | On every affinity change |
| **Read pattern** | On every auth attempt | On startup only (then in-memory) |
| **Config section** | `[auth_cache]` | `[cluster.affinity]` |
| **Without it** | All auth hits PostgreSQL | Affinities rebuilt from gossip |

Both caches:
- Are strictly optional (server continues without them)
- Auto-recover from SQLite corruption
- Use WAL mode for performance
- Never block the main request path
- Are closed cleanly during graceful shutdown

## File Layout

```
affinitycache/
├── affinitycache.go          # Core store implementation
└── affinitycache_test.go     # 12 unit tests (race-safe)
```

Integration points:
- `config/config.go` — `ClusterAffinityConfig.CachePath` field
- `server/affinity_manager.go` — `AffinityPersistStore` interface, write-through hooks
- `cmd/sora/main.go` — Initialization and lifecycle management
- `server/adminapi/affinity.go` — `/admin/affinity/stats` endpoint
- `cmd/sora-admin/affinity_cache.go` — CLI `affinity-cache status` command
