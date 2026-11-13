# Sora Cluster

This document explains Sora's cluster: a group of Sora processes that talk to each other over a
gossip protocol so they can share a small amount of live state. It covers what the cluster is for,
how nodes find each other, how traffic between them is encrypted, how the leader is chosen, exactly
what is shared and what is not, and what happens when nodes or the network fail.

It is written for operators who run more than one Sora node, and for contributors who change the
`cluster/` package or one of the subsystems that use it. Certificates are covered in
[TLS.md](TLS.md); how proxies choose a backend is covered in [PROXY.md](PROXY.md).

## Contents

1. [What the cluster is](#1-what-the-cluster-is)
2. [When you need it](#2-when-you-need-it)
3. [Membership: addresses, ports and peers](#3-membership-addresses-ports-and-peers)
4. [Encryption](#4-encryption)
5. [Leader election](#5-leader-election)
6. [What the cluster shares](#6-what-the-cluster-shares)
7. [What the cluster does not share](#7-what-the-cluster-does-not-share)
8. [Failures: nodes leaving, the leader dying, network splits](#8-failures-nodes-leaving-the-leader-dying-network-splits)
9. [Delivery, queues and limits](#9-delivery-queues-and-limits)
10. [Checking the cluster](#10-checking-the-cluster)
11. [Configuration reference](#11-configuration-reference)
12. [Code map](#12-code-map)

---

## 1. What the cluster is

Each Sora process can join a cluster. The nodes of a cluster find each other, watch each other's
health, and pass small messages around. Sora uses HashiCorp
[memberlist](https://github.com/hashicorp/memberlist) for this. memberlist is a gossip library: a
node sends each message to a few random other nodes, and they pass it on, until every node has it.

The cluster is not a database and not a consensus system. It has no quorum and stores nothing on
disk. It carries:

- **Per-user connection counts** from the IMAP, POP3 and ManageSieve proxies, so a per-user
  connection limit counts a user's connections on every proxy node.
- **Kicks and "forget cached logins" events** sent through the admin API, so a user is
  disconnected, or must sign in afresh, on every proxy node.
- **Backend affinity**, the record of which backend a user was last sent to, so every proxy node
  sends the user to the same backend.
- **Leadership**, which only Let's Encrypt uses: only the leader orders and renews certificates.

Section 6 describes each of these in detail. Section 7 lists what stays on one node or lives in
PostgreSQL instead.

Turn the cluster on with `[cluster] enabled = true`. It is off by default.

---

## 2. When you need it

You do **not** need the cluster to run a single Sora node that serves IMAP, POP3, LMTP and
ManageSieve directly. Backend servers keep their own connection counts locally and do not use the
cluster at all.

You need the cluster when you want any of the following:

| You want | Why it needs the cluster |
|---|---|
| `max_connections_per_user` or `max_connections_per_user_per_ip` on an IMAP, POP3 or ManageSieve **proxy** | A proxy only tracks per-user connections in cluster mode. Without the cluster these two keys have no effect on a proxy, even on a single proxy node. |
| To kick a user's proxy sessions with `sora-admin connections kick` or the admin API | The kick reaches proxy sessions only through the cluster's connection tracker. |
| `enable_affinity = true` on a proxy | The affinity store only exists in cluster mode. |
| Several nodes that use Let's Encrypt with one S3 bucket | Without the cluster every node orders and renews certificates on its own. See [TLS.md](TLS.md#8-lets-encrypt-in-a-cluster). |

A single proxy node can run a cluster of one: set `enabled = true`, leave `peers` empty, and the
node logs `No peers to join - running as standalone single-node cluster` and becomes its own leader.

Backends gain nothing from joining unless they use Let's Encrypt. If some nodes use Let's Encrypt
and some do not, read [Leader election](#5-leader-election) first: the leader may otherwise be a
node that never orders certificates.

---

## 3. Membership: addresses, ports and peers

### The gossip address

Each node listens for gossip on one IP address and one port, and tells the other nodes to reach it
there. You set both with `[cluster] addr`:

```toml
[cluster]
enabled = true
addr = "10.0.0.11:7946"     # this node's own address, reachable from the other nodes
```

Rules for `addr`:

- It must be an **IPv4 address literal** that exists on this host and that the other nodes can
  reach. Sora binds to it and advertises it unchanged.
- `0.0.0.0`, `localhost`, an empty value, `::` and `::1` are refused at startup with
  `cluster addr '<value>' must be a specific IP address reachable from other nodes`. Other IPv6
  addresses and host names fail at startup inside memberlist (`failed to create memberlist: ...`):
  Sora splits `addr` at the first colon, so IPv6 cannot be used.
- `127.0.0.1` is accepted with a warning. It only works when every node runs on the same machine.
- The port can be written in `addr` (`"10.0.0.11:7946"`) or in `port`. If `addr` has a port, it
  wins and a warning says `port` is ignored. With neither, the port is `7946`.

### Ports to open

Open the gossip port between the cluster nodes, on **both TCP and UDP**:

- UDP carries the gossip itself and the health probes.
- TCP carries the full-state exchange (every 30 seconds), the join, and the direct delivery of
  kicks.

Nothing outside the cluster needs to reach this port. Restrict it to the cluster nodes with your
firewall.

### Peers

`peers` lists the other nodes this node contacts when it starts:

```toml
peers = ["10.0.0.12:7946", "10.0.0.13:7946"]
```

- A peer can be an IP address or a host name, with or without a port. Without a port, this node's
  own gossip port is used.
- Joining one live node is enough: memberlist then learns about every other member from it. Still,
  list all the other nodes, so a node can start whichever of them is up.
- If no peer answers, the node starts anyway. It logs
  `Failed to join cluster peers (will retry in background)` and tries again every 10 seconds.
- The retry stops once the node sees at least as many members as it has peers, plus itself. A peer
  that is gone for good keeps the retry running, with an Info log line every 10 seconds.
- Do not list the node itself. Sora removes an entry only if it is exactly equal to this node's
  `node_id`, which an address never is.

### Node names

Each node has a name in the cluster, `node_id`. It defaults to the host name.

- It must be unique in the cluster. The leader is chosen by name (section 5), and nodes ignore
  affinity events that carry their own name.
- `node_id` is only the gossip name. It is not the name other mail servers see (that is the host
  name, see [ARCHITECTURE.md](ARCHITECTURE.md)), and it is not the upload lease identity, which
  comes from `[uploader] instance_id` (see [STORAGE.md](STORAGE.md)). Changing `node_id` does not
  affect queued uploads.

The connection tracker names each proxy listener by **host name plus `[[server]]` name**, not by
`node_id`. Two nodes with the same host name and a proxy listener of the same name would read each
other's events as their own and ignore them. Give every node a distinct host name.

---

## 4. Encryption

All gossip is encrypted and authenticated. `[cluster] secret_key` is required whenever the cluster
is on: without it Sora refuses to start with
`cluster secret_key is required when cluster mode is enabled (generate one with: openssl rand -base64 32)`.

Why it is mandatory: the gossip carries commands that close user sessions and drop cached logins.
Without the key, any host that can reach the gossip port could forge them.

The key is 32 random bytes, written in standard base64. Generate it once and use the same key on
every node:

```sh
openssl rand -base64 32
```

A key that is not valid base64 stops startup with `failed to decode cluster secret_key: ...`. A key
that does not decode to exactly 32 bytes stops startup with
`cluster secret_key must be 32 bytes (got N bytes)`.

memberlist encrypts every packet with AES-256-GCM and drops anything it cannot decrypt. A node with
a different key cannot join: it logs `Failed to join cluster peers`, then `Cluster: Retry join
failed` every 10 seconds, and stays a cluster of one that names itself leader.

Sora accepts only one key. To change it, stop or reconfigure all nodes together: during the change,
nodes with the old key and nodes with the new key form two separate clusters.

---

## 5. Leader election

Every node works out the leader on its own, at startup and then every 5 seconds:

- The leader is the member with the **smallest `node_id`**, compared as plain strings. `node-10`
  sorts before `node-2`; pad numbers (`node-01`, `node-02`) if you want the order to follow them.
- A node that sees no other member is its own leader.
- There is no hand-over and no vote. When the leader leaves, the node with the next smallest name
  leads. When the node with the smallest name comes back, it leads again.
- A change is logged as `Cluster leader changed` with the fields `old`, `new` and `is_leader`. The
  first election at startup logs this line too, with an empty `old`.

**Only Let's Encrypt uses the leader.** The leader is the only node that orders or renews
certificates. Nothing else in Sora depends on which node leads: proxies, backends, the uploader and
the cleaner work the same on every node. Background workers such as the cleaner coordinate through
PostgreSQL locks, not through the cluster.

Because the leader is the smallest name among all members, a cluster that mixes Let's
Encrypt nodes with nodes that do not run Let's Encrypt must make sure a Let's Encrypt node has the
smallest name. If a node without `[tls] provider = "letsencrypt"` leads, no node orders or renews
certificates. Either give the Let's Encrypt nodes the smallest names, or keep the other nodes out
of the cluster.

---

## 6. What the cluster shares

### 6.1 Per-user connection counts (IMAP, POP3 and ManageSieve proxies)

In cluster mode, every `imap_proxy`, `pop3_proxy` and `managesieve_proxy` listener runs a
connection tracker. It counts each signed-in user's connections, per client IP, and gossips every
change to the other nodes. Each node therefore knows how many connections a user holds on every
proxy node of the same protocol.

Two `[[server]]` keys use these counts:

| Key | Counts |
|---|---|
| `max_connections_per_user` | The user's connections on all proxy nodes of this protocol. |
| `max_connections_per_user_per_ip` | The user's connections from one client IP on all proxy nodes of this protocol. |

Both default to `0` (no limit). When a login would go over a limit, the proxy refuses it. The
counts are per protocol: IMAP connections never count against a POP3 limit.

Details:

- Counts are eventually consistent. memberlist gossips every 200 ms, so a change normally reaches
  the other nodes within a fraction of a second, a little longer in a large cluster. Two logins on
  two nodes at the same moment can both pass a limit.
- Each node also sends its full state to one random peer every 30 seconds (memberlist push/pull,
  over TCP), which repairs counts after a lost message.
- Each tracker sends a small heartbeat every 30 seconds. If a node hears nothing from another
  node's tracker for 5 minutes, it drops that tracker's counts (checked every minute).
- The LMTP proxy keeps a local tracker only, never gossips, and never enforces these limits on
  delivery connections.
- Without the cluster, these proxies run no tracker, and the two keys do nothing on a proxy.
- On backends (`imap`, `pop3`, `managesieve`), the same keys are counted per server, from local
  counts only, and never shared. Which backend protocols enforce them is described in
  [SECURITY.md](SECURITY.md).

The admin API shows these counts: `GET /admin/connections` lists the users connected to this node,
each with `local_count` (this node) and `total_count` (the whole cluster). See
[ADMIN_API.md](ADMIN_API.md).

### 6.2 Kicks and dropped logins

The admin API can end a user's sessions (`POST /admin/connections/kick`, also used by
`sora-admin connections kick`) and drops a user's cached logins when their password changes or a
credential is deleted. Both go through the connection trackers:

1. The node that handles the request applies it to every tracker it runs.
2. Each tracker that runs in cluster mode also sends the event to every other member directly over
   TCP, and queues it for gossip as a backstop for members it could not reach.
3. Every node that receives it applies it to its trackers of the same protocol: a kick closes the
   user's sessions there and drops the user's entries from that listener's lookup cache; a
   "forget logins" event drops only the lookup cache entries.

What this means for you:

- A kick reaches the proxy sessions on every node, but only for the protocols the receiving node's
  admin API has trackers for. Run the admin API on a node that also runs the proxy listeners (or
  call it on each node). If the node has no trackers at all, the kick fails with
  `503 Connection tracking not available (requires cluster mode)`.
- Backend trackers do not gossip. A kick closes backend sessions only on the node whose admin API
  handled it. Closing a proxy session also closes its connection to the backend.
- After a password change or a deleted credential made through the admin API, every proxy node
  drops the user's entries from its lookup cache, so the next login is looked up again instead of
  waiting for the entry to expire. The proxies' persistent auth cache (`[auth_cache]`) is not
  touched by these events; how it handles a changed password is described in
  [PROXY.md](PROXY.md).

### 6.3 Backend affinity

Affinity remembers which backend a user was last routed to, per protocol, so the next connection
goes to the same backend (warm caches, fewer surprises for clients). The IMAP, POP3, ManageSieve
and LMTP proxies use it only when their `[[server]]` block sets `enable_affinity = true`; the User
API proxy uses it whenever the cluster is on. How routing uses affinity is described in
[PROXY.md](PROXY.md).

The cluster shares the affinity store:

- When the cluster is on, every node has an affinity store, whatever `[cluster.affinity] enabled`
  says. Without the cluster there is no store, and `enable_affinity` has no effect.
- Each assignment, change and removal is gossiped to every node. When two nodes disagree, the
  newer assignment wins.
- An entry expires after `[cluster.affinity] ttl` (default `24h`), counted from when it was set.
  Expired entries are removed every `cleanup_interval` (default `1h`).
- Affinity has no full-state exchange. A node that joins or restarts learns only the assignments
  made after it joined, unless it keeps them on disk: with `[cluster.affinity] cache_path` set, the
  node writes every entry to a local SQLite file and loads it at startup.
- The admin API can read one entry (`GET /admin/affinity?user=...&protocol=imap`), set and
  delete entries (`POST` and `DELETE /admin/affinity`), and count them (`GET /admin/affinity/stats`).
  A change made there is gossiped too. Listing all entries (`/admin/affinity/list`) answers
  `501 Not Implemented`. See [ADMIN_API.md](ADMIN_API.md).

### 6.4 Let's Encrypt leadership

The cluster decides which node may order certificates (the leader, section 5). The certificates
themselves never travel over the cluster: nodes share them through an S3 bucket. On nodes that have
a database, a PostgreSQL lock additionally makes sure only one node orders a new certificate for a
name at a time. See [TLS.md](TLS.md#8-lets-encrypt-in-a-cluster).

---

## 7. What the cluster does not share

These stay on one node, or live in PostgreSQL:

| Thing | Where it lives |
|---|---|
| Authentication rate limits (failure counts, delays, IP blocks) | In the memory of each listener on each node. An attacker spreading attempts over several nodes meets each node's limits separately. `[cluster.rate_limit_sync]` exists in the config but nothing reads it. See [AUTHENTICATION.md](AUTHENTICATION.md). |
| `max_connections` and `max_connections_per_ip` | Counted per listener on each node. |
| Per-user limits on backends | Counted per backend server (see [SECURITY.md](SECURITY.md) for which protocols enforce them). |
| The proxies' lookup cache | Per proxy server, in memory. The cluster only tells it to drop a user's entries (section 6.2). |
| The proxies' auth cache (`[auth_cache]`) | A local SQLite file per node. The cluster does not touch it. |
| Backend health checks | Each proxy checks its backends itself. |
| Backend maintenance mode | The `backend_maintenance` table in PostgreSQL, polled by every proxy. See [PROXY.md](PROXY.md). |
| Certificates | The Let's Encrypt S3 bucket and each node's local fallback directory. See [TLS.md](TLS.md). |
| Uploads, cleanup, account purges, certificate order claims | PostgreSQL rows and locks. |

---

## 8. Failures: nodes leaving, the leader dying, network splits

### A node stops cleanly

On shutdown a node first closes its listeners and sessions, then announces that it leaves (it
waits up to 5 seconds for that to go out). The other nodes remove it at once and recompute the
leader within 5 seconds. The node's trackers gossip the disconnects of its closing sessions while
gossip still runs; any counts that do not get out are dropped by the other nodes after 5 minutes,
as for a crash.

### A node crashes or loses the network

memberlist probes each member about once a second. A member that stops answering is first marked
suspect, then dead once a suspicion timeout passes: a few seconds in a small cluster, up to about
half a minute in a larger one. The leader is then recomputed within 5 seconds.

The connection counts the lost node held stay counted on the other nodes until they have heard
nothing from it for 5 minutes. During that time its users may hit `max_connections_per_user`
early. Affinity entries the node set stay valid: they name backends, not the node.

### The leader dies

The node with the next smallest name becomes leader and takes over Let's Encrypt orders and
renewals. If the old leader died in the middle of ordering a certificate, its PostgreSQL claim on
that name blocks new orders for that name for up to 10 minutes. Certificates already in S3 keep
working on every node.

### A node comes back

A restarted node joins through its `peers` list. It gets the current connection counts from the
next full-state exchange (within about 30 seconds) and only new affinity assignments, unless
`cache_path` is set.

### A network split

The cluster has no quorum. During a split each side sees only its own members and elects its own
leader. For Let's Encrypt this means both sides may renew certificates; ordering a **new**
certificate is still limited to one node on nodes with a database (section 6.4).

After the network heals, memberlist only keeps trying to reach a member it declared dead for about
30 seconds. Sora retries its `peers` list only at startup, until it has seen all of them. So a
split that lasted longer than about 30 seconds may leave the two sides as two clusters. Check the
`Cluster leader changed` lines (section 10); if the sides still name different leaders, restart the
nodes on one side so they join again.

### Clocks

Every gossip event carries the sender's time. A receiver ignores events that are more than
**5 minutes old** by its own clock, so that a healed split does not replay old news. A node whose
clock runs more than 5 minutes behind therefore has its connection events, kicks and affinity
changes ignored. Keep all nodes in sync with NTP.

---

## 9. Delivery, queues and limits

These details matter when you size a busy cluster or read a warning in the log.

- **Gossip rate.** memberlist gossips every 200 ms to 3 random members, over UDP. A gossip
  datagram holds at most 1400 bytes, so an encoded event may be at most 1364 bytes, leaving room
  for framing and encryption. A larger event is dropped with `Gossip: Dropping oversized broadcast`.
- **Retransmission.** An event is retransmitted a number of times that grows with the logarithm of
  the cluster size, then retired. Delivery is at least once; receivers drop duplicates by event ID.
  Order is not preserved; the receivers handle events that arrive in the wrong order.
- **Fairness.** Connection events and affinity events take turns at the datagram budget, so a busy
  kind cannot starve the other. Within the connection events, heartbeats go first, then kicks
  (with at most half of the remaining space), then ordinary connect and disconnect events.
- **Connection event queue.** Each proxy tracker queues outgoing connection events, up to
  `[cluster] max_event_queue_size` (default `50000`). When it overflows, memberlist drops the
  messages that were already sent most often, and Sora logs
  `Gossip: Broadcast queue full - dropping queued messages`. The next full-state exchange repairs
  the counts.
- **Kick queue.** Kicks and "forget logins" events have their own queue of up to 10000, sent before
  ordinary events. They are also sent directly over TCP when issued, so this queue matters only
  for members that were unreachable at that moment. An overflow is logged at Error level.
- **Affinity queue.** Up to 5000 outgoing affinity events.
- **Receiving.** Each subsystem handles received events on its own worker, with a queue of 256. If
  it falls behind, new events are dropped and
  `Cluster: Gossip handler queue full, dropping events` is logged (at most every 10 seconds).
- **Full-state exchange.** Every 30 seconds each node exchanges its connection tracker state with
  one random member over TCP. memberlist refuses a state larger than 20 MB.
- **memberlist's own log.** Sora passes only memberlist's gossip and broadcast lines to its log, at
  Debug level. memberlist's own warnings and errors are not logged.

---

## 10. Checking the cluster

Sora has no command or endpoint that lists the members. Use the log, the admin API and the metrics.

**At startup**, each node logs:

- `Cluster manager initialized` with `node_id`, `members` and `leader`, right after joining.
- `Join returned - contacted peers` and `Cluster members after join (expected 2+)` with the member
  count when the join worked, or `Failed to join cluster peers (will retry in background)` when it
  did not.
- `Cluster: Successfully joined all peers - stopping retry loop` only when one of its own retries
  completes the join. A node that the others joined, or that saw all its peers at the first
  attempt, stops retrying without an Info line.
- `Cluster leader changed` whenever its view of the leader changes.

Every node should end up naming the same leader. With the default logging to standard error under
systemd:

```sh
journalctl -u sora | grep "Cluster leader changed" | tail -n 1
```

With `[logging] output` set to a file path, grep that file instead.

**Connection tracking.** Sign in as the same user through two proxy nodes, then on one node:

```sh
curl -s -H "Authorization: Bearer $API_KEY" http://127.0.0.1:8080/admin/connections
```

The user's entry shows `local_count` 1 and `total_count` 2 once the gossip has arrived.

**Metrics** (see [METRICS.md](METRICS.md)):

| Metric | Meaning |
|---|---|
| `sora_connection_tracker_users{protocol,server_name,hostname}` | Users the tracker knows, on all nodes. |
| `sora_connection_tracker_instance_ids{...}` | For each tracked user, the number of proxy listeners (on any node) where the user has connections, summed over all users. |
| `sora_connection_tracker_ips{...}` | Client IPs tracked across all users. |
| `sora_connection_tracker_broadcast_queue_size{...}` | Events waiting to be gossiped. A value that keeps growing means gossip is not draining (no reachable members, or too much traffic). |
| `sora_affinity_manager_entries` | Affinity entries on this node. |
| `sora_affinity_manager_broadcast_queue_size` | Affinity events waiting to be gossiped. |

The tracker metrics are refreshed every minute, the affinity metrics every `cleanup_interval`.

**Network.** From one node, check the gossip port of another over TCP, for example with
`nc -zv 10.0.0.12 7946`. UDP cannot be checked this way; make sure the firewall allows it.

---

## 11. Configuration reference

The cluster is configured once per node. Sora reads `[cluster]` only at startup; a SIGHUP reload
does not apply changes to it and does not report them. Restart the node instead.

### `[cluster]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | Join a gossip cluster. |
| `addr` | string | none | This node's gossip address: an IPv4 address, optionally with `:port`. Required when `enabled`. See [section 3](#3-membership-addresses-ports-and-peers). |
| `port` | integer | `7946` | Gossip port, TCP and UDP, used when `addr` has no port. |
| `node_id` | string | the host name | This node's name in the cluster. Unique per node; the smallest leads. |
| `peers` | list of strings | `[]` | Other nodes to contact at startup, as `host` or `host:port`. |
| `secret_key` | string | none | Base64 of exactly 32 bytes. Required when `enabled`. The same on every node. |
| `max_event_queue_size` | integer | `50000` | Outgoing connection events each proxy tracker may queue. A value of `0` or less means the default. |

### `[cluster.affinity]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | Has no effect. The affinity store exists whenever the cluster is on; the mail proxies opt in with `enable_affinity`. |
| `ttl` | duration | `"24h"` | How long an affinity entry lives after it is set. An invalid value logs a warning and uses `24h`. |
| `cleanup_interval` | duration | `"1h"` | How often expired entries are removed (and the affinity metrics refreshed). An invalid value logs a warning and uses `1h`. |
| `cache_path` | string | `""` | Path of a SQLite file that keeps affinity entries across restarts. Empty keeps them in memory only. The directory must exist and be writable; if the file cannot be opened Sora logs `Failed to initialize affinity cache - continuing without persistence` and runs without it. A corrupt file is deleted and recreated. |

Durations accept Go units (`"30m"`, `"24h"`) and days (`"7d"`); see
[CONFIGURATION.md](CONFIGURATION.md).

### `[cluster.rate_limit_sync]`

| Key | Type | Meaning |
|---|---|---|
| `enabled` | bool | Read but not used. |
| `sync_blocks` | bool | Read but not used. |
| `sync_failure_counts` | bool | Read but not used. |

Authentication rate limits are kept per node; see [section 7](#7-what-the-cluster-does-not-share).

### Related `[[server]]` keys

These live in the proxy `[[server]]` blocks and are documented in [PROXY.md](PROXY.md) and
[SECURITY.md](SECURITY.md):

- `max_connections_per_user`, `max_connections_per_user_per_ip`: cluster-wide on IMAP, POP3 and
  ManageSieve proxies (section 6.1).
- `enable_affinity`: use the shared affinity store (section 6.3).

### A complete example

Node `node-01` of three, with addresses `10.0.0.11` to `10.0.0.13`:

```toml
[cluster]
enabled = true
node_id = "node-01"
addr = "10.0.0.11:7946"
peers = ["10.0.0.12:7946", "10.0.0.13:7946"]
secret_key = "REPLACE-WITH-OUTPUT-OF-openssl-rand-base64-32"

[cluster.affinity]
ttl = "24h"
cleanup_interval = "1h"
cache_path = "/var/cache/sora/affinity.db"
```

On the other nodes only `node_id`, `addr` and `peers` change.

---

## 12. Code map

| Path | What it does |
|---|---|
| [cluster/manager.go](../cluster/manager.go) | memberlist setup, address and key checks, join and retry, leader election, message routing by type, full-state exchange. |
| [server/gossip.go](../server/gossip.go) | Shared gossip plumbing: bounded transmit queues, priority tiers, duplicate suppression, tombstones for out-of-order removals, the 5-minute staleness rule. |
| [server/connection_tracker.go](../server/connection_tracker.go) | Per-user connection counts, limits, kicks, "forget logins", heartbeats, state reconciliation. |
| [server/affinity_manager.go](../server/affinity_manager.go) | Affinity store, its gossip and its optional SQLite persistence ([affinitycache/](../affinitycache/)). |
| [server/ip_limit_tracker.go](../server/ip_limit_tracker.go) | Cluster-wide per-IP counts. The proxies can use it, but the server does not pass them the cluster, so it is not active. |
| [server/auth_rate_limiter_cluster.go](../server/auth_rate_limiter_cluster.go) | Cluster sync for authentication rate limits. Not connected to any server. |
| [tlsmanager/](../tlsmanager/) | Uses leadership for Let's Encrypt; see [TLS.md](TLS.md). |
| [cmd/sora/main.go](../cmd/sora/main.go) | Starts the cluster, the affinity store and the proxy trackers. |
