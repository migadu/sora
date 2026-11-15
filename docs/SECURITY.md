# Sora Security

This document lists the protections Sora applies to every connection, with their defaults: TLS and
plaintext logins, trusted networks and the PROXY protocol, connection limits, timeouts and the
slow-client guard, limits on failed logins, memory and size limits, search limits, the metrics
endpoint and client-side encryption of stored mail. For each it says what an attacker or a client
sees, and whether the limit is counted per node or across the cluster. It is written for operators
who expose Sora to the internet and for contributors who change these paths.

How logins are checked, password schemes, master credentials and the authentication rate limiter
are in [AUTHENTICATION.md](AUTHENTICATION.md). Certificates are in [TLS.md](TLS.md). Proxy routing is
in [PROXY.md](PROXY.md).

## Contents

1. [Defaults at a glance](#1-defaults-at-a-glance)
2. [TLS and plaintext logins](#2-tls-and-plaintext-logins)
3. [Trusted networks and the PROXY protocol](#3-trusted-networks-and-the-proxy-protocol)
4. [Connection limits](#4-connection-limits)
5. [Timeouts and slow clients](#5-timeouts-and-slow-clients)
6. [Limits on failed logins per connection](#6-limits-on-failed-logins-per-connection)
7. [Session memory limits](#7-session-memory-limits)
8. [Message, script and line size limits](#8-message-script-and-line-size-limits)
9. [Search and command limits](#9-search-and-command-limits)
10. [The metrics endpoint](#10-the-metrics-endpoint)
11. [The HTTP APIs](#11-the-http-apis)
12. [Client-side encryption of message bodies](#12-client-side-encryption-of-message-bodies)
13. [Per node or across the cluster](#13-per-node-or-across-the-cluster)
14. [Startup checks and warnings](#14-startup-checks-and-warnings)
15. [Checklist](#15-checklist)

---

## 1. Defaults at a glance

| Protection | Default | Section |
|---|---|---|
| Plaintext logins | Refused before TLS on a listener with `tls = true`; always allowed on a listener with `tls = false` | 2 |
| Trusted networks | None: no host may forward a client address | 3 |
| PROXY protocol | Off per listener; when on, only from trusted networks | 3 |
| Total connections per listener | No limit, except LMTP: 1000 | 4 |
| Connections per IP | No limit | 4 |
| Connections per user | No limit | 4 |
| Idle timeout | IMAP 30 min, POP3 10 min, ManageSieve 3 min | 5 |
| Session length | 24 h (LMTP proxy: 5 min) | 5 |
| Slow-client guard (`min_bytes_per_minute`) | Off | 5 |
| Authentication rate limiting | Off | [AUTHENTICATION.md](AUTHENTICATION.md#10-authentication-rate-limiting) |
| Failed logins per connection | POP3 backend: 4 errors; ManageSieve backend: 10; proxies: 2 protocol errors before login | 6 |
| Session memory | 100 MiB per IMAP or POP3 session | 7 |
| IMAP APPEND | 25 MiB | 8 |
| LMTP message | 50 MiB | 8 |
| Sieve script | 16 KiB | 8 |
| Searches | 60 expensive searches per minute per account | 9 |
| Metrics endpoint | No access control unless configured | 10 |
| Message bodies in S3 | Not encrypted by Sora | 12 |

Sizes are binary: `1mb` is 1024 × 1024 bytes. Size units are not case-sensitive: `25MB` is the
same as `25mb`.

---

## 2. TLS and plaintext logins

All login mechanisms Sora offers send the password as it is (`LOGIN`, `USER`/`PASS`, SASL `PLAIN`),
so they must travel inside TLS. Each listener decides with three keys in its `[[server]]` block:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `tls` | bool | `false` | The listener uses TLS. Certificates come from `tls_cert_file`/`tls_key_file` or from the global `[tls]` section ([TLS.md](TLS.md)). |
| `tls_use_starttls` | bool | `false` | With `tls = true`: listen in plaintext and offer STARTTLS (STLS for POP3) instead of TLS from the first byte. |
| `insecure_auth` | bool | `false` | Allow logins before the connection is encrypted. |

The rule: **a login over an unencrypted connection is allowed when `insecure_auth = true` or
`tls = false`.** In practice:

| Listener configuration | Plaintext logins |
|---|---|
| `tls = false` | Always allowed. There is no TLS at all. Use this only on a private network, such as a backend that only proxies reach. |
| `tls = true` (implicit TLS) | Every connection is encrypted from the start, so the question does not arise. |
| `tls = true`, `tls_use_starttls = true` | Refused until the client runs STARTTLS, unless `insecure_auth = true`. |

The rule applies to `imap`, `pop3`, `managesieve`, `imap_proxy`, `pop3_proxy` and
`managesieve_proxy`. LMTP has no login, so `insecure_auth` does nothing there. The HTTP APIs do not use
it.

What a client sees when a login is refused for lack of TLS:

| Listener | Capabilities before STARTTLS | Reply to a login |
|---|---|---|
| `imap` | `STARTTLS LOGINDISABLED`, no `AUTH=` | `NO [PRIVACYREQUIRED] TLS is required to authenticate` |
| `imap_proxy` | `... STARTTLS LOGINDISABLED` | `<tag> NO [PRIVACYREQUIRED] Authentication requires TLS connection` |
| `pop3`, `pop3_proxy` | `STLS`, no `USER`, no `SASL` | `-ERR Authentication requires TLS. Use STLS first` |
| `managesieve`, `managesieve_proxy` | `"STARTTLS"`, `"SASL" ""` | `NO "Authentication not permitted on insecure connection. Use STARTTLS first."` |

On POP3, ManageSieve and the proxies these refusals count as errors (section 6).

When plaintext logins are allowed on a listener whose address is reachable from the internet, Sora
logs a warning at startup:

```
plaintext authentication is allowed without TLS on a publicly reachable address; ...
```

"Publicly reachable" means bound to a public IP, or to a wildcard address (`:143`, `0.0.0.0`, `::`)
on a host that has a public address. Loopback, private (RFC 1918, ULA), link-local and CGNAT binds
do not warn. On a listener with `tls = false`, setting `insecure_auth = false` does not change
anything: configure TLS instead. The POP3 backend also logs
`POP3: TLS not configured; cleartext authentication auto-enabled. ...` whenever its `tls` is off.

A backend behind Sora proxies usually runs with `tls = false` on a private address. Keep its ports
reachable only from the proxies, or turn on TLS on the backend leg ([PROXY.md](PROXY.md#8-the-backend-leg)):
the proxies log in to backends with the master SASL password
([AUTHENTICATION.md](AUTHENTICATION.md#8-master-credentials)).

---

## 3. Trusted networks and the PROXY protocol

### 3.1 `trusted_networks`

```toml
[servers]
trusted_networks = ["10.20.0.5/32", "10.20.0.6/32"]
```

A list of CIDRs or bare IPs (a bare IP is one host). It is **empty** by default. It names the hosts
Sora trusts to tell it who the real client is. Keep it to the addresses of your own proxies and load
balancers.

| What | Effect of `trusted_networks` |
|---|---|
| PROXY protocol | A listener with `proxy_protocol = true` accepts connections only from these addresses (3.2). |
| Client address forwarding | IMAP ID forwarding fields, POP3 `XCLIENT`, and LMTP `XCLIENT`/`XRCPTFORWARD` are honoured only from these addresses. From anyone else they are ignored (IMAP) or refused (POP3: `-ERR Connection not from trusted proxy`). Behind a PROXY header, IMAP ID and POP3 `XCLIENT` are judged by the client the header names, not the load balancer that sent it; LMTP has its own rule (below). |
| Per-IP connection limit | Connections from these addresses do not count against `max_connections_per_ip`. Behind a PROXY header the address is the client the header names, not the load balancer that sent it (section 4). |
| Authentication rate limiting | These addresses are exempt, unless the server's `auth_rate_limit.exempt_networks` says otherwise ([AUTHENTICATION.md](AUTHENTICATION.md#105-exempt-networks)). |
| LMTP backend admission | Only these addresses may connect to an `lmtp` listener. **When the list is empty**, the LMTP backend accepts `127.0.0.0/8`, `::1`, `10.0.0.0/8`, `172.16.0.0/12` and `192.168.0.0/16` instead. |
| LMTP proxy admission | Only these addresses may connect to an `lmtp_proxy` listener. Other connections are closed and logged as `LMTP Proxy: Connection rejected - not from trusted network`. An `lmtp_proxy` with an empty list is reported at startup. |

Most of these check the TCP peer, the host that actually connected. The exceptions:

- The rate-limit exemption checks the client address after forwarding, subject to the POP3
  `XCLIENT` metadata requirement in
  [AUTHENTICATION.md](AUTHENTICATION.md#11-trusted-networks-and-logins).
- The per-IP limit checks the client a PROXY header names when there is one.
- IMAP ID forwarding and POP3 `XCLIENT` check the client a PROXY header names when there is one,
  else the TCP peer (also when the header names no client: `LOCAL` or `UNKNOWN`). A load balancer
  that sends PROXY headers is trusted to say who the client is, not to vouch for the commands that
  follow, which are the client's own. So behind a trusted layer-4 load balancer (HAProxy, nginx
  `stream`), a proxy that reaches the backend through the load balancer may forward only when its
  own address is in the list. Other clients have their ID forwarding fields ignored and `XCLIENT`
  refused unless their own address is also in the list.
- LMTP `XCLIENT` is accepted from a trusted TCP peer: an `lmtp_proxy` may send a PROXY header and
  `XCLIENT` on one connection. Its `ADDR` and `PORT` replace the address a PROXY header gave only
  when that address is itself in the list; otherwise they are ignored and the other attributes
  (`HELO`, `PROTO`, `LOGIN`, `NAME`) still apply. `XRCPTFORWARD` checks the TCP peer.

Sora reads `trusted_networks` at startup. A SIGHUP reload logs
`Config reload: servers.trusted_networks changed but requires restart to take effect; ...` and keeps
the old list until a restart.

At startup Sora logs the list's posture:

- empty: an INFO line starting `trusted_networks is empty (fail-closed default): ...`;
- an entry that covers a whole private range (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`,
  `fc00::/7`, `fe80::/10`, or anything wider): a WARN line, because every host on that network could
  then fake client addresses and skip rate limits.

### 3.2 The PROXY protocol

The PROXY protocol (v1 text or v2 binary) lets a load balancer pass the client's address to Sora in
front of the connection. Turn it on per listener:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `proxy_protocol` | bool | `false` | Require a PROXY header on every connection to this listener. |
| `proxy_protocol_timeout` | duration | `5s` | How long to wait for the header. |

It works on `imap`, `pop3`, `managesieve`, `lmtp`, `imap_proxy`, `pop3_proxy`, `managesieve_proxy`,
`lmtp_proxy`, `http_admin_api`, `http_user_api` and `user_api_proxy` listeners. (Sora proxies send
PROXY headers to their backends with `remote_use_proxy_protocol`; see
[PROXY.md](PROXY.md#8-the-backend-leg).)

```toml
[servers]
trusted_networks = ["10.20.0.5/32"]   # the load balancer

[[server]]
type = "imap"
name = "imap"
addr = ":143"
proxy_protocol = true
```

With `proxy_protocol = true`:

- A connection from an address **not** in `trusted_networks` is closed at once, without a reply.
- A connection from a trusted address must send a valid header within `proxy_protocol_timeout`, or
  it is closed. There is no "optional" mode.
- The client address from the header is used for logs, rate limiting and `max_connections_per_ip`.
  It is also the address IMAP ID forwarding and POP3 `XCLIENT` are judged by: a client behind a
  trusted load balancer may forward an address only when its own address is in `trusted_networks`.
  LMTP `XCLIENT` is accepted from the TCP peer, but its `ADDR` and `PORT` replace the header's
  address only when that address is in `trusted_networks` (3.1). Which hosts may send a header,
  and which may use master SASL (`master_sasl_allowed_networks`), are judged by the TCP peer.
- A client the header names is exempt from `max_connections_per_ip` only when its own address is in
  `trusted_networks`: the load balancer's address does not exempt the clients behind it. A header
  that names no client (`LOCAL` or `UNKNOWN`) counts against the TCP peer, which is trusted and so
  exempt. On `imap`, `pop3` and `managesieve`, a client the header names that is refused for its own
  address gets a refusal greeting instead of a silent close (section 4).
- Headers are read in parallel, at most 1024 at a time per listener, so a peer that never sends its
  header delays only its own connection.

Sora refuses to start when any listener has `proxy_protocol = true` and `trusted_networks` is empty,
with the message `proxy_protocol is enabled on server(s) <names> but [servers] trusted_networks is
empty; set trusted_networks to your trusted proxy IPs/CIDRs (otherwise any client could spoof its
source IP via a PROXY header)`.

There is no `proxy_protocol_trusted_proxies` key: Sora ignores it (with an unknown-key warning) and
always uses `trusted_networks`.

---

## 4. Connection limits

Connection limits stop one client, or a flood, from using up a listener. They are set per
`[[server]]` block:

| Key | Default | Meaning |
|---|---|---|
| `max_connections` | `0` (no limit); `lmtp`: `1000` | Open connections on this listener. |
| `max_connections_per_ip` | `0` (no limit) | Open connections from one client IP. |
| `max_connections_per_user` | `0` (no limit) | Logged-in sessions of one account. |
| `max_connections_per_user_per_ip` | `0` (no limit) | Logged-in sessions of one account from one IP. |

Where each applies:

| Key | `imap`, `pop3`, `managesieve` | `imap_proxy`, `pop3_proxy`, `managesieve_proxy` |
|---|---|---|
| `max_connections` | yes | yes |
| `max_connections_per_ip` | yes, except for trusted networks; with `proxy_protocol = true` it counts the client the header names | as on the backends; with `[cluster]`, counted across the cluster ([CLUSTER.md](CLUSTER.md#65-per-ip-connection-counts-imap-pop3-and-managesieve-proxies)) |
| `max_connections_per_user` | enforced, per listener | enforced across the cluster; needs `[cluster]`, otherwise not enforced |
| `max_connections_per_user_per_ip` | as above; on `imap` the IP is the client's real address, as forwarded by a proxy | as above |

`max_connections` also applies to `lmtp` (unset, `0` or less gives 1000) and `lmtp_proxy` listeners.
`lmtp_proxy` ignores the per-user limits, with a warning.

Behind Sora proxies that send PROXY headers (`remote_use_proxy_protocol`), a backend's
`max_connections_per_ip` limits each client a second time, by the address the proxy names. Set it no
lower than on the proxies, or to `0` to leave the limit to them.

What a client sees:

- Over `max_connections` or `max_connections_per_ip`: the TCP connection is closed before any
  greeting or TLS handshake. Sora sends no banner on purpose, so a flooder cannot see where the limit
  is. On `imap`, a connection from an IP the authentication rate limiter has blocked is closed the
  same way.
- The exception is a client named by a PROXY header on an `imap`, `pop3` or `managesieve` listener,
  when it is refused for its own address: over `max_connections_per_ip`, or, on `imap`, blocked by
  the rate limiter. Such a client is answered. The TLS handshake completes (on an implicit-TLS
  listener), then Sora sends a refusal greeting and closes the connection:
  `* BYE [LIMIT] Too many connections` (IMAP; a blocked IP gets
  `* BYE [ALERT] Too many failed authentication attempts. Please try again later.`),
  `-ERR [SYS/TEMP] Too many connections` (POP3), `NO (TRYLATER) "Too many connections"`
  (ManageSieve). The header's sender is a proxy or load balancer, not the client: a Sora proxy that
  saw its backend close the socket before the TLS handshake would count a backend failure and could
  mark a healthy backend down for every user. The refusal greeting fails only that client's login.
  Over `max_connections` the connection is still closed silently, and so is every connection that
  `imap_proxy`, `pop3_proxy` and `managesieve_proxy` refuse over `max_connections_per_ip`, with or
  without a PROXY header.
- Over a per-user limit on a backend, after a correct login: `NO [LIMIT] Maximum connections reached`
  (IMAP), or a temporary error, `-ERR [SYS/TEMP]` (POP3) or `NO (TRYLATER)` (ManageSieve).
- Over a per-user limit on a proxy: `<tag> NO [LIMIT] Too many connections` and
  `* BYE Too many connections` (IMAP), `-ERR [SYS/TEMP] Too many connections` (POP3),
  `NO (TRYLATER) "Too many connections"` (ManageSieve). The connection is closed.

**Startup throttle.** For 30 seconds after a listener starts, it accepts at most about 200
connections per second (a 5 ms pause between accepts). This spreads out the reconnect wave after a
restart. It applies to the IMAP, POP3 and ManageSieve backends and to all four mail proxies, and
cannot be changed.

`listen_backlog` (TCP accept queue, default 1024) is described in
[PROTOCOLS.md](PROTOCOLS.md). The cluster-wide parts are described in
[CLUSTER.md](CLUSTER.md#6-what-the-cluster-shares).

---

## 5. Timeouts and slow clients

Timeouts free connections that do nothing, that last too long, or that trickle bytes to hold a
connection open (a "slowloris" attack). They are set per `[[server]]` block, in a `timeouts` table,
plus `auth_idle_timeout` at the top of the block:

```toml
[[server]]
type = "imap"
name = "imap"
addr = ":993"
tls = true
auth_idle_timeout = "2m"

[server.timeouts]
command_timeout = "30m"
absolute_session_timeout = "24h"
min_bytes_per_minute = 512
```

| Key | Meaning |
|---|---|
| `timeouts.command_timeout` | Idle timeout: close a connection that has sent and received nothing for this long. |
| `timeouts.absolute_session_timeout` | Close a connection this long after it opened, active or not. `0` turns it off. |
| `timeouts.min_bytes_per_minute` | The slow-client guard (5.2). `0` turns it off. |
| `auth_idle_timeout` | Idle limit before login (see the table). |

Defaults by listener type:

| Type | `command_timeout` | `absolute_session_timeout` | `min_bytes_per_minute` | `auth_idle_timeout` |
|---|---|---|---|---|
| `imap` | `30m` | `24h` | off | `2m` |
| `pop3` | `10m` | `24h` | off | `2m` |
| `managesieve` | `3m` | `24h` | off | `2m` |
| `imap_proxy` | `30m` | `24h` | off | `2m` |
| `pop3_proxy` | `10m` | `24h` | off | `2m` |
| `managesieve_proxy` | `3m` | `24h` | off | `2m` |

LMTP:

- On `lmtp`, an idle timeout of 5 minutes bounds each read from the client, between commands and
  while message data arrives; an idle connection gets a `421` reply. Each write may take 2 minutes.
- On `lmtp_proxy`, `absolute_session_timeout` defaults to `5m`, and `auth_idle_timeout` (`2m`)
  bounds each read until the first recipient is accepted, and while message data is relayed.

Notes:

- On `pop3` and `managesieve` backends, `command_timeout = "0"` does not turn the idle timer off. The
  protocol library then uses its own default: 10 minutes for POP3, 30 minutes for ManageSieve. On
  the other types, `0` turns the idle timer off (before login, `auth_idle_timeout` still applies).
- `command_timeout`, `absolute_session_timeout` and `min_bytes_per_minute` reload on SIGHUP for the
  six IMAP, POP3 and ManageSieve types, and `auth_idle_timeout` for the three proxies. Reloaded values
  apply to connections accepted afterwards.

### 5.1 What a client sees

| Listener | Idle timeout | Session length reached | Too slow (5.2) |
|---|---|---|---|
| `imap` | `* BYE [UNAVAILABLE] Idle timeout, please reconnect` | `* BYE [UNAVAILABLE] Maximum session duration exceeded, please reconnect` | `* BYE [UNAVAILABLE] Connection too slow, please reconnect` |
| `imap_proxy` | `* BYE Idle timeout, please reconnect` | `* BYE Maximum session duration exceeded, please reconnect` | `* BYE Connection too slow, please reconnect` |
| `pop3` | `-ERR Idle timeout, connection timed out` | `-ERR [IN-USE] Maximum session duration exceeded` | `-ERR [IN-USE] Connection too slow, please reconnect` |
| `managesieve` | `BYE (TRYLATER) "Connection timed out due to inactivity, please reconnect"` | `BYE (TRYLATER) "Maximum session duration exceeded, please reconnect"` | `BYE (TRYLATER) "Connection too slow, please reconnect"` |

The connection is then closed. Each timeout is logged as `Connection closed - timeout` with a
`reason` and counted in `sora_connection_timeouts_total{protocol, server_name, hostname, reason}`,
where `reason` is `idle`, `session_max` or `slow_throughput`.

**IMAP IDLE.** A client in IDLE may stay silent for a long time. The IMAP backend sends
`* OK Still here` every 2 minutes (or every half `command_timeout`, if that is shorter), which keeps
the idle timer from firing, and pauses the slow-client guard while the client is in IDLE.

### 5.2 The slow-client guard: `min_bytes_per_minute`

The guard closes a connection that sends a command a few bytes at a time and never finishes it. It
measures each connection in one-minute windows, starting two minutes after the connection opened:

- A window in which the server sent anything means a command completed. The count of stalled windows
  goes back to zero.
- A window in which the client sent some bytes, fewer than `min_bytes_per_minute`, and the server
  sent nothing is a **stalled** window.
- A window with no bytes at all is left to the idle timeout.

Two stalled windows in a row close the connection with reason `slow_throughput`. A client that polls
with a small command every few seconds is not affected, because each command gets a reply. `512` is a
reasonable value. The guard works on `imap`, `pop3`, `managesieve` and their three proxies.

### 5.3 Limits of the IMAP library

The IMAP backend's protocol library has a fixed read limit of its own: after login, it closes a
connection silently after **35 minutes** without a command. A `command_timeout` of 35 minutes or
more is therefore capped, and Sora warns at startup:
`IMAP: command_timeout is at or above the protocol library's 35m read deadline; idle sessions will
be closed silently at 35m instead`.

### 5.4 Per-command time limits

Separate from the timeouts above, each expensive command has a hard time limit, after which it is
stopped and answered with a failure. They protect against runaway database work. Defaults: IMAP
`SEARCH`, `SORT`, `THREAD`, multi-mailbox search, `COPY` and `MOVE` 30 s, `STORE` 15 s, `RENAME`
60 s, `FETCH` none; POP3 `STAT`, `LIST`, `UIDL` and `DELE` 10 s, `RETR` and `TOP` 30 s, `QUIT` 15 s;
ManageSieve script commands 10 s; LMTP `RCPT` 10 s and the processing of `DATA` 60 s. Logins are not
capped, because the rate limiter's delays would hit the cap. The keys
(`timeouts.imap_command_timeouts.*` and the like) are described in [PROTOCOLS.md](PROTOCOLS.md).

---

## 6. Limits on failed logins per connection

Besides the rate limiter, which works across connections, some listeners close a connection that
fails too often:

| Listener | Limit | What counts | Reply when the limit is reached |
|---|---|---|---|
| `imap` | none | | Failed logins are only paced by the rate limiter. |
| `pop3` | 4 errors (fixed) | Failed logins and protocol errors. After each, the reply waits 3 s times the number of errors so far, up to 30 s. | `-ERR Too many errors, closing connection` |
| `managesieve` | 10 errors (fixed) | Failed logins and protocol errors | `BYE "Too many errors, closing connection"` |
| `imap_proxy` | `limits.max_auth_errors` (default 2) | Protocol errors before login: malformed or unknown commands, refused logins without TLS. Wrong passwords do not count. | `* BYE Too many invalid commands` |
| `pop3_proxy`, `managesieve_proxy` | `limits.max_auth_errors` (default 2) | Protocol errors before login. Wrong passwords do not count. | `-ERR Too many errors, closing connection` / `BYE "Too many errors, closing connection"` |

`limits.max_auth_errors` is read only by the three proxies. `0` or a negative value gives 2. It
reloads on SIGHUP.

The authentication rate limiter, its delays and what a blocked client sees are in
[AUTHENTICATION.md](AUTHENTICATION.md#10-authentication-rate-limiting).

---

## 7. Session memory limits

`limits.session_memory_limit` caps the memory one IMAP or POP3 session may hold for message data.
It protects a backend from a client that asks for many large messages at once.

| Property | Value |
|---|---|
| Applies to | `imap` and `pop3` backends |
| Default | `100mb` |
| `0` | no limit |
| Reload | SIGHUP, for connections accepted afterwards |

What is counted: IMAP `APPEND` data, message bodies and body sections loaded for `FETCH`, preview
work, and 64 bytes per message in a `SEARCH` result; POP3 the message list of the session and the
bodies loaded for `RETR` and `TOP`. POP3 checks the stored size of a message before loading it.

When a request does not fit:

| Request | Reply |
|---|---|
| IMAP `FETCH` of a body or section | `NO [UNAVAILABLE] Message too large for the session memory limit` |
| IMAP `APPEND` | `NO [UNAVAILABLE] Session memory limit reached, please try again later` |
| IMAP `SEARCH` | an internal error reply |
| POP3 `RETR`, `TOP` | `-ERR [SYS/TEMP] Message too large to retrieve in this session` |
| POP3 opening a mailbox whose message list is too large | `-ERR [SYS/TEMP] Mailbox too large to open in this session` |

Each case is counted in `sora_session_memory_limit_exceeded_total{protocol, server_name, hostname}`.
Raise the limit if legitimate users hit it with large messages.

---

## 8. Message, script and line size limits

| Key | Applies to | Default | Over the limit |
|---|---|---|---|
| `append_limit` | `imap` | `25mb` | `NO [TOOBIG] Literals are limited to <n> bytes for this command`, before the data is accepted (data already sent with a non-synchronizing literal is read and dropped). Advertised as `APPENDLIMIT=<n>`. `0` also gives 25 MiB: there is no "unlimited". |
| `max_message_size` | `lmtp` | `50mb` | `552 5.3.4 message size exceeds maximum allowed size of <n> bytes`. Sora reads at most the limit plus one byte into memory. `0` also gives 50 MiB. Reloads on SIGHUP. |
| `max_message_size` | `lmtp_proxy` | `50mb` | Advertised as `SIZE <n>` in the proxy's `LHLO` reply. A `MAIL` whose `SIZE=` is above it gets `552 5.3.4`, one whose `SIZE=` is not a number `501 5.5.4`, before the data. The declared size is passed on to a backend that advertises `SIZE`, and the backend enforces its own limit. |
| `max_script_size` | `managesieve` | `16kb` | `NO (QUOTA/MAXSIZE)`. Advertised as `MAXSCRIPTSIZE`. Reloads on SIGHUP. |

LMTP accepts one recipient per transaction (`RCPTMAX=1`), so one `DATA` is stored for one account.

Fixed limits that bound memory before login:

| Where | Limit |
|---|---|
| IMAP backend command line | 50 KiB |
| IMAP proxy, before login | 64 KiB per line, 8 KiB per literal |
| POP3 backend and proxy | 1024 bytes per line |
| ManageSieve backend | 8192 bytes per line |

---

## 9. Search and command limits

IMAP searches can be expensive. These limits are on `imap` server blocks; the full cost model is in
[SEARCH.md](SEARCH.md):

| Key | Default | Meaning |
|---|---|---|
| `limits.search_rate_limit_per_min` | `60` | Expensive searches per window and account. `0` or less turns the limit off. |
| `limits.search_rate_limit_window` | `1m` | The window. |
| `limits.search_rate_limit_burst` | the per-minute value | Searches allowed back to back. |
| `limits.thread_max_messages` | `50000` | Most messages one `THREAD` may process. `0` or less gives the default. |

Searches that use only UIDs, flags, dates or sizes are not charged. A refused search gets
`NO [LIMIT]`. A filtered search matching more than 100,000 messages gets
`NO [LIMIT] Search matches too many messages, narrow the search` instead of a partial result. The search rate limit is counted per account in each IMAP listener of each node.

Other per-account limits, described elsewhere:

- `FETCH PREVIEW` downloads from S3 (`limits.preview_s3_*`): [PROTOCOLS.md](PROTOCOLS.md).
- Sieve redirects (`limits.redirect_rate_limit`, `limits.redirect_rate_window`,
  `limits.max_redirect_hops`): [SIEVE.md](SIEVE.md).
- IMAP METADATA sizes (`[metadata]`): [PROTOCOLS.md](PROTOCOLS.md).

---

## 10. The metrics endpoint

The Prometheus endpoint (`type = "metrics"`) shows per-domain activity, optionally per-user
activity, and a detailed picture of internal state. **It has no access control unless you configure
one.**

| Key | Meaning |
|---|---|
| `allowed_hosts` | IPs or CIDRs allowed to scrape. Matched against the TCP peer; `X-Forwarded-For` is ignored. Others get HTTP 403 `forbidden`. |
| `api_key` | Requires `Authorization: Bearer <key>`, compared in constant time. A missing token gets 401 with `WWW-Authenticate: Bearer realm="metrics"`; a wrong one gets 403 with `WWW-Authenticate: Bearer realm="metrics", error="invalid_token"`. |

With both set, a request must pass both. The endpoint is always plain HTTP: `tls` on a metrics block
is ignored with a warning, so put a TLS proxy in front if a token crosses an untrusted network.

```toml
[[server]]
type = "metrics"
name = "metrics"
addr = "10.20.0.7:9090"
path = "/metrics"
allowed_hosts = ["10.20.0.50/32"]
api_key = "a-long-random-token"
```

When neither key is set and the address is publicly reachable (as defined in section 2), Sora warns
at startup: `metrics endpoint is served without access control on a publicly reachable address; set
allowed_hosts and/or api_key`. The metrics themselves are in [METRICS.md](METRICS.md).

---

## 11. The HTTP APIs

- **Admin API** (`http_admin_api`): every request needs `Authorization: Bearer <api_key>`, and
  `allowed_hosts` can restrict the client addresses. Sora refuses to start without an `api_key`, with
  one shorter than 16 characters, or with the placeholder from `config.toml.example`. An optional
  `read_only_api_key` allows `GET` requests only; give it to monitoring tools. The Admin API
  can create and delete accounts, deliver mail and end sessions: keep it on a private address. See
  [ADMIN_API.md](ADMIN_API.md).
- **User API** (`http_user_api`): users sign in with their password and receive a JWT signed with
  `jwt_secret`. Sora refuses to start without a secret, with one shorter than 32 bytes, or with the
  placeholder. Token lifetimes over 7 days are cut to 7 days. The block's own `auth_rate_limit` applies to
  these logins, with the same rules as for the mail protocols. See [USER_API.md](USER_API.md).

---

## 12. Client-side encryption of message bodies

Sora can encrypt message bodies before it uploads them to S3, so the storage provider sees only
ciphertext. Only the S3 copy is encrypted. Bodies waiting for upload and the local cache on each
node's disk hold plaintext, and the metadata and search data in PostgreSQL are not encrypted.

```toml
[s3]
encrypt = true
encryption_key = "64 hex characters"   # 32 bytes, e.g. from: openssl rand -hex 32
```

Bodies are encrypted with AES-256-GCM using this key. The key must be exactly 64 hex characters.
**If you lose the key, every encrypted body is lost.** Back it up apart from the servers, and use the
same key on every node. Details are in [STORAGE.md](STORAGE.md).

---

## 13. Per node or across the cluster

| Protection | Counted |
|---|---|
| Limit of 10 waiting logins per IP | Per node, over all its listeners. |
| `max_connections`; `max_connections_per_ip` on backends and the User API proxy | Per listener on each node. |
| `max_connections_per_ip` on IMAP, POP3 and ManageSieve proxies | Across the cluster, through gossip. Per listener without `[cluster]`. |
| `max_connections_per_user`, `..._per_user_per_ip` on proxies | Across the cluster, through gossip. Not enforced without `[cluster]`. |
| `max_connections_per_user`, `..._per_user_per_ip` on backends | Per listener. |
| Authentication rate limits on IMAP, POP3 and ManageSieve proxies | Tier 2 blocks, Tier 2 counts and the name statistics across the cluster, through gossip, as `[cluster.rate_limit_sync]` says; Tier 1 blocks per listener. Per listener without `[cluster]`. |
| Authentication rate limits on backends, the User API and the User API proxy | Per listener. |
| Search rate limit | Per account in each IMAP listener of each node. |
| Session memory, error counts, timeouts | Per connection. |
| Lookup caches | Per listener; an account's entries are dropped on every node after a kick or an Admin API change. |
| Auth cache | Per proxy node; an account's entries are dropped on every node after an Admin API change. |

See [CLUSTER.md](CLUSTER.md#7-what-the-cluster-does-not-share).

---

## 14. Startup checks and warnings

Sora **refuses to start** when:

- a listener has `proxy_protocol = true` and `[servers] trusted_networks` is empty (section 3.2);
- a `[servers] trusted_networks` entry is neither an IP address nor a CIDR block;
- a block sets `master_username` without `master_password`, or `master_sasl_username` without
  `master_sasl_password` ([AUTHENTICATION.md](AUTHENTICATION.md#8-master-credentials));
- `master_sasl_allowed_networks` has an entry that is not an IP or CIDR;
- an `auth_rate_limit` duration does not parse;
- an `http_admin_api` block has a missing, short or placeholder `api_key`, or an `http_user_api` block
  a missing, short or placeholder `jwt_secret` (section 11);
- a listener has `tls = true` with neither certificate files nor a global `[tls]` section
  ([TLS.md](TLS.md)).

Sora **warns** at startup when:

- plaintext logins are allowed on a publicly reachable address (section 2);
- the metrics endpoint has no access control on a publicly reachable address (section 10);
- master SASL is configured without `master_sasl_allowed_networks`;
- `trusted_networks` contains a whole private range (section 3.1);
- an IMAP `command_timeout` is 35 minutes or more (section 5.3);
- `tls` is set on a metrics block (section 10).

---

## 15. Checklist

- Give every listener that clients reach `tls = true`. On STARTTLS ports, keep `insecure_auth = false`.
- Keep backend ports, LMTP ports and the Admin API reachable only from your own hosts.
- Set `trusted_networks` to your proxies and load balancers, and nothing wider. Set it on every node
  that runs an `lmtp_proxy`.
- Turn on `auth_rate_limit` on the listeners that face clients.
- Set `master_sasl_allowed_networks` on backends to the proxy addresses. Use long random master
  secrets.
- Set `max_connections` and `max_connections_per_ip` on public listeners, and the per-user limits on
  the proxies (with the cluster on).
- Set `min_bytes_per_minute = 512` on public IMAP, POP3 and ManageSieve listeners.
- Restrict the metrics endpoint with `allowed_hosts` and/or `api_key`.
- Store passwords as bcrypt. Move old SHA-512 accounts to bcrypt by setting a new password.
- If you turn on S3 encryption, back up `encryption_key`.
- After every change, read the startup log for the warnings of section 14.
