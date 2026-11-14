# Sora TLS

This document explains how Sora encrypts the connections that clients make to it: where each
listener gets its certificate, the difference between implicit TLS and STARTTLS for each protocol,
what `tls_verify` does, how SNI and the default domain work, and how automatic certificates
from Let's Encrypt are ordered, stored in S3, shared across a cluster, renewed and reloaded.

It is written for operators who put Sora on the internet and for contributors who change the
`tlsmanager/` package or a listener's TLS setup. TLS from a proxy to its backends (the "backend
leg") is covered in [PROXY.md](PROXY.md). Plaintext logins and other protections are covered in
[SECURITY.md](SECURITY.md).

## Contents

1. [Where TLS is used](#1-where-tls-is-used)
2. [Giving a listener a certificate](#2-giving-a-listener-a-certificate)
3. [Implicit TLS and STARTTLS](#3-implicit-tls-and-starttls)
4. [Plaintext logins](#4-plaintext-logins)
5. [Client certificates: `tls_verify`](#5-client-certificates-tls_verify)
6. [SNI and the default domain](#6-sni-and-the-default-domain)
7. [Let's Encrypt](#7-lets-encrypt)
8. [Let's Encrypt in a cluster](#8-lets-encrypt-in-a-cluster)
9. [Renewal and reload](#9-renewal-and-reload)
10. [Protocol details](#10-protocol-details)
11. [Configuration reference](#11-configuration-reference)
12. [Managing stored certificates with `sora-admin tls`](#12-managing-stored-certificates-with-sora-admin-tls)
13. [Other TLS connections](#13-other-tls-connections)
14. [Troubleshooting](#14-troubleshooting)
15. [Code map](#15-code-map)

---

## 1. Where TLS is used

Every listener is a `[[server]]` block. TLS on a listener is off until you set `tls = true` in that
block. These listener types can use TLS:

| `type` | TLS modes |
|---|---|
| `imap`, `pop3`, `managesieve`, `lmtp` | Implicit TLS, or STARTTLS with `tls_use_starttls = true` |
| `imap_proxy`, `pop3_proxy`, `managesieve_proxy`, `lmtp_proxy` | Implicit TLS, or STARTTLS with `tls_use_starttls = true` |
| `http_admin_api`, `http_user_api`, `user_api_proxy` | HTTPS (implicit TLS only) |
| `metrics` | None. The metrics endpoint is always plain HTTP; `tls = true` there only logs a warning. |

A certificate comes from one of two places (section 2):

- **The global `[tls]` section**: one certificate source for the whole process, either a
  certificate file pair (`provider = "file"`) or automatic certificates from Let's Encrypt
  (`provider = "letsencrypt"`).
- **The listener's own files**: `tls_cert_file` and `tls_key_file` in its `[[server]]` block.

Turning on `[tls]` does not turn on TLS anywhere by itself. Each listener still needs `tls = true`.

---

## 2. Giving a listener a certificate

### Per-listener files

```toml
[[server]]
type = "imap"
name = "imap"
addr = ":993"
tls = true
tls_cert_file = "/etc/sora/tls/fullchain.pem"   # certificate followed by the intermediate chain
tls_key_file  = "/etc/sora/tls/privkey.pem"
```

- Both files are PEM. Put the full chain in the certificate file; clients that do not have the
  intermediate certificate fail otherwise.
- The files are read once, when the listener starts. See [section 9](#9-renewal-and-reload) for
  what that means when the certificate is renewed.
- A file that cannot be read or parsed stops Sora. For the mail listeners and proxies the error
  reads `failed to load TLS certificate: ...`.

### The global `[tls]` section with files

```toml
[tls]
enabled = true
provider = "file"
cert_file = "/etc/sora/tls/fullchain.pem"
key_file  = "/etc/sora/tls/privkey.pem"

[[server]]
type = "imap"
name = "imap"
addr = ":993"
tls = true          # no tls_cert_file / tls_key_file needed
```

Every listener with `tls = true` that does not have files of its own (see the table below) serves
this one certificate. `cert_file` and `key_file` are both required; without them Sora stops with
`cert_file and key_file are required for provider='file'`.

### The global `[tls]` section with Let's Encrypt

```toml
[tls]
enabled = true
provider = "letsencrypt"

[tls.letsencrypt]
email = "postmaster@example.com"
domains = ["mail.example.com"]
storage_provider = "s3"

[tls.letsencrypt.s3]
bucket = "example-sora-certs"
```

See [section 7](#7-lets-encrypt).

### When both are set

Give each listener one certificate source: either the global `[tls]` section or its own
`tls_cert_file` and `tls_key_file`, not both. When both are configured, Sora uses one of them and
logs a startup warning naming the one it does not use.

### When neither is set

A listener with `tls = true`, no files of its own and no global `[tls]` stops startup, for example
`TLS enabled for IMAP [imap] but no tls_cert_file/tls_key_file provided and no global TLS manager configured`.
For the admin and user APIs the message is
`TLS certificate and key files are required when TLS is enabled (or use TLS manager)`. Sora never
falls back to plaintext on a port meant for TLS.

---

## 3. Implicit TLS and STARTTLS

There are two ways to encrypt a mail protocol:

- **Implicit TLS**: the client starts TLS as soon as it connects. These are the "secure" ports:
  IMAPS 993, POP3S 995.
- **STARTTLS**: the client connects in plaintext, reads the greeting, and asks to upgrade with a
  command (`STARTTLS` in IMAP, LMTP and ManageSieve, `STLS` in POP3). These are the standard ports:
  IMAP 143, POP3 110, ManageSieve 4190.

Each listener does exactly one of these, chosen by two keys:

| `tls` | `tls_use_starttls` | The listener |
|---|---|---|
| `false` | any | Plaintext. STARTTLS is not offered. A warning is logged if `tls_use_starttls = true`. |
| `true` | `false` (default) | Implicit TLS. STARTTLS is not offered. |
| `true` | `true` | Plaintext that offers STARTTLS (STLS for POP3). |

`tls_use_starttls` applies to `imap`, `pop3`, `lmtp`, `managesieve` and their four proxies. On any
other type it is ignored with a warning: the HTTP listeners only do HTTPS.

To serve both 993 and 143, configure two `[[server]]` blocks with different `name` and `addr`:

```toml
[[server]]
type = "imap"
name = "imaps"
addr = ":993"
tls = true

[[server]]
type = "imap"
name = "imap-starttls"
addr = ":143"
tls = true
tls_use_starttls = true
```

On the IMAP, POP3 and ManageSieve servers and on the mail proxies, the client's JA4 fingerprint
is captured during the STARTTLS handshake too, so client filters apply from the upgrade on (see
[PROTOCOLS.md](PROTOCOLS.md)).

Behaviour on the wrong kind of port:

- A client that sends plaintext to an implicit-TLS port of an IMAP, POP3, ManageSieve or LMTP
  server, or of a mail proxy, gets the line
  `ERROR: Plain-text connection attempted on TLS port. Use STARTTLS or connect to the plain-text port.`
  and is disconnected. The log says `Plain-text connection detected on TLS port - rejecting`.
- A client that starts a TLS handshake on a plaintext port of an IMAP, POP3 or ManageSieve server,
  or of a mail proxy, gets
  `ERROR: TLS connection attempted on plain-text port. Use STARTTLS or connect to the TLS port.`
  and is disconnected. The log says `TLS handshake detected on plain-text port - rejecting`.
- Both are counted in `sora_connection_timeouts_total` with `reason` `plain_text_on_tls_port` or
  `tls_on_plain_port`.

The PROXY protocol header, when a listener accepts one, is read before the TLS handshake. See
[PROXY.md](PROXY.md).

---

## 4. Plaintext logins

`insecure_auth` decides whether a listener accepts a password over an unencrypted connection. The
rule is the same for `imap`, `pop3`, `managesieve` and their proxies:

- `tls = false`: plaintext logins are always allowed. Sora assumes a trusted network, such as a
  backend behind a proxy.
- `tls = true`: logins are refused until the connection is encrypted (after STARTTLS, or always on
  implicit TLS), unless `insecure_auth = true`.

LMTP has no user login. The HTTP APIs do not use `insecure_auth`. The capabilities clients see
before and after STARTTLS are described in [PROTOCOLS.md](PROTOCOLS.md), and the full rules in
[SECURITY.md](SECURITY.md).

---

## 5. Client certificates: `tls_verify`

`tls_verify` in a `[[server]]` block is about **client** certificates (mutual TLS). It does not
make Sora check anything about its own certificate. It defaults to `false`, and you rarely want it
on a mail listener.

With `tls_verify = true`, every client of that listener must present a certificate, on every
listener type and with either certificate source. Connections without one fail the handshake.
Mail clients do not send client certificates, so leave it off on listeners that mail clients use.

The client certificate must chain to the host's system root certificates. There is no setting for
a private client CA.

Do not confuse it with `remote_tls_verify`, which makes a proxy check its **backends'**
certificates; see [PROXY.md](PROXY.md).

---

## 6. SNI and the default domain

SNI (Server Name Indication) is the name a client puts in its TLS hello, for example
`mail.example.com`. With Let's Encrypt, Sora picks the certificate by this name:

- The name is lowercased and must be one of `[tls.letsencrypt] domains`. Any other name fails the
  handshake, and the log says `TLS: Rejected certificate request for unconfigured domain`.
- A client that sends no name (old clients, or clients that connect by IP address) is treated as if
  it had sent the default domain: `[tls.letsencrypt] default_domain`, or the first entry of
  `domains` when that is empty.
- A listener can set its own default with `tls_default_domain` in its `[[server]]` block. That name
  must also be listed in `domains`, or SNI-less clients on that listener fail with
  `host not allowed`.

`tls_default_domain` only matters with `provider = "letsencrypt"`. With `provider = "file"` or with
per-listener files there is one certificate per listener, served to every client whatever name it
asks for.

Let's Encrypt gives Sora **one certificate per name**, not one certificate that lists all names.
Each name in `domains` gets its own certificate the first time a client asks for it.

---

## 7. Let's Encrypt

With `provider = "letsencrypt"`, Sora gets certificates from Let's Encrypt on its own, using the
`golang.org/x/crypto/acme/autocert` package, keeps them in an S3 bucket, and renews them before
they expire.

### What you need

- **DNS**: every name in `domains` resolves to the node (or nodes) that run Sora.
- **Port 80**: open from the internet to every Sora node with this provider. Let's Encrypt checks
  that you control a name by fetching a token over HTTP on port 80 (the HTTP-01 challenge).
- **An S3 bucket** that exists before Sora starts, with permission to check the bucket and to get,
  put and delete objects. It can be any S3-compatible store and can be different from the bucket
  in `[s3]`.
- **Outbound HTTPS** from Sora to `acme-v02.api.letsencrypt.org` and to the S3 endpoint.
- **An email address** for the Let's Encrypt account.

Sora always uses the Let's Encrypt **production** directory. There is no setting for the staging
directory, so mind Let's Encrypt's rate limits while you test.

### The HTTP-01 listener on port 80

With this provider, Sora starts an HTTP server on `:80` (all addresses; the port cannot be
changed). It answers Let's Encrypt's challenge requests under `/.well-known/acme-challenge/`. Any
other `GET` or `HEAD` request is redirected to the same URL over `https://`; other methods get
`400 Use HTTPS`. The log says `Starting HTTP-01 challenge server on :80 for Let's Encrypt`.

If Sora cannot bind port 80 (another program has it, or the process lacks the permission to bind a
port below 1024), it stops with `HTTP-01 challenge server failed: ...`. The shipped systemd unit
grants `CAP_NET_BIND_SERVICE`, which covers this.

### TLS-ALPN-01

The ACME library always tries the TLS-ALPN-01 challenge first, then HTTP-01. TLS-ALPN-01 is
answered on port **443**. Every listener that uses the global Let's Encrypt certificate can answer
it, so if one of them (for example `http_user_api`) listens on 443 for that name, the first
challenge succeeds. Otherwise each new order spends one failed TLS-ALPN-01 validation before
HTTP-01 succeeds. Let's Encrypt limits failed validations per name per hour, so avoid restarting
in a loop while a certificate fails to issue.

### Getting the first certificate

Sora does not order certificates at startup. A certificate is ordered the first time a client
connects with that name and no valid certificate is stored:

1. The client's handshake reaches Sora with SNI `mail.example.com`.
2. Sora looks in its local fallback directory, then in S3. Neither has it.
3. Sora orders it from Let's Encrypt, answers the challenge, stores the certificate and its key in
   S3 and in the local directory, and finishes the handshake.

The order takes some seconds. A client may time out on that first connection (implicit-TLS
listeners give a handshake 10 seconds); the order still completes, and the next connection works.
You can trigger it yourself after starting Sora:

```sh
openssl s_client -connect mail.example.com:993 -servername mail.example.com </dev/null
```

At startup Sora checks which certificates are already stored, logs `Pre-warm: Completed` with
`found`, `missing` and `total`, and arms renewal for every configured name (section 9).

### Storage in S3

Every object is stored under the prefix `autocert/`, named `cert-` plus the SHA-256 (hex) of the
lowercased entry name. The entries are:

| Entry | Contents |
|---|---|
| `<name>` | ECDSA certificate chain and its private key, PEM |
| `<name>+rsa` | RSA certificate and key, for clients that do not support ECDSA |
| `acme_account+key` | The Let's Encrypt account key |
| `<token>+http-01`, `<name>+token` | Short-lived challenge material |

Because every object holds a private key, Sora asks the store to encrypt it at rest on every write:
`server_side_encryption = "AES256"` by default. Set it to `"aws:kms"` with
`server_side_encryption_kms_key_id` to use a KMS key, or to `""` to send no encryption header. Use
`""` for stores that reject the header (for example MinIO without a KMS): such a store refuses
every certificate write otherwise. Other values stop startup.

The S3 client uses path-style addressing and signs its requests for `region`. With `access_key` and
`secret_key` set, it signs with them; without them, it uses the AWS default credential chain
(environment variables, the shared AWS config, an instance role). At startup Sora checks that the
bucket exists and is reachable, and stops with `failed to verify S3 bucket access: ...` if it is
not.

Each S3 request has a 5-second time limit, because a TLS handshake may be waiting on it.

### The local fallback directory

Each node keeps a copy of the certificates in a local directory, `fallback_dir`
(default `/var/lib/sora/certs`, created with mode `0700`):

- A certificate a node already holds in memory is served from memory. For any other, the node
  reads the local copy first and only goes to S3 when the local copy is missing. A node that has
  its certificates locally keeps serving them while S3 is down.
- A certificate found in S3 is written to the local directory at once.
- When an S3 write fails, the certificate is written locally and Sora keeps retrying the S3 write
  until it succeeds.
- When an S3 read fails with anything other than "not found", Sora returns an error to the
  handshake instead of ordering a new certificate, so an S3 outage does not burn Let's Encrypt
  rate limits.

If the directory cannot be created, Sora logs an error and runs from S3 alone. With
`enable_fallback = false` it also runs from S3 alone, logging a warning. Without the local copy
every handshake for a certificate not yet in memory reads S3, and handshakes fail while S3 is
unavailable.

The shipped systemd unit (`dist/sora.service`) makes the file system read-only apart from
`/var/spool/sora`, `/var/cache/sora`, `/var/lib/sora` and `/var/log/sora`, so the default
`/var/lib/sora/certs` is writable under it. A `fallback_dir` elsewhere must be added to
`ReadWritePaths`.

### The sync worker

Every `sync_interval` (default `5m`) a background worker compares the local copy of each name in
`domains` (ECDSA and RSA) with the copy in S3. If S3 holds a newer certificate, it replaces the
local copy and logs `CertSync: Updating certificate from S3`. This is how a node picks up a
certificate that another node renewed (section 8). `sync_interval = "0"` turns the worker off.

---

## 8. Let's Encrypt in a cluster

When several nodes use Let's Encrypt with the same bucket, run them in one cluster
([CLUSTER.md](CLUSTER.md)). Then:

- **Only the leader orders and renews.** On any other node, the ACME client's requests are refused
  before they leave the node, and its writes of new certificates to the shared store are blocked.
- **Any node can answer the HTTP-01 challenge.** The leader stores the challenge token in S3; a
  node that receives Let's Encrypt's request on port 80 reads the token from there. A load
  balancer can therefore send port 80 to any node.
- **A database claim stops duplicate orders.** On nodes that have a database, the leader takes a
  claim in PostgreSQL (the `locks` row `acme_issuance:<name>`, held for up to 10 minutes) before it
  orders a certificate, for a first issuance and for a renewal alike. During a network split both
  sides have a leader, but only one gets the claim. If the database cannot be reached, the order
  goes ahead anyway: an expired certificate is worse than a duplicate order. Nodes without a
  database (proxy-only) rely on leadership alone.
- **Other nodes wait for the leader.** A handshake on a non-leader node for a name with no stored
  certificate waits up to 5 seconds, reading the store every second, for the leader to publish one
  (`TLS: Waiting for the cluster leader to publish a certificate`). If none appears, the handshake
  fails.

Two consequences:

- **The first certificate for a name is ordered only when a client reaches the leader with that
  name.** Connections to other nodes wait 5 seconds and fail until then. After adding a name,
  connect to the leader with that name (the `openssl s_client` command in section 7).
- **The leader must be a node that runs Let's Encrypt.** The leader is the member with the
  smallest `node_id`. If that node does not use `provider = "letsencrypt"`, nobody orders or renews.
  See [CLUSTER.md](CLUSTER.md#5-leader-election).

Without the cluster, every node that uses Let's Encrypt orders and renews on its own, and only the
database claim keeps two nodes from ordering for the same name at once.

---

## 9. Renewal and reload

### Let's Encrypt certificates

Renewal is armed at startup for every name in `domains`, whether or not a client has used it since
the node started:

- The renewal starts `renew_before` before expiry. Unset (or `"0"`), it is the lesser of 30 days and
  one third of the certificate's lifetime (30 days for Let's Encrypt's 90-day certificates). A
  value above 30 days is treated as 30 days. A small random delay (at most 1 hour) spreads
  renewals.
- When the timer fires, the node first reads the store. If the store already holds a certificate
  that is not due for renewal, the node switches to it. Otherwise it orders a new one (only the
  leader can, in a cluster).
- A failed renewal is retried after 30 to 60 minutes. The old certificate keeps being served until
  it expires.
- The new certificate is used for the next handshake. Open connections keep the certificate they
  started with. No restart is needed.

In a cluster, a non-leader's renewal attempt is refused, and it retries every 30 to 60 minutes.
Meanwhile the leader renews and writes to S3, the sync worker copies the result into the
non-leader's local directory within `sync_interval`, and the non-leader's next attempt finds it and
switches. With `sync_interval = "0"` and the local directory enabled, a non-leader keeps reading
its old local copy and never picks up the renewed certificate; it serves the old one until it
expires.

### File certificates

Certificate files, per listener or in `[tls]`, are read once at startup. A SIGHUP reload
(`systemctl reload sora`) does not read them again:

- If a renewal tool replaces the files in place, Sora keeps serving the old certificate until it
  restarts. Restart Sora after each renewal, for example from the renewal tool's deploy hook.
- If you change `tls_cert_file`, `tls_key_file`, `tls`, `tls_use_starttls`, `tls_verify` or
  `tls_default_domain` in a `[[server]]` block, a reload logs
  `Config reload: server settings changed but require restart to take effect` with the changed
  fields.
- Changes to the `[tls]` section are not applied by a reload; it reports them as changed but
  requiring a restart to take effect.

See [OPERATIONS.md](OPERATIONS.md) for what a reload does in general.

---

## 10. Protocol details

- TLS 1.2 is the minimum version on every listener. TLS 1.3 is used when the client supports it.
- Renegotiation is refused.
- Implicit-TLS handshakes on IMAP, POP3, ManageSieve, LMTP and the mail proxies have 10 seconds to
  complete. The handshake runs in the connection's own goroutine, so a slow client does not delay
  other connections.
- ALPN: mail listeners using per-listener files offer their own protocol (`imap`, `pop3`, `sieve`
  or `lmtp`). Listeners using the global `[tls]` certificate offer `imap`, `pop3`, `sieve`, `lmtp`,
  `http/1.1` and `h2`, plus `acme-tls/1` (last) with Let's Encrypt. A client that offers no ALPN at
  all is accepted. A client that offers ALPN values, none of which the listener offers, is refused
  by Go's TLS stack.
- JA4 fingerprints are captured on the IMAP, POP3 and ManageSieve servers and on the mail proxies,
  for implicit TLS and STARTTLS alike. The LMTP server and the HTTP listeners do not capture them.

---

## 11. Configuration reference

### `[tls]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | Start the global certificate manager. |
| `provider` | string | none | `"file"` or `"letsencrypt"`. Required when `enabled`; anything else stops startup with `unknown TLS provider`. |
| `cert_file` | string | none | PEM certificate (with chain), for `provider = "file"`. |
| `key_file` | string | none | PEM private key, for `provider = "file"`. |

### `[tls.letsencrypt]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `email` | string | none | Contact address for the Let's Encrypt account. Required. |
| `domains` | list of strings | none | Every name clients connect with. Exact names, no wildcards. Required. |
| `default_domain` | string | first entry of `domains` | Name used for clients that send no SNI. Must be in `domains`. |
| `storage_provider` | string | none | Must be `"s3"`. Required: any other value, including empty, stops startup. |
| `renew_before` | duration | lesser of 30 days and 1/3 of the lifetime | How long before expiry to renew, such as `"720h"` or `"30d"`. Capped at 30 days. An invalid value stops startup. |
| `enable_fallback` | bool | `true` | Keep a local copy of the certificates in `fallback_dir`. |
| `fallback_dir` | string | `"/var/lib/sora/certs"` | Directory for the local copy. Created if missing. |
| `sync_interval` | duration | `"5m"` | How often to refresh the local copy from S3. `"0"` turns it off. An invalid value stops startup. |

### `[tls.letsencrypt.s3]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `bucket` | string | none | Bucket for certificates. Must exist. Required. |
| `endpoint` | string | `"s3.amazonaws.com"` | S3 endpoint, with or without `https://`/`http://`. |
| `disable_tls` | bool | `false` | Use `http://` for an endpoint written without a scheme. Ignored when the endpoint has one. |
| `region` | string | none | Region the requests are signed for. |
| `access_key` | string | none | Static credentials. Used only when `secret_key` is set too. Without both, the AWS default credential chain is used. |
| `secret_key` | string | none | Static credentials. Used only when `access_key` is set too. |
| `server_side_encryption` | string | `"AES256"` | Encryption asked of the store on every write: `"AES256"`, `"aws:kms"` or `""` (no header). |
| `server_side_encryption_kms_key_id` | string | none | KMS key ID. Required with `"aws:kms"`, refused with anything else. |
| `debug` | bool | `false` | Log the S3 client's requests and responses. |

### Per-listener keys (in `[[server]]` blocks)

| Key | Type | Default | Meaning |
|---|---|---|---|
| `tls` | bool | `false` | Encrypt this listener. |
| `tls_use_starttls` | bool | `false` | With `tls = true`: plaintext with STARTTLS instead of implicit TLS. Mail listeners and mail proxies only. |
| `tls_cert_file` | string | none | PEM certificate (with chain) for this listener. |
| `tls_key_file` | string | none | PEM private key for this listener. |
| `tls_verify` | bool | `false` | Require client certificates (section 5). |
| `tls_default_domain` | string | none | Name used for SNI-less clients on this listener, with Let's Encrypt (section 6). |
| `insecure_auth` | bool | `false` | Allow plaintext logins on a `tls = true` listener (section 4). |

Backend-leg keys (`remote_tls`, `remote_tls_use_starttls`, `remote_tls_verify`,
`remote_tls_ca_file`) are documented in [PROXY.md](PROXY.md).

---

## 12. Managing stored certificates with `sora-admin tls`

`sora-admin tls` works on the Let's Encrypt bucket from `[tls.letsencrypt.s3]` and on the local
directory of the host you run it on (`--cache-dir`, default `fallback_dir` or
`/var/lib/sora/certs`). It does not touch other nodes' directories or the certificates a running
Sora holds in memory:

| Command | What it does |
|---|---|
| `sora-admin tls list` | Lists certificates in S3, whether each is in the local directory, and with `--details` their expiry. |
| `sora-admin tls cache` | Copies certificates from S3 into the local directory, for example on a new node. |
| `sora-admin tls delete --domain <name>` | Deletes a name's certificates, ECDSA and RSA, from S3 and from the local directory. `--key` deletes one object from S3 by the full key that `tls list --details` shows. |
| `sora-admin tls clean` | Deletes expired certificates. |

Flags and output are in [ADMIN_CLI.md](ADMIN_CLI.md).

---

## 13. Other TLS connections

Sora also makes TLS connections of its own. They are configured elsewhere:

| Connection | Where |
|---|---|
| Proxy to backend | [PROXY.md](PROXY.md) |
| Proxy to the remote lookup API | [PROXY.md](PROXY.md) |
| Sora to PostgreSQL | [DATABASE.md](DATABASE.md) |
| Sora to the message-body S3 store | [STORAGE.md](STORAGE.md) |
| Outbound relay for redirects and vacation replies | [RELAY.md](RELAY.md) |
| `sora-admin` to the admin API | [ADMIN_CLI.md](ADMIN_CLI.md) |

---

## 14. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Sora exits at startup with `HTTP-01 challenge server failed` | Something else listens on port 80, or Sora may not bind ports below 1024. | Free port 80, or grant `CAP_NET_BIND_SERVICE` (the shipped unit does). |
| Sora exits with `failed to verify S3 bucket access` | The bucket does not exist, or the credentials cannot reach it. | Create the bucket; check `endpoint`, keys and network. |
| The log shows `Cannot create certificate fallback directory - degrading to S3-only` | `fallback_dir` cannot be created or written by the `sora` user, or is outside the systemd unit's `ReadWritePaths`. | Make the directory writable (section 7). |
| A client's handshake fails, log `TLS: Rejected certificate request for unconfigured domain` | The client asked for a name that is not in `domains`. | Add the name, or have clients use a listed name. |
| Handshakes for a new name fail on every node but one | In a cluster only the leader orders the first certificate. | Connect to the leader with that name. |
| Log `TLS: Domain marked as rate-limited` | Let's Encrypt refused with a rate limit; this node places no new order for that name until the time Let's Encrypt gave (24 hours if it gave none, or until a restart). | Wait; fix the cause of the failed orders (DNS, port 80) first. |
| Mail clients cannot connect; the log shows `TLS handshake failed` with `tls: client didn't provide a certificate` | `tls_verify = true` on that listener: it demands client certificates. | Set `tls_verify = false`. |
| An old certificate is still served after renewing the files | File certificates are read only at startup. | Restart Sora. |
| Non-leader nodes serve an expiring certificate the leader has renewed | `sync_interval = "0"`, or S3 writes fail on the leader. | Set `sync_interval`; check the leader's `S3-Cache: Failed to upload certificate to S3` lines. |
| `ERROR: Plain-text connection attempted on TLS port` | The client is set to plaintext or STARTTLS on an implicit-TLS port. | Change the client to SSL/TLS, or point it to the STARTTLS port. |

---

## 15. Code map

| Path | What it does |
|---|---|
| [tlsmanager/manager.go](../tlsmanager/manager.go) | The global manager: file provider, Let's Encrypt setup, SNI checks, default domain, rate-limit memory. |
| [tlsmanager/issuance_gate.go](../tlsmanager/issuance_gate.go) | Decides whether this node may order: leadership, rate limits, the database claim; waits for the leader's certificate. |
| [tlsmanager/cluster_cache.go](../tlsmanager/cluster_cache.go) | Blocks certificate writes on non-leaders. |
| [tlsmanager/cluster_http_handler.go](../tlsmanager/cluster_http_handler.go) | The HTTP-01 handler wrapper. |
| [tlsmanager/s3cache.go](../tlsmanager/s3cache.go) | S3 storage, key naming, server-side encryption. |
| [tlsmanager/fallback_cache.go](../tlsmanager/fallback_cache.go) | The local fallback directory in front of S3. |
| [tlsmanager/cert_sync.go](../tlsmanager/cert_sync.go) | The periodic S3-to-local sync. |
| [cmd/sora/certificate_fence.go](../cmd/sora/certificate_fence.go) | The PostgreSQL claim for orders and renewals. |
| [server/sora_conn.go](../server/sora_conn.go) | Implicit-TLS listener, deferred handshake, wrong-port detection, STARTTLS helpers. |
| [cmd/sora-admin/tls.go](../cmd/sora-admin/tls.go) | `sora-admin tls`. |
