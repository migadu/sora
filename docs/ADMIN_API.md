# Sora Admin API

The Admin API is an HTTP interface for running Sora. With it you create and delete accounts,
manage their addresses and passwords, restore deleted mail, inject messages, see and end
client sessions, and read the health, cache and upload state of the system. Automation, a
control panel or `sora-admin` can drive it.

This document is the reference: every endpoint, its request and response, and its status
codes, as the code on `main` implements them. It is for operators who script against the API
and for contributors who change it. The handlers live in
[server/adminapi/](../server/adminapi/). A machine-readable OpenAPI description of the same
endpoints is kept next to them in
[admin_api_openapi.yaml](../server/adminapi/admin_api_openapi.yaml); a test fails when a route
is registered without being described there.

1. [Overview](#1-overview)
2. [Configuration](#2-configuration)
3. [Authentication and access control](#3-authentication-and-access-control)
4. [Requests, responses and errors](#4-requests-responses-and-errors)
5. [Endpoint summary](#5-endpoint-summary)
6. [What an endpoint needs on the node](#6-what-an-endpoint-needs-on-the-node)
7. [Accounts](#7-accounts)
8. [Credentials](#8-credentials)
9. [Deleted messages](#9-deleted-messages)
10. [Mail delivery](#10-mail-delivery)
11. [Connections and kicks](#11-connections-and-kicks)
12. [Shared mailbox ACLs](#12-shared-mailbox-acls)
13. [Proxy backends and affinity](#13-proxy-backends-and-affinity)
14. [Cache](#14-cache)
15. [Upload queue](#15-upload-queue)
16. [Authentication statistics](#16-authentication-statistics)
17. [Health](#17-health)
18. [System information](#18-system-information)

---

## 1. Overview

The Admin API is a `[[server]]` block of type `http_admin_api`. It runs inside the `sora`
process, next to whatever else that node serves. All paths start with `/admin/`. Requests and
responses are JSON, except where this document says otherwise.

Things to know before you start:

- **It always needs PostgreSQL.** Sora refuses to start when an `http_admin_api` server is
  configured and `[database]` is not. It does not need S3: account changes, health and usage
  are all database reads and writes.
- **Some endpoints act on the node they run on.** The cache, the mail injector, the session
  list and kicks, the blocked-address list and the proxy backend list all read state that lives
  inside the `sora` process answering the request. Section 6 lists which endpoints those are.
  Put the Admin API on a node that runs the servers you want to manage, or call it on each
  node.
- **Two keys at most.** `api_key` opens every endpoint. The optional `read_only_api_key` opens
  only the `GET` endpoints. There is no finer per-endpoint permission. Treat `api_key` like a
  database password, and limit who can reach the port with `allowed_hosts`.
- **No browser support.** The API sends no CORS headers. Call it from a server or a script.

---

## 2. Configuration

A minimal block:

```toml
[[server]]
type = "http_admin_api"
name = "admin-api"
addr = "127.0.0.1:8080"
api_key = "a-long-random-value-of-at-least-16-characters"
allowed_hosts = ["127.0.0.1", "10.0.0.0/24"]
```

| Key | Default | Meaning |
|---|---|---|
| `type` | required | `http_admin_api`. |
| `name` | required | Names the server in logs. |
| `addr` | required | Listen address, for example `":8080"` or `"127.0.0.1:8080"`. |
| `api_key` | none | The bearer token every request must carry. When it is empty the server is skipped and Sora logs `HTTP Admin API server enabled but no API key configured - skipping`. When it is shorter than 16 characters, or is one of the placeholders from `config.toml.example` (`your-api-key-here`, `your-secret-api-key-here`), Sora refuses to start. |
| `read_only_api_key` | none | An optional second key for clients that only read, such as monitoring and dashboards. It is accepted for `GET` requests only. It follows the same length and placeholder rules as `api_key` and must differ from it, or Sora refuses to start. See [section 3](#3-authentication-and-access-control). |
| `allowed_hosts` | `[]` (everyone) | Client addresses allowed to connect: IP addresses and CIDR blocks. Entries that are neither, such as host names, never match. |
| `max_connections` | `0` (no limit) | Most concurrent TCP connections. |
| `max_message_size` | `"50mb"` | Largest request body `POST /admin/mail/deliver` accepts. |
| `tls` | `false` | Serve HTTPS. |
| `tls_cert_file`, `tls_key_file` | none | Certificate and key for `tls = true`, when this listener does not use the `[tls]` certificate manager. Use one source per listener. See [TLS.md](TLS.md). |
| `tls_default_domain` | none | Certificate name for clients that send no SNI, when the `[tls]` manager provides certificates. |
| `tls_verify` | `false` | Require a client certificate. Sora sets no client CA list, so the certificate must chain to the system's trusted roots. |
| `[server.limits] redirect_rate_limit` | `100` | For Sieve `redirect` during `POST /admin/mail/deliver`: redirects per account per window. `0` is unlimited. |
| `[server.limits] redirect_rate_window` | `"1h"` | The window for `redirect_rate_limit`. |
| `[server.limits] max_redirect_hops` | `2` | How often one message may be redirected before further redirects are suppressed. `0` is unlimited. |

With `proxy_protocol = true`, the Admin API expects a PROXY protocol header on each
connection, from an address in `[servers] trusted_networks`. The client address in it is then
used for `allowed_hosts`. `proxy_protocol_timeout` (default `"5s"`) is how long it waits for
that header.

The HTTP server's own limits are fixed: 10 seconds to read the request headers, 5 minutes to
read the whole request and 5 minutes to write the response, 120 seconds for an idle
keep-alive connection, and 5 seconds to finish open requests at shutdown.

**Reload.** On SIGHUP Sora re-reads `api_key`, `read_only_api_key` and `allowed_hosts` and
applies them to new requests. An empty `api_key` in the reloaded file keeps the old key. An
empty or removed `read_only_api_key` revokes the read-only key. A key that fails the length or
placeholder check is refused, and so is a reload that sets `api_key` to the read-only key in use,
or `read_only_api_key` to the `api_key` it replaces. The two keys change together: when either is
refused, both previous keys stay in use and the reload is logged as failed; `allowed_hosts` still
reloads. When you retire a key, give the slot a fresh value instead of moving a key from the other
slot. An empty or removed `allowed_hosts` opens the API to every address, as it does at
start-up. Every other key needs a restart. See [OPERATIONS.md](OPERATIONS.md) for reloads in
general.

Keys other server types read have no effect here and are reported with a startup warning:
among them `[server.auth_rate_limit]`, `[server.lookup_cache]`, `allowed_origins`,
`max_connections_per_ip`, `max_connections_per_user` and `max_connections_per_user_per_ip`.

The full list of server keys and how the file is read is in
[CONFIGURATION.md](CONFIGURATION.md).

---

## 3. Authentication and access control

Every request goes through two checks, in this order.

**1. The client address.** When `allowed_hosts` is not empty, the client's address (the TCP
peer's, or the one in the PROXY header with `proxy_protocol = true`) must match one of its
entries. A bare address matches itself (as `/32` or `/128`); a CIDR block
matches every address in it. IPv6 entries are compared by value. Forwarded headers
(`X-Forwarded-For`, `X-Real-IP`) are never read. A client that does not match gets:

```
HTTP/1.1 403 Forbidden
{"error":"Host not allowed"}
```

**2. The API key.** The request must carry the key in the `Authorization` header:

```
Authorization: Bearer a-long-random-value-of-at-least-16-characters
```

The word `Bearer` may be in any case. The key is compared in constant time.

| Situation | Status | Body | `WWW-Authenticate` |
|---|---|---|---|
| No `Authorization` header | 401 | `{"error":"Authorization header required"}` | `Bearer realm="admin-api"` |
| Header is not `Bearer <key>` | 401 | `{"error":"Authorization header must be 'Bearer <token>'"}` | `Bearer realm="admin-api"` |
| Wrong key | 401 | `{"error":"Invalid API key"}` | `Bearer realm="admin-api", error="invalid_token"` |
| `read_only_api_key` with a method other than `GET` | 403 | `{"error":"API key is read-only"}` | `Bearer realm="admin-api", error="insufficient_scope"` |

Every refusal of the key carries a Bearer challenge (RFC 6750 section 3); a key that was
presented and refused also says why, with the error codes of RFC 6750 section 3.1, and gets the
status that section gives the code: 401 for `invalid_token`, 403 for `insufficient_scope`.

`api_key` grants every endpoint. `read_only_api_key`, when set, grants every `GET` endpoint and
nothing else: every endpoint that changes something uses `POST`, `PUT` or `DELETE`. Give the
read-only key to monitoring and reporting tools, and keep `api_key` for administration.

Both checks run before the path is looked at, so an unknown path also answers 401 or 403
until the request is authenticated.

`sora-admin` commands that talk to this API read the address and key from `[admin_cli]`; see
[ADMIN_CLI.md](ADMIN_CLI.md).

---

## 4. Requests, responses and errors

**Request bodies** are JSON objects, except for `POST /admin/mail/deliver`, which also
accepts a raw message or a form upload. The handlers decode the body whatever the
`Content-Type` header says (mail delivery is the exception). Unknown fields are ignored.

**Email addresses in paths** are written as they are: `/admin/accounts/user@example.com`.
`%40` for `@` works too. An address is one path segment, so a `/` inside a local part must be
sent as `%2F`. Addresses are matched case-insensitively, and an internationalized domain
(`user@bücher.example`) is matched in its ASCII form (`user@xn--bcher-kva.example`). An address
that does not parse gives `400`, usually with `invalid email address: ...`.

**Responses** are JSON with `Content-Type: application/json`. Most field names are
snake_case. A few responses encode internal structures directly and use Go field names
instead (`Address`, `TotalPending`, `ID`); the sections below name each one.

**Times** are RFC 3339 strings (`2026-03-01T09:30:00Z`), with two exceptions:

- `created_at` in account summaries (domain listing and usage) and the credential list's
  `CreatedAt` and `UpdatedAt` are text in Go's default time format, such as
  `2026-03-01 09:30:00.123456 +0000 UTC`.
- Nullable times in the upload queue are objects: `{"Time":"...","Valid":true}`.

**Empty lists** are `[]`, never `null`.

**Errors** are JSON objects with one field:

```json
{"error": "Account not found"}
```

A method the path does not serve is `405 {"error":"Method not allowed"}` with an `Allow`
header listing the methods it does serve; a path no endpoint has is
`404 {"error":"Not found"}`.

**Status codes** used across the API:

| Code | Meaning here |
|---|---|
| 200 | Done. |
| 201 | Created (account, credential). |
| 202 | Accepted: an account purge was requested and runs in the background. |
| 207 | Mail delivery to several recipients where at least one failed. |
| 400 | The request is wrong: bad JSON, a missing field, a bad parameter, or a refused change. |
| 401 | No or malformed `Authorization` header, or a wrong key. |
| 403 | The read-only key on a write, or client address not in `allowed_hosts`. |
| 404 | The account, credential, mailbox or record does not exist, or no endpoint has the path. |
| 405 | Wrong method for the path; `Allow` lists the methods it serves. |
| 409 | An address already exists. |
| 500 | Server-side failure. |
| 503 | A component this endpoint needs is not running on this node, or the backend is in maintenance. |

**Pagination** exists only on `GET /admin/usage/accounts`. Other list endpoints take a
`limit` or return everything.

**Rate limiting** does not apply to the Admin API. The `[server.auth_rate_limit]` settings are
not used by it.

---

## 5. Endpoint summary

| Method | Path | Section | What it does |
|---|---|---|---|
| POST | `/admin/accounts` | 7.1 | Create an account. |
| GET | `/admin/accounts/{email}` | 7.2 | Account details. |
| PUT | `/admin/accounts/{email}` | 7.3 | Set the password of one credential. |
| DELETE | `/admin/accounts/{email}` | 7.4 | Soft-delete an account. |
| DELETE | `/admin/accounts/{email}?purge=true` | 7.5 | Request permanent deletion (asynchronous). |
| POST | `/admin/accounts/{email}/restore` | 7.6 | Undo a soft delete. |
| GET | `/admin/accounts/{email}/exists` | 7.7 | Does an address exist, and is its account deleted. |
| GET | `/admin/domains/{domain}/accounts` | 7.8 | Accounts whose primary address is in a domain. |
| GET | `/admin/usage/accounts` | 7.9 | Every account with its usage, page by page. |
| POST | `/admin/accounts/{email}/credentials` | 8.1 | Add an address (alias) to an account. |
| GET | `/admin/accounts/{email}/credentials` | 8.2 | List an account's addresses. |
| GET | `/admin/credentials/{email}` | 8.3 | Details of one address and its account. |
| DELETE | `/admin/credentials/{email}` | 8.4 | Remove an address from its account. |
| GET | `/admin/accounts/{email}/messages/deleted` | 9.1 | List expunged messages that can still be restored. |
| POST | `/admin/accounts/{email}/messages/restore` | 9.2 | Restore expunged messages. |
| POST | `/admin/mail/deliver` | 10 | Deliver a message, as LMTP would. |
| GET | `/admin/connections` | 11.1 | Accounts with sessions on this node. |
| GET | `/admin/connections/stats` | 11.2 | Connection statistics per tracker. |
| GET | `/admin/connections/user/{email}` | 11.3 | One account's tracked sessions. |
| POST | `/admin/connections/kick` | 11.4 | End an account's sessions. |
| POST | `/admin/mailboxes/acl/grant` | 12.1 | Set an identifier's rights on a shared mailbox. |
| POST | `/admin/mailboxes/acl/revoke` | 12.2 | Remove an identifier's rights. |
| GET | `/admin/mailboxes/acl` | 12.3 | List a mailbox's ACL. |
| GET | `/admin/proxy/backends` | 13.1 | Backend health as this node's proxies see it. |
| GET | `/admin/affinity` | 13.2 | A user's affinity backend. |
| POST | `/admin/affinity` | 13.2 | Set a user's affinity backend. |
| DELETE | `/admin/affinity` | 13.2 | Remove a user's affinity. |
| GET | `/admin/affinity/list` | 13.2 | Every affinity this node holds. |
| GET | `/admin/affinity/stats` | 13.2 | Affinity table statistics. |
| GET | `/admin/cache/stats` | 14.1 | This node's local cache. |
| GET | `/admin/cache/metrics` | 14.2 | Recorded cache hit rates of every node. |
| POST | `/admin/cache/purge` | 14.3 | Empty this node's local cache. |
| GET | `/admin/uploader/status` | 15.1 | Upload queue totals. |
| GET | `/admin/uploader/failed` | 15.2 | Uploads that reached the attempt limit. |
| GET | `/admin/auth/stats` | 16.1 | Describes the auth statistics endpoints. |
| GET | `/admin/auth/blocked` | 16.2 | Addresses this node's rate limiters block. |
| GET | `/admin/auth-cache/stats` | 16.3 | This node's persistent auth cache. |
| GET | `/admin/health/overview` | 17.1 | Summary of component health. |
| GET | `/admin/health/servers/{hostname}` | 17.2 | Component health of one host (or all). |
| GET | `/admin/health/servers/{hostname}/components/{component}` | 17.3 | One component's current state. |
| GET | `/admin/config` | 18 | Server type, enabled features and the endpoint list. |

Every `GET` endpoint accepts `read_only_api_key`; every other method needs `api_key` (see
[section 3](#3-authentication-and-access-control)).

**Destructive and asynchronous endpoints.** Know these before you script against them:

- `DELETE /admin/accounts/{email}` ends the account's sessions and stops logins. It is
  reversible until the grace period ends.
- `DELETE /admin/accounts/{email}?purge=true` cannot be undone once the purge worker starts.
  It returns `202` at once; the deletion runs later on a node with object storage.
- `DELETE /admin/credentials/{email}` takes effect at once.
- `POST /admin/connections/kick` closes sessions on this node at once and tells cluster peers
  in the background.
- `POST /admin/cache/purge` empties this node's cache. No mail is lost; bodies are fetched
  from S3 again.
- `POST /admin/accounts/{email}/messages/restore` restores in chunks and may stop part-way.

---

## 6. What an endpoint needs on the node

The Admin API process always has a database. Other parts exist only when the node runs the
servers that create them. An endpoint that needs a missing part answers as listed here.

| Endpoint | Needs on this node | Without it |
|---|---|---|
| Accounts, credentials, deleted messages, usage, ACLs, health, cache metrics, upload queue | Database only | Always available. |
| `DELETE /admin/accounts/{email}?purge=true` | Database to record the request; a purge worker on any node with S3 to carry it out | The request is recorded. It waits until a node with S3 runs. |
| `POST /admin/mail/deliver` | The upload worker: an `imap`, `pop3` or `lmtp` server on this node | `503 {"error":"Mail delivery not available on this node: no upload worker"}` with `Retry-After: 60`. Sora logs a warning at start-up. |
| `GET /admin/cache/stats`, `POST /admin/cache/purge` | The local cache: an `imap`, `pop3` or `lmtp` server on this node | `503 {"error":"Cache not available"}` |
| `/admin/connections*` | Connection trackers | List and stats answer with an empty list and a `note`; kick answers `503`. |
| `GET /admin/proxy/backends` | Proxy servers on this node | `{"proxies":[]}` |
| `/admin/affinity*` | `[cluster] enabled = true` and `[cluster.affinity] enabled = true` | `503 {"error": "Affinity manager not enabled on this server"}` |
| `GET /admin/auth/blocked` | Servers with `[server.auth_rate_limit] enabled = true` | Empty list. |
| `GET /admin/auth-cache/stats` | `[auth_cache] enabled = true` | `200` with `"enabled": false` (see 16.3). |

**Connection trackers.** Every `imap`, `pop3` and `managesieve` backend server has one for
its own sessions. An `lmtp_proxy` has a local one. `imap_proxy`, `pop3_proxy` and
`managesieve_proxy` have one only in cluster mode, and it shares state with the other nodes.
A node with only an Admin API, or only a non-cluster proxy, has none.

---

## 7. Accounts

An account owns mailboxes and messages. It has one or more credentials: addresses that sign in
and receive mail. One credential is the primary identity. Any credential's address identifies
the account in these paths. See [AUTHENTICATION.md](AUTHENTICATION.md) for how logins use
credentials and [STORAGE.md](STORAGE.md) for what deletion does to stored mail.

### 7.1 Create an account

`POST /admin/accounts`

With one address:

```json
{
  "email": "alice@example.com",
  "password": "correct horse battery staple"
}
```

| Field | Type | Meaning |
|---|---|---|
| `email` | string | The address, which becomes the primary identity. Required. |
| `password` | string | Hashed with bcrypt at the server's `bcrypt_cost`. bcrypt reads at most 72 bytes, so a longer password is refused with `400`. |
| `password_hash` | string | A ready hash, stored as given once Sora has checked that it is in a scheme Sora verifies ([AUTHENTICATION.md](AUTHENTICATION.md#4-password-schemes)). A hash Sora could not check is refused with `400`, so no credential is stored that no password signs in to. |

Give exactly one of `password` and `password_hash`.

Response `201`:

```json
{"account_id": 1042, "email": "alice@example.com", "message": "Account created successfully"}
```

With several addresses at once, use `credentials` and leave the top-level fields out:

```json
{
  "credentials": [
    {"email": "alice@example.com", "password": "secret-one", "is_primary": true},
    {"email": "a.smith@example.com", "password_hash": "{BLF-CRYPT}$2a$12$...", "is_primary": false},
    {"email": "info@example.com", "password": "secret-two", "hash_type": "ssha512"}
  ]
}
```

| Field | Type | Meaning |
|---|---|---|
| `email` | string | Required. |
| `password` / `password_hash` | string | Exactly one of them. |
| `is_primary` | bool | Exactly one credential must be `true`. |
| `hash_type` | string | How `password` is hashed: `bcrypt` (default) or `ssha512`. |

Response `201`:

```json
{
  "account_id": 1043,
  "credentials": ["alice@example.com", "a.smith@example.com", "info@example.com"],
  "message": "Account created successfully with multiple credentials"
}
```

All credentials are created in one transaction, or none are.

Errors:

| Status | Body `error` | When |
|---|---|---|
| 400 | `Invalid JSON body` | The body is not JSON. |
| 400 | `Email is required` | Single form without `email`. |
| 400 | `Either password or password_hash is required` | Neither given. |
| 400 | `Cannot specify both password and password_hash` | Both given. |
| 400 | `Cannot specify email, password, or password_hash when using credentials array` | Both forms mixed. |
| 400 | `Credential N: email is required` (and the same two password messages, prefixed) | A bad entry in `credentials`. |
| 400 | The reason | An invalid address, an address held by an account in its deletion grace period, no or several `is_primary`, duplicate addresses in the request, a `hash_type` other than `bcrypt` or `ssha512`. |
| 409 | `Account already exists` / `One or more email addresses already exist` | An address already exists. |
| 500 | `Failed to create account` / `Failed to create account with credentials` | A server-side failure. The server log has the reason. |

### 7.2 Get account details

`GET /admin/accounts/{email}`

Response `200`:

```json
{
  "account_id": 1042,
  "created_at": "2026-03-01T09:30:00Z",
  "primary_email": "alice@example.com",
  "status": "active",
  "credentials": [
    {"address": "alice@example.com", "primary_identity": true,
     "created_at": "2026-03-01T09:30:00Z", "updated_at": "2026-03-01T09:30:00Z"},
    {"address": "a.smith@example.com", "primary_identity": false,
     "created_at": "2026-03-02T11:00:00Z", "updated_at": "2026-03-02T11:00:00Z"}
  ],
  "mailbox_count": 6,
  "message_count": 4211,
  "storage_used": 1834201991
}
```

| Field | Meaning |
|---|---|
| `status` | `active` or `deleted` (soft-deleted, in its grace period). |
| `deleted_at` | When it was soft-deleted. Absent while active. |
| `purge_requested_at` | Present while a requested purge is pending (7.5). |
| `credentials` | Primary first, then by address. |
| `mailbox_count` | Mailboxes not deleted. |
| `message_count`, `storage_used` | Counted live from the messages table: messages not expunged, in mailboxes not deleted. `storage_used` is bytes. |

Soft-deleted accounts are returned too. `404 {"error":"Account not found"}` when no
credential has that address.

### 7.3 Change a password

`PUT /admin/accounts/{email}`

```json
{"password": "a new secret"}
```

or `{"password_hash": "..."}`. Exactly one is required. This sets the password of the one
credential named in the path, not of every credential of the account. A `password` is hashed
with bcrypt.

Response `200 {"message":"Account updated successfully"}`.

After the change, the account's cached logins are dropped on every node, in the proxies'
persistent auth cache and in the User API's login cache too. The next login is checked against
the database. Open sessions are not ended; kick them (11.4) if needed.

Errors: `400` for a bad body, a missing or doubled password field, or an invalid address;
`404 Account not found` for an unknown address; `500 Failed to update account` otherwise.

### 7.4 Soft-delete an account

`DELETE /admin/accounts/{email}`

Marks the account deleted. It can no longer sign in or receive mail. Its data stays until the
cleaner removes it after `[cleanup] grace_period` (default 14 days); until then it can be
restored (7.6). Its sessions are ended and its cached logins dropped, as a kick does (11.4),
on every node.

Response `200`:

```json
{"email": "alice@example.com",
 "message": "Account soft-deleted successfully. It will be permanently removed after the grace period."}
```

Errors: `404` when the address is unknown, `400 account is already deleted`, `500` otherwise.

### 7.5 Purge an account

`DELETE /admin/accounts/{email}?purge=true`

Requests the permanent deletion of the account and everything it holds, without waiting for
the grace period: mailboxes, messages and their S3 objects, search data, Sieve scripts,
credentials and the account row. This is the same operation as
`sora-admin accounts delete --purge` (see [ADMIN_CLI.md](ADMIN_CLI.md)).

The request is **asynchronous**. In one transaction it soft-deletes the account (if it is
not already), and marks it for purging. Then it ends the account's sessions as a soft delete
does, wakes this node's purge worker if it has one, and answers:

```
HTTP/1.1 202 Accepted
```
```json
{
  "email": "alice@example.com",
  "purge_requested_at": "2026-03-10T08:15:02.481Z",
  "message": "Account is out of service and marked for purging; a purge worker on a node with object storage deletes it. GET /admin/accounts/{email} shows purge_requested_at until the account is gone."
}
```

The deletion is done by the purge worker, which runs on every node with an `imap`, `pop3` or
`lmtp` server. It polls every `[cleanup] purge_poll_interval` (default `30s`) and claims each
marked account so that one node works on it. A failed attempt is retried after a delay that
starts at one minute and doubles up to one hour. Repeating the request clears that delay and
keeps the original `purge_requested_at`.

To follow it, poll `GET /admin/accounts/{email}`: `purge_requested_at` is shown while the purge
is pending, and the request answers `404` once the account is gone. The metrics
`sora_account_purges_pending` and `sora_account_purge_oldest_pending_seconds` show the backlog
(see [METRICS.md](METRICS.md)). An age that keeps growing means no purge worker is running.

`POST /admin/accounts/{email}/restore` cancels a purge that has not started. See
[STORAGE.md](STORAGE.md) for what a purge deletes and in which order.

The `purge` parameter must be exactly `true`; any other value is a soft delete.

Errors: `404` when the address is unknown, `500 Error requesting account purge` otherwise.

### 7.6 Restore a soft-deleted account

`POST /admin/accounts/{email}/restore`

Clears the deletion mark and any pending purge request. No body.

Response `200 {"email":"alice@example.com","message":"Account restored successfully."}`.

Errors: `404` for an unknown address, `400 account is not deleted`, `500` otherwise. An
account the cleaner or a purge has already removed is unknown.

### 7.7 Check whether an address exists

`GET /admin/accounts/{email}/exists`

Response `200`:

```json
{"email": "alice@example.com", "exists": true, "deleted": false, "status": "active"}
```

`status` is `active`, `deleted` (soft-deleted) or `not_found`. An unknown address is still
`200`, with `exists: false`. An address that does not parse gives `400`.

### 7.8 List a domain's accounts

`GET /admin/domains/{domain}/accounts`

Lists the active accounts whose primary address is in `{domain}`, newest first. Soft-deleted
accounts and accounts that only have an alias in the domain are left out. There is no paging.

Response `200`:

```json
{
  "domain": "example.com",
  "accounts": [
    {
      "account_id": 1042,
      "primary_email": "alice@example.com",
      "credential_count": 2,
      "mailbox_count": 6,
      "message_count": 4211,
      "storage_used": 1834201991,
      "created_at": "2026-03-01 09:30:00.123456 +0000 UTC"
    }
  ],
  "total": 1
}
```

`message_count` and `storage_used` come from the per-mailbox statistics the database keeps
with every message change, not from a live count. They can differ slightly from 7.2.

### 7.9 Usage of every account

`GET /admin/usage/accounts?after={account_id}&limit={n}`

Walks all active accounts in `account_id` order, one page per request, for usage exports and
billing. Soft-deleted accounts are left out.

| Parameter | Default | Meaning |
|---|---|---|
| `after` | `0` | Return accounts with an id above this. |
| `limit` | `1000` | Page size, from 1 to 10000. |

Response `200`: `{"accounts":[...], "next_after": 2051}`. Each entry has the fields shown in
7.8. `next_after` is present when the page is full; pass it as the next `after`. The last page
has no `next_after`. Each page costs the same wherever it starts. Pages are separate reads, so
an account created during a walk may or may not appear.

Errors: `400 after must be an account id (0 or more)`, `400 limit must be between 1 and
10000`, `500 Error listing accounts`.

---

## 8. Credentials

### 8.1 Add an address to an account

`POST /admin/accounts/{email}/credentials`

`{email}` is any address of an active account. The body names the address to add:

```json
{"email": "a.smith@example.com", "password": "alias-secret"}
```

or with `password_hash`. Exactly one of the two. A `password` is hashed with bcrypt. The new
credential is not primary. Each credential has its own password.

Response `201 {"new_email":"a.smith@example.com","message":"Credential added successfully"}`.

Errors: `400` for a bad body or an invalid address; `404 Account not found for the specified
primary email`; `409 Credential with this email already exists`; `500 Failed to add credential`
otherwise.

### 8.2 List an account's addresses

`GET /admin/accounts/{email}/credentials`

Response `200`. The credential objects use Go field names, and the times are Go time text:

```json
{
  "email": "alice@example.com",
  "credentials": [
    {"Address": "alice@example.com", "PrimaryIdentity": true,
     "CreatedAt": "2026-03-01 09:30:00.123456 +0000 UTC",
     "UpdatedAt": "2026-03-01 09:30:00.123456 +0000 UTC"}
  ],
  "count": 1
}
```

`404 {"error":"Account not found"}` for an unknown address.

### 8.3 Get one address

`GET /admin/credentials/{email}`

Response `200`:

```json
{
  "address": "a.smith@example.com",
  "primary_identity": false,
  "created_at": "2026-03-02T11:00:00Z",
  "updated_at": "2026-03-02T11:00:00Z",
  "account": {
    "account_id": 1042,
    "account_created_at": "2026-03-01T09:30:00Z",
    "account_status": "active",
    "mailbox_count": 6,
    "message_count": 4211,
    "total_credentials": 2
  }
}
```

`account_deleted_at` appears in `account` when the account is soft-deleted. `404` for an
unknown address.

### 8.4 Remove an address

`DELETE /admin/credentials/{email}`

Removes the credential. The address stops signing in and receiving mail at once; the
account's cached logins are dropped on every node. Sessions already signed in with it are not
ended.

Response `200 {"email":"a.smith@example.com","message":"Credential deleted successfully"}`.

Errors:

| Status | Body `error` |
|---|---|
| 404 | `credential with email ... not found: user not found` |
| 400 | `cannot delete the primary credential...` |
| 400 | `cannot delete the last credential for an account...` |
| 500 | `Failed to delete credential` |

The API has no endpoint that changes which credential is primary; use `sora-admin` for that.

---

## 9. Deleted messages

When a client expunges a message, Sora keeps the row, marked with the time of the expunge, until
the cleaner removes it after `[cleanup] grace_period`. Until then these endpoints can list and
restore it. See [STORAGE.md](STORAGE.md) for the two-phase deletion.

Both endpoints need an active account.

### 9.1 List restorable messages

`GET /admin/accounts/{email}/messages/deleted`

| Parameter | Default | Meaning |
|---|---|---|
| `mailbox` | all | Only messages from this mailbox, matched case-insensitively. That is the mailbox's current name, or for a mailbox that was deleted, the name it had. |
| `since` | none | Expunged at or after this time. `YYYY-MM-DD` or RFC 3339. |
| `until` | none | Expunged at or before this time. Same formats. |
| `limit` | `100` | Most messages returned. `0` returns all of them. |

Newest expunge first. Response `200`; the message objects use Go field names:

```json
{
  "email": "alice@example.com",
  "messages": [
    {
      "ID": 98321, "UID": 4410, "ContentHash": "4f1c...",
      "MailboxPath": "INBOX", "MailboxID": 5511,
      "Subject": "Quarterly report", "MessageID": "abc@example.com",
      "InternalDate": "2026-03-04T10:11:12Z", "ExpungedAt": "2026-03-09T16:00:00Z",
      "Size": 48211
    }
  ],
  "total": 1
}
```

`MessageID` is the bare `Message-ID` header without angle brackets, or `""` when the message had
none that parsed. `MailboxID` is `null` when the mailbox itself has been deleted; `MailboxPath` is
then the name recorded at deletion. A message with neither shows an empty `MailboxPath`;
criteria-based restores skip it and it can only be named by id.

Errors: `400` for a bad `since`, `until` or `limit`, or `since` after `until`;
`404 Account not found`; `500` otherwise.

### 9.2 Restore messages

`POST /admin/accounts/{email}/messages/restore`

```json
{"message_ids": [98321, 98322]}
```

or by criteria:

```json
{"mailbox": "INBOX", "since": "2026-03-01", "until": "2026-03-09T23:59:59Z"}
```

At least one of `message_ids`, `mailbox`, `since`, `until` is required. They combine. Ids must
be positive.

Each message goes back to the mailbox it was expunged from. A mailbox that has since been
deleted is created again, with its parents. Restored messages get new UIDs, in their original
arrival order per mailbox, and new mod-sequences, so IMAP clients are told of them as new messages
(the mailbox's HIGHESTMODSEQ rises). The expunge of the old UID stays on record until the cleaner
removes it, so a client not yet told of it still is (`EXPUNGE`, or `VANISHED (EARLIER)` to a QRESYNC
client). A restored message has a new id: deleted again, it is listed under that id. Messages
already restored or already purged are skipped.

With `[shared_mailboxes]` enabled, a mailbox recreated in the shared namespace is a shared
mailbox of the account, and so is a parent recreated there. Each one starts with owner-only
rights: one entry, the owner's primary address with `default_rights`. The ACL entries it had
before it was deleted are not restored, and a shared parent's entries are not copied as they
are for a new folder ([SHARED_MAILBOXES.md](SHARED_MAILBOXES.md)). The server logs a warning
naming it. Grant other users access again with `POST /admin/mailboxes/acl/grant` (section 12.1).

The restore runs in chunks, each in its own transaction. Response `200`:

```json
{"email": "alice@example.com", "restored": 2, "message": "Successfully restored 2 message(s)"}
```

If it fails part-way, the chunks already done stay restored and the answer is `500` with
`Error restoring messages: N message(s) restored before the failure; repeat the request to
restore the rest`. Repeating the same request is safe.

Errors: `400` for a bad body, no filter, a non-positive id, bad dates, or `since` after
`until`; `404 Account not found`; `500` otherwise.

---

## 10. Mail delivery

`POST /admin/mail/deliver`

Delivers a message to local accounts the way LMTP does: the recipient's Sieve script runs,
vacation replies and redirects go out through `[relay]`, a `Received:` and a `Delivered-To:`
header are added, and the body is staged for upload to S3. Use it to inject mail from
software that speaks HTTP, or to migrate mail with its UIDs.

The node must run an `imap`, `pop3` or `lmtp` server, since delivery uses its upload worker
(section 6). The body may be at most `max_message_size` (default 50 MiB).

### Request formats

The `Content-Type` header picks the format.

**`application/json`**

```json
{
  "recipients": ["alice@example.com"],
  "message": "From: billing@example.net\r\nTo: alice@example.com\r\nSubject: Invoice\r\n\r\nHello.\r\n",
  "from": "billing@example.net",
  "mailbox": "Archive",
  "uid": 4410,
  "uid_validity": 1700000000
}
```

| Field | Meaning |
|---|---|
| `message` | The whole RFC 5322 message. Required. |
| `recipients` | Addresses to deliver to. When empty, the `To`, `Cc` and `Bcc` header addresses are used, each once (`From`, `Sender` and `Reply-To` are not recipients; a group such as `team: a@example.com;` contributes its members, an empty group such as `undisclosed:;` none). |
| `from` | Envelope sender, as Sieve and vacation see it, written as it would be between the angle brackets of `MAIL FROM` (RFC 5321 section 4.1.2). It is read as LMTP reads `MAIL FROM` ([PROTOCOLS.md section 8.3](PROTOCOLS.md#83-envelope)): `first..last@example.com` is accepted, `a@b.example@example.com` is the sender `"a@b.example"@example.com` (not a master login suffix), and a quoted local part is decoded once, so `"John Doe"@example.com` is that mailbox and `"\"Sender\""@example.com` keeps its inner quotes. Whitespace around the value is ignored. A `"` or space outside one whole quoted string (`Sen"der@example.com`, `John Doe@example.com`), a quoted string that does not end, or invalid UTF-8 does not parse. When `from` is empty, the first `From` header address is the sender, as the header names it (its quotes already decoded, nothing trimmed). `<>` is the null sender. A `from` that does not parse is refused with `400 Invalid sender: ...`, as LMTP refuses it with `553 5.1.7`; a `From` header address that does not parse is ignored, and the message is delivered with no envelope sender. |
| `mailbox` | Deliver straight into this mailbox. Sieve does not run, and no `Received:` or `Delivered-To:` header is added. A mailbox that does not exist means `INBOX`. |
| `uid`, `uid_validity` | Keep these IMAP values, for migrations. |

**`message/rfc822` or `text/plain`**: the body is the message. Recipients come from the
`recipients` query parameter or the `X-Recipients` header (comma-separated), else from the
`To`, `Cc` and `Bcc` headers as above. The sender comes from the `from` query parameter or the `X-From` header.

```bash
curl -X POST "http://127.0.0.1:8080/admin/mail/deliver?recipients=alice@example.com" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: message/rfc822" \
  --data-binary @message.eml
```

**`multipart/form-data`**: the field `message` holds the message, as a value or a file
upload; `recipients` may repeat; `from` is a single value. `mailbox`, `uid` and
`uid_validity` are available only in the JSON form.

Any other `Content-Type` gives `400 Unsupported Content-Type. Use application/json,
message/rfc822, or multipart/form-data`.

### What happens per recipient

Each recipient is handled on its own: the address is looked up (`+tag` suffixes are removed
for the lookup), the default mailboxes are created if missing, Sieve runs, and the message is
stored. A duplicate of a message already delivered counts as delivered. A message the script
discards counts as accepted.

A recipient is read as LMTP reads `RCPT TO`. One that is not a valid address fails with
`invalid recipient address: ...` (not transient). That includes an address with more than one
`@`, such as `user@example.com@SUFFIX`: the master-login suffix has no meaning in a recipient,
and the message is not delivered to `user@example.com`.

### Response

```json
{
  "success": false,
  "recipients": [
    {"email": "alice@example.com", "accepted": true},
    {"email": "nobody@example.com", "accepted": false, "error": "recipient not found: nobody@example.com"}
  ],
  "message_id": "<abc@example.net>",
  "error": "Partial delivery failure"
}
```

| Field | Meaning |
|---|---|
| `success` | `true` when every recipient was accepted. |
| `recipients[].accepted` | This recipient's outcome. |
| `recipients[].error` | Why it failed, or `Message discarded by Sieve filter` on an accepted discard. A node with no room to stage the message answers `Insufficient system storage (staging limit reached)` or `Insufficient system storage (spool disk full or read-only)`, the condition LMTP answers with `452 4.3.1`. Local file paths are never included; the server log has the full error. |
| `recipients[].transient` | `true` when the failure was on the server side (database, storage, staging space): retry later; the message may even be stored already. |
| `message_id` | The message's `Message-ID` header, or a generated `<{nanoseconds}.http-delivery@{hostname}>` when it has none. The generated value is not written into the message. |
| `error` | `Partial delivery failure` when several recipients were given and any failed. |

Status codes:

| Status | When |
|---|---|
| 200 | Every recipient accepted. |
| 207 | Two or more recipients, and at least one failed (also when all failed). |
| 400 | One recipient, and it failed for a reason in the request (unknown or invalid address, or a message too large to store); or the request itself is bad: no message, an unparseable message, no recipients, a `from` that does not parse, a body over the size limit, a bad form. |
| 503 | One recipient, and it failed on the server side. `Retry-After: 30`. |
| 503 | This node has no upload worker: `{"error":"Mail delivery not available on this node: no upload worker"}` with `Retry-After: 60`. Send the request to a node that runs an `imap`, `pop3` or `lmtp` server. |
| 503 | This backend is in maintenance: `{"error":"Server in maintenance, try again later"}` with `Retry-After: 60`. See [PROXY.md](PROXY.md) for maintenance mode. |

In-flight deliveries count as this server's sessions while a backend drains for maintenance.

---

## 11. Connections and kicks

These endpoints read the connection trackers of the node that answers (section 6). In cluster
mode a proxy's tracker also holds entries gossiped by peers. See [CLUSTER.md](CLUSTER.md) for
how tracking is shared.

Tracker names are `PROTOCOL-` followed by the server name (backends: `IMAP-imap`) or by
`hostname-servername` (proxies: `IMAP-mail1-imap-proxy`). The protocol part is `IMAP`, `POP3`,
`ManageSieve` or `LMTP`.

### 11.1 List sessions

`GET /admin/connections`

One entry per account and tracker, for accounts with at least one session on this node:

```json
{
  "connections": [
    {
      "protocol": "IMAP",
      "instance": "IMAP-imap",
      "account_id": 1042,
      "email": "alice@example.com",
      "local_count": 3,
      "total_count": 3,
      "last_update": "2026-03-10T08:20:11Z"
    }
  ],
  "count": 1,
  "source": "in-memory connection tracker"
}
```

`local_count` is this node's sessions for the account; `total_count` includes peers' sessions
the tracker knows of. Without trackers: `{"connections":[],"count":0,"note":"Connection
tracking not available (requires cluster mode or backend server with tracking enabled)"}`.

### 11.2 Statistics

`GET /admin/connections/stats`

```json
{"total_connections": 120, "connections_by_protocol": {"IMAP-imap": 100, "POP3-pop3": 20},
 "source": "in-memory connection tracker"}
```

The keys are tracker names. The numbers count sessions on this node, not accounts, and leave
out sessions that other nodes report through gossip. Without trackers the answer has zeros and
a `note`.

### 11.3 One account's sessions

`GET /admin/connections/user/{email}`

```json
{"email": "alice@example.com",
 "connections": [{"protocol": "IMAP", "instance": "IMAP-imap", "account_id": 1042,
                  "email": "alice@example.com", "local_count": 3, "total_count": 3,
                  "last_update": "2026-03-10T08:20:11Z"}],
 "count": 1, "source": "in-memory connection tracker"}
```

The entries have the same fields as in 11.1. The address is first resolved to its account, so
any address of the account finds all of the account's entries. Entries created under any of the
account's addresses are listed too (a proxy keys a session that a remote lookup authenticated
by the address the lookup answered). An address the database does not know matches the entries
created under that address, compared case-insensitively. Unlike 11.1, entries with
`local_count: 0` (sessions on peers only) are included. An address that does not parse gives
`400`. Without trackers the answer is an empty list with a `note`.

### 11.4 Kick an account

`POST /admin/connections/kick`

```json
{"user_email": "alice@example.com", "protocol": "imap"}
```

| Field | Meaning |
|---|---|
| `user_email` | Required. |
| `protocol` | Optional: `imap`, `pop3`, `managesieve` or `lmtp` (any case). Only trackers of that protocol kick. Without it, every tracker kicks. |

`server_addr` and `client_addr` are accepted and ignored.

The address is resolved to every id the account's sessions can be held under: the database's
account id, and the ids Sora derives from each of the account's addresses, which is how a proxy
keys a login that a remote lookup authenticated. An address the database does not know (an
account served only by a remote lookup) gets just the derived id.

For each chosen tracker, the kick closes every session the account has on this node at once
and drops its cached logins there, so the next login is looked up afresh. In cluster mode it
also sends the kick to every peer, over TCP and by gossip, in the background; peers close their
sessions when it arrives. The kick does not block the account: the client may sign straight
back in.

Response `200`:

```json
{
  "message": "User kicked successfully via gossip protocol",
  "user": "alice@example.com",
  "protocols": ["IMAP-imap"],
  "note": "Kick event broadcast to cluster. Connections will be terminated within seconds."
}
```

`protocols` lists the tracker names that kicked.

Errors:

| Status | Body `error` |
|---|---|
| 400 | `Invalid JSON body`, `user_email is required for kick operation`, `invalid email address: ...` |
| 404 | `No connection trackers found for protocol: imap` |
| 503 | `Connection tracking not available (requires cluster mode)`: this node has no tracker. |
| 500 | `Failed to resolve account`: the database could not be asked. |
| 500 | `Failed to kick user on any protocol` |

To kick an account everywhere, call the API on a node that has trackers in cluster mode, or on
every node.

---

## 12. Shared mailbox ACLs

These endpoints manage RFC 4314 access control lists on shared mailboxes. The rights, the
same-domain rule and the `anyone` identifier are explained in
[SHARED_MAILBOXES.md](SHARED_MAILBOXES.md).

The mailbox is named as its owner sees it, for example `Shared/Sales`. The owner must be an
active account.

### 12.1 Grant

`POST /admin/mailboxes/acl/grant`

```json
{"owner": "sales-lead@example.com", "mailbox": "Shared/Sales",
 "identifier": "bob@example.com", "rights": "lrsw"}
```

All four fields are required. The identifier's rights become exactly `rights`, replacing
what it had. `rights` is any combination of `lrswipkxtea`. `identifier` is an address in the
owner's domain, or `anyone` when `[shared_mailboxes] allow_anyone_identifier = true`.

Response `200`:

```json
{"status": "success", "message": "ACL rights granted successfully",
 "owner": "sales-lead@example.com", "mailbox": "Shared/Sales",
 "identifier": "bob@example.com", "rights": "lrsw"}
```

Errors:

| Status | When |
|---|---|
| 400 | Invalid body or a missing field (`owner is required`, `mailbox is required`, ...). |
| 400 | An invalid right, a mailbox that is not shared, an identifier in another domain, the owner as identifier, or `anyone` while it is disabled. The `error` text says which. |
| 404 | Owner or mailbox not found. |
| 500 | `Failed to grant ACL` |

### 12.2 Revoke

`POST /admin/mailboxes/acl/revoke`

```json
{"owner": "sales-lead@example.com", "mailbox": "Shared/Sales", "identifier": "bob@example.com"}
```

Removes the identifier's entry. Revoking an entry that does not exist succeeds, as RFC 4314
asks. Response `200` with `"message": "ACL rights revoked successfully"` and the three fields
echoed. Errors as for grant.

### 12.3 List

`GET /admin/mailboxes/acl?owner=sales-lead@example.com&mailbox=Shared/Sales`

```json
{"mailbox": "Shared/Sales", "owner": "sales-lead@example.com",
 "acls": [{"identifier": "bob@example.com", "rights": "lrsw"}]}
```

Both parameters are required (`400 owner parameter is required`, `400 mailbox parameter is
required`). `404` when the owner or mailbox is not found.

---

## 13. Proxy backends and affinity

### 13.1 Backend health

`GET /admin/proxy/backends`

Shows each proxy server on this node and the backends it routes to, with their health as that
proxy sees it. See [PROXY.md](PROXY.md) for health checks, pools and maintenance mode.

```json
{
  "proxies": [
    {
      "proxy_name": "IMAP-imap-proxy",
      "backends": [
        {
          "address": "10.0.0.11:143",
          "pool": "sora1",
          "is_healthy": true,
          "failure_count": 0,
          "consecutive_fails": 0,
          "last_failure": "0001-01-01T00:00:00Z",
          "last_success": "2026-03-10T08:20:00Z",
          "health_check_enabled": true,
          "is_remote_lookup": false,
          "in_maintenance": false
        }
      ]
    }
  ],
  "timestamp": "2026-03-10T08:20:15Z"
}
```

| Field | Meaning |
|---|---|
| `proxy_name` | `IMAP-`, `POP3-`, `ManageSieve-`, `LMTP-` or `UserAPI-` followed by the server name. |
| `pool` | The named pool the backend belongs to; absent for a flat `remote_addrs` list. |
| `last_failure`, `last_success` | `0001-01-01T00:00:00Z` means never. |
| `is_remote_lookup` | The backend came from a remote lookup answer, not from the configuration. |
| `in_maintenance` | This proxy treats the backend as in maintenance. |

A node without proxies answers `{"proxies":[], "timestamp": ...}`.

### 13.2 Affinity

Affinity remembers which backend a user last used per protocol, so the proxy sends them back
there. The table exists only when `[cluster]` is enabled with `[cluster.affinity] enabled =
true`; it is gossiped to every node. See
[PROXY.md](PROXY.md) and [CLUSTER.md](CLUSTER.md).

**Get:** `GET /admin/affinity?user=alice@example.com&protocol=imap`

Answers with the user's backend for that protocol:
`200 {"user":"alice@example.com","protocol":"imap","backend":"10.0.0.11:143","found":true}`.
`protocol` is matched in any case. Both parameters are required
(`400 user and protocol query parameters are required`). A user without an affinity for that
protocol answers `404 {"error":"No affinity set for alice@example.com (imap)"}`.

**Set:** `POST /admin/affinity`

```json
{"user": "alice@example.com", "protocol": "imap", "backend": "10.0.0.12:143"}
```

`protocol` must be `imap`, `pop3` or `managesieve`. `backend` must be one of the backends
configured on this node for that protocol: an entry of `remote_addrs` of an enabled
`imap_proxy`, `pop3_proxy` or `managesieve_proxy`, written the same way, or a member of a
`[[pool]]`, as `host:port` with that proxy's `remote_port` added when the pool entry has no
port. Response `200`:

```json
{"success": true, "message": "Affinity set for alice@example.com (imap) -> 10.0.0.12:143 and gossiped to cluster",
 "user": "alice@example.com", "protocol": "imap", "backend": "10.0.0.12:143"}
```

Errors: `400 Invalid JSON`; `400 user, protocol, and backend are required`;
`400 protocol must be imap, pop3, or managesieve`; `400` for a backend not configured for the
protocol (`Backend ... is not configured for protocol imap. Valid backends: [...]`) or a
protocol without configured backends (`No backends configured for protocol imap`).

**Delete:** `DELETE /admin/affinity?user=alice@example.com&protocol=imap`

`200 {"success":true,"message":"Affinity deleted for alice@example.com (imap) and gossiped to cluster","user":"alice@example.com","protocol":"imap"}`.
Deleting an affinity that does not exist also answers `200`. Both parameters are required, as
for get. Get and delete take any protocol name, `userapi` included (the User API proxy's
affinities); only set is limited to `imap`, `pop3` and `managesieve`.

**List:** `GET /admin/affinity/list?protocol=imap&backend=10.0.0.11:143`

Lists the unexpired affinities this node holds: those it assigned and those it received by
gossip. Both parameters are optional filters; `protocol` is matched in any case, `backend`
exactly. Entries are sorted by user, then protocol.

```json
{
  "affinities": [
    {"user": "alice@example.com", "protocol": "imap", "backend": "10.0.0.11:143",
     "assigned_at": "2026-03-10T08:00:00Z", "expires_at": "2026-03-11T08:00:00Z",
     "node_id": "node-1"}
  ],
  "count": 1
}
```

`node_id` is the cluster node that assigned the affinity. Nodes do not exchange their full
tables, so a node that was down or joined after an affinity was gossiped does not hold it, and
two nodes can list different affinities.

**Statistics:** `GET /admin/affinity/stats`

```json
{
  "stats": {
    "enabled": true,
    "total_entries": 5120,
    "ttl": "24h0m0s",
    "cleanup_interval": "1h0m0s",
    "by_protocol": {"imap": 4000, "pop3": 900, "managesieve": 200, "userapi": 20},
    "memory_usage": {"affinity_entries": 5120, "broadcast_queue": 0,
                     "broadcast_queue_max": 5000, "queue_utilization": 0}
  }
}
```

`queue_utilization` is the gossip broadcast queue's fill level as a percentage.

**Without the affinity table** every affinity endpoint answers
`503 {"error": "Affinity manager not enabled on this server"}`.

---

## 14. Cache

The local cache keeps message bodies on this node's disk. See [STORAGE.md](STORAGE.md).

### 14.1 Statistics

`GET /admin/cache/stats`

This node's cache. The fields use Go names:

```json
{"TotalSizeBytes": 5368709120, "ObjectCount": 81234, "Hits": 45678, "Misses": 3421,
 "HitRatio": 0.93, "Uptime": 86400000000000}
```

`TotalSizeBytes` is the size on disk in bytes. `HitRatio` is from 0 to 1. `Uptime` is in
nanoseconds. Hits, misses and uptime count from the process start.
`503 {"error":"Cache not available"}` on a node without a cache.

### 14.2 Recorded hit rates

`GET /admin/cache/metrics`

Every node with a cache records its hit and miss counts in the database at an interval (see
`[local_cache]` in [STORAGE.md](STORAGE.md)). This endpoint reads those records, for every
node.

| Parameter | Default | Meaning |
|---|---|---|
| `latest` | `false` | `true`: the latest record of each `instance_id` and `server_hostname` pair, and the other parameters are ignored. |
| `instance_id` | all | Only this instance. |
| `since` | 24 hours ago | RFC 3339 only. |
| `limit` | `100` | Most records. A value that is not a positive number means 100. |

```json
{
  "metrics": [
    {"instance_id": "mail1", "server_hostname": "mail1.example.com",
     "hits": 45678, "misses": 3421, "hit_rate": 93.03, "total_operations": 49099,
     "uptime_seconds": 86400, "recorded_at": "2026-03-10T08:00:00Z"}
  ],
  "count": 1,
  "instance_id": "",
  "since": "2026-03-09T08:20:00Z"
}
```

Here `hit_rate` is a percentage. With `latest=true` the answer has only `metrics` and
`count`. Newest record first. `400 Invalid since parameter format (use RFC3339)`.

### 14.3 Purge the cache

`POST /admin/cache/purge`

Empties this node's cache. Bodies are fetched from S3 again as clients ask for them.

```json
{"message": "Cache purged successfully",
 "stats_before": { ... },
 "stats_after": { ... }}
```

`stats_before` and `stats_after` are the statistics of 14.1.

`503` on a node without a cache.

---

## 15. Upload queue

New message bodies are staged on the receiving node and uploaded to S3 in the background. Each
waiting upload is a row in the `pending_uploads` table. These endpoints read that table for the
whole system, not only this node. See [STORAGE.md](STORAGE.md).

Both take `max_attempts`: an upload with at least this many attempts counts as failed. It
defaults to the configured `[uploader] max_attempts`, the limit at which the uploader stops
retrying.

### 15.1 Status

`GET /admin/uploader/status`

| Parameter | Default | Meaning |
|---|---|---|
| `max_attempts` | `[uploader] max_attempts` | See above. |
| `show_failed` | `false` | `true` adds the failed uploads. |
| `failed_limit` | `10` | How many failed uploads to add. |

The fields use Go names:

```json
{
  "stats": {
    "TotalPending": 15,
    "TotalPendingSize": 1048576,
    "FailedUploads": 2,
    "OldestPending": {"Time": "2026-03-10T08:10:00Z", "Valid": true}
  },
  "failed_uploads": [ ... ],
  "failed_count": 2
}
```

`TotalPending` and `TotalPendingSize` (bytes) cover uploads below `max_attempts`.
`OldestPending.Valid` is `false` when nothing is pending. `failed_uploads` and
`failed_count` appear only with `show_failed=true`; entries are as in 15.2.

### 15.2 Failed uploads

`GET /admin/uploader/failed?limit=50`

`limit` defaults to 50. Newest first. Go field names:

```json
{
  "failed_uploads": [
    {"ID": 77, "AccountID": 1042, "ContentHash": "4f1c...", "InstanceID": "mail1",
     "Size": 48211, "Attempts": 20,
     "CreatedAt": "2026-03-09T10:00:00Z", "UpdatedAt": "2026-03-10T07:00:00Z",
     "LastAttempt": {"Time": "2026-03-10T07:00:00Z", "Valid": true}}
  ],
  "count": 1,
  "max_attempts": 20,
  "limit": 50
}
```

`InstanceID` is the upload identity of the node that staged the body (`[uploader]
instance_id`, by default its host name); only that node can upload it. `ContentHash` is the
body's BLAKE3 hash, which also names its S3 object.

In both endpoints a `max_attempts`, `limit` or `failed_limit` that is not a positive number
means the default.

---

## 16. Authentication statistics

### 16.1 Description

`GET /admin/auth/stats` returns a fixed description, not numbers:

```json
{
  "implementation": "in-memory",
  "tracking_mode": "per-address rate limiting with automatic expiry",
  "available_stats": {"blocked_entries": "GET /admin/auth/blocked"},
  "access_methods": {"blocked_list": "GET /admin/auth/blocked - list currently blocked addresses"}
}
```

### 16.2 Blocked addresses

`GET /admin/auth/blocked?protocol=imap`

Lists the blocks that the authentication rate limiters of **this node** currently hold. See
[AUTHENTICATION.md](AUTHENTICATION.md) for how blocks are made.

`protocol` is optional and exact: `imap`, `pop3`, `managesieve`, `imap_proxy`, `pop3_proxy`,
`managesieve_proxy`, `userapi` or `userapi_proxy`.

```json
{
  "blocked_entries": [
    {"ip": "203.0.113.7", "username": "alice@example.com",
     "blocked_until": "2026-03-10T08:35:00Z", "failure_count": 5,
     "first_failure": "2026-03-10T08:18:00Z", "last_failure": "2026-03-10T08:20:00Z",
     "protocol": "imap", "type": "ip_username"},
    {"ip": "198.51.100.9", "blocked_until": "2026-03-10T08:50:00Z", "failure_count": 50,
     "first_failure": "2026-03-10T08:00:00Z", "last_failure": "2026-03-10T08:20:00Z",
     "protocol": "imap", "type": "ip"}
  ],
  "count": 2
}
```

`type` is `ip_username` (one user from one address) or `ip` (the whole address). Only servers
with `[server.auth_rate_limit] enabled = true` have a limiter.

### 16.3 Persistent auth cache

`GET /admin/auth-cache/stats`

On a node with `[auth_cache] enabled = true` (see [PROXY.md](PROXY.md)):

```json
{"enabled": true, "total_entries": 18234, "session_hits": 5120, "session_misses": 312,
 "hit_rate_percent": 94.25, "lifetime_hit_count": 912345}
```

`session_*` count since the process started; `lifetime_hit_count` sums the hit counts stored
in the cache file.

On a node without the auth cache:

```json
{"enabled": false, "note": "Auth cache is not enabled. Enable it in [auth_cache] config section."}
```

---

## 17. Health

Every node with a database runs periodic health checks and writes each component's state to the
`health_status` table, keyed by the machine's host name as the operating system reports it.
These endpoints read that table, so any node can report on all of them. Components include `database`, `database_read_pool`, `s3_storage`, `cache`,
`database_failover`, `relay_queue` and `circuit_breaker_<name>` checks; which ones exist
depends on what the node runs. See [METRICS.md](METRICS.md) for the checks and the health
endpoints of the metrics server.

A component's status is `healthy`, `degraded`, `unhealthy` or `unreachable`.

### 17.1 Overview

`GET /admin/health/overview?hostname=mail1`

`hostname` is optional; without it, all hosts are counted.

```json
{"overall_status": "healthy", "component_count": 8, "healthy_count": 8, "degraded_count": 0,
 "unhealthy_count": 0, "unreachable_count": 0, "last_updated": "2026-03-10T08:20:00Z"}
```

`overall_status` is `unreachable` when there are no rows, `unhealthy` when any component is
unhealthy or unreachable, `degraded` when any is degraded, else `healthy`. Rows are not
filtered by age, so a host that stopped reporting keeps its last state.

### 17.2 One host

`GET /admin/health/servers/{hostname}`

```json
{
  "hostname": "mail1",
  "statuses": [
    {"component_name": "database", "status": "healthy",
     "last_check": "2026-03-10T08:20:00Z", "check_count": 1523, "fail_count": 0,
     "server_hostname": "mail1", "updated_at": "2026-03-10T08:20:00Z"}
  ],
  "count": 1
}
```

`last_error` and `metadata` appear when set; the `relay_queue` component carries its queue
counts in `metadata`. `GET /admin/health/servers/` (trailing slash, no host name) returns every
host's components.

### 17.3 One component

`GET /admin/health/servers/{hostname}/components/{component}`

The current row, as one object of the shape above. Only the current state is kept, so
`?history=true` answers `400 Health history is not recorded; request the current status without
history=true`. An unknown component answers `404 {"error":"Health status not found"}`; a failed
database query answers `500`.

---

## 18. System information

`GET /admin/config`

```json
{
  "server_type": "sora-http-api",
  "features_enabled": {
    "account_management": true, "connection_management": true, "cache_management": true,
    "health_monitoring": true, "auth_statistics": true, "uploader_monitoring": true,
    "message_restoration": true
  },
  "endpoints": { "account_management": ["POST /admin/accounts", "..."], "...": [] }
}
```

`cache_management` is `false` on a node without a cache; the other flags are always `true`.
The flags say what the API can do, not what this node runs: section 6 lists what each endpoint
needs. `endpoints` lists every endpoint, grouped as `account_management`, `domain_management`,
`usage`, `credential_management`, `message_restoration`, `connection_management`,
`cache_management`, `health_monitoring`, `uploader_monitoring`, `auth_statistics`,
`proxy_monitoring`, `system_information`, `mail_delivery`, `acl_management` and
`affinity_management`.
