# Sora User API

The User API gives mail users HTTP access to their own mailboxes: sign in, list folders and
messages, read and flag messages, search, and manage Sieve filters. It suits webmail front
ends, mobile apps and scripts that would rather speak JSON than IMAP. The User API proxy
spreads these requests over several backends.

This document is the reference for both: every endpoint with its request, response and status
codes, how tokens are issued and checked, and the configuration, as the code on `main`
implements them. It is for operators who deploy the API and for developers who build clients
against it. The handlers live in [server/userapi/](../server/userapi/) and the proxy in
[server/userapiproxy/](../server/userapiproxy/).

1. [Overview](#1-overview)
2. [Configuration](#2-configuration)
3. [Signing in and tokens](#3-signing-in-and-tokens)
4. [Requests, responses and errors](#4-requests-responses-and-errors)
5. [Endpoint summary](#5-endpoint-summary)
6. [Mailboxes](#6-mailboxes)
7. [Messages](#7-messages)
8. [Search](#8-search)
9. [Sieve filters](#9-sieve-filters)
10. [The message object](#10-the-message-object)
11. [Cross-origin requests (CORS)](#11-cross-origin-requests-cors)
12. [The User API proxy](#12-the-user-api-proxy)

---

## 1. Overview

The User API is a `[[server]]` block of type `http_user_api` inside the `sora` process. All
paths start with `/user/`. A client signs in with an address and password and receives a JSON
Web Token (JWT). It sends that token with every other request. The token says which account
the request is for; the server keeps no session.

What it covers, compared with IMAP:

- Mailboxes: list (with counts), create, delete, subscribe, unsubscribe.
- Messages: list with paging, metadata, the raw message, the body, flags and keywords, and
  marking as deleted.
- Search within one mailbox, in headers and body text.
- Sieve scripts: list, read, store, delete, activate, and the supported extensions.

What it does not do: there is no push or IDLE (poll instead), no expunge, no moving or copying
of messages, no append or sending, and no fetching of single MIME parts.

What a node needs:

- **PostgreSQL**, always. Sora refuses to start when an `http_user_api` server is configured
  without `[database]`.
- **S3 and the upload worker**, to serve message bodies (`/body` and `/raw`). Metadata, flags,
  search and filters work without them.

---

## 2. Configuration

```toml
[[server]]
type = "http_user_api"
name = "user-api"
addr = ":8081"
jwt_secret = "at-least-32-bytes-of-random-secret-material"
token_duration = "24h"
allowed_origins = ["https://webmail.example.com"]
```

| Key | Default | Meaning |
|---|---|---|
| `type` | required | `http_user_api`. |
| `name` | required | Names the server in logs and in the rate limiter. |
| `addr` | required | Listen address. |
| `jwt_secret` | none | The HMAC key tokens are signed with (HS256). When it is empty the server is skipped and Sora logs `HTTP User API server enabled but no JWT secret configured - skipping`. When it is shorter than 32 bytes, or is the placeholder `your-secret-jwt-signing-key-here`, Sora refuses to start. |
| `token_duration` | `"24h"` | How long a token is valid, written like the other durations: `"12h"`, `"90m"`, `"7d"`. Values above `168h` (7 days) are cut to `168h` with a warning. `"0"` means `24h`. Negative values are rejected. |
| `token_issuer` | `"sora-mail-api"` | Written into each token's `iss` claim, and required to match when a token is checked. |
| `allowed_origins` | `[]` | Browser origins allowed by CORS (section 11). Empty: no CORS headers, so browsers block cross-origin calls. |
| `allowed_hosts` | `[]` (everyone) | Client addresses allowed to connect: IP addresses and CIDR blocks. |
| `max_connections` | `0` (no limit) | Most concurrent TCP connections. |
| `tls` | `false` | Serve HTTPS. |
| `tls_cert_file`, `tls_key_file` | none | Certificate and key for `tls = true`, when this listener does not use the `[tls]` certificate manager. Use one source per listener. See [TLS.md](TLS.md). |
| `tls_default_domain` | none | Certificate name for clients without SNI, with the `[tls]` manager. |
| `tls_verify` | `false` | Require a client certificate, verified against the system's roots. |
| `proxy_protocol` | `false` | Expect a PROXY protocol header on each connection, from an address in `[servers] trusted_networks`. The client address in it is then used for `allowed_hosts` and rate limiting. See [PROXY.md](PROXY.md). |
| `proxy_protocol_timeout` | `"5s"` | How long to wait for that header. |
| `[server.auth_rate_limit]` | off | Login rate limiting and progressive delays. The keys are in [AUTHENTICATION.md](AUTHENTICATION.md). |
| `[server.lookup_cache]` | off | A cache of login results, see below. |

**`[server.lookup_cache]`** keeps successful logins in memory. A repeated login with the same
password, while the cached entry is younger than `positive_revalidation_window`, skips the
credential lookup and the password check. Every other login is checked against the database.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Turn the cache on. |
| `positive_ttl` | `"5m"` | How long a successful login stays in the cache. |
| `negative_ttl` | `"1m"` | How long a failed login stays in the cache. A cached failure never refuses a login; the next attempt is checked again. |
| `max_size` | `10000` | Most entries. |
| `cleanup_interval` | `"5m"` | How often expired entries are removed. |
| `positive_revalidation_window` | `"30s"` | A cached success is used only while it is younger than this. |

The durations here take Go units or whole days, like the other durations; a value that does not
parse means the default. A
password change drops the account's cached logins.

The HTTP server's limits are fixed: 10 seconds for the request headers, 30 seconds to read
the request, 30 seconds to write the response (this bounds a `/raw` download), 120 seconds for
an idle keep-alive connection, and 15 seconds to finish open requests at shutdown. A login the
rate limit delays has its 30 seconds to write from the end of the delay
([AUTHENTICATION.md](AUTHENTICATION.md#103-progressive-delays) section 10.3).

**Reload.** On SIGHUP, `jwt_secret`, `allowed_origins` and `allowed_hosts` are re-read. A
changed `jwt_secret` makes every token signed with the old one invalid at once. An empty
`jwt_secret` in the reloaded file keeps the old one; a too-short or placeholder secret is
refused, the old one stays, and the reload is logged as failed. Other keys need a restart.

---

## 3. Signing in and tokens

### 3.1 Log in

`POST /user/auth/login`

```json
{"email": "alice@example.com", "password": "correct horse battery staple"}
```

Any of the account's addresses (credentials) can sign in, with that credential's password.
See [AUTHENTICATION.md](AUTHENTICATION.md) for credentials and password schemes.

Response `200`:

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_at": 1773216000,
  "email": "alice@example.com",
  "account_id": 1042
}
```

`expires_at` is a Unix time in seconds. `email` is the address as you sent it.

| Status | Body `error` | When |
|---|---|---|
| 400 | `Invalid request body` | Not JSON. |
| 400 | `Email and password are required` | A field is missing or empty. |
| 401 | `Invalid credentials` | Unknown address, deleted account, wrong password, or the client is blocked by the rate limiter. The four look the same on purpose. |
| 429 | `Too many concurrent authentication attempts. Please try again later.` | Too many logins are waiting out a progressive delay at once. |
| 503 | `Service unavailable` | Database error, a stored password hash that cannot be verified, or the request was cancelled while it waited out a delay. Not counted as a failed login. |
| 500 | `Token generation failed` | Signing error. |

With `[server.auth_rate_limit] enabled = true`, failed logins are counted per client address
and per address-and-user, and a blocked client gets the same `401` as a wrong password.
Blocked clients show in the Admin API at `GET /admin/auth/blocked?protocol=userapi`. Behind a
User API proxy, rate limit on the proxy instead (section 12.1).

### 3.2 Use the token

Send it in the `Authorization` header of every request except the two under `/user/auth/`:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

| Situation | Status | Body |
|---|---|---|
| No header | 401 | `{"error":"Authorization header required"}` |
| Not `Bearer <token>` | 401 | `{"error":"Authorization header must be 'Bearer <token>'"}` |
| Bad signature, expired, wrong issuer, not HS256 | 401 | `{"error":"Invalid or expired token"}` |

On these requests the server checks the token only: its HS256 signature with `jwt_secret`, its
expiry, and its issuer. It does **not** look up the account. A token keeps working until it
expires even if the password is changed or the account is deleted in the meantime.

### 3.3 Refresh the token

`POST /user/auth/refresh`

```json
{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}
```

No `Authorization` header is needed. The token must still be valid (not expired). The server
then checks the account:

- the credential must still exist and its account must not be deleted;
- the credential's password must not have changed since the token was issued.

If both hold, the answer is a fresh token with a full `token_duration`, in the same shape as
the login response, with the current `account_id`. Otherwise it is
`401 {"error":"Invalid or expired token"}` and the client must log in again.

| Status | Body `error` |
|---|---|
| 400 | `Invalid request body`, `Token is required` |
| 401 | `Invalid or expired token` |
| 503 | `Service unavailable` (database error while checking the account) |
| 500 | `Token generation failed` |

Refresh before the token expires; an expired token cannot be refreshed.

### 3.4 What this means for revocation

Tokens are stateless and cannot be revoked one by one. The limits are:

- A password change or an account deletion stops the next refresh. A token already issued
  stays usable until it expires, so for at most `token_duration` (at most 7 days).
- Changing `jwt_secret` and reloading invalidates every token at once.
- A shorter `token_duration` shortens the window, at the cost of more refreshes.

### 3.5 Token contents

The token is a standard JWT signed with HS256. Its claims:

| Claim | Meaning |
|---|---|
| `email` | The address used to sign in. |
| `account_id` | The account. Every request acts on this account. |
| `auth_epoch` | The credential's password version at issue time (Unix seconds); used by refresh. |
| `sub` | The address, again. |
| `iss` | `token_issuer`. |
| `iat`, `exp` | Issue and expiry times. |

Every server that accepts a token trusts its `account_id`. Servers that share a `jwt_secret`
must therefore share one database of accounts, or be kept apart by routing (section 12).

---

## 4. Requests, responses and errors

**Bodies** are JSON. The handlers decode the body whatever the `Content-Type` header says.
Unknown fields are ignored.

**Mailbox names in paths.** Mailbox names use `/` as the hierarchy separator. In a path you
can write the separator as it is (`/user/mailboxes/Archive/2024/messages`) or as `%2F`. Encode
spaces and other special characters with percent-encoding. The name is decoded once:
`Work%2BPersonal` names `Work+Personal`, and `100%25` names `100%`.

Because the path ends in an operation name, a mailbox whose last level is called `messages`,
`search`, `subscribe` or `unsubscribe` cannot be deleted through the API, and a top-level
mailbox with one of those names cannot be listed or searched.

**Responses** are JSON with `Content-Type: application/json`, except the message body and raw
message (section 7). Times are RFC 3339.

**Errors** are JSON objects with an `error` field:

```json
{"error": "Mailbox not found"}
```

A method the path does not serve is `405 {"error":"Method not allowed"}` with an `Allow`
header listing the methods it does serve; a path no endpoint has is
`404 {"error":"Not found"}`.

**Status codes:**

| Code | Meaning here |
|---|---|
| 200 | Done. |
| 201 | Mailbox created. |
| 400 | Bad request: bad JSON, a missing or invalid field or parameter, a script that does not compile. |
| 401 | No, bad or expired token; failed login. |
| 403 | Client address not in `allowed_hosts`; creating a mailbox in the shared namespace; deleting `INBOX`; or deleting a shared mailbox, changing flags or deleting a message in one without the right. |
| 404 | Mailbox, message or script not found, or no endpoint has the path. |
| 405 | Wrong method for the path; `Allow` lists the methods it serves. |
| 409 | Mailbox already exists, or has child mailboxes. |
| 410 | The message body is gone for good. |
| 413 | Sieve script over 65536 bytes. |
| 422 | A message would have more than 50 keywords. |
| 429 | Too many logins waiting on a delay. |
| 500 | Server error. |
| 503 | Message body not available yet, or storage unreachable (with `Retry-After`). |

**Access control.** The `allowed_hosts` check runs first on every request, the login
included: `403 {"error":"Host not allowed"}`. Then CORS (section 11), then the token. The
client address is the TCP peer, or the address from a PROXY protocol header when
`proxy_protocol` is on. `X-Forwarded-For` and `X-Real-IP` are never read.

**Limits.** Message lists return at most 1000 messages per request, searches 100. There is
no rate limit on requests other than logins.

---

## 5. Endpoint summary

| Method | Path | Section |
|---|---|---|
| POST | `/user/auth/login` | 3.1 |
| POST | `/user/auth/refresh` | 3.3 |
| GET | `/user/mailboxes` | 6.1 |
| POST | `/user/mailboxes` | 6.2 |
| DELETE | `/user/mailboxes/{name}` | 6.3 |
| POST | `/user/mailboxes/{name}/subscribe` | 6.4 |
| POST | `/user/mailboxes/{name}/unsubscribe` | 6.4 |
| GET | `/user/mailboxes/{name}/messages` | 7.1 |
| GET | `/user/mailboxes/{name}/search` | 8 |
| GET | `/user/messages/{id}` | 7.2 |
| GET | `/user/messages/{id}/body` | 7.3 |
| GET | `/user/messages/{id}/raw` | 7.4 |
| PATCH | `/user/messages/{id}` | 7.6 |
| DELETE | `/user/messages/{id}` | 7.7 |
| GET | `/user/filters` | 9.1 |
| GET | `/user/filters/capabilities` | 9.6 |
| GET | `/user/filters/{name}` | 9.2 |
| PUT | `/user/filters/{name}` | 9.3 |
| DELETE | `/user/filters/{name}` | 9.4 |
| POST | `/user/filters/{name}/activate` | 9.5 |

Every endpoint answers `OPTIONS` with `200` and no body, for CORS preflight.

---

## 6. Mailboxes

The account sees its own mailboxes and the shared mailboxes it has the lookup (`l`) right on.
See [SHARED_MAILBOXES.md](SHARED_MAILBOXES.md).

### 6.1 List mailboxes

`GET /user/mailboxes`

| Parameter | Meaning |
|---|---|
| `subscribed=true` | Only subscribed mailboxes. |

```json
{
  "mailboxes": [
    {"name": "INBOX", "path": "INBOX", "subscribed": true, "total": 142, "unseen": 5, "uid_next": 3871},
    {"name": "Archive/2024", "path": "Archive/2024", "subscribed": false, "total": 980, "unseen": 0, "uid_next": 981}
  ],
  "count": 2
}
```

| Field | Meaning |
|---|---|
| `name`, `path` | The full mailbox name; both fields are the same. |
| `subscribed` | Whether the account is subscribed to it. |
| `total`, `unseen` | Messages, and messages without `\Seen`. `0` for a shared mailbox the account may see but not read (no `r` right), and `0` when counting fails. |
| `uid_next` | The UID the next message added to the mailbox gets, as IMAP reports it in `UIDNEXT`. |

The counts are computed per mailbox on each call, so this request costs more with many
mailboxes.

### 6.2 Create a mailbox

`POST /user/mailboxes`

```json
{"name": "Projects/Acme"}
```

Missing parent mailboxes are created too. A trailing `/` is removed. The User API does not
create shared mailboxes: with `[shared_mailboxes]` enabled, a name in the shared namespace
(with the default prefix, `Shared` or any name under `Shared/`, in any letter case) is refused
with 403. Create those over IMAP or with `sora-admin mailbox create`.

Response `201 {"message":"Mailbox created successfully","name":"Projects/Acme"}`.

| Status | Body `error` |
|---|---|
| 400 | `Invalid request body`, `Mailbox name is required`, `mailbox name contains invalid characters` (NUL, CR or LF), `mailbox name too long (max 255 characters)`, `Invalid mailbox name` |
| 403 | `Mailboxes in the shared namespace cannot be created through the User API` |
| 409 | `Mailbox already exists` |
| 500 | `Failed to create mailbox` |

### 6.3 Delete a mailbox

`DELETE /user/mailboxes/{name}`

The mailbox disappears at once and its name can be reused. Its messages are expunged by the
background cleaner later, as IMAP `DELETE` does, so the request takes the same time for a
mailbox of any size. Until the cleaner removes them, an operator can restore those messages
(see [ADMIN_API.md](ADMIN_API.md#9-deleted-messages)).

Response `200 {"message":"Mailbox deleted successfully","name":"Projects/Acme"}`.

| Status | Body `error` |
|---|---|
| 400 | `Invalid mailbox name` |
| 403 | `Cannot delete INBOX`; `Not permitted to delete this mailbox` (a shared mailbox without the `x` right) |
| 404 | `Mailbox not found` |
| 409 | `Mailbox has child mailboxes; delete them first` |
| 500 | `Failed to delete mailbox` |

### 6.4 Subscribe and unsubscribe

`POST /user/mailboxes/{name}/subscribe` and `POST /user/mailboxes/{name}/unsubscribe`, no body.

```json
{"message": "Subscribed to mailbox successfully", "name": "Archive/2024", "subscribed": true}
```

```json
{"message": "Unsubscribed from mailbox successfully", "name": "Archive/2024", "subscribed": false}
```

A mailbox that does not exist gives `404 Mailbox not found`.

---

## 7. Messages

Messages are addressed by their `id`, a number that identifies the message row across the
whole system. The `id`-based endpoints (7.2 to 7.7) work on every message the account can list,
in its own mailboxes and in shared mailboxes, subject to the mailbox's ACL as in IMAP: the `r`
right to read a message, the write and delete rights to change its flags.

### 7.1 List a mailbox's messages

`GET /user/mailboxes/{name}/messages`

| Parameter | Default | Meaning |
|---|---|---|
| `limit` | `50` | Messages per page. At least 1. Values above 1000 are lowered to 1000. |
| `offset` | `0` | How many to skip. |
| `unseen` | `false` | `true`: only messages without `\Seen`, including messages with no stored flags. |

Newest arrival first (by `internal_date`).

```json
{
  "messages": [ { "id": 98321, "uid": 4410, "subject": "Quarterly report", "...": "..." } ],
  "total": 142,
  "limit": 50,
  "offset": 0
}
```

`messages` holds message objects (section 10). `total` is the number of messages in the
mailbox, or of unseen ones with `unseen=true`. To page, add `limit` to `offset` until
`offset >= total`. Offsets count from the newest message, so mail arriving while you page shifts
the pages.

| Status | Body `error` |
|---|---|
| 400 | `Invalid mailbox name`, `Invalid limit parameter`, `Invalid offset parameter` |
| 404 | `Mailbox not found` (also a shared mailbox without the `r` right) |
| 500 | `Failed to retrieve messages` |

### 7.2 Get a message's metadata

`GET /user/messages/{id}`

Returns one message object (section 10), with `references`.

`400 Invalid message ID`, `404 Message not found`, `500 Failed to retrieve message`.

### 7.3 Get the message body

`GET /user/messages/{id}/body`

Returns everything after the message's header block, with the message's own top-level
`Content-Type` as the response's content type (`text/plain; charset=utf-8` when the message
has none). For a simple text message that is the text. For a multipart message it is the whole
MIME body, boundaries and all; the API does not pick out the text or HTML part. The transfer
encoding is not undone. To work with parts, fetch `/raw` and parse it.

### 7.4 Get the raw message

`GET /user/messages/{id}/raw`

Returns the complete message as stored, with `Content-Type: message/rfc822`,
`Content-Disposition: attachment; filename="message-{id}.eml"` and `Content-Length`.

### 7.5 Body availability

Both `/body` and `/raw` look for the body in this order: the node's local cache, S3, and the
upload staging area of this node. A message that arrived moments ago may still be waiting for its
upload on another node. The answers:

| Status | Body `error` | Meaning |
|---|---|---|
| 200 | | The body. |
| 503, `Retry-After: 5` | `Message body not yet available, retry shortly` | The upload is still pending. |
| 503, `Retry-After: 30` | `Storage temporarily unavailable, retry later` | S3 did not answer. |
| 410 | `Message body is no longer available` | The body is gone and is not coming back. |
| 500 | `Failed to parse message` / `Failed to read message body` | `/body` only: the message could not be parsed. |

`400 Invalid message ID` and `404 Message not found` as in 7.2.

### 7.6 Change flags and keywords

`PATCH /user/messages/{id}`

```json
{"add_flags": ["\\Seen", "\\Flagged", "$Work"], "remove_flags": ["\\Draft"]}
```

At least one of the two lists must be non-empty. Flags are spelled as in IMAP; in JSON the
backslash is escaped, so `"\\Seen"` is the flag `\Seen`.

- **System flags**, with the backslash, in any case: `\Seen`, `\Answered`, `\Flagged`,
  `\Deleted`, `\Draft`. `\Recent` cannot be set or removed.
- **Keywords**, without a backslash: any valid IMAP atom, such as `$Forwarded` or `Work`
  (ASCII, no spaces, none of `( ) { % * " \ ]`). Keywords are matched without regard to case,
  and the spelling already used in the mailbox is kept.
- A system flag name without its backslash (`"Seen"`) is refused, with a hint:
  `Invalid flag: Seen (system flags take a backslash: \Seen)`.

Additions are applied before removals, so a keyword in both lists ends up removed. Two
further rules follow RFC 9979:

- Removing `\Flagged` also removes the flag colour keywords, and a colour keyword cannot stay
  on a message without `\Flagged`.
- `$hasattachment` and `$hasnoattachment` replace each other; adding both removes both.

Response `200`:

```json
{"message": "Message flags updated successfully", "data": { "id": 98321, "flags": ["\\Seen", "\\Flagged"], "...": "..." }}
```

`data` is the updated message object (section 10). If reading it back fails after the
change, the answer is `{"message": "Message flags updated successfully", "id": 98321}`.

| Status | Body `error` |
|---|---|
| 400 | `Invalid message ID`, `Invalid request body`, `At least one of add_flags or remove_flags must be specified`, `Invalid flag: ...` |
| 403 | `Not permitted to change these flags in this mailbox`: a shared mailbox where the account may change none of the flags asked for. Flags it may not change are otherwise left alone. |
| 404 | `Message not found` |
| 422 | `Too many keywords on a message (maximum 50)` |
| 500 | `Failed to update message flags` |

The change is visible to IMAP clients, which learn of it at their next poll.

### 7.7 Delete a message

`DELETE /user/messages/{id}`

Adds the `\Deleted` flag. That is all: the message stays in the mailbox until an IMAP client
expunges it. The User API has no expunge.

Response `200 {"message":"Message marked as deleted successfully","id":98321}`.
`400 Invalid message ID`, `403 Not permitted to delete messages in this mailbox` (a shared
mailbox without the `t` right), `404 Message not found`, `500 Failed to delete message`.

---

## 8. Search

`GET /user/mailboxes/{name}/search?q={text}`

Searches one mailbox. A message matches when either is true:

- `q` appears anywhere in the subject, or in the address or name of any `From`, `To` or `Cc`
  entry, ignoring case;
- the body text matches `q` as a full-text query: every word of `q` must occur (words are
  lower-cased but not stemmed, so `running` does not find `run`).

The body part uses the per-account search index, which the background worker fills after
delivery and which `fts_retention` may prune. A message that is not indexed can still match by
its headers. See [SEARCH.md](SEARCH.md).

`q` is required plain text, with no field prefixes or operators. Optional filters narrow
its results, and all supplied filters must match:

| Parameter | Meaning |
|---|---|
| `from` | Literal substring of any sender's address or display name, ignoring case. |
| `subject` | Literal substring of the subject, ignoring case. |
| `unseen=true` | Only messages without `\Seen`, including messages with no stored flags. |

The text filters have no wildcard syntax. A `q`, `from` or `subject` containing a NUL or
invalid UTF-8 is refused with `400 Bad Request`, and so is one longer than 1000 bytes, the
length IMAP `SEARCH` allows one search term ([SEARCH.md](SEARCH.md#9-limits)).

Response `200`:

```json
{
  "messages": [ { "id": 98321, "subject": "Quarterly report", "...": "..." } ],
  "total": 1,
  "truncated": false,
  "limit": 100,
  "query": "quarterly"
}
```

| Field | Meaning |
|---|---|
| `messages` | Up to 100 matches, newest arrival first. Message objects without `references`. |
| `total` | The number of messages in this response. |
| `truncated` | `true` when more than 100 messages matched. Narrow the query to reach the others. |
| `limit` | Always `100`. |
| `query` | `q` as received. |

| Status | Body `error` |
|---|---|
| 400 | `Invalid mailbox name`, `Search query parameter 'q' is required`, `Search query parameter 'q' must be UTF-8 text without NUL`, `Search query parameter 'q' must be at most 1000 bytes`, `Search filters 'from' and 'subject' must be UTF-8 text without NUL`, `Search filters 'from' and 'subject' must be at most 1000 bytes each` |
| 404 | `Mailbox not found` (also a shared mailbox without `r`) |
| 500 | `Failed to search messages` |

Searches through this API are not rate limited.

---

## 9. Sieve filters

These endpoints manage the account's Sieve scripts, as ManageSieve does. One script at most
is active; delivery runs the active one. See [SIEVE.md](SIEVE.md) for the language, the
extensions and how delivery runs scripts.

Script names may contain letters, digits, `-`, `_` and `.`, up to 128 characters. An account
may have at most 100 scripts.

### 9.1 List scripts

`GET /user/filters`

```json
{"scripts": [{"name": "main", "active": true, "updated_at": "2026-03-01T09:30:00Z"}], "count": 1}
```

The list has no script content and no set order.

### 9.2 Get a script

`GET /user/filters/{name}`

```json
{"name": "main", "script": "require \"fileinto\";\n...", "active": true, "updated_at": "2026-03-01T09:30:00Z"}
```

`404 Script not found`.

### 9.3 Store a script

`PUT /user/filters/{name}`

```json
{"script": "require [\"fileinto\"];\nif header :contains \"Subject\" \"[list]\" {\n  fileinto \"Lists\";\n}\n"}
```

Creates the script or replaces its content. It does not change which script is active. The
script is compiled against the server's enabled extensions (`[sieve] enabled_extensions`)
first, and refused if it does not compile.

Response `200`: the stored script, in the shape of 9.2.

| Status | Body `error` |
|---|---|
| 400 | `Invalid script name`, `Script name is required`, `Invalid request body` (also for a body far over the size limit), `Script content is required`, `script name contains invalid characters`, `script name too long (max 128 characters)`, `Script validation failed: ...` |
| 413 | `Script exceeds maximum size` (over 65536 bytes) |
| 500 | `Failed to save script` |

A new script on an account that already has 100 is refused with a client error that says the
limit is reached.

### 9.4 Delete a script

`DELETE /user/filters/{name}`

Response `200 {"message":"Script deleted successfully","name":"main"}`. Deleting the active
script leaves the account with no active script. `404 Script not found`.

### 9.5 Activate a script

`POST /user/filters/{name}/activate`, no body.

Makes this script the active one and deactivates any other. The stored script is compiled
again first, because the enabled extensions may have changed since it was stored; a script
that no longer compiles is refused with `400 Script validation failed: ...`.

Response `200 {"message":"Script activated successfully","name":"main","active":true}`.
`404 Script not found`.

There is no endpoint to deactivate all scripts; delete the active one, or activate another.

Scripts named `capabilities` or `activate` cannot be read, stored or deleted through these
paths, which treat those names as operations.

### 9.6 Capabilities

`GET /user/filters/capabilities`

```json
{
  "implementation": "Sora Mail Server",
  "version": "1.0",
  "extensions": ["fileinto", "envelope", "..."],
  "notify_methods": [],
  "max_redirects": 5,
  "max_script_size": 65536
}
```

`extensions` is the set delivery compiles scripts with: `[sieve] enabled_extensions`, or the
default set when that is empty. Offer users only rules that use these. `max_redirects` is the
Sieve engine's limit on `redirect` actions in one script run.

---

## 10. The message object

Message lists, search results, `GET /user/messages/{id}` and the `data` of a flag change
return messages in this shape:

```json
{
  "id": 98321,
  "uid": 4410,
  "mailbox_id": 5511,
  "mailbox_path": "INBOX",
  "subject": "Quarterly report",
  "from": "bob@example.com",
  "to": ["alice@example.com"],
  "cc": ["carol@example.com"],
  "date": "2026-03-04T10:11:00Z",
  "internal_date": "2026-03-04T10:11:12Z",
  "size": 48211,
  "flags": ["\\Seen"],
  "custom_flags": ["$Work", "$hasattachment"],
  "message_id": "abc@example.com",
  "in_reply_to": "xyz@example.com",
  "content_hash": "4f1c...",
  "has_attachments": true
}
```

| Field | Meaning |
|---|---|
| `id` | The message's id, used in `/user/messages/{id}`. |
| `uid` | Its IMAP UID in the mailbox. |
| `mailbox_id`, `mailbox_path` | The mailbox it is in. |
| `subject` | The decoded `Subject`. |
| `from` | The first `From` address, address only (no display name). |
| `to`, `cc`, `bcc` | Addresses only, the same in lists, search results and `GET /user/messages/{id}`. `to` is always present (`[]` when the message has none); empty `cc` and `bcc` are left out. |
| `date` | The message's `Date` header; its `internal_date` when it has none that parses. |
| `internal_date` | When the message arrived in Sora. |
| `size` | Bytes. |
| `flags` | System flags. `[]` when there are none. |
| `custom_flags` | Keywords. Left out when there are none. |
| `message_id`, `in_reply_to` | From the headers, without angle brackets; `in_reply_to` holds its IDs separated by spaces and is left out when there are none. `message_id` is `""` when the message has no `Message-ID` that parses. |
| `references` | The `References` header; only in `GET /user/messages/{id}` and the `data` of a flag change. |
| `content_hash` | The hash that names the stored body. Messages with the same content share it. |
| `has_attachments` | From the RFC 9979 keywords: `true` with `$hasattachment`, `false` with `$hasnoattachment`, left out when the message carries neither (mail Sora stored before it set them, or mail it could not inspect). |

---

## 11. Cross-origin requests (CORS)

Browsers send a cross-origin request only when the server allows the page's origin. The User
API decides with `allowed_origins`:

| `allowed_origins` | Request's `Origin` | Headers sent |
|---|---|---|
| `[]` (default) | any | none: browsers refuse the response. |
| contains `"*"` | any | `Access-Control-Allow-Origin: *`, no credentials. |
| lists the origin, e.g. `"https://webmail.example.com"` | that origin | `Access-Control-Allow-Origin: https://webmail.example.com` and `Access-Control-Allow-Credentials: true` |
| lists other origins | not listed | none. |

With any allowed origin, the server also sends `Access-Control-Allow-Methods: GET, POST, PUT,
PATCH, DELETE, OPTIONS`, `Access-Control-Allow-Headers: Content-Type, Authorization` and
`Access-Control-Max-Age: 3600`. When `allowed_origins` lists specific origins rather than
`"*"`, every response also carries `Vary: Origin`, so caches keep the answers for different
origins apart. Every `OPTIONS` request is answered `200` without a token. Origins are compared
as exact strings, so list the scheme and any port: `"https://webmail.example.com:8443"`.

Use specific origins in production. With `"*"`, any website a user visits can call the API
with a token it has obtained.

---

## 12. The User API proxy

A `[[server]]` block of type `user_api_proxy` is an HTTP reverse proxy in front of several
`http_user_api` backends. It sends all of a user's requests to the backend that serves that
user, using the same routing as the other Sora proxies: a remote lookup, named backend pools,
affinity and consistent hashing. That routing is described in full in [PROXY.md](PROXY.md);
this section covers what is particular to the User API.

```toml
[[server]]
type = "user_api_proxy"
name = "user-api-proxy"
addr = ":8443"
tls = true
remote_addrs = ["10.0.0.21:8081", "10.0.0.22:8081"]
jwt_secret = "the-same-secret-as-every-backend-uses"
remote_use_proxy_protocol = true
```

### 12.1 How a request is routed

1. **Login and refresh** (`/user/auth/*`) carry no token. The proxy reads the body (at most
   64 KiB, else `413 Request body too large`) to find the user: the `email` of a login, or the
   user named in the (valid) token of a refresh. It routes by that user and passes the body on
   unchanged. A malformed body or a login without a usable email and password goes to
   the default pool, or the first pool in configuration order with an available backend,
   which answers it without looking up an account. A refused refresh token gets `401`
   from the proxy. Normally the backend checks the password. A login the lookup refuses
   (`401`/`403`) or does not know (`404`/`3xx`, with `lookup_local_users` off) instead
   gets `401 {"error":"Invalid credentials"}` after one dummy password verification, and
   reaches no backend, with named pools or `remote_addrs`. A request carrying a token for
   such a user, and its refresh, get `503 Service unavailable`.

   With `[server.auth_rate_limit]` on the proxy, the proxy rate limits every login with an
   email and a password before routing it: the progressive delay, then the blocks, a blocked
   login getting `401 {"error":"Invalid credentials"}` at once. A backend's `200` counts as a
   success and its `401` as a failure, and so does the proxy's own refusal, so a client's
   delays and blocks do not depend on whether the lookup knows the addresses it tries. Leave
   the limiter off on the backends behind the proxy: they see only the logins for addresses
   the lookup knows. See [AUTHENTICATION.md](AUTHENTICATION.md#10-authentication-rate-limiting).

2. **Every other request** must carry a valid token, except a CORS preflight (12.3). The proxy
   checks the signature with its own `jwt_secret` and the expiry (not the issuer; the backend
   checks that), and routes by the token's `email`. A missing or bad token gets
   `401 Unauthorized` from the proxy.
3. The backend is chosen by the lookup cache, then the remote lookup (which only routes here:
   it does not check passwords), then the user's pool, then affinity (with `enable_affinity =
   true` and the cluster's affinity store), then a consistent hash of the address. Backends in
   maintenance are skipped.
4. With named pools, routing fails closed. A lookup that fails or names no usable route gets
   `503 Service unavailable`, never a backend of another pool, because backends trust the
   token's `account_id` and another pool's backend would read another tenant's account.

Logins and refreshes read affinity but never write it.

### 12.2 What the backend sees

The proxy keeps the `Authorization` header, sets `X-Forwarded-Host` to the original `Host`,
and sets `X-Real-IP` and `X-Forwarded-For` to the client address. **The User API backend does
not read `X-Real-IP` or `X-Forwarded-For`.** Without more, every request reaches the backend
from the proxy's address, so the backend's `allowed_hosts` must list the proxies, and its login
rate limiter counts all clients as one address and may block the proxy.

To pass the real client address, turn on PROXY protocol on both sides:

```toml
# On the proxy
remote_use_proxy_protocol = true

# On each http_user_api backend
proxy_protocol = true

# On the backends: [servers] trusted_networks lists the proxies' addresses
```

The proxy then writes a PROXY protocol v2 header with the client's address on each backend
connection. With named pools, the pool's own `remote_use_proxy_protocol` decides.

### 12.3 Errors from the proxy itself

These come from the proxy as `application/json`, before any backend is involved.
Each body is `{"error":"message"}` with the message below. Set the proxy's
`allowed_origins` to the same list as its backends so browsers can read these errors.

| Status | Body | When |
|---|---|---|
| 401 | `Authorization header required`, `Authorization header must be 'Bearer <token>'`, `Invalid or expired token` | Missing, malformed, expired or wrongly signed bearer token. |
| 401 | `Invalid or expired token` | A refused refresh token, including one without usable account identity. |
| 401 | `Invalid credentials` | A login the remote lookup refuses or does not know, or a login the proxy's rate limiter blocks, as described in 12.1. |
| 413 | `Request body too large` | A login or refresh body over 64 KiB. |
| 429 | `Too many concurrent authentication attempts. Please try again later.` | Too many logins from the client are waiting out a progressive delay at once. |
| 503 | `Service unavailable` | No route for the user (including a token whose user the remote lookup refuses or does not know), or the backend maintenance list has not been read yet after start-up. |
| 503 | `Backend route unavailable` | The chosen backend could not be bound to a connection. |
| 502 | `Bad gateway` | The backend request failed. |
| 500 | `Internal server error` | The backend request could not be constructed. |

Backend responses are passed through unchanged. Protected bearer-token errors carry a
`WWW-Authenticate: Bearer` challenge; public JSON login and refresh errors do not.

A CORS preflight (`OPTIONS`) needs no token, on any path. It is answered with the backend's
CORS headers, as when the backend is reached directly, so browser clients on another origin can
call the API through the proxy.

### 12.4 Proxy configuration

| Key | Default | Meaning |
|---|---|---|
| `type`, `name`, `addr` | required | `user_api_proxy`, a name, the listen address. |
| `jwt_secret` | none | Must equal the backends' `jwt_secret`. Empty: the proxy is skipped with `User API proxy server enabled but no JWT secret configured - skipping`. Under 32 bytes or the placeholder: Sora refuses to start. Reloaded on SIGHUP, with the same rules as on the backend. |
| `allowed_origins` | `[]` | CORS origins of the errors the proxy answers itself (12.3); set it to the backends' list. Reloaded on SIGHUP. |
| `remote_addrs` | none | Backend `host:port` list. Either this or `[[pool]]` blocks are required. |
| `remote_port` | none | Port for backends listed without one. |
| `remote_tls` | `false` | Speak HTTPS to the backends. |
| `remote_tls_verify` | `false` | Verify the backends' certificates: a pool member against its pool's `remote_tls_ca_file`, any other backend against this block's `remote_tls_ca_file`, or the system roots when that is unset. |
| `remote_use_proxy_protocol` | `false` | Send a PROXY protocol v2 header to the backends (12.2). |
| `connect_timeout` | `"30s"` | Time to open a backend connection. |
| `remote_dns_refresh` | `"5m"` | How often backend host names are resolved again. `"0"` keeps the start-up addresses. |
| `remote_health_checks` | `true` | Check backend health and avoid failing backends. |
| `max_connections` | `0` | Most concurrent client connections on this node. |
| `max_connections_per_ip` | `0` | Most concurrent connections per client address, on this node. Addresses in `[servers] trusted_networks` are exempt. |
| `proxy_protocol` | `false` | Expect a PROXY protocol header from a load balancer in `[servers] trusted_networks`. |
| `proxy_protocol_timeout` | `"5s"` | How long to wait for it. |
| `tls` | `false` | Serve HTTPS. |
| `tls_cert_file`, `tls_key_file` | none | Certificate files. Without them, `tls = true` uses the `[tls]` certificate manager, and fails at start-up if there is none. |
| `tls_verify` | `false` | Require client certificates. |
| `tls_default_domain` | none | Certificate name for clients without SNI, with the `[tls]` manager. |
| `[server.remote_lookup]` | off | Route lookups; see [PROXY.md](PROXY.md). |
| `[server.lookup_cache]` | off | Caches lookup answers; same keys and defaults as in section 2. |
| `[server.auth_rate_limit]` | off | Login rate limiting of every login through the proxy (12.1). The keys are in [AUTHENTICATION.md](AUTHENTICATION.md). Blocked clients show at `GET /admin/auth/blocked?protocol=userapi_proxy`. |

`allowed_hosts`, `token_duration` and `token_issuer` have no effect on this proxy; set in its block,
each is reported with a startup warning. Affinity is
used when the block sets `enable_affinity = true` and the cluster runs its affinity store
(`[cluster.affinity] enabled = true`). The proxy's HTTP
limits are fixed: 30 seconds to read a request and 30 seconds to write a response (from the end
of the delay for a login the proxy's rate limit delays), 120 seconds for an idle connection.

The Admin API shows the proxy's backends under the name `UserAPI-{name}` at
`GET /admin/proxy/backends` (see [ADMIN_API.md](ADMIN_API.md#13-proxy-backends-and-affinity)).
