# IMAP NOTIFY (RFC 5465) — Implementation Plan

Status: **design / not implemented**

This document describes how to implement the IMAP NOTIFY extension across the
`migadu/go-imap` fork (protocol layer) and sora (backend), such that it is
correct with **multiple sora servers** and **multiple PostgreSQL read
replicas** from day one.

---

## 1. Goal and scope

- Implement RFC 5465 `NOTIFY` for IMAP sessions: `NOTIFY SET`, `NOTIFY NONE`,
  mailbox specifiers `SELECTED`, `SELECTED-DELAYED`, `PERSONAL`, `INBOXES`,
  `SUBSCRIBED`, `SUBTREE`, and explicit mailbox lists.
- Events in v1: `MessageNew`, `MessageExpunge`, `FlagChange`, `MailboxName`,
  `SubscriptionChange` (the RFC-mandatory core plus subscriptions, which come
  nearly free). `AnnotationChange`, `MailboxMetadataChange`,
  `ServerMetadataChange` are answered with `NO [BADEVENT ...]` in v1 and can
  be added later on top of the metadata tables.
- `NOTIFICATIONOVERFLOW` as the safety valve: when a session's watch falls too
  far behind, tell the client and drop to `NOTIFY NONE` (RFC-sanctioned).
- Multi-node correctness comes from the existing modseq-polling design: the
  shared PostgreSQL database is the event bus, so no cross-server coordination
  is required. Notification latency is `poll interval + replica lag`
  (~15–20 s worst case), same QoS as IDLE today. A gossip-based fast path is
  an optional later phase.

## 2. Why the current architecture already carries NOTIFY

- Every message mutation (create / flag change / expunge) is stamped from the
  global `messages_modseq` sequence, and triggers maintain
  `mailbox_stats.highest_modseq` per mailbox.
- IDLE sessions detect changes by polling `PollMailbox` (`db/poll.go`) with a
  session-local modseq cursor every `idlePollInterval` (15 s,
  `server/imap/idle.go`). A change made by LMTP on node A is seen by an IMAP
  watcher on node B on its next poll, with zero coordination.
- Read replicas only affect freshness: a modseq cursor polled against a lagged
  replica delays events, never loses them, as long as the cursor is
  monotonic (see §6.1 for the one hardening fix required).

NOTIFY widens *what* a session watches (many mailboxes, mailbox-tree events),
not *how* changes propagate. The plan below reuses the poll pipeline for the
selected mailbox and adds one cheap account-level fan-in query for everything
else.

## 3. Key design decisions

1. **Non-selected mailboxes get STATUS only.** Per RFC 5465 §5.2, message
   events in non-selected mailboxes are reported as untagged `STATUS`
   responses — no sequence numbers, no trackers, no per-mailbox state beyond a
   modseq high-water mark. All data (`MESSAGES`, `UIDNEXT`, `UNSEEN`,
   `HIGHESTMODSEQ`) is served from `mailbox_stats` + `mailboxes.highest_uid`,
   which the fan-in query returns anyway. This makes the multi-mailbox part of
   NOTIFY trivially replica-safe.
2. **One account-level fan-in query per poll tick**, not one query per watched
   mailbox: `mailboxes JOIN mailbox_stats WHERE account_id = $1 AND
   highest_modseq > $cursor`. Steady-state cost is one indexed query per
   session per tick — the same order as IDLE today.
3. **Mailbox-tree events via snapshot diffing.** `MailboxName` and
   `SubscriptionChange` are detected by diffing a per-session snapshot of
   `(id, name, subscribed)` for the account against the previous tick.
   Renames are `same id, new name`; deletes are disappearance (soft-delete
   tombstones in `mailboxes.deleted_at` make this reliable). No schema
   changes, no wall-clock comparisons, inherently multi-server/replica
   correct.
4. **`SELECTED-DELAYED` is the default and comes free.** The
   `MailboxTracker`/`SessionTracker` pair already implements delayed expunge
   delivery (`allowExpunge` plumbed through `Poll`). Plain `SELECTED` is the
   same path with immediate expunge flushes.
5. **`INBOXES` maps to `INBOX`** in v1 (Dovecot parity). Sieve `fileinto` can
   technically deliver anywhere; treating `INBOXES` as `PERSONAL` is a
   possible later refinement.
6. **The library drives delivery timing; the backend drives detection.** The
   fork spawns a long-lived per-connection notify pump (IDLE-style session
   callback) that runs concurrently with command handling; sora's
   implementation of that callback is the poll loop.

---

## 4. Workstream A — `migadu/go-imap` fork

What exists already: RFC 5465 types (`notify.go`: `NotifyOptions`,
`NotifyItem`, `NotifyEvent`, `NotifyMailboxSpec`), `imap.CapNotify`, and a
complete **client** implementation (`imapclient/notify.go` + tests). Missing:
everything server-side.

### A1. Shared types: fetch-atts for `MessageNew`

`NotifyItem` cannot express `MessageNew [(fetch-atts)]`. Extend:

```go
type NotifyItem struct {
    // ... existing fields ...

    // MessageNewFetch holds the optional fetch attributes for MessageNew
    // events in the selected mailbox (RFC 5465 §5.1). Nil means the default
    // (UID FLAGS) behaviour.
    MessageNewFetch *FetchOptions
}
```

Update `imapclient/notify.go` `encodeNotifyOptions` to emit the fetch-att list
and add encode/decode round-trip tests.

### A2. Server command parser: `imapserver/notify.go` (new file)

- Add `case "NOTIFY":` to the dispatch switch in `imapserver/conn.go` (~line
  326).
- Parse `NONE` | `SET [(STATUS)] event-groups...`, mirroring the client
  encoder exactly (the client encoder + its tests are the wire-format oracle).
- Validation per RFC 5465 §4/§5, returning tagged `BAD`/`NO` as appropriate:
  - `MessageNew` and `MessageExpunge` must be requested together.
  - At most one `SELECTED`/`SELECTED-DELAYED` item; message events only valid
    there and in mailbox-set items.
  - Unknown/unsupported events → `NO [BADEVENT MessageNew MessageExpunge
    FlagChange MailboxName SubscriptionChange]` listing what we support.
  - Fetch-atts only valid on `MessageNew` for the selected spec.
- State: allowed in authenticated and selected state.
- Capability gating: same pattern as `handleIdle` — consult
  `SessionCapabilities.GetCapabilities()` when implemented so sora's JA4-based
  per-client capability filtering also gates NOTIFY.

### A3. Session interface

IDLE-style long-lived callback, which matches both the existing fork idiom
(`Session.Idle(ctx, w, stop)`) and sora's pull model:

```go
// SessionNotify is implemented by sessions that support RFC 5465 NOTIFY.
type SessionNotify interface {
    // Notify runs the notification watch described by options until stop is
    // closed or ctx is cancelled. The connection runs it in its own
    // goroutine, concurrently with command processing. options is never nil
    // (NOTIFY NONE stops the previous watch without starting a new one).
    Notify(ctx context.Context, options *imap.NotifyOptions, w *UpdateWriter, stop <-chan struct{}) error
}
```

Servers whose session type does not implement `SessionNotify` never advertise
`NOTIFY` (capability auto-stripped, as with other optional interfaces).

### A4. Connection plumbing: the notify pump

This is the one genuinely new mechanism in the library. Unlike IDLE — where
the read loop is parked while the session goroutine writes — NOTIFY requires
the session goroutine to write **while the client keeps issuing commands**.

Building blocks already in place:

- All response writes go through `responseEncoder`, which holds
  `conn.encMutex` for the duration of one response (`conn.go:680`), so a
  background goroutine can never interleave mid-response. `writeStatusResp` is
  already documented as safe from tracker/UpdateWriter callbacks.
- The read loop already computes per-command expunge safety: `c.poll(cmd)`
  passes `allowExpunge=false` for `FETCH`/`STORE`/`SEARCH` (`conn.go:632-646`).

New pieces:

1. Conn fields: `notifyStop chan struct{}`, `notifyDone chan error`, plus the
   active `*imap.NotifyOptions` (for CAPABILITY/state introspection and for
   replacing the watch atomically). `NOTIFY SET` stops any previous pump
   (close + await, with the same 30 s leak guard used by IDLE), then starts
   the new one. `NOTIFY NONE`, `LOGOUT`, and connection teardown stop it.
2. **Command-in-progress gate for expunges.** Track the currently executing
   command on the conn (a small mutex-guarded string / atomic). `UpdateWriter`
   gains an internal check so `WriteExpunge`/`WriteVanished` from the pump are
   only permitted when no expunge-unsafe command is in flight; the pump
   observes this via a new `w.AllowExpunge() bool` (or the writer buffers and
   the post-command `c.poll()` flush delivers, since selected-mailbox expunges
   flow through the `SessionTracker` in any case). `STATUS`/`LIST`/`FETCH`
   flag updates are legal at any time and need no gate.
3. **UpdateWriter additions** (needed for non-selected-mailbox and
   mailbox-tree events):
   - `WriteStatus(mailbox string, data *imap.StatusData) error`
   - `WriteList(data *imap.ListData) error` (covers new/renamed mailboxes,
     `\NonExistent` for deletes, `\Subscribed`/unsubscribed transitions;
     `OLDNAME` extended item for renames is a nice-to-have follow-up)
   - `WriteNotificationOverflow() error` — untagged
     `* OK [NOTIFICATIONOVERFLOW]`; the conn then clears its notify state as
     if `NOTIFY NONE` was issued.
   Reuse the existing STATUS/LIST encoders from `imapserver/status.go` /
   `list.go`.
4. **IDLE interplay.** When a notify watch is active, the pump remains the
   single event source; `handleIdle` still calls `session.Idle`, and the
   backend decides what Idle does (sora: keepalives only, no second poller —
   see B4). Library-side nothing special is required beyond both writers being
   encMutex-safe, which they are.
5. **SELECT/EXAMINE/CLOSE transitions.** The `SELECTED`/`SELECTED-DELAYED`
   spec follows the currently selected mailbox. The pump does not need
   restarting on SELECT; the session (sora) rebinds its internal "selected"
   component. Document this contract on `SessionNotify`.

### A5. Reference implementation + tests in the fork

- Implement `SessionNotify` in `imapserver/imapmemserver` (in-memory server).
  This gives conformance tests that exercise parser + pump + writers against
  the already-shipped client: `NOTIFY SET` → deliver events from a second
  in-memory session; `SELECTED-DELAYED` expunge deferral during FETCH;
  `NOTIFY NONE`; watch replacement; `BADEVENT`; overflow.
- `go test -race` coverage for pump-vs-command concurrency (background STATUS
  writes racing a pipelined FETCH; stop/replace races; teardown while
  writing).
- Wire-format round-trip tests: server parser fed by the client encoder for
  every specifier/event/fetch-atts combination.

Estimated size: ~1.5–2.5 k LOC including tests. This workstream has no
dependency on sora and ships first.

---

## 5. Workstream B — sora

### B0. Prep (independent, do first)

1. **Monotonic cursor hardening** in `server/imap/poll.go` (~line 97): never
   store a modseq lower than the current cursor. Today, a no-update poll
   answered by a laggier replica than the previous poll can move
   `currentHighestModSeq` backwards and replay updates (duplicate unsolicited
   FETCHes are harmless; replayed EXPUNGEs can trip the desync-BYE path).
   One-line `max()` guard plus a regression test. This is a live IDLE bug in
   multi-replica deployments and a prerequisite for NOTIFY's heavier cursor
   usage. Apply the same rule to the new account-level cursor from day one.
2. **Extract the IDLE loop skeleton** (`server/imap/idle.go`) into a reusable
   `runWatchLoop(ctx, tick, keepalive, fn)` so IDLE and the NOTIFY pump share
   the timer/keepalive/stop mechanics. No behaviour change.

### B1. DB layer: `db/notify.go` (new)

```go
type MailboxStatsDelta struct {
    MailboxID     int64
    Name          string
    HighestModSeq uint64
    MessageCount  uint32
    UnseenCount   uint32
    HighestUID    uint32 // -> UIDNEXT = HighestUID + 1
}

// PollAccountMailboxes returns stats rows for all live mailboxes of the
// account whose highest_modseq advanced past sinceModSeq.
func (db *Database) PollAccountMailboxes(ctx context.Context, accountID int64, sinceModSeq uint64) ([]MailboxStatsDelta, uint64 /*maxModSeq*/, error)

type MailboxSnapshotEntry struct {
    MailboxID  int64
    Name       string
    Subscribed bool
}

// GetMailboxSnapshot returns (id, name, subscribed) for all live mailboxes
// of the account, for mailbox-tree diffing.
func (db *Database) GetMailboxSnapshot(ctx context.Context, accountID int64) ([]MailboxSnapshotEntry, error)
```

Implementation notes:

- Fan-in query:
  `SELECT mb.id, mb.name, mb.highest_uid, ms.message_count, ms.unseen_count,
  ms.highest_modseq FROM mailboxes mb JOIN mailbox_stats ms ON ms.mailbox_id
  = mb.id WHERE mb.account_id = $1 AND mb.deleted_at IS NULL AND
  ms.highest_modseq > $2`. Walks `idx_mailboxes_account_id` then PK lookups
  into `mailbox_stats`; fine for realistic mailbox counts. No new index
  expected; verify with `EXPLAIN` on a large test account and add a composite
  only if needed.
- Both functions go through `GetReadPoolWithContext` so the existing
  `useMasterDB` session pinning applies unchanged.
- Retry wrappers mirroring `PollMailboxWithRetry`.

### B2. Config & capability

- `[servers.imap] enable_notify = false` (default off for rollout), optional
  `notify_poll_interval` (default: reuse `idlePollInterval`), and an overflow
  threshold `notify_max_changed_mailboxes_per_tick` (default e.g. 100).
- Advertise `imap.CapNotify` in `server/imap/server.go` caps only when
  enabled, and register it with the JA4 capability-filter config so it can be
  masked for broken clients. The proxy is a transparent pass-through after
  auth; audit `server/imapproxy/server.go` greeting/capability paths
  (~lines 71, 190, 312) to confirm NOTIFY is not stripped pre-auth.

### B3. Session state: `server/imap/notify.go` (new)

```go
type notifyState struct {
    options       *imap.NotifyOptions
    matcher       *notifyMatcher       // resolves specs/wildcards/SUBTREE -> event filter per mailbox
    accountModSeq atomic.Uint64        // fan-in cursor (monotonic)
    snapshot      map[int64]MailboxSnapshotEntry // last mailbox-tree snapshot
    statusCursors map[int64]uint64     // per-mailbox modseq high-water for STATUS dedup
}
```

- `notifyMatcher` precompiles the item list: selected spec (+delayed flag,
  fetch-atts), and for each non-selected mailbox name → the requested event
  set. `PERSONAL` = all live mailboxes; `SUBSCRIBED` = `subscribed = TRUE`;
  `INBOXES` = `INBOX`; explicit lists support `*` wildcards and `SUBTREE`.
  Matching is by mailbox *name* against the snapshot, so newly created
  mailboxes automatically join `PERSONAL`/`SUBTREE` watches.
- Cleared on logout and on `NOTIFY NONE`/replacement.

### B4. The pump: implementing `imapserver.SessionNotify`

`IMAPSession.Notify(ctx, options, w, stop)`:

1. **Bootstrap** (runs before first tick): resolve the watch set; take the
   initial mailbox snapshot; initialize `accountModSeq` to the max
   `highest_modseq` across the account (so only *future* changes notify); if
   the `STATUS` option was given, emit initial `STATUS` for every matched
   non-selected mailbox from the same snapshot query. (The tagged `OK` for
   NOTIFY is written by the conn after bootstrap; coordinate via the pump
   contract — bootstrap happens synchronously in `handleNotify` before the
   goroutine detaches.)
2. **Tick loop** (reuses `runWatchLoop`, default 15 s + keepalive writes):
   a. *Selected mailbox*: run the existing `s.Poll(ctx, w, allowDelayedRules)`
      path, extended with the event filter (see B5). This preserves all the
      tracker/desync machinery in `server/imap/poll.go` untouched.
   b. *Fan-in*: `PollAccountMailboxes(accountID, accountModSeq)`. For each
      changed, matched, non-selected mailbox → `w.WriteStatus` with
      `MESSAGES`, `UIDNEXT`, `UNSEEN`, `HIGHESTMODSEQ` straight from the
      delta row (dedup via `statusCursors` so an unchanged mailbox isn't
      re-announced). Advance `accountModSeq` monotonically to the returned
      max.
   c. *Tree diff* (only when `MailboxName`/`SubscriptionChange` requested):
      `GetMailboxSnapshot`, diff against previous — new id → `LIST`; missing
      id → `LIST (\NonExistent)`; same id/new name → rename (`LIST` new +
      `\NonExistent` old; `OLDNAME` later); subscribed flip →
      `LIST (\Subscribed)` / without. Piggybacks on b's query when possible
      (one query serving both is an easy optimization since b already joins
      `mailboxes`).
   d. *Overflow*: if a tick matches more than the configured threshold of
      changed mailboxes (or the selected-mailbox poll would flood), call
      `w.WriteNotificationOverflow()`, tear down the watch, return. Client
      re-syncs and re-issues NOTIFY per RFC.
3. **IDLE while NOTIFY active**: `Idle()` checks `notifyState != nil` and, if
   so, only does keepalives — the pump stays the single poller, avoiding
   double delivery and double DB load.
4. **SELECT/UNSELECT rebinding**: the pump reads `s.selectedMailbox` under the
   existing session locks each tick, so mailbox switches need no pump
   restart; the previously selected mailbox naturally moves to STATUS-based
   reporting on the next tick.

### B5. Event filtering + `MessageNew` fetch-atts in the selected mailbox

Extend the update-application section of `server/imap/poll.go` (or a thin
wrapper) with the session's active filter:

- `FlagChange` not requested → skip `QueueMessageFlags` for updated messages.
- `MessageNew` not requested → don't emit `EXISTS` growth (RFC 5465 §5.2:
  without MessageNew for the selected mailbox, new-message notifications are
  suppressed until the client syncs).
- `MessageExpunge` not requested → suppress expunge delivery (tracker still
  records internally to keep sequence numbering coherent — this is exactly
  what `SessionTracker`'s delayed mode provides).
- `MessageNew` with fetch-atts: after the poll applies `EXISTS`, run the
  requested attributes for the new UIDs through the existing FETCH writer
  (`server/imap/fetch.go`). v1 supports DB-resident attributes (`UID`,
  `FLAGS`, `MODSEQ`, `INTERNALDATE`, `RFC822.SIZE`, `ENVELOPE`,
  `BODYSTRUCTURE`); body-section atts reuse the S3-backed fetch path — no new
  I/O machinery, just invocation from the pump context with the expunge-safety
  writer.

### B6. Metrics & observability

Following `pkg/metrics` conventions: `imap_notify_sessions` gauge,
`imap_notify_events_sent_total{type=status|list|fetch|expunge|exists}`,
`imap_notify_overflow_total`, fan-in query duration histogram, and a
`imap_notify_poll_errors_total` counter. Log watch installs/teardowns at info
with the resolved spec summary.

---

## 6. Multi-server and multi-replica correctness

### 6.1 Replicas

- **Delay, not loss**: all three detection mechanisms (selected-mailbox poll,
  account fan-in, snapshot diff) compare monotonic session cursors/snapshots
  against replica state. A lagged replica postpones events to a later tick.
- **Cursor monotonicity** is mandatory (B0.1) because the read pool may span
  replicas with different lag; both the per-mailbox and the account cursor
  only ever move forward.
- **Read-your-own-writes**: unchanged — sessions pin to the master pool via
  `useMasterDB` after their own writes (`db/db.go GetReadPoolWithContext`),
  and NOTIFY reads flow through the same context plumbing.
- **STATUS coherence**: every STATUS response is built from a single fan-in
  row, i.e. one consistent replica read — no cross-query tearing.

### 6.2 Multiple sora servers

- Any node's write bumps modseq/`mailbox_stats` via DB triggers; watchers on
  every other node observe it on their next tick. LMTP, POP3, ManageSieve,
  admin API, and IMAP mutations all notify uniformly, with no new
  cross-node protocol.
- Proxy affinity pins a client to one backend, but correctness does not
  depend on it — two clients of the same account on different backends both
  see all events.

### 6.3 Optional latency fast path (later phase)

The 15 s tick is a QoS floor, not a correctness bound. If sub-second
notifications become a requirement:

- **Gossip hint (preferred)**: reuse the memberlist broadcast-handler pattern
  in `cluster/manager.go` (as done for rate limits/affinity/connections) to
  broadcast best-effort `account dirty` hints from LMTP/APPEND/STORE/EXPUNGE
  paths; receiving nodes wake matching NOTIFY/IDLE watchers into an immediate
  poll. Lossy by design — the tick remains the backstop.
- **`pg_notify` alternative**: works but LISTEN/NOTIFY does not fire on
  physical replicas, so each node would hold a LISTEN connection to the
  primary; adds primary load that gossip avoids. Only worth it for
  non-clustered deployments.

---

## 7. Test plan

**Fork** (see A5): parser round-trips against the shipped client encoder,
imapmemserver conformance, `-race` pump/command concurrency.

**Sora unit/DB tests**:
- `PollAccountMailboxes` deltas across create/deliver/flag/expunge/rename;
  cursor monotonicity under simulated regressing reads.
- Snapshot diff: create/delete/rename/subscribe transitions, including
  rename-with-children and soft-delete tombstones.
- Matcher: spec resolution (`PERSONAL`, `SUBSCRIBED`, `INBOXES`, `SUBTREE`,
  wildcards), MessageNew/MessageExpunge pairing validation.

**Integration tests** (`integration_tests/`, real client = the fork's
`imapclient`):
- `NOTIFY SET (PERSONAL ...)` + LMTP delivery to a non-selected mailbox →
  untagged STATUS.
- Flag change from a second IMAP connection → unsolicited FETCH in the first.
- `SELECTED-DELAYED`: expunge from connection B while connection A runs a long
  FETCH → EXPUNGE delivered only after the FETCH completes.
- NOTIFY + IDLE combined; watch replacement; `NOTIFY NONE`.
- Overflow: mass change → `NOTIFICATIONOVERFLOW`, watch dropped, session still
  usable.
- **Two server instances on one database** (the multi-node story): deliver via
  instance A, observe STATUS on a NOTIFY session on instance B.
- JA4/capability gating and proxy pass-through smoke test.

## 8. Phasing

| Phase | Deliverable | Depends on | Size |
|-------|-------------|------------|------|
| 0 | Sora prep: monotonic cursor fix + idle-loop extraction (B0) | — | S |
| 1 | Fork: types, parser, `SessionNotify`, pump, writers, memserver + tests (A1–A5) | — | L |
| 2 | Sora: DB fan-in + snapshot (B1), config/caps (B2), session state + pump (B3–B4), STATUS/LIST events, overflow; capability behind `enable_notify` | 0, 1 | L |
| 3 | Selected-mailbox event filtering + MessageNew fetch-atts incl. body sections (B5); metrics (B6) | 2 | M |
| 4 | Optional: gossip fast path (§6.3), `OLDNAME`, metadata/annotation events, `INBOXES`≈`PERSONAL` refinement | 3 | M |

Phases 0 and 1 can proceed in parallel. Ship sora with `enable_notify = false`,
soak on a staging cluster (two nodes + lagged replica), then enable per
environment.

## 9. Open questions

1. Should `STATUS` fan-in announce `RECENT`? (`mailbox_stats` doesn't track
   it; RFC doesn't require it; recommend omitting.)
2. Overflow threshold default (proposed 100 changed mailboxes/tick) — tune on
   staging data.
3. Whether `NOTIFY SET STATUS` bootstrap for very large accounts should page
   its initial STATUS burst (RFC allows interleaving before the tagged OK).
4. Body-section fetch-atts in v1 or defer to phase 3+ — S3 latency inside the
   pump tick is the concern; proposal keeps it in phase 3 with a per-tick
   budget.
