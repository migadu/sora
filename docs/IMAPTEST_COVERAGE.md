# imaptest port coverage

Source: [dovecot/imaptest at `0682be5f3617149e55cb6a2f4de4b23be8092c53`](https://github.com/dovecot/imaptest/tree/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests).

The pinned normal suite has **74 top-level scripts**. This runner contains native Go ports
for **all 61 scripts whose extensions Sora supports**, and excludes **13** that require
unsupported extensions. The 36 original supplemental Go cases remain available, making
**97 executable cases**. These are scenario counts, not individual command/assertion counts.

Each port is named `imaptest/<source-name>`. JSON listings and results include its `upstream`
field. A checked-in [coverage manifest](../internal/imaptest/testdata/imaptest/coverage.json)
accounts for every source script; a unit test checks that all 61 port mappings exist exactly
once and that no excluded script enters the executable catalog. Runtime capability checks
can still skip a supported extension disabled on the chosen server.

The runner uses Go case functions and native command/expectation tables, not an upstream
script interpreter. Pinned message fixtures and adapted assertion tables retain the upstream
[MIT notice](../internal/imaptest/testdata/imaptest/COPYING). Dovecot libraries are not linked.

## Source mapping

| Upstream script | Go case or exclusion |
|---|---|
| [append](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/append) | `imaptest/append` |
| [append-binary](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/append-binary) | `imaptest/append-binary` |
| [atoms](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/atoms) | `imaptest/atoms` |
| [catenate](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/catenate) | Unsupported extensions: CATENATE |
| [catenate-multiappend](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/catenate-multiappend) | Unsupported extensions: CATENATE, MULTIAPPEND |
| [close](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/close) | `imaptest/close` |
| [copy](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/copy) | `imaptest/copy` |
| [esearch](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/esearch) | `imaptest/esearch` |
| [esearch-condstore](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/esearch-condstore) | `imaptest/esearch-condstore` |
| [esort](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/esort) | `imaptest/esort` |
| [expunge](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/expunge) | `imaptest/expunge` |
| [expunge2](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/expunge2) | `imaptest/expunge2` |
| [fetch](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/fetch) | `imaptest/fetch` |
| [fetch-binary-mime](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/fetch-binary-mime) | `imaptest/fetch-binary-mime` |
| [fetch-binary-mime-base64](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/fetch-binary-mime-base64) | `imaptest/fetch-binary-mime-base64` |
| [fetch-binary-mime-qp](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/fetch-binary-mime-qp) | `imaptest/fetch-binary-mime-qp` |
| [fetch-body](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/fetch-body) | `imaptest/fetch-body` |
| [fetch-body-message-rfc822](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/fetch-body-message-rfc822) | `imaptest/fetch-body-message-rfc822` |
| [fetch-body-message-rfc822-mime](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/fetch-body-message-rfc822-mime) | `imaptest/fetch-body-message-rfc822-mime` |
| [fetch-body-message-rfc822-x2](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/fetch-body-message-rfc822-x2) | `imaptest/fetch-body-message-rfc822-x2` |
| [fetch-body-mime](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/fetch-body-mime) | `imaptest/fetch-body-mime` |
| [fetch-bodystructure](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/fetch-bodystructure) | `imaptest/fetch-bodystructure` |
| [fetch-envelope](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/fetch-envelope) | `imaptest/fetch-envelope` |
| [id](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/id) | `imaptest/id` |
| [list](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/list) | `imaptest/list` |
| [listext](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/listext) | `imaptest/listext` |
| [logout](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/logout) | `imaptest/logout` |
| [move](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/move) | `imaptest/move` |
| [multiappend](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/multiappend) | Unsupported extensions: MULTIAPPEND |
| [mutf7](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/mutf7) | `imaptest/mutf7` |
| [nil](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/nil) | `imaptest/nil` |
| [notify](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/notify) | `imaptest/notify` |
| [pipeline](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/pipeline) | `imaptest/pipeline` |
| [pipeline-connections](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/pipeline-connections) | `imaptest/pipeline-connections` |
| [search-addresses](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/search-addresses) | `imaptest/search-addresses` |
| [search-body](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/search-body) | `imaptest/search-body` |
| [search-context-update](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/search-context-update) | Unsupported extensions: CONTEXT=SEARCH |
| [search-context-update2](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/search-context-update2) | Unsupported extensions: CONTEXT=SEARCH |
| [search-context-update3](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/search-context-update3) | Unsupported extensions: CONTEXT=SEARCH |
| [search-date](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/search-date) | `imaptest/search-date` |
| [search-flags](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/search-flags) | `imaptest/search-flags` |
| [search-header](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/search-header) | `imaptest/search-header` |
| [search-partial](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/search-partial) | Unsupported extensions: CONTEXT=SEARCH |
| [search-sets](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/search-sets) | `imaptest/search-sets` |
| [search-size](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/search-size) | `imaptest/search-size` |
| [select](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/select) | `imaptest/select` |
| [sort-addresses](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/sort-addresses) | `imaptest/sort-addresses` |
| [sort-arrival](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/sort-arrival) | `imaptest/sort-arrival` |
| [sort-date](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/sort-date) | `imaptest/sort-date` |
| [sort-display-from](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/sort-display-from) | `imaptest/sort-display-from` |
| [sort-display-to](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/sort-display-to) | `imaptest/sort-display-to` |
| [sort-partial](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/sort-partial) | Unsupported extensions: CONTEXT=SORT |
| [sort-size](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/sort-size) | `imaptest/sort-size` |
| [sort-subject](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/sort-subject) | `imaptest/sort-subject` |
| [store](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/store) | `imaptest/store` |
| [subscribe](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/subscribe) | `imaptest/subscribe` |
| [thread](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/thread) | `imaptest/thread` |
| [thread-orderedsubject](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/thread-orderedsubject) | `imaptest/thread-orderedsubject` |
| [thread-orderedsubject2](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/thread-orderedsubject2) | `imaptest/thread-orderedsubject2` |
| [thread2](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/thread2) | `imaptest/thread2` |
| [thread3](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/thread3) | `imaptest/thread3` |
| [thread4](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/thread4) | `imaptest/thread4` |
| [thread5](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/thread5) | `imaptest/thread5` |
| [thread6](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/thread6) | `imaptest/thread6` |
| [thread7](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/thread7) | `imaptest/thread7` |
| [thread8](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/thread8) | `imaptest/thread8` |
| [uidbatches](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/uidbatches) | Unsupported extensions: UIDBATCHES |
| [uidbatches-empty](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/uidbatches-empty) | Unsupported extensions: UIDBATCHES |
| [uidplus](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/uidplus) | `imaptest/uidplus` |
| [uidvalidity](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/uidvalidity) | `imaptest/uidvalidity` |
| [uidvalidity-rename](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/uidvalidity-rename) | `imaptest/uidvalidity-rename` |
| [urlauth](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/urlauth) | Unsupported extensions: URLAUTH |
| [urlauth-binary](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/urlauth-binary) | Unsupported extensions: URLAUTH, URLAUTH=BINARY |
| [urlauth2](https://github.com/dovecot/imaptest/blob/0682be5f3617149e55cb6a2f4de4b23be8092c53/src/tests/urlauth2) | Unsupported extensions: URLAUTH |

`broken/search-intdate` is outside upstream's normal suite and is not included. It assumes
INTERNALDATE is stored/retrieved in EET/EEST; RFC 3501 does not require that storage timezone.
The regular `search-date` port retains its sent-date/DST/calendar-date assertions.

## RFC adaptations

- UID assignments are captured from replies. UIDNEXT is treated as a lower bound, and
  equivalent compressed UID sets are accepted. UID regeneration is permitted only with a
  valid UIDVALIDITY generation change; persistence-dependent cases can explicitly skip
  a UIDNOTSTICKY mailbox.
- Mailbox names are generated per case. LIST discovers the hierarchy delimiter. Hierarchy
  containers, wildcard/reference-name behavior and ghost subscriptions are checked without
  depending on the account's default folders or a specific server layout.
- FETCH attributes can arrive split across replies and in legal orders. MIME token case,
  equivalent quoted/literal strings, header-name quoting, parameter ordering and optional
  trailing BODYSTRUCTURE fields are handled semantically. Message bytes remain exact.
- APPEND/COPY flag and date recommendations are not promoted from SHOULD to MUST.
  Flag preconditions are established with STORE. SORT/THREAD fixtures supply explicit
  mbox-envelope INTERNALDATE values; if the server does not honor this optional date
  precondition, those timestamp-dependent cases skip with a reason.
- DISPLAYFROM/DISPLAYTO expectations are derived from the actual FETCH ENVELOPE address
  structures, using RFC 5957 display-name and mailbox fallbacks. This avoids requiring
  Dovecot's reconstruction of malformed address headers; ENVELOPE group correctness is
  independently checked by `imaptest/fetch-envelope`. Reverse order, ties and UID variants
  remain covered.
- Unsolicited FLAGS notifications recommended with SHOULD are verified using subsequent
  FETCH state. Concurrent Recent allocation is not treated as an exactly-one-session policy:
  RFC 3501 leaves that choice undefined. Local Recent state remains covered. EXPUNGE checks
  apply legal updates queued before FETCH and validate per-session sequence/UID mappings.
- SELECT's READ-WRITE recommendation is not mandatory; EXAMINE's READ-ONLY requirement is.
  Redundant LIST-EXTENDED parents permitted by RFC 5258 are accepted when their flags and
  CHILDINFO are correct, instead of requiring Dovecot's omission preference.
- MOVE accepts COPYUID on tagged or untagged OK, validates mappings when supplied, and
  does not require a particular allocation change for self-MOVE. A permitted NO for
  self-MOVE must leave its message intact.
- The binary APPEND script's inconsistent expected literal/size is replaced by a known
  seven-octet payload checked exactly through BINARY.PEEK and BINARY.SIZE. The specific
  RFC 3516 NO[UNKNOWN-CTE] mailbox refusal is an explicit skip.
- The fifth `fetch-binary-mime-base64` part contains deliberate mixed CR/LF bytes. A copy
  used for APPEND labels it `application/octet-stream`, avoiding textual CRLF normalization
  ambiguity; the vendored upstream fixture remains unchanged.
- ID retains the original maximum-length 30-field scenario, without requiring any
  implementation name or version in the server response. It uses a pre-authentication
  connection when ID is advertised there, otherwise the state that advertises ID.
- Search expectations follow Sora's intentional design: arbitrary non-indexed HEADER queries
  return no matches, while their NOT complement matches every message. Interior body substrings
  also return no matches. `TEXT` keeps substring matches from indexed Subject/address fields
  but does not search arbitrary headers. This adapts `imaptest/search-header`, the substring
  and non-indexed-header parts of `imaptest/search-body`, and the supplemental
  `search/arbitrary-header` and `search/body-substring` cases.
- Positive whole-word BODY/TEXT queries, indexed-header searches, NIL keyword/mailbox/body
  tests, UID wildcard ranges, initial NOTIFY STATUS, SORT/THREAD structures and multi-session
  updates remain enabled. `imaptest/nil` and `imaptest/search-body` poll for successful body
  indexing of their fixtures before running those unchanged assertions. Appended copies use
  current Date headers to stay eligible under FTS retention; bodies, vendored originals and
  INTERNALDATE are preserved. The wait polls every five seconds and is bounded
  by `-fts-timeout` (90 seconds by default) and the case/suite deadlines. Refusals, unexpected
  matches and transport/protocol errors are not retried; an unready index fails at the deadline.

The upstream scripted corpus does not provide a randomized stress workload or exhaustive
coverage of every supported IMAP extension. Separate rev2, broader QRESYNC/IDLE timing, ACL
and randomized stress coverage are not implied by completing these 61 ports.

## Concurrency

`-clients N` runs up to N independent case workers concurrently (default 1). Each worker
owns its mailbox namespace, connections and cleanup. An upstream scenario can itself open
multiple connections, so N is a worker count, not a hard TCP-connection cap.

Reports retain catalog order; text progress follows completion order. Traces carry connection
IDs and are synchronized, as are progress callbacks. Cancellation stops queued cases, closes active protocol I/O
and allows bounded cleanup. A canceled or empty run cannot pass.
