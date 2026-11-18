# Standalone IMAP conformance runner

`sora-imaptest` connects as a client to an already running IMAP server and checks deterministic
protocol requirements with documented Sora search expectations. It uses a dedicated account to create mailboxes, append fixture messages,
issue commands, and remove the mailboxes afterward. It can target a Sora backend or its IMAP proxy.

The executable depends only on Go's standard library and its own runner package. No Dovecot
installation, database credentials, S3 access, Sora configuration file, or server startup helper
is required.

## Build and run

```sh
make sora-imaptest
./sora-imaptest -list
```

Use an existing test account that permits mailbox creation and deletion. Supply its password
through `SORA_IMAPTEST_PASSWORD`, another environment variable, or a local password file. The CLI
has no password argument, so the password need not appear in process arguments.

For implicit TLS:

```sh
./sora-imaptest -addr mail.example.test:993 -user imaptest@example.test
```

For STARTTLS:

```sh
./sora-imaptest -addr mail.example.test:143 -tls starttls \
  -user imaptest@example.test -password-env IMAP_TEST_PASSWORD
```

For a local plaintext test listener and a password file:

```sh
./sora-imaptest -addr 127.0.0.1:1143 -tls none \
  -user imaptest@example.test -password-file /path/to/test-password
```

TLS certificates are verified by default. `-ca-file` adds a PEM certificate authority;
`-server-name` overrides the TLS name when connecting by IP. `-insecure` disables certificate
verification for a test endpoint. STARTTLS must be advertised and successfully negotiated before
the client sends credentials; there is no fallback to plaintext. LOGIN is used for authentication.

The account's existing folders are left alone. Each run generates a random prefix, and each
case gets separate mailbox names and connections. Cleanup uses the exact names successfully
created by that case, closes selected sessions, unsubscribes those names, then deletes them.
It does not enumerate or purge the account. Cleanup also runs after a failed or canceled case,
with its own bounded connection. A killed process or unreachable server can leave temporary
mailboxes; failed cleanup reports their names. If a CREATE or RENAME completion is lost, the
runner reports the generated names whose outcome is unknown for manual inspection.

## Select cases and obtain reports

Case names use `group/scenario`. `-run` is a Go regular expression:

```sh
./sora-imaptest -list -run '^(fetch|search)/'
./sora-imaptest -addr mail.example.test:993 -user imaptest@example.test \
  -run '^(append|fetch|store)/'
./sora-imaptest -addr mail.example.test:993 -user imaptest@example.test \
  -format json > imap-report.json
```

Text output shows each result immediately. JSON output is one report containing the server's
post-authentication capabilities, per-case results and RFC references, durations in nanoseconds,
summary counts, assertion diagnostics, and cleanup errors. `-list -format json` lists the catalog
without opening a connection or requiring credentials.

Exit statuses:

| Status | Meaning |
|---|---|
| `0` | At least one case passed, with no assertion, infrastructure, or cleanup failures. |
| `1` | One or more RFC assertions failed. |
| `2` | Invalid configuration, connection/authentication/parser failure, interrupted run, cleanup failure, empty selection, or no executed cases. |

Cases for optional extensions skip when the server does not advertise their required
capabilities. Some mailbox-specific optional features, such as permanent user keywords, may
also skip with a reason. An all-skipped selection exits `2`.

To make required coverage explicit, specify capabilities expected on the endpoint:

```sh
./sora-imaptest -addr mail.example.test:993 -user imaptest@example.test \
  -require-cap UIDPLUS,MOVE,CONDSTORE,LITERAL+
```

Missing required capabilities are errors. They are checked again on every test connection,
which also detects an inconsistent backend reached through a proxy. Unsupported extensions
such as CATENATE, MULTIAPPEND, URLAUTH, and CONTEXT are absent from this catalog.

`-rawlog /path/to/new.log` writes a protocol trace to a new file with mode `0600`. Existing files
are not overwritten. Authentication commands and their replies are suppressed; known credential
representations are redacted. Literal payloads are represented by their octet lengths. Connection
IDs distinguish interleaved traffic from concurrent workers. The trace
contains mailbox names and other protocol data and can help diagnose a failed assertion.

## Coverage

The catalog contains **97 independent scenarios**: native Go ports for all **61 applicable**
scripts in the pinned upstream imaptest corpus, plus the original **36 supplemental** Go cases.
The other 13 upstream scripts require unsupported extensions and are excluded. `-list` includes
the RFC reference and JSON `upstream` mapping for each case. See
[the complete source mapping and RFC adaptations](IMAPTEST_COVERAGE.md).

Select the complete upstream port with `-run '^imaptest/'`. The table below summarizes the
original supplemental cases; the ports additionally retain upstream MIME, LIST, SORT, THREAD,
ESEARCH, NOTIFY, UID and multi-session command sequences and fixtures.

| Area | Checks |
|---|---|
| Session | CAPABILITY, NOOP, unknown command rejection, LOGOUT. |
| Mailboxes | CREATE/LIST/RENAME/DELETE, subscriptions, SELECT/STATUS agreement, EXAMINE and read-only CLOSE. |
| Messages | APPEND octet round-trip and size; partial, PEEK, header, MIME, ENVELOPE and BODYSTRUCTURE fetching. |
| Message state | UID/range semantics, STORE system flags and optional keywords, COPY contents, EXPUNGE sequence remapping, CLOSE expunging. |
| SEARCH | Flags and Boolean criteria, indexed subject/address substrings, empty results for non-indexed headers and interior body substrings, sent dates, strict size boundaries. |
| Extensions | UIDPLUS mappings when supplied and targeted UID EXPUNGE; MOVE; LITERAL+; ESEARCH; CONDSTORE; ENABLE; UNSELECT; decoded BINARY. |
| Multiple commands/sessions | APPEND visibility after NOOP on another connection; independent pipelined STATUS commands. |

This is an IMAP4rev1 profile. Dual rev1/rev2 servers are exercised without enabling rev2, and
rev2-only endpoints are rejected. Completing the applicable scripted corpus does not imply
exhaustive RFC coverage: separate rev2 expectations, broader QRESYNC/IDLE timing, ACL, and
randomized stress workloads remain additional work.

Assertions accept legal response ordering, split FETCH data, server-generated keywords, and
dynamically assigned UIDs. UIDPLUS response codes are validated when present; their absence
alone is not a failure where the RFC permits it. The runner does not assert server-specific
human-readable response text or exact UID allocation.

## Interpreting a Sora run

Sora deliberately searches complete body words and a fixed set of indexed headers. The runner
checks that non-indexed `HEADER` criteria return no matches, including when that header exists.
Negated non-indexed criteria match all messages. Interior body substrings also expect no
matches; `TEXT` still matches substrings in indexed Subject/address fields. These Sora-specific
expectations replace the corresponding upstream RFC expectations and are documented in the
[coverage adaptations](IMAPTEST_COVERAGE.md).

Positive full-word BODY/TEXT checks and indexed-header searches remain enabled.
`imaptest/nil` and `imaptest/search-body` first wait for asynchronous fixture indexing using
successful IMAP SEARCH responses. The body case waits until all four fixture messages are
searchable by their complete body words; the NIL case waits for its single message. Each case
then runs its normal result assertions, including the intentional negative substring checks.

These two cases refresh the Date header on appended fixture copies so their 2007 sent dates do
not exclude them from a server's FTS retention policy. Bodies, source fixture files, and
INTERNALDATE values remain unchanged.

The indexing wait polls every five seconds and defaults to 90 seconds (`-fts-timeout`). It is also
bounded by the case and suite deadlines. A timeout fails with the last observed matches;
server refusals such as `NO [LIMIT]`, unexpected results, and protocol/transport errors stop
immediately. The runner does not access the database or substitute a fixed indexing sleep.
See [SEARCH.md](SEARCH.md) for the search model.

`-clients N` runs N independent case workers concurrently (default `1`, maximum `1024`):

```sh
./sora-imaptest -addr mail.example.test:993 -user imaptest@example.test \
  -run '^imaptest/' -clients 4 -format json > imap-report.json
```

Each case retains its isolated mailboxes. Cases with multiple protocol sessions open additional
connections, so the worker setting is not a hard connection cap. Results retain catalog order;
text progress follows completion order. Shared traces are synchronized, and cleanup remains
bounded on cancellation. JSON reports record the configured worker count as `clients`.

Use a conformance test endpoint whose SEARCH and login/connection limits allow the chosen
catalog. The full run uses fresh logins for case isolation and cleanup, and performs a burst of
SEARCH commands. A refusal such as `NO [LIMIT]` is reported, never retried invisibly. The runner
does not change server settings. Disable `limits.search_rate_limit_per_min` on a dedicated
test instance if it would interfere with the run.

Defaults are a 30-second command timeout, two-minute case timeout, 90-second indexing wait,
and 15-minute suite timeout. `-command-timeout`, `-case-timeout`, `-fts-timeout`, and `-timeout`
override them. Cleanup has a separate budget
of one command timeout for its connection and commands. Ctrl-C cancels the active case and
attempts cleanup before exiting.

## Developing the runner

```sh
make tests-imaptest
go test -race ./internal/imaptest ./cmd/sora-imaptest
```

Controlled TCP/TLS peers verify protocol framing, binary literals, continuations, pipelined
completions, deadlines, cancellation, credential redaction, case isolation, cleanup, and CLI
reporting without a Sora instance. A live conformance run is a separate explicit invocation.

The command families and scenarios in [Dovecot imaptest](https://github.com/dovecot/imaptest)
inspired this catalog. The cases, fixtures, client, and runner are native Go implementations;
there is no imaptest script interpreter or runtime dependency. Each new case should cite the
applicable RFC section and distinguish mandatory behavior from optional or recommended behavior.
