# Sora Testing

This document is for contributors. It describes every kind of test in the repository, what each
one needs, how to run it, and the mistakes that make a test run lie to you. It also explains the
test databases, because most of Sora's tests talk to a real PostgreSQL.

For the code layout and conventions, see [HACKING.md](HACKING.md).

## Contents

1. [What you need](#1-what-you-need)
2. [The test tiers at a glance](#2-the-test-tiers-at-a-glance)
3. [Unit tests](#3-unit-tests)
4. [Database tests](#4-database-tests)
5. [Integration tests](#5-integration-tests)
6. [The test database](#6-the-test-database)
7. [Environment variables](#7-environment-variables)
8. [Race detector runs](#8-race-detector-runs)
9. [Performance tests, benchmarks and fuzzing](#9-performance-tests-benchmarks-and-fuzzing)
10. [Compile-only checks](#10-compile-only-checks)
11. [Writing tests](#11-writing-tests)
12. [Known pitfalls](#12-known-pitfalls)
13. [Reading the results](#13-reading-the-results)

---

## 1. What you need

- **Go 1.26 or newer.** `go.mod` says `go 1.26.0`.
- **PostgreSQL** on `localhost:5432`, for the database tests and the integration tests. The
  project supports PostgreSQL 14 and newer (see [DATABASE.md](DATABASE.md)).
  - The role `postgres` must be able to log in over TCP from `localhost` **without a password**.
    The integration helpers connect with an empty password, the `db` tests send the password
    `password` from `config-test.toml`, and some tests put `postgres:password@` in their URLs.
    Only `trust` authentication accepts all of these. Set it for `127.0.0.1/32` and `::1/128` in
    `pg_hba.conf`.
  - The role must be allowed to create databases and extensions. Some tests create databases of
    their own (see [section 6.3](#63-databases-the-tests-create-themselves)), and the migrations
    run `CREATE EXTENSION IF NOT EXISTS` for `pg_trgm` and `btree_gin`. A superuser is simplest.
  - The database `sora_test_db` must exist. Nothing creates it for you:

    ```sh
    createdb -h localhost -U postgres sora_test_db
    ```

- **No S3 server.** The tests run the upload path against in-process fakes, and none of them
  reads S3 settings from the environment.

You do not need to create tables. Every test helper migrates its database to the newest version
when it connects.

A quick way to get such a PostgreSQL for tests is the official container image with trust
authentication:

```sh
docker run -d --name sora-test-pg -p 5432:5432 -e POSTGRES_HOST_AUTH_METHOD=trust postgres:16
createdb -h localhost -U postgres sora_test_db
```

Do not point the tests at a database that holds data you care about. The test targets of the
Makefile drop and recreate the schema of `sora_test_db`.

---

## 2. The test tiers at a glance

| Tier | Command | Needs | Where the tests live |
|---|---|---|---|
| Unit tests | `go test $(go list ./... \| grep -v '/sora/db$')` | Go only | `*_test.go` next to the code |
| Database tests | `go test ./db` | PostgreSQL, `sora_test_db` | `db/*_test.go` |
| Integration tests | `make integration-tests`, or `go test -tags=integration ./integration_tests/...` | PostgreSQL, `sora_test_db` | `integration_tests/<area>/`, plus `//go:build integration` files elsewhere |
| Race runs | `make tests-race`, `make integration-tests-race` | as above | the same tests |
| Performance tests | `make performance-tests` | PostgreSQL | `db/search_*_test.go` |
| Benchmarks, fuzzing | `go test -bench`, `go test -fuzz` | Go only, except the `db` benchmarks | `Benchmark...` and `Fuzz...` functions |

The Makefile test targets:

| Target | What it runs |
|---|---|
| `make tests` | `go test -v ./...`: unit tests and database tests, without the `integration` tag. |
| `make tests-race` | The same with `-race`. |
| `make integration-tests` | Every integration target below, one after the other, and every other package with the `integration` tag. |
| `make integration-tests-quick` | The same, but the IMAP tests run with `-short` and the slowloris tests are left out. |
| `make integration-tests-race`, `make integration-tests-quick-race` | The two above with `RACE=1`. |
| `make integration-tests-<scope>` | One area. The scopes are listed in [section 5.2](#52-the-packages-and-their-make-targets). |
| `make reset-test-db` | Drops and recreates the schema of the test database. See [section 6.4](#64-make-reset-test-db). |
| `make build-test-sora-admin` | Builds `integration_tests/sora-admin`. |
| `make performance-tests`, `make performance-tests-short` | The search performance tests. See [section 9](#9-performance-tests-benchmarks-and-fuzzing). |

There is no CI configuration in the repository. Tests run only when someone runs them.

---

## 3. Unit tests

Unit tests sit next to the code they test and need nothing but Go. The servers they talk to run
in the test process, on loopback ports the system picks.

Every package except `db` runs without PostgreSQL. To run all of them:

```sh
go test $(go list ./... | grep -v '/sora/db$')
```

Add `-short` to skip the slower tests. A dozen packages honour it, for example `server/imap`,
`server/pop3proxy` and `storage`.

Run one package, or one test:

```sh
go test ./server/imap
go test -run '^TestValidateSearchCriteria_AcceptsTypicalCriteria$' -v ./server/imap
```

A few unit tests use the self-signed certificate in `testdata/sora.crt` and `testdata/sora.key`,
and some skip themselves when the machine has no IPv6 loopback address.

`make tests` runs `go test -v ./...`, which includes `./db`, so it needs PostgreSQL. See the next
section.

---

## 4. Database tests

The `db` package's tests run real SQL against PostgreSQL. They have no build tag: `go test ./db`
runs them.

They connect with the settings in [`config-test.toml`](../config-test.toml), found by walking up
from the package directory: host `localhost`, port `5432`, user `postgres`, password `password`,
database `sora_test_db`. `SORA_TEST_DB_NAME` overrides the database name. The helper is
`setupTestDatabase` in [`db/test_helpers_test.go`](../db/test_helpers_test.go).

```sh
go test ./db
go test -run 'TestSearch' -v ./db
```

Every database test starts with `if testing.Short() { t.Skip(...) }`, so `go test -short ./db`
skips them and needs no PostgreSQL.

### 4.1 Integration-tagged files in `db`

Four files in `db` carry `//go:build integration`: `cross_account_ownership_test.go`,
`mailbox_case_test.go`, `mailbox_path_maintenance_test.go` and
`unseen_count_underflow_test.go`. They run only with the tag:

```sh
go test -tags=integration ./db
```

`make integration-tests` runs them too.

---

## 5. Integration tests

Integration tests start real Sora servers inside the test process, connect to them over TCP like
a client would, and check what comes back and what lands in the database.

### 5.1 How they are built

- Every file has `//go:build integration` at the top. Without `-tags=integration` the packages
  compile to nothing and `go test` reports `[no test files]`.
- Each area is its own Go package under [`integration_tests/`](../integration_tests). Go runs
  test packages at the same time, so separate packages can run concurrently.
- Shared helpers live in [`integration_tests/common`](../integration_tests/common). The main ones:

| Helper | What it does |
|---|---|
| `SkipIfDatabaseUnavailable(t)` | Connects to the test database without migrating. If that fails, it skips the test. It also skips when `SKIP_INTEGRATION_TESTS=1`. |
| `SetupTestDatabase(t)` | Connects to `localhost:5432` as `postgres` with no password, to `sora_test_db` or `SORA_TEST_DB_NAME`, and runs the migrations. The test fails if this fails. |
| `CreateTestAccount(t, rdb)` | Creates an account with a unique address (`test-<test name>-<nanoseconds>@example.com`) and the default mailboxes. |
| `SetupIMAPServer(t)` | Creates an account and starts an IMAP server on a free loopback port. Returns the server and the account. |
| `SetupLMTPServer`, `SetupPOP3Server`, `SetupManageSieveServer` | The same for the other protocols. Variants add PROXY protocol, XCLIENT, master users, timeouts and more. |
| `SetupIMAPServerWithRealS3` | An IMAP server backed by `FakeS3`, an in-memory S3, so a message really goes through upload and download. |
| `GetRandomAddress(t)` | A free `127.0.0.1` port. |
| `CaptureLogs(t)` | Collects what the `logger` package writes while the test runs. `WaitForLine` waits for a log line. |
| `GetSoraAdminBinary(t)`, `GetSoraBinary(t)` | Build `sora-admin` or `sora` from the working tree, for tests that run the real program. |

The server that `SetupIMAPServer` starts has an upload worker in synchronous mode with a no-op
S3. A message is marked uploaded before the server answers the APPEND, so a test can FETCH it at
once. The bcrypt cost is set to the minimum in `common`'s `init`, so logins are fast.

### 5.2 The packages and their make targets

| Package | Make target | What it covers |
|---|---|---|
| `integration_tests/imap` | `integration-tests-imap`, `integration-tests-imap-quick` | IMAP commands and extensions, shared mailboxes and ACL, flags and keywords, search, IDLE, and maildir import through the `sora-admin` binary. The largest package. |
| `integration_tests/imap_slowloris` | `integration-tests-imap-slowloris` | The slow-client disconnect. Real wall-clock waits, about 16 minutes. |
| `integration_tests/lmtp` | `integration-tests-lmtp` | Delivery, Sieve (fileinto, redirect, vacation, editheader, imap4flags), subaddressing, SMTPUTF8, TLS, timeouts. |
| `integration_tests/pop3` | `integration-tests-pop3` | POP3 commands, master users, timeouts, TLS. |
| `integration_tests/managesieve` | `integration-tests-managesieve` | ManageSieve commands, extensions, master users, timeouts, TLS. |
| `integration_tests/imapproxy` | `integration-tests-imapproxy` | IMAP proxy: routing, affinity, remote lookup, pools, maintenance, PROXY protocol, ID forwarding. |
| `integration_tests/pop3proxy` | `integration-tests-pop3proxy` | POP3 proxy, including SASL and XCLIENT. |
| `integration_tests/lmtpproxy` | `integration-tests-lmtpproxy` | LMTP proxy: routing, pools, health, XCLIENT, SMTPUTF8 end to end. |
| `integration_tests/managesieveproxy` | `integration-tests-managesieveproxy` | ManageSieve proxy. |
| `integration_tests/userapiproxy` | `integration-tests-userapiproxy` | User API proxy: JWT checks, pools, PROXY protocol. |
| `integration_tests/connection_limits` | `integration-tests-connection-limits` | IMAP connection limits. |
| `integration_tests/lmtp_connection_limits`, `pop3_connection_limits`, `managesieve_connection_limits`, `proxy_connection_limits` | `integration-tests-<name with dashes>` | Connection limits for the other servers and the proxies. |
| `integration_tests/adminapi` | `integration-tests-adminapi` | The admin HTTP API, its delivery endpoint, account purges. |
| `integration_tests/userapi` | `integration-tests-userapi` | The user HTTP API. |
| `integration_tests/config` | `integration-tests-config` | Configuration loading and IPv6 proxy addresses. |
| `integration_tests/relay` | `integration-tests-relay` | The relay client against an in-process SMTP server. Needs no database. |
| `cmd/sora-admin` | `integration-tests-sora-admin` | `sora-admin` import and export, ACLs, purges, mailbox commands. Uses a database of its own. |
| `integration_tests/delivery` | part of `integration-tests` | Delivery paths shared by LMTP and the admin API: Sieve, vacation claims, attachment keywords. |
| `integration_tests/pools` | part of `integration-tests` | Starts the real `sora` binary from a config file with `[[pool]]` blocks and checks routing from outside. |
| `integration_tests/tls` | part of `integration-tests` | TLS and STARTTLS on the LMTP and ManageSieve proxies. |

Every `make integration-tests-<scope>` target except `relay` first runs `make reset-test-db`. The
three IMAP targets (`imap`, `imap-quick`, `imap-slowloris`) also run `make build-test-sora-admin`.
Each target then runs, in the package's directory (`cmd/sora-admin` for `sora-admin`):

```sh
go test -v -tags=integration -count=1 -timeout=20m .
```

The timeout is 40 minutes with `RACE=1`. The slowloris target uses 25 minutes (35 with
`RACE=1`).

`make integration-tests` also covers `integration_tests/delivery`, `integration_tests/pools`,
`integration_tests/tls`, and the integration-tagged files in `db`, `pkg/resilient`, `server`,
`server/lmtp`, `server/lmtpproxy`, `server/proxy` and `tlsmanager`. To run everything with the
tag without `make`:

```sh
go test -tags=integration -count=1 -timeout=40m ./...
```

### 5.3 Running a package or a single test

```sh
go test -tags=integration -count=1 -timeout=20m -v ./integration_tests/imap
go test -tags=integration -count=1 -v -run '^TestIMAP_Namespace$' ./integration_tests/imap
```

- Always pass `-count=1`. Otherwise `go test` may print a cached `ok` without running anything,
  because it cannot see that the database changed.
- Pass a `-timeout` when you run a whole package. The default is 10 minutes per package; the
  Makefile uses 20.
- `-short` skips the long IMAP tests (large mailboxes, the IDLE long poll) and the slowloris
  tests.
- `go test ./integration_tests/...` runs several packages at once against one database. Add `-p 1`
  to run them one after the other.

### 5.4 Tests that run the real binaries

A few tests run the programs instead of calling the code:

- `TestSharedMailboxE2E`, `TestSoraAdminACLWithoutConfigFails`,
  `TestIMAP_MaildirImport_UIDStability` and `TestSoraAdminMailboxCreateMakesSharedMailbox` in
  `integration_tests/imap` run `sora-admin`.
- `TestSoraNodeRoutesByPoolsFromConfigFile` in `integration_tests/pools` runs `sora`.

They build the program from your working tree on first use, to `integration_tests/sora-admin` or
`integration_tests/sora` (both ignored by git), so they never run a stale binary.
`make build-test-sora-admin` builds the same file ahead of time. To use a binary you built
yourself, set `SORA_ADMIN_BIN` or `SORA_BIN` to its path.

---

## 6. The test database

### 6.1 One shared database

All test packages use one database, `sora_test_db`, by default. That includes the `db` tests, the
integration packages and the integration-tagged tests in other packages. No test empties it
between tests, and `go test ./...` runs packages at the same time. So at any moment, other tests
may be adding and deleting accounts, mailboxes and messages next to yours.

Tests use only `sora_test_db` (or `SORA_TEST_DB_NAME`) and the databases derived from it in
[section 6.3](#63-databases-the-tests-create-themselves). They never touch `sora_mail_db`, the
default database name in `config.NewDefaultConfig`, or any other development database.

### 6.2 `SORA_TEST_DB_NAME`

Set `SORA_TEST_DB_NAME` to use a different database. Use it when:

- your branch adds or changes migrations, so you do not migrate the shared database to a schema
  other branches do not have;
- you want a run that nobody else's tests can disturb.

```sh
createdb -h localhost -U postgres sora_test_db_mybranch
SORA_TEST_DB_NAME=sora_test_db_mybranch go test -tags=integration -count=1 ./integration_tests/imap
```

These read it: the helpers in `integration_tests/common`, the `db` tests, `testutils`, the
`sora-admin` tests, `pkg/resilient`'s integration tests and `scripts/reset-test-db`.

The integration helpers always connect to `localhost:5432` as `postgres` with no password. Only
the database name can change. The tests that run `sora-admin` write the database name into a
temporary copy of the config.

### 6.3 Databases the tests create themselves

Some tests empty whole tables or drop the schema. They use a database of their own, named after
the test database with a suffix, and create it when it does not exist:

| Database | Used by | Why |
|---|---|---|
| `<test db>_migrations` | `db/concurrent_migration_test.go` | Drops the schema and rolls the migrations back to version 11. |
| `<test db>_uploader` | `db/upload_worker_test.go` | Truncates the tables before each test. |
| `<test db>_admin` | the `cmd/sora-admin` integration tests | Several drop the whole schema. |

`<test db>` is `sora_test_db` or the value of `SORA_TEST_DB_NAME`. This is why the `postgres`
role must be allowed to create databases.

### 6.4 `make reset-test-db`

`make reset-test-db` runs [`scripts/reset-test-db`](../scripts/reset-test-db/main.go). It:

1. connects to the test database as `postgres` on `localhost:5432` (Make variables `DB_NAME`,
   `DB_USER`, `DB_HOST`, `DB_PORT`; `DB_NAME` defaults to `SORA_TEST_DB_NAME`, or to
   `sora_test_db` when that is unset);
2. terminates every other connection to that database;
3. drops the `pg_trgm` and `btree_gin` extensions and the `public` schema, and creates an empty
   `public` schema;
4. if that fails, truncates every table in the `public` schema instead.

The next test that connects runs all migrations again. A failed reset fails the make target.

Every `integration-tests-<scope>` target except `relay` runs it first. So `make
integration-tests-imap` cuts off any other run that is using `sora_test_db` at that moment, on
your machine or by a colleague sharing the server.

With `SORA_TEST_DB_NAME` set, the reset and the tests use that database, and the shared one is
left alone:

```sh
SORA_TEST_DB_NAME=sora_test_db_mybranch make integration-tests-imap
```

### 6.5 `config-test.toml`

[`config-test.toml`](../config-test.toml) in the repository root holds the database settings for
the `db` tests, for `testutils.SetupTestDatabase`, and for the tests that run `sora-admin`. It
also has `[s3]` and `[[server]]` blocks with placeholder values. The integration helpers in
`integration_tests/common` do not read it; their settings are in code.

---

## 7. Environment variables

| Variable | Read by | Effect |
|---|---|---|
| `SORA_TEST_DB_NAME` | most database and integration tests, `scripts/reset-test-db`, `make reset-test-db` | The test database name. Default `sora_test_db`. |
| `SKIP_INTEGRATION_TESTS=1` | `common.SkipIfDatabaseUnavailable` | Skips every integration test that calls it. |
| `SKIP_DB_TESTS=true` | many `cmd/sora-admin` tests | Skips them. |
| `SORA_ADMIN_BIN` | `common.GetSoraAdminBinary` | Use this `sora-admin` binary instead of building one. |
| `SORA_BIN` | `common.GetSoraBinary` | Use this `sora` binary instead of building one. |

`SORA_ADMIN_SKIP_S3=1` is read by `sora-admin` itself, in `import`: it skips the S3 upload. The
maildir import test sets it.

---

## 8. Race detector runs

```sh
make tests-race                          # go test -v -race ./...
make integration-tests-imap RACE=1       # any integration target
make integration-tests-race              # all integration targets with RACE=1
make integration-tests-quick-race
```

`RACE=1` adds `-race` and raises the per-package timeout from 20 to 40 minutes (slowloris: 25 to
35). Race-instrumented binaries run considerably slower.

`make tests-race` has no `-timeout`, so each package gets Go's default of 10 minutes. The `db`
package's tests are slow under the race detector. If a race run of `./db` dies with
`panic: test timed out`, that is the timeout, not a failure; run it alone with a longer one:

```sh
go test -race -timeout 60m ./db
go test -race $(go list ./... | grep -v '/sora/db$')
```

A data race fails the test with `WARNING: DATA RACE` and the two stacks.

---

## 9. Performance tests, benchmarks and fuzzing

### 9.1 Search performance tests

`make performance-tests` runs, in order:

1. `TestSearchConstants` and `TestSearchCriteriaValidation` (30 s timeout);
2. the `TestValidate...` tests of the search validator (30 s);
3. `TestSearchPerformanceBasic` (60 s);
4. every test whose name contains `TestSearchPerformance` (10 minutes). `TestSearchPerformance`
   loads 500 messages;
5. `BenchmarkSearchOperations` with `-benchtime=5s` (5 minutes).

`make performance-tests-short` runs only step 4, with `-short`, which makes the data sets
smaller.

Both are `db` tests, so they need PostgreSQL and `sora_test_db`. They measure the query code on
your machine with small data sets. They do not tell you how a query behaves on a production
database; for that, see [SEARCH.md](SEARCH.md).

### 9.2 Benchmarks

Benchmarks exist in `db`, `helpers`, `server`, `server/delivery`, `server/idgen` and
`server/relayqueue`. Run them with `-run '^$'` so the tests do not run too:

```sh
go test -run '^$' -bench . ./server/idgen
go test -run '^$' -bench . -benchmem ./helpers
```

The `db` benchmarks need PostgreSQL.

### 9.3 Fuzzing

`helpers` has one fuzz target, `FuzzExtractPlaintextBody`. Without `-fuzz`, `go test` runs only
its seed inputs. To fuzz:

```sh
go test -run '^$' -fuzz '^FuzzExtractPlaintextBody$' -fuzztime 60s ./helpers
```

When it finds a failing input, Go writes it under `helpers/testdata/fuzz/`. Keep that file in your
change: it becomes a regression test.

---

## 10. Compile-only checks

To check that every test compiles without running anything:

```sh
go vet ./...
go vet -tags=integration ./...
```

Both pass on `main`. The second one compiles all integration tests. It is a quick check after a
change to a helper in `integration_tests/common` or to a function many tests call.

---

## 11. Writing tests

### 11.1 Unit tests

Put them next to the code, in the same package or in `<package>_test`. Use loopback listeners on
port 0 (`net.Listen("tcp", "127.0.0.1:0")`) for any server, never a fixed port. If a test is slow,
let it skip under `-short`.

### 11.2 Database tests

Put them in `db`, start with a `-short` skip, and use `setupTestDatabase`:

```go
func TestSomethingInTheDatabase(t *testing.T) {
	if testing.Short() {
		t.Skip("requires PostgreSQL")
	}
	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()
	// create this test's own account, mailboxes and messages here
}
```

- Create your own accounts with unique addresses (add `time.Now().UnixNano()`), and clean up what
  you can.
- A test that must empty tables or drop the schema uses
  `setupTestDatabaseWithSuffix(t, "_<name>")`, which gives it a database of its own. Never
  truncate tables in the shared database.

### 11.3 Integration tests

Put them in the package for the area, with the build tag, and start from a helper:

```go
//go:build integration

package imap_test

import (
	"testing"

	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

func TestIMAP_Namespace(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	// ...
}
```

This is [`integration_tests/imap/namespace_test.go`](../integration_tests/imap/namespace_test.go),
shortened.

- Start with `common.SkipIfDatabaseUnavailable(t)`, then a `Setup...` helper. Close the server
  with `defer server.Close()`.
- Use `imapclient` from go-imap for normal client behaviour. Write raw lines on a `net.Conn` when
  you test exact wire bytes or malformed input.
- `server.WaitForUploads(t)` drains the server's upload worker. Call it between an APPEND and a
  FETCH when your setup does not upload synchronously. Call `server.FlushFTSQueue()` before a
  body SEARCH: it runs the full-text indexing that a body search needs.
- To check a log line, use `common.CaptureLogs(t)` and `WaitForLine`, which waits because servers
  often log after they answer.
- If you start a server yourself instead of through a helper, wait until its port accepts
  connections before you dial. A fixed `time.Sleep` races with the listener on a busy machine.
  `waitForLMTPListener` in `integration_tests/lmtp/lmtp_test.go` shows how.
- Assert only on rows your test created. See [section 12.1](#121-never-assert-exact-global-row-counts).

---

## 12. Known pitfalls

### 12.1 Never assert exact global row counts

The test database is shared, and packages run at the same time (see
[section 6.1](#61-one-shared-database)). Between two queries in your test, another package can
add or delete accounts, domains, credentials or messages. So a test like this fails at random:

```go
before := len(listAllAccounts())
createThreeAccounts()
assert.Len(t, listAllAccounts(), before+3) // another package may have added one meanwhile
```

Assert on what your test owns instead: that the three accounts you created are in the list, or
the number of messages in your own mailbox.

The same applies to functions with a global limit. A query that returns "the oldest 1000 rows" or
"the first 100 candidates" over the whole database may not include your rows when other suites
have left many older ones behind.

### 12.2 A green run can be a skipped run

`SkipIfDatabaseUnavailable` skips a test when it cannot connect to the test database. If
PostgreSQL is down, or `sora_test_db` does not exist, every integration test skips, and
`go test` still prints `ok`. A run that finishes in seconds instead of minutes is the sign.

Count the results before you trust an `ok`:

```sh
go test -tags=integration -count=1 -v ./integration_tests/imap > imap.log 2>&1
grep -c '^--- PASS' imap.log
grep -c '^--- SKIP' imap.log
grep 'Database unavailable' imap.log | head -1
```

### 12.3 Migration numbers that do not match the database

The helpers migrate the test database when they connect. If the database's recorded version is a
migration your tree does not have (another branch migrated it), every test that connects fails
with `no migration found for version N`. If the database is ahead of your tree, the tests run
against a schema your code does not know. [HACKING.md](HACKING.md#92-what-goes-wrong-with-numbers)
explains why.

Fix the shared database with `make reset-test-db`, or better, run a branch with migrations against
its own database ([section 6.2](#62-sora_test_db_name)).

### 12.4 Make targets reset the shared database

Every `make integration-tests-<scope>` target (except `relay`) drops the schema of the test
database first and disconnects everyone using it. Do not run them while another run uses the same
database. Run the package with `go test` instead, or use your own database
([section 6.4](#64-make-reset-test-db)).

### 12.5 Leftovers from earlier runs

Nothing cleans the shared database between runs. A test that queries the whole database with a
limit can stop seeing its own rows once many leftover rows exist. When a test fails only on a
database that has seen many runs, try it on a fresh one before you look for a regression:
`make reset-test-db`, or a new `SORA_TEST_DB_NAME`.

### 12.6 Your local `config.toml` is a test input

`TestConfigLoading` in `integration_tests/config` loads `config.toml` from the repository root if
it exists, and fails if it does not parse. The file is ignored by git, so this test can fail on
your machine and nowhere else.

### 12.7 Timing-sensitive tests on a loaded machine

Some tests wait for timeouts or measure throughput. Under the race detector or a busy CPU they
can fail where they pass alone. Rerun the single test with `-count=1 -run '^Name$'` before you
assume a regression.

---

## 13. Reading the results

- `go test` prints one `ok` or `FAIL` line per package. `[no test files]` for an integration
  package means you forgot `-tags=integration`.
- With `-v`, each test prints `=== RUN`, then `--- PASS`, `--- FAIL` or `--- SKIP` with its time.
  Subtests are indented.
- A failing integration test usually logs the server's side too: the servers log through `logger`
  to standard error, and their lines carry `session=<id>`. Search the output for the session ID
  of the failing connection to see what the server did.
- `panic: test timed out after 20m0s` means the package ran out of time. The stack dump after it
  shows which test was running.
- `Failed to set up test database:` at the start of every test means the connection or the
  migration failed. Read the rest of the line: a connection error, a missing database, or a
  migration error (see [section 12.3](#123-migration-numbers-that-do-not-match-the-database)).
