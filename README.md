# Sora

Sora is a mail server written in Go. It stores mail for many accounts and serves it to mail
clients over IMAP and POP3. It takes incoming mail from your mail transfer agent over LMTP, runs
each user's Sieve filters, and lets users manage those filters over ManageSieve. An Admin API
manages accounts and watches the servers, and a User API serves web and mobile apps.

Sora keeps message metadata (mailboxes, flags, headers, structure) in PostgreSQL and message bodies
in S3-compatible object storage. The same `sora` program runs as a backend, which stores mail, or
as a proxy, which checks logins and routes each user to a backend, so one setup can grow from a
single server to many.

## What it does

- **IMAP** (IMAP4rev1 and IMAP4rev2) with IDLE, NOTIFY, CONDSTORE and QRESYNC, MOVE, SORT and
  THREAD, ESEARCH, METADATA, ACL and, when you turn it on, PREVIEW. See
  [Protocol Support](https://github.com/migadu/sora/wiki/Protocol-Support).
- **POP3**, **LMTP** and **ManageSieve**.
- **Sieve** filtering at delivery, with vacation replies, redirects, `fileinto`, plus addressing
  and, when you turn it on, `editheader`.
- **Full-text search** of message bodies, indexed in PostgreSQL per account.
- **Shared mailboxes** with RFC 4314 access control lists (off by default).
- **Proxies** for every protocol, with routing by remote lookup, affinity, consistent hashing and
  named backend pools.
- **A gossip cluster** between nodes, for per-user connection limits on proxies, cluster-wide
  kicks, routing affinity and Let's Encrypt certificates.
- **Protection** with login rate limits, connection limits, command and idle timeouts, and limits
  on message size, session memory and search cost.
- **Operations**: Prometheus metrics, health checks, an Admin API, the `sora-admin` tool, and
  maildir import and export (with Dovecot UIDs and keywords).

## Requirements

- Go 1.26.0 or later, to build (`go 1.26.0` in `go.mod`).
- PostgreSQL 14 or later, with the `pg_trgm` and `btree_gin` extensions. Both ship with
  PostgreSQL's contrib package. Sora applies its own database migrations when it starts.
- An S3-compatible object store for message bodies, such as MinIO.
- A mail transfer agent, such as Postfix, that delivers to Sora over LMTP.

## Building

```sh
git clone https://github.com/migadu/sora.git
cd sora
make build
```

`make build` creates two programs in the repository root, with the version, commit and build date
stamped in:

- `sora`, the server.
- `sora-admin`, the command-line tool for accounts, mailboxes, messages, imports and checks.

`make build-linux-musl` and `make build-freebsd` cross-compile static binaries. `make help` lists
every target.

## Running

Sora reads one TOML file, given with `-config`:

```sh
./sora -config config.toml
./sora -version
```

[`config.toml.example`](config.toml.example) shows every option with a comment. Start from a small
file instead: [Configuration Overview](https://github.com/migadu/sora/wiki/Configuration-Overview)
has a minimal working one, and [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) lists every key
with its default. Check a file without starting the server:

```sh
./sora-admin --config config.toml config validate
```

To try Sora on your own computer, follow
[Local Try-Out](https://github.com/migadu/sora/wiki/Setup-Local-Try-Out). To run it as a service,
see [Running in Production](https://github.com/migadu/sora/wiki/Running-in-Production) and the
service files in [`dist/`](dist).

## Running the tests

```sh
make tests                        # all Go tests; the db package needs PostgreSQL
make integration-tests            # the integration suite; needs PostgreSQL
make integration-tests-imap       # one area; `make help` lists them all
```

The database and integration tests need PostgreSQL on `localhost:5432`, where the `postgres` role
can log in from localhost without a password and create databases and extensions. They use the
database `sora_test_db`. [`docs/TESTING.md`](docs/TESTING.md) explains the test tiers, the test
database and the known pitfalls.

To check an already running IMAP endpoint, build `make sora-imaptest` and run
`./sora-imaptest -clients 4`. Defaults match the local seed: `localhost:143`, no TLS,
`alice@example.com`, and password `password`. The runner creates and removes temporary test mailboxes through IMAP.
See [`docs/IMAPTEST.md`](docs/IMAPTEST.md) for TLS modes, case selection and reports.

## Documentation

The [wiki](https://github.com/migadu/sora/wiki) is the place to start: it explains Sora, walks
through common setups, and covers configuration and operations in plain steps. The reference
documents in [`docs/`](docs) give the full detail:

| Document | What it covers |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | The programs, backend and proxy roles, components, and a message's life from delivery to deletion. |
| [STORAGE.md](docs/STORAGE.md) | PostgreSQL and S3, deduplication, encryption, the local cache, uploads, deletion, retention and account purge. |
| [SEARCH.md](docs/SEARCH.md) | Full-text search, what is indexed, retention, limits and the search rate limit. |
| [DATABASE.md](docs/DATABASE.md) | PostgreSQL requirements, read and write endpoints, timeouts, PgBouncer and migrations. |
| [PROTOCOLS.md](docs/PROTOCOLS.md) | IMAP, POP3, LMTP and ManageSieve: capabilities, limits, timeouts and client filters. |
| [PROXY.md](docs/PROXY.md) | Proxies, remote lookup, affinity, backend pools, backend TLS, maintenance mode and the proxy caches. |
| [CLUSTER.md](docs/CLUSTER.md) | The gossip cluster: membership, what it shares, and what happens when nodes fail. |
| [TLS.md](docs/TLS.md) | Certificates, implicit TLS and STARTTLS, and Let's Encrypt with S3 storage. |
| [AUTHENTICATION.md](docs/AUTHENTICATION.md) | Credentials and aliases, password schemes, master users, SASL and login rate limits. |
| [SECURITY.md](docs/SECURITY.md) | Connection limits, timeouts, size and memory limits, trusted networks and the PROXY protocol. |
| [SIEVE.md](docs/SIEVE.md) | The Sieve engine and its extensions, vacation, redirect and ManageSieve. |
| [RELAY.md](docs/RELAY.md) | The outbound relay, the relay queue and spam training. |
| [SHARED_MAILBOXES.md](docs/SHARED_MAILBOXES.md) | The shared namespace and ACL rights. |
| [CONFIGURATION.md](docs/CONFIGURATION.md) | The config file as a whole and every key with its default. |
| [OPERATIONS.md](docs/OPERATIONS.md) | Service files, signals and reload, logs, disk use, upgrades, backups and outbound connections. |
| [METRICS.md](docs/METRICS.md) | Every Prometheus metric, the health checks, and what to alert on. |
| [ADMIN_CLI.md](docs/ADMIN_CLI.md) | Every `sora-admin` command and flag. |
| [IMPORT_EXPORT.md](docs/IMPORT_EXPORT.md) | Maildir import and export, Dovecot UIDs and keywords, and incremental runs. |
| [ADMIN_API.md](docs/ADMIN_API.md) | The Admin HTTP API, endpoint by endpoint. |
| [USER_API.md](docs/USER_API.md) | The User HTTP API and the User API proxy, endpoint by endpoint. |
| [HACKING.md](docs/HACKING.md) | A tour of the code, its conventions, and how to add a command or a migration. |
| [TESTING.md](docs/TESTING.md) | Unit, database and integration tests, the test database and pitfalls. |

## Contributing

Report bugs and send changes through GitHub issues and pull requests. Before you send a change,
run the tests that cover it, and read [`docs/HACKING.md`](docs/HACKING.md) for the code's
conventions.

## License

Sora is released under the MIT License. See [LICENSE](LICENSE).
