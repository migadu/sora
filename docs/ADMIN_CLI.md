# Sora Admin CLI

`sora-admin` is the command-line tool for running a Sora installation. You use it to create
accounts and aliases, manage folders, restore deleted mail, share folders, upload Sieve scripts,
import and export maildirs, check S3 objects, drain a backend before maintenance, look at caches
and queues, and apply database migrations.

This document lists every command, subcommand and flag of `sora-admin` as built from
[cmd/sora-admin/](../cmd/sora-admin/), with defaults and with what each command changes. It is
written for operators who run Sora and for contributors who change the tool. Maildir import and
export have their own reference, [IMPORT_EXPORT.md](IMPORT_EXPORT.md).

## Contents

1. [Running sora-admin](#1-running-sora-admin)
2. [What each command needs](#2-what-each-command-needs)
3. [The `[admin_cli]` section](#3-the-admin_cli-section)
4. [accounts](#4-accounts)
5. [credentials](#5-credentials)
6. [mailbox](#6-mailbox)
7. [messages](#7-messages)
8. [acl](#8-acl)
9. [sieve](#9-sieve)
10. [import and export](#10-import-and-export)
11. [verify](#11-verify)
12. [uploader](#12-uploader)
13. [cache](#13-cache)
14. [auth-cache and affinity-cache](#14-auth-cache-and-affinity-cache)
15. [stats](#15-stats)
16. [connections](#16-connections)
17. [affinity](#17-affinity)
18. [backends](#18-backends)
19. [health](#19-health)
20. [relay](#20-relay)
21. [tls](#21-tls)
22. [config](#22-config)
23. [migrate](#23-migrate)
24. [version and help](#24-version-and-help)
25. [Destructive commands at a glance](#25-destructive-commands-at-a-glance)

---

## 1. Running sora-admin

### Building

`make sora-admin` (or `make build`, which builds both binaries) produces `./sora-admin`. You can
also build it directly:

```sh
go build -o sora-admin ./cmd/sora-admin
```

### Command line shape

```sh
sora-admin --config /etc/sora/config.toml <command> <subcommand> [flags]
```

- `--config PATH` is **required** for every command except `help` and `version`. There is no
  default path. The flag may appear anywhere on the line, and `--config=PATH` works too. Use two
  dashes: `-config` is not recognised and the tool stops with `--config flag is required`.
- `sora-admin` reads the same TOML file as the server. It loads it with the server's loader, so
  unknown keys and duplicate keys produce the same warnings, and a file the server cannot load
  stops the tool. Settings the file leaves out take the server's defaults, so a command that
  works on the server's spool, cache or queue finds them where the server keeps them.
- Apart from `config validate`, which checks the whole file, the commands use only some
  sections: `[database]`, `[s3]`, `[local_cache]`, `[uploader]`, `[cleanup]`,
  `[shared_mailboxes]`, `[tls]`, `[admin_cli]`, `[relay]`, `[sieve]`, the `[[server]]` blocks and
  the top-level `bcrypt_cost`. The tool stops at once if `[s3] body_deletion_protocol`,
  `[shared_mailboxes]`, `[cleanup]` or `[uploader]` holds a value the server would refuse.
- The config file is loaded before anything else, so even `sora-admin --config PATH accounts
  --help` needs a file that loads. Only `sora-admin help`, `sora-admin --help`, `sora-admin -h`,
  `sora-admin version`, `sora-admin -v`, `sora-admin --version` and `sora-admin config --help`
  work without one.
- Flags of a subcommand come **after** the subcommand. They are parsed with Go's `flag` package,
  so `--flag value`, `--flag=value` and `-flag value` all work. A boolean flag that defaults to
  `true` is turned off with `--flag=false`.
- Worker counts (`--jobs`, `--workers`) must be at least `1`. So must the batch sizes and limits
  this document marks "at least 1"; a smaller value stops the command with an error.
- `sora-admin <command> --help` lists the subcommands. `sora-admin <command> <subcommand> --help`
  prints the subcommand's flags.

### Output, logs and exit status

- Reports and tables go to standard output. Log lines (`INFO`, `WARN`, `ERROR`, with a
  timestamp) go to standard error. `sora-admin` does not use the `[logging]` section.
- The exit status is `0` on success and `1` on error. A few commands report problems but still
  exit `0`; this is noted where it applies (for example `verify s3`).
- Ctrl+C (SIGINT) or SIGTERM cancels the running operation. Long operations such as imports stop
  at the next safe point.

### Database connections

Commands that use PostgreSQL connect to the `[database.write]` endpoint only. They never use read
replicas, and they never apply migrations on their own (only `sora-admin migrate` does). See
[DATABASE.md](DATABASE.md) for the `[database]` section.

---

## 2. What each command needs

Some commands talk to PostgreSQL, some to S3, some to a running server's Admin API, and some only
read files on the host where you run them. This decides where you run each command and what its
config file must contain.

| Command | PostgreSQL | S3 (`[s3]`) | Admin API | Local files on this host |
|---|---|---|---|---|
| `accounts create, list, show, update, delete, restore` | yes | | | |
| `accounts delete --purge`, `accounts purge-domain` | yes | yes | | |
| `credentials *` | yes | | | |
| `mailbox *` | yes | | | |
| `messages *` | yes | | | |
| `acl *` | yes | | | |
| `sieve *` | yes | | | |
| `import maildir` | yes | yes | | the maildir, and `sora-maildir.db` written into it |
| `import s3` | yes | yes | | a temporary SQLite file in the system temp directory |
| `import rekey` | yes | yes | | |
| `export maildir` | yes | yes | | the target directory |
| `verify s3` | yes | yes | | |
| `verify hash` | optional | yes | | `--download` targets |
| `verify body-deletions` | yes | with `--reconcile` | | |
| `uploader status` | yes | for the failed-uploads list | | |
| `uploader resolve` | yes | yes | | this host's upload spool (`[uploader] path`) |
| `cache stats`, `cache purge` | | | | this host's `[local_cache] path` |
| `cache metrics` | yes | | | |
| `auth-cache status`, `affinity-cache status` | | | yes, via `[admin_cli]` | |
| `stats blocked`, `stats connection` | | | yes, via `[admin_cli]` | |
| `connections list`, `connections kick` | | | yes, via `[admin_cli]` | |
| `affinity set, get, list, delete` | | | yes, via `[admin_cli]` | |
| `backends *` | yes (primary) | | | |
| `health status` | yes | | | |
| `health status --backends` | | | yes, via `[admin_cli]` | |
| `relay *` | | | | this host's relay queue directory |
| `tls *` | | the `[tls.letsencrypt.s3]` bucket, not `[s3]` | | `[tls.letsencrypt] fallback_dir` |
| `config validate`, `config dump` | | | | the config file only |
| `migrate *` | yes | | | |

Commands marked "local files on this host" act on the node where you run them. Run `uploader
resolve`, `cache stats`, `cache purge`, `relay *` and `tls cache` on the node whose spool, cache,
queue or certificate directory you mean, with that node's config file.

### Commands that delete message bodies

Some commands delete message bodies from S3. They run only when the config file you pass sets
`[s3] body_deletion_protocol = "global-hash-v1"`. With the default, `"paused"`, they stop with an
error before they change anything:

- `accounts delete --purge` and `accounts purge-domain`
- `verify s3 --fix-orphaned` (without `--dry-run`)
- `import rekey --delete-old-objects` (without `--dry-run`)
- `verify body-deletions --reconcile`

Set the value only after the cut-over described in
[OPERATIONS.md](OPERATIONS.md#16-message-body-deletion). Dry runs, and every
command that does not delete bodies, work with either value.

---

## 3. The `[admin_cli]` section

`[admin_cli]` holds settings that only `sora-admin` reads. The server ignores it. The commands
that call a running server's Admin API use `addr` and `api_key`; the maildir importer uses
`import_message_limit`.

```toml
[admin_cli]
addr = "https://10.0.0.5:8080"   # the Admin API, with scheme
api_key = "the-admin-api-key"
# insecure_skip_verify = false   # default: skip only when addr is a loopback address
import_message_limit = "100mb"
```

| Key | Type | Default | What it does |
|---|---|---|---|
| `addr` | string | none | Base URL of an Admin API server (an `http_admin_api` `[[server]]` block), including `http://` or `https://`. Required by `auth-cache`, `affinity-cache`, `stats`, `connections`, `affinity` and `health status --backends`. |
| `api_key` | string | none | Sent as `Authorization: Bearer <api_key>`. Must match the `api_key` of that Admin API server. Required by the same commands. |
| `insecure_skip_verify` | bool | depends on `addr` | When unset, TLS certificate checks are skipped only if `addr` points at a loopback address (`localhost`, `127.0.0.0/8`, `::1`) and kept for any other host. `true` or `false` overrides this. Leave it unset or `false` for a remote Admin API: the API key travels in every request. |
| `import_message_limit` | size (`"50mb"`) | see below | Largest message `import maildir` accepts. Larger files are counted as failed. |

The `import_message_limit` default comes from the first enabled `[[server]]` block of type `imap`
in the same file: its `append_limit`, which itself defaults to 25 MB. With no IMAP server in the
file, the limit is 50 MB. An unparsable value logs a warning and falls back the same way.

The Admin API requests time out after 30 seconds. The Admin API itself is described in
[ADMIN_API.md](ADMIN_API.md).

---

## 4. accounts

An account is one mailbox owner. It has one or more credentials: addresses that log in and
receive mail. One credential is the primary identity. See [AUTHENTICATION.md](AUTHENTICATION.md)
for how logins are checked.

```mermaid
flowchart LR
    A[active] -- "accounts delete" --> B[soft-deleted<br/>no logins, no delivery]
    B -- "accounts restore<br/>(within grace period)" --> A
    B -- "cleaner, after [cleanup] grace_period" --> C[data removed]
    A -- "accounts delete --purge" --> D[out of service,<br/>purged at once]
    B -- "accounts delete --purge" --> D
```

### accounts create

Creates an account with one credential, or with several from a JSON list.

```sh
sora-admin --config config.toml accounts create --email user@example.com --password 'secret'
```

| Flag | Default | Meaning |
|---|---|---|
| `--email` | | Address of the new account. Required unless `--credentials` is given. It becomes the primary identity. |
| `--password` | | Password to hash. Required unless `--password-hash` or `--credentials` is given. |
| `--password-hash` | | A ready-made hash, stored as given once Sora has checked it is in a scheme it verifies ([AUTHENTICATION.md](AUTHENTICATION.md#4-password-schemes)). Use instead of `--password`. |
| `--hash` | `bcrypt` | Scheme for `--password`: `bcrypt` or `ssha512` (`sha512` is refused). |
| `--credentials` | | JSON list of credentials. Cannot be combined with `--email`, `--password` or `--password-hash`. |

- `--password` and `--password-hash` are mutually exclusive.
- `bcrypt` hashes are stored as `{BLF-CRYPT}$2a$...` with the cost set by the top-level
  `bcrypt_cost` key (default 12), as on the server.
- bcrypt hashes at most 72 bytes of a password; a longer `--password` is refused with `bcrypt`.
- `--password-hash` is checked before it is stored: a hash in a scheme Sora cannot verify, or
  one that is malformed, is refused and nothing is created. The accepted schemes (bare bcrypt,
  `{BLF-CRYPT}`, `{CRYPT}` with bcrypt data, `{SSHA512}` and `{SHA512}`) are listed in
  [AUTHENTICATION.md](AUTHENTICATION.md#4-password-schemes). Quote the hash in single quotes so
  the shell leaves `$` alone. The same checks apply to `password` and `password_hash` in
  `--credentials`, and to `accounts update` and `credentials add`.
- The address is validated and stored in lower case. Creation fails if any account (active or
  soft-deleted) already has this address.

The `--credentials` JSON is a list of objects:

| Field | Meaning |
|---|---|
| `email` | Address (required). |
| `password` | Password to hash. |
| `password_hash` | Ready-made hash, used instead of `password`. |
| `is_primary` | Exactly one credential must be `true`. |
| `hash_type` | Scheme for `password`. Default `bcrypt`. |

```sh
sora-admin --config config.toml accounts create --credentials \
  '[{"email":"user@example.com","password":"pass1","is_primary":true},
    {"email":"alias@example.com","password":"pass2","is_primary":false}]'
```

### accounts list

Lists the accounts whose **primary** address is in a domain. Soft-deleted accounts are not
listed.

```sh
sora-admin --config config.toml accounts list --domain example.com
```

| Flag | Default | Meaning |
|---|---|---|
| `--domain` | | Domain to list (required). |

Columns: ID, primary email, number of credentials, mailboxes, messages, storage used, creation
time, newest account first.

### accounts show

Shows one account: ID, status (`active` or `deleted`), primary address, creation and deletion
times, mailbox and message counts, storage used, and every credential.

| Flag | Default | Meaning |
|---|---|---|
| `--email` | | Any address of the account (required). |
| `--json` | `false` | Print JSON instead of text. |

### accounts update

Changes the password of one credential, or makes it the primary identity, or both.

```sh
sora-admin --config config.toml accounts update --email user@example.com --password 'new-secret'
sora-admin --config config.toml accounts update --email alias@example.com --make-primary
```

| Flag | Default | Meaning |
|---|---|---|
| `--email` | | The credential to change (required). |
| `--password` | | New password for this credential. |
| `--password-hash` | | New ready-made hash for this credential. |
| `--make-primary` | `false` | Make this credential the primary identity. The previous primary becomes an alias. |
| `--hash` | `bcrypt` | Scheme for `--password`: `bcrypt` or `ssha512`. |

- At least one of `--password`, `--password-hash` and `--make-primary` is required.
- Passwords belong to credentials, not to the account. Changing the password of
  `user@example.com` does not change the password of `alias@example.com`.
- `--make-primary` is refused when the new primary is in a different domain and the account
  already has messages: message bodies in S3 are stored under the primary address's domain, and
  the change would split them.
- A password change drops the account's cached logins on every node, as the Admin API does, so
  the old password stops working at once.

### accounts delete

Without `--purge`, soft-deletes the account. With `--purge`, deletes all of its data right away.

```sh
sora-admin --config config.toml accounts delete --email user@example.com --confirm
sora-admin --config config.toml accounts delete --email user@example.com --confirm --purge
```

| Flag | Default | Meaning |
|---|---|---|
| `--email` | | Any address of the account (required). |
| `--confirm` | `false` | Required. Without it the command refuses. There is no interactive prompt. |
| `--purge` | `false` | Delete everything right away instead of soft-deleting. Irreversible. |

**Soft delete** marks the account deleted. From then on it cannot log in and receives no mail. The
data stays until the cleaner removes it after `[cleanup] grace_period` (default `14d`; see
[STORAGE.md](STORAGE.md)). Until then, `accounts restore` brings everything back. Deleting an
account that is already soft-deleted is an error.

**Purge** first takes the account out of service and marks it for purging, the same mark the
Admin API sets. It then deletes the account's mailboxes, messages, S3 objects, search index,
credentials and the account itself. It needs `[s3]`, with `body_deletion_protocol =
"global-hash-v1"` ([see above](#commands-that-delete-message-bodies)). It cannot be undone. If it stops partway,
the account stays out of service and marked; a server's purge worker (on a node with object
storage) finishes it, or you run the command again. If a server's purge worker is already
purging the account, the command waits for it and reports when it is done.

Both forms end the account's open sessions and drop its cached logins on every node, as the
Admin API does.

### accounts restore

Restores a soft-deleted account and clears any pending purge request on it.

| Flag | Default | Meaning |
|---|---|---|
| `--email` | | Any address of the account (required). |

Restore before `[cleanup] grace_period` ends. Once the cleaner has started removing the
account's data, `restore` cannot bring that data back. A purged account cannot be restored.
Restoring an account that is not deleted is an error.

### accounts purge-domain

Purges every account whose primary address is in a domain, then deletes the remaining credentials
in that domain that are aliases of accounts kept elsewhere.

```sh
sora-admin --config config.toml accounts purge-domain --domain example.com --confirm
```

| Flag | Default | Meaning |
|---|---|---|
| `--domain` | | Domain to purge (required). |
| `--confirm` | `false` | Required. There is no interactive prompt. |

- Each account is purged as with `accounts delete --purge`, including soft-deleted accounts. It
  needs `[s3]` with `body_deletion_protocol = "global-hash-v1"`, and cannot be undone. With
  deletion paused it stops before it looks at the domain.
- It is resumable. If it is interrupted, or some accounts fail, run the same command again:
  accounts already gone are skipped. The command exits `1` if any account or alias failed.
- Accounts whose primary address is in another domain are kept, but their aliases in this
  domain are deleted, so the domain stops receiving mail.

---

## 5. credentials

A credential is an address with its own password. Aliases are credentials that are not the
primary identity.

### credentials add

Adds a credential to an existing account.

```sh
sora-admin --config config.toml credentials add --primary user@example.com \
  --email alias@example.com --password 'alias-secret'
```

| Flag | Default | Meaning |
|---|---|---|
| `--primary` | | An existing address of the account to add to (required). Any credential of the account works, not only the primary. |
| `--email` | | The new address (required). |
| `--password` | | Password for the new credential. |
| `--password-hash` | | Ready-made hash for the new credential. |
| `--make-primary` | `false` | Make the new credential the primary identity. |
| `--hash` | `bcrypt` | Scheme for `--password`: `bcrypt` or `ssha512`. |

One of `--password` and `--password-hash` is required. `--make-primary` follows the same domain
rule as `accounts update --make-primary`.

### credentials list

Lists the credentials of the account that owns an address, marking the primary.

| Flag | Default | Meaning |
|---|---|---|
| `--email` | | Any address of the account (required). |

### credentials show

Shows one credential: its role (primary identity or alias), creation and update times, and a
summary of its account.

| Flag | Default | Meaning |
|---|---|---|
| `--email` | | The credential (required). |
| `--json` | `false` | Print JSON. |

### credentials delete

Deletes one credential. There is no confirmation prompt and no undo; add it again with
`credentials add` if needed.

| Flag | Default | Meaning |
|---|---|---|
| `--email` | | The credential to delete (required). |

The primary credential cannot be deleted: make another one primary first with `accounts update
--make-primary`. The last credential of an account cannot be deleted: delete the account
instead.

The deleted address's cached logins are dropped on every node, as the Admin API does.

---

## 6. mailbox

Mailbox names use `/` as the hierarchy delimiter (`Projects/2024`). Name lookups are
case-insensitive. Every subcommand takes `--email` (any address of the account, required).

### mailbox create

```sh
sora-admin --config config.toml mailbox create --email user@example.com --mailbox "Projects/2024/Q1"
```

| Flag | Default | Meaning |
|---|---|---|
| `--mailbox` | | Name to create (required). Missing parents are created. A trailing `/` is dropped. |

With `[shared_mailboxes] enabled = true`, a name under the shared namespace prefix creates a
shared mailbox, whatever `allow_user_create` says. See [SHARED_MAILBOXES.md](SHARED_MAILBOXES.md).

### mailbox list

| Flag | Default | Meaning |
|---|---|---|
| `--subscribed` | `false` | List only subscribed mailboxes. |

### mailbox delete

Deletes a mailbox. It disappears from the account at once.

```sh
sora-admin --config config.toml mailbox delete --email user@example.com --mailbox "Old" --confirm
```

| Flag | Default | Meaning |
|---|---|---|
| `--mailbox` | | Name to delete (required). |
| `--confirm` | `false` | Required. There is no interactive prompt. |
| `--purge` | `false` | Expunge every message in the mailbox before deleting it. |

- `INBOX` cannot be deleted.
- `--mailbox` may name a shared mailbox of another account that this account can see. Deleting
  it needs the `x` (delete) right on it.
- A mailbox with child mailboxes is refused, and nothing is changed. Delete the children first.
  These checks all run before `--purge` touches a message.
- Without `--purge`, the cleaner removes the mailbox and its messages later, after `[cleanup]
  grace_period`. There is no command that brings back a deleted mailbox.
- With `--purge`, the messages are marked expunged right away, the same way IMAP EXPUNGE does.
  They then show up in `messages list-deleted` and can be restored with `messages restore` until
  the cleaner reclaims them after `[cleanup] grace_period`. The cleaner deletes an S3 object only
  when no other message (a copy in another folder) still uses it.

### mailbox rename

Renames or moves a mailbox, with its children.

| Flag | Default | Meaning |
|---|---|---|
| `--old-name` | | Current name (required). |
| `--new-name` | | New name (required). Missing parents are created. |

Refused, with nothing changed, when:

- the mailbox is `INBOX` (unlike IMAP RENAME, which moves INBOX's messages into a new folder);
- the new name has an empty level, or a level `.` or `..` (a trailing `/` is dropped);
- the new name lies below the mailbox itself;
- with shared mailboxes enabled, the rename would move the mailbox, or a child it carries along,
  across the shared namespace boundary.

### mailbox subscribe and mailbox unsubscribe

| Flag | Default | Meaning |
|---|---|---|
| `--mailbox` | | Name to subscribe to or unsubscribe from (required). |

### mailbox fix-utf7

Finds mailbox names that still contain IMAP modified UTF-7 sequences (for example
`R&AOk-pertoire`) and renames them to UTF-8 (`Répertoire`). Children follow their parents.

```sh
sora-admin --config config.toml mailbox fix-utf7 --dry-run
sora-admin --config config.toml mailbox fix-utf7 --email user@example.com
```

| Flag | Default | Meaning |
|---|---|---|
| `--email` | all accounts | Limit to one account. Optional for this subcommand. |
| `--dry-run` | `false` | Print `WOULD RENAME` lines and change nothing. |

Each line of the output names one mailbox:

| Line | Meaning |
|---|---|
| `OK` | Renamed. |
| `WOULD RENAME` | Dry run: would be renamed. |
| `SKIP` | The name does not decode, or decodes to itself. |
| `FAIL` / `WOULD FAIL` | The rename is refused, with the reason: the decoded name is taken or invalid, or it would cross the shared namespace boundary. The dry run checks the same conditions. |

### mailbox repair-hierarchy

Finds mailboxes whose place in the hierarchy disagrees with their name and, with `--apply`,
repairs them. Clients find a mailbox by its name (LIST, SELECT, APPEND, Sieve `fileinto`), while
`\HasChildren`, the renaming of children on RENAME and the refusal to DELETE a mailbox with
children follow its place in the hierarchy. Where the two disagree, LIST shows the mailbox without
its parent, the parent shows no children, and a RENAME of the parent leaves the mailbox behind.

```sh
sora-admin --config config.toml mailbox repair-hierarchy
sora-admin --config config.toml mailbox repair-hierarchy --email user@example.com --apply
```

| Flag | Default | Meaning |
|---|---|---|
| `--email` | all accounts | Limit to one account. Optional for this subcommand. |
| `--apply` | `false` | Repair. Without it the command is a dry run: it changes nothing and prints `WOULD REPAIR` lines for what `--apply` does. |
| `--batch-size` | `1000` | Accounts read per query when walking all accounts (1 to 10000). |

It reports these problems (the second column of each line):

| Problem | Meaning |
|---|---|
| `root_with_delimiter` | A name with `/` at the top level, such as `Parent/Child` with no parent. |
| `detached` | Below a mailbox that is not its name's parent, such as `Alpha/Beta` below `Gamma`. Only the top of such a subtree is listed. |
| `parent_deleted` | Below a deleted mailbox. |
| `parent_missing` | Below a mailbox that does not exist. |
| `bad_path` | The stored hierarchy path is malformed or contains anything except canonical lowercase ASCII hex. Reported only (`REPORT`); nothing is changed. |

What `--apply` does with each one (`REPAIRED`):

- It moves the mailbox, with every mailbox below it, under the mailbox whose name is its name's
  parent part: `Parent/Child` under `Parent`, and a name without `/` to the top level. Names, ids,
  UIDVALIDITY, messages, flags and subscriptions stay as they are, so clients do not resync.
- A missing parent is created as IMAP CREATE creates it (RFC 9051 section 6.3.4), empty and
  unsubscribed. The line names the mailboxes created.

A mailbox is left alone (`MANUAL`) when no mailbox has its name's parent part and its place gives
it another name: `Alpha/Beta` below `Gamma` with no `Alpha`, or `X/a/Beta` below `X`, whose place
makes it `X/Beta`. A CREATE that raced a RENAME of the parent, or a later RENAME, left it so, and
only the user knows which name is right. The line shows the name its place gives it. Fix it with
`mailbox rename` to the right name; the rename links it under that name's parent and creates the
parent if needed.

Each account is repaired in a transaction of its own, which locks the account's mailboxes while it
runs, and is rolled back unless every mailbox it repaired comes out right. Run it again after
`--apply`: only `MANUAL` and `REPORT` lines are left. The exit status is `1` only when an account
fails; `MANUAL` and `REPORT` lines do not change it.

### mailbox repair-unseen

Finds mailboxes whose cached unseen count (served by STATUS, LIST and NOTIFY) is higher than
the number of unseen messages they hold, and with `--apply` recomputes it. Older builds left
such counts when the failed-upload cleanup, `uploader resolve` or an importer rollback
hard-deleted an unseen message. A count that has gone negative is repaired by the server
itself.

```sh
sora-admin --config config.toml mailbox repair-unseen
sora-admin --config config.toml mailbox repair-unseen --apply
```

| Flag | Default | Meaning |
|---|---|---|
| `--email` | all accounts | Limit to one account. Optional for this subcommand. |
| `--apply` | `false` | Repair the mailboxes found. Without it, print `WOULD REPAIR` lines and change nothing. |
| `--batch-size` | `200` | Mailboxes checked per batch. |
| `--start-after` | `0` | Resume after this mailbox id. |

Mailboxes are checked in id order. After each batch the command prints the id to pass to
`--start-after` if it is interrupted. Each repair is a short transaction that holds only that
mailbox's lock, so it can run while the servers are serving mail. It is safe to run again: a
repaired mailbox is not reported any more.

---

## 7. messages

Expunged messages stay in the database, marked with their expunge time, until the cleaner
removes them after `[cleanup] grace_period` (default `14d`). Until then you can list and restore
them. See [STORAGE.md](STORAGE.md) for two-phase deletion.

### messages list-deleted

```sh
sora-admin --config config.toml messages list-deleted --email user@example.com --since 2026-11-01
```

| Flag | Default | Meaning |
|---|---|---|
| `--email` | | Any address of the account (required). |
| `--mailbox` | | Only messages that were in this mailbox (case-insensitive). |
| `--since` | | Only messages expunged at or after this time. |
| `--until` | | Only messages expunged at or before this time. |
| `--limit` | `100` | Maximum rows, newest expunge first. |

Times are `YYYY-MM-DD` (midnight UTC) or RFC 3339 (`2026-11-01T08:00:00Z`). The ID column is the
message's database ID, which `messages restore --ids` takes.

### messages restore

Puts expunged messages back into the mailboxes they came from.

```sh
sora-admin --config config.toml messages restore --email user@example.com --mailbox INBOX
sora-admin --config config.toml messages restore --email user@example.com --ids 123,456 --confirm
```

| Flag | Default | Meaning |
|---|---|---|
| `--email` | | Any address of the account (required). |
| `--ids` | | Comma-separated message IDs from `list-deleted`. |
| `--mailbox` | | All expunged messages from this mailbox. |
| `--since` | | Messages expunged at or after this time. |
| `--until` | | Messages expunged at or before this time. |
| `--confirm` | `false` | Skip the prompt. |

- At least one of `--ids`, `--mailbox`, `--since` and `--until` is required. Given together,
  they all apply.
- Without `--confirm`, the command lists up to ten of the matching messages and asks
  `Continue with restoration? (yes/no)`. Only `yes` or `y` continues.
- A mailbox that no longer exists is created again.
- Restored messages get new UIDs and new mod-sequences, so IMAP clients see them as new
  messages. The expunge of the old UID stays on record until the cleaner removes it, so a client
  that has not yet heard of the expunge still hears of it.
- A restored message also gets a new database id. If it is deleted again, `list-deleted` shows
  it under the new id.
- With sharing enabled in the config file you pass, a mailbox (or parent) recreated in the
  shared namespace is a shared mailbox of the account, as `mailbox create` makes one. It starts
  with owner-only rights: one entry, the owner's primary address with `default_rights`. The ACL
  entries it had before it was deleted are not restored, and a shared parent's entries are not
  copied as they are for a new folder ([SHARED_MAILBOXES.md](SHARED_MAILBOXES.md)). The restore
  logs a warning naming the mailbox. Grant access again with `acl grant`.
- Restores run in chunks, each committed on its own. If a run fails partway, the restored
  messages stay restored; run the same command again for the rest. Messages already back are
  skipped, not duplicated.

### messages repair-references

Fills in the stored References of messages that have none. `SEARCH HEADER References` and
THREAD read the References chain from a column of the message row
([SEARCH.md](SEARCH.md)). Messages stored before the column was added (migration 000036), and
messages copied or moved by older builds, have no value in it (NULL). Search does not find them
by References, and THREAD links them by In-Reply-To only. A message without a References header
is stored with an empty value, not NULL.

```sh
sora-admin --config config.toml messages repair-references
sora-admin --config config.toml messages repair-references --apply
```

| Flag | Default | Meaning |
|---|---|---|
| `--apply` | `false` | Fill the rows that can be filled. Without it, only count them and change nothing. |
| `--batch-size` | `1000` | Message rows read per batch. |
| `--start-after` | `0` | Resume after this message id. |

How it works:

- It reads the message rows of all accounts in id order, in batches. A live message with no
  stored References is filled with the value stored for another row with the same body
  (content hash): the same bytes have the same References header. Expunged messages are not
  filled.
- It uses only PostgreSQL and reads nothing from S3. A message whose body no other row has a
  value for cannot be filled: it is counted and left as it is.
- Each batch is read from the primary in one statement and, with `--apply`, filled in one short
  transaction on the primary, like every admin command ([section 1](#database-connections)). It
  keeps no session state, so it works through PgBouncer in transaction mode, and it can run
  while the servers are serving mail.
- The summary gives the rows checked, how many have no stored References, how many can be filled
  and how many cannot, and with `--apply` how many were filled.
- At most every 10 seconds, and when it stops on an error or Ctrl+C, it prints the id to pass to
  `--start-after`. Running it again is safe: a filled row is not counted again.
- A message restored later with `messages restore` gets the value its expunged row had, so run
  the command again after restoring old mail.
- The dry run runs the same read queries as `--apply`, so its run time shows how long the reads
  take on your database.
- `--batch-size` must be at least 1. Extra words after the flags are refused.

---

## 8. acl

Manages access control lists (RFC 4314) on shared mailboxes. Rights, identifiers and the
same-domain rule are explained in [SHARED_MAILBOXES.md](SHARED_MAILBOXES.md). The tool acts as
a trusted administrator: it does not need the `a` right.

| Subcommand | Flags | What it does |
|---|---|---|
| `grant` | `--email`, `--mailbox`, `--identifier` (or `--user`), `--rights` | Sets the identifier's rights on the mailbox. The given rights **replace** any it already had. |
| `revoke` | `--email`, `--mailbox`, `--identifier` (or `--user`) | Removes the identifier's entry. It is an error if there is none. |
| `list` | `--email`, `--mailbox` | Lists the entries and their rights. |

- `--email` is the mailbox owner (required). `--mailbox` is the owner's mailbox name, for
  example `Shared/Sales` (required).
- `--identifier` is an address or `anyone`. `--user` is another name for it.
- `--rights` is a string of the letters `l r s w i p k x t e a` (required for `grant`).
- A grant is checked: the mailbox must be shared, and the grantee must be an active account in
  the owner's domain other than the owner. `anyone` is accepted only when `[shared_mailboxes]
  allow_anyone_identifier` allows it.

```sh
sora-admin --config config.toml acl grant --email owner@example.com --mailbox "Shared/Sales" \
  --user bob@example.com --rights lrs
```

---

## 9. sieve

Manages a user's Sieve scripts. Every subcommand takes `--email` (required). See
[SIEVE.md](SIEVE.md) for the Sieve engine and its extensions.

| Subcommand | Flags | What it does |
|---|---|---|
| `list` | `--email` | Lists the account's scripts and which one is active. |
| `show` | `--email`, `--name` | Prints a script. |
| `put` | `--email`, `--name`, `--file` | Creates a script, or replaces the content of the script with that name. |
| `delete` | `--email`, `--name` | Deletes a script, also the active one. No prompt. |
| `activate` | `--email`, `--name` | Makes this script the active one and deactivates every other. |
| `deactivate` | `--email` | Deactivates all scripts: no Sieve script runs for the account. |
| `rename` | `--email`, `--old`, `--new` | Renames a script. |

- `put` reads the script from `--file`, or from standard input when `--file` is missing or `-`.
- `put` refuses a script larger than 65536 bytes, and a script that does not compile with the
  extensions in `[sieve] enabled_extensions`. `activate` checks the stored script the same way.
- A new script is inactive. Updating a script keeps its active state.
- Script names (for `put` and `rename --new`) may contain only letters, digits, `-`, `_` and `.`,
  up to 128 characters. An account can have at most 100 scripts.

```sh
sora-admin --config config.toml sieve put --email user@example.com --name main --file main.sieve
sora-admin --config config.toml sieve activate --email user@example.com --name main
```

---

## 10. import and export

| Command | What it does |
|---|---|
| `import maildir` | Imports a maildir (Dovecot or other) into an account, with flags, Dovecot keywords, UIDs, subscriptions and a Sieve script. |
| `import s3` | Recovery: creates database rows for message objects already in S3 under an account's prefix. |
| `import rekey` | Repair: moves bodies that an older `import maildir` stored under their SHA-256 digest to their BLAKE3 key. |
| `export maildir` | Writes an account's mail to a maildir, optionally with Dovecot files. |

All four, with every flag, the SQLite cache and the re-run rules, are described in
[IMPORT_EXPORT.md](IMPORT_EXPORT.md).

```sh
sora-admin --config config.toml import maildir --email user@example.com \
  --maildir-path /var/vmail/example.com/user/Maildir --dovecot
```

---

## 11. verify

Checks message bodies in S3 against the database.

### verify s3

Compares one account's messages in the database with the objects under its S3 prefix.

```sh
sora-admin --config config.toml verify s3 --email user@example.com --show-missing
```

| Flag | Default | Meaning |
|---|---|---|
| `--email` | | The account (required). Its domain and local part also form the S3 prefix that is listed. Use the primary address. |
| `--show-missing` | `false` | List every missing, orphaned and corrupt key. |
| `--deep` | `false` | Download, decrypt and BLAKE3-hash every object. Slow: it transfers all of the account's mail. |
| `--fix-orphaned` | `false` | Delete S3 objects under the prefix that no message (expunged or not, in any account) or pending upload uses. Needs `[s3] body_deletion_protocol = "global-hash-v1"` unless `--dry-run` is set ([section 2](#commands-that-delete-message-bodies)). |
| `--fix-missing` | `false` | Set `uploaded = false` on live messages whose object is missing. |
| `--dry-run` | `false` | With the `--fix-*` flags, report and change nothing. |
| `--batch-size` | `1000` | Messages per batch in the database-to-S3 pass. At least 1. |

The address is put in the form S3 keys use: lower case, with an internationalized domain in its
ASCII (`xn--`) form.

It runs two passes:

1. **Database to S3.** Every live (not expunged) message's key gets a HEAD request; with
   `--deep`, the full body is also downloaded and checked. Messages whose upload is still
   pending are counted, not checked.
2. **S3 to database.** Every object under `domain/localpart/` of `--email` is looked up among all
   message rows that reference it (expunged or not, and in any account) and all pending uploads
   of its content hash. Objects that nothing references are reported as orphaned.

With `--deep`, an intact body stored under the SHA-256 digest of its bytes, as an older `import
maildir` stored them, is reported apart from corrupt ones, with the `import rekey` command that
moves it ([IMPORT_EXPORT.md](IMPORT_EXPORT.md#14-import-rekey)).

Things to know before you use the fix flags:

- `--fix-orphaned` leaves alone an object that an expunged message still uses: that message can
  still be restored with `messages restore` during the grace period.
- `--fix-missing` does not recover a body. Objects that pass HEAD but fail `--deep` are not
  "missing", and `--fix-missing` does not touch them.

The command exits `0` even when it finds problems; read the summary.

### verify hash

Checks one object. The key is built from `--email` and `--hash` alone (`domain/localpart/hash`),
so the S3 part needs no database.

```sh
sora-admin --config config.toml verify hash --email user@example.com --hash 31feeacf... --details
```

| Flag | Default | Meaning |
|---|---|---|
| `--hash` | | Content hash (required). |
| `--email` | | Address whose domain and local part form the key (required). This is the primary address the message was stored under. |
| `--details` | `false` | List the messages that use this hash. |
| `--skip-db` | `false` | Do not connect to the database. |
| `--download PATH` | | Save the raw stored object (still encrypted, if `[s3] encrypt` is on), including whatever a truncated object returns. |
| `--download-decrypted PATH` | | Save the decrypted message. Fails on a corrupt object. |

Steps:

1. HEAD the key.
2. Download, decrypt and BLAKE3-hash the body. A body that hashes to its SHA-256 digest instead
   is intact but stored by an older `import maildir`; the summary names the `import rekey`
   command that moves it.
3. Best effort: list the account's messages that use this exact key, and their upload state.
   When the account has none, check whether another account or a pending upload still uses
   the object, and report it as orphaned if nothing does. If the database cannot be reached,
   this step is skipped and the S3 result still stands.

`--email` is put in the S3 key form, as for `verify s3`.

### verify body-deletions

Lists, and on request clears, the message-body deletions that did not finish cleanly. Before
the cleaner, a purge or another command sends an S3 DELETE for a body, it records a deletion
intent in the database (content hash, keys and an operation id). If the outcome is uncertain,
for example because the database connection or the S3 request was lost, the intent stays, and
Sora refuses to store that body again until an operator reconciles it. The protocol is described
in [OPERATIONS.md](OPERATIONS.md#16-message-body-deletion).

```sh
sora-admin --config config.toml verify body-deletions
sora-admin --config config.toml verify body-deletions --reconcile \
  --content-hash HASH --operation-id UUID --storage-drained
```

| Flag | Default | Meaning |
|---|---|---|
| `--reconcile` | `false` | Reconcile one intent. Without it the command only lists the intents and changes nothing. |
| `--content-hash` | | The intent's content hash, from the listing. Required with `--reconcile`. |
| `--operation-id` | | The intent's exact operation UUID, from the listing. Required with `--reconcile`. |
| `--storage-drained` | `false` | Your statement that the old S3 requests and writers for this body can no longer arrive. Required with `--reconcile`. Sora cannot detect this itself. |

The listing prints one line per intent: content hash, operation id, creation time, keys and the
last error. `--content-hash`, `--operation-id` and `--storage-drained` are refused without
`--reconcile`.

`--reconcile` needs `[s3] body_deletion_protocol = "global-hash-v1"`. Holding the body's lock, it
downloads and checks every key that a message still needs (restore a missing or corrupt body from
a trusted copy first), deletes the keys nothing needs, and then clears that one intent. Any
failure leaves the intent in place.

---

## 12. uploader

Messages delivered to a backend are written to its local spool and uploaded to S3 by its upload
worker. An upload that keeps failing is "parked" once it reaches `[uploader] max_attempts`
(default 20 when the key is unset). See [STORAGE.md](STORAGE.md) for the uploader.

### uploader status

Shows the queue: pending uploads and their size, parked ("failed") uploads, the oldest pending
upload, a per-instance breakdown, and up to `--failed-limit` parked uploads with an S3 existence
check.

| Flag | Default | Meaning |
|---|---|---|
| `--show-failed` | `true` | List parked uploads. |
| `--failed-limit` | `10` | How many parked uploads to list. |

### uploader resolve

Decides, for each parked upload, whether its body is safe, and acts on it.

```sh
sora-admin --config config.toml uploader resolve --dry-run
sora-admin --config config.toml uploader resolve
```

| Flag | Default | Meaning |
|---|---|---|
| `--dry-run` | `false` | Print the decisions and change nothing. |
| `--limit` | `100` | Maximum parked uploads to process. |

| Result | When | Action |
|---|---|---|
| `[REPAIR]` | The object exists in S3, or nothing is left to write. | Marks the messages uploaded and removes the pending row. |
| `[REARM]` | Not in S3, owned by this host, and the spool file is here with the right size. | Resets the attempt count; this host's uploader tries again. |
| `[SKIP]` owned by other host | Not in S3 and another instance owns it. | Nothing. Run `resolve` on that host. |
| `[SKIP]` size differs | The spool file is here but has another size. | Nothing. Inspect it by hand. |
| `[SKIP]` spool unreadable | `[uploader] path` is not a directory on this host, or the file cannot be checked. | Nothing: the body is not proven missing. Check the path, and run `resolve` as the server's user. |
| `[DELETE]` | Not in S3, owned by this host, and no spool file. | Deletes the message rows and the pending row. The message is lost. |

"This host" is the instance ID from `[uploader] instance_id`, or the hostname when unset. The
spool is `[uploader] path`, with the server's default when unset. Run `resolve` on the backend
that owns the uploads, with its own config file. Always look at a `--dry-run` first.

An upload that a new delivery re-armed, or that is being written while `resolve` runs, is left to
the uploader: `[DELETE]` then deletes nothing, and `[REPAIR]` marks the messages whose objects
exist but keeps the pending row.

**The old default spool.** Earlier releases staged bodies in `/tmp/sora/uploads` by default.
When `[uploader] path` is the current default, `resolve` (also with `--dry-run`) refuses to run
while that old directory still holds staged bodies, because `[DELETE]` would take them for lost.
It counts a file there whoever owns it, and also refuses when it cannot read a directory there.
The error starts with `Failed to resolve uploads:` and names the old spool. Drain or move the old
spool first, as [OPERATIONS.md](OPERATIONS.md#5-what-a-restart-loses-and-keeps) describes.

---

## 13. cache

The local cache keeps recently fetched message bodies on a backend's disk. See
[STORAGE.md](STORAGE.md).

| Subcommand | What it does |
|---|---|
| `stats` | Shows the cache path, object count, total size, capacity, maximum object size and utilisation. |
| `metrics` | Shows hit and miss ratios that the servers record in the database, per instance. |
| `purge` | Deletes every cached object and clears the cache index. |

`stats` and `purge` act on `[local_cache] path` (the server's default when unset) **on the host
where you run them**. They need no database. `stats` only reads the cache.

`cache purge` flags:

| Flag | Default | Meaning |
|---|---|---|
| `--confirm` | `false` | Skip the `(y/N)` prompt. |

A purge loses nothing: the bodies are in S3 and are fetched again on the next miss.

`cache metrics` flags:

| Flag | Default | Meaning |
|---|---|---|
| `--instance` | all | Only this instance ID. |
| `--history` | `false` | Show history instead of the latest record per instance. |
| `--since` | `24h` | With `--history`: how far back. Accepts Go durations and whole days (`7d`). |
| `--limit` | `50` | With `--history`: maximum records. |
| `--json` | `false` | Print JSON. |

---

## 14. auth-cache and affinity-cache

Both call the Admin API set in `[admin_cli]`. Neither takes flags; `--help` after `status`
prints the usage.

| Command | Admin API endpoint | Shows |
|---|---|---|
| `auth-cache status` | `GET /admin/auth-cache/stats` | Whether the proxy auth cache is enabled, entries, session hits and misses, hit rate, lifetime hits. |
| `affinity-cache status` | `GET /admin/affinity/stats` | Whether the affinity cache is enabled, entries, TTL, cleanup interval, entries per protocol, gossip broadcast queue use. |

The figures are those of the server that answers at `addr`. The caches are described in
[PROXY.md](PROXY.md).

---

## 15. stats

Both subcommands call the Admin API set in `[admin_cli]`.

### stats blocked

Lists IP addresses and IP-plus-username pairs that authentication rate limiting has blocked,
with the time left and the failure counts. See [AUTHENTICATION.md](AUTHENTICATION.md).

| Flag | Default | Meaning |
|---|---|---|
| `--protocol` | all | Filter: `imap`, `pop3`, `managesieve` or `userapi` (backend servers), `imap_proxy`, `pop3_proxy`, `managesieve_proxy` or `userapi_proxy` (proxies). |

### stats connection

Shows connection counts by protocol, or one user's connections.

| Flag | Default | Meaning |
|---|---|---|
| `--user` | | Show this user's connections, with local and cluster-wide counts per protocol. |
| `--detail` | `true` | With `--user`: print the per-protocol table. |

Connection tracking lives in memory: on IMAP, POP3 and ManageSieve backends, and on proxies in a
cluster, which share it through the cluster. The answer
says where its figures come from. See [CLUSTER.md](CLUSTER.md).

---

## 16. connections

Both subcommands call the Admin API set in `[admin_cli]`.

### connections list

| Flag | Default | Meaning |
|---|---|---|
| `--user` | | Only this user (asked of the API). |
| `--domain` | | Only users in this domain (filtered by the tool). |
| `--protocol` | | Only trackers whose name is this protocol, for example `IMAP`, `POP3`, `LMTP` (case-insensitive). |
| `--instance` | | Only trackers whose name contains this text. |

Columns: user, protocol, server, local count, count on other nodes, last update.

### connections kick

Closes a user's connections on every node: the Admin API broadcasts the kick through the
cluster.

```sh
sora-admin --config config.toml connections kick --user user@example.com --protocol IMAP -y
```

| Flag | Default | Meaning |
|---|---|---|
| `--user` | | The user to kick (required). |
| `--protocol` | all | Only `IMAP`, `POP3` or `ManageSieve` (case-insensitive). |
| `--confirm`, `-y` | `false` | Skip the `(y/N)` prompt. |

The Admin API that answers must run on a node with connection tracking: one that runs IMAP, POP3
or ManageSieve servers, or proxies with the cluster enabled. Otherwise it answers
`503 Connection tracking not available (requires cluster mode)`. A kick does not stop the user
from logging in again.

---

## 17. affinity

Affinity pins a user to a backend, per protocol, on proxies. See [PROXY.md](PROXY.md).

| Subcommand | Flags | What it does |
|---|---|---|
| `set` | `--user`, `--protocol`, `--backend` | Pins the user to the backend; the change is gossiped to every node. |
| `get` | `--user`, `--protocol` | Prints the user's backend, or says there is none. |
| `list` | `--protocol`, `--backend` (both optional) | Lists affinities: user, protocol, backend, expiry and the node that assigned it, then a total. |
| `delete` | `--user`, `--protocol` | Removes the pin; gossiped to every node. |

- `--user` and `--protocol` are required for `set`, `get` and `delete`; `--backend` is required
  for `set`.
- `--protocol` is `imap`, `pop3` or `managesieve`. `--backend` is a backend address as the proxy
  knows it, for example `10.0.0.21:993`; the Admin API refuses a backend that is not in its
  configured list for that protocol.
- `list` shows what the node behind `[admin_cli] addr` holds: the affinities it assigned and the
  ones it received by gossip. A node that was down, or joined after an affinity was gossiped,
  does not hold it, so two nodes can list different affinities.
- These commands call the Admin API set in `[admin_cli]`, like the other Admin API commands.

---

## 18. backends

Puts a backend into maintenance so you can stop it without losing mail or cutting users off
abruptly. In maintenance, proxies send it no new logins or deliveries, re-route users with
affinity to it, and close its IMAP sessions gradually. After `[backend_maintenance]
refuse_after` (default `30s`) the backend also refuses new sessions itself. It keeps running so
that it can finish the uploads only its own spool holds. The whole mechanism is described in
[PROXY.md](PROXY.md).

```sh
sora-admin --config config.toml backends maintenance on --host storage2.example.com --reason "disk swap" --wait
sora-admin --config config.toml backends status
sora-admin --config config.toml backends maintenance off --host storage2.example.com
```

### backends maintenance on

| Flag | Default | Meaning |
|---|---|---|
| `--host` | | Backend host as the proxies know it: a name or an IP, **without a port** (required). Maintenance covers every port. |
| `--instance` | the host | The backend's uploader instance ID (`[uploader] instance_id`, default its hostname). An ID no node has ever reported under is refused, and the error lists the IDs seen in the last 24 hours. |
| `--reason` | | A note that `status` shows. |
| `--wait` | `false` | Then block until the backend is safe to stop. |

The command records who set the maintenance (`user@host` of the shell running it). Proxies pick
up the change within `[backend_maintenance] poll_interval` (default `5s`); they need database
access to see it.

### backends maintenance off

| Flag | Default | Meaning |
|---|---|---|
| `--host` | | The backend (required). |

Proxies route to it again within one poll. Users moved off it keep their new backend until
their affinity expires.

### backends status

| Flag | Default | Meaning |
|---|---|---|
| `--host` | all | Show only this backend. Exits `1` if it is not in maintenance. |
| `--wait` | `false` | Block until `--host` is safe to stop (`--host` is required with it). |

For each backend in maintenance it shows since when and by whom, the reason, the uploader
instance, the node's own addresses, pending and parked uploads, open client sessions and whether
new sessions are refused yet.

"Safe to stop" means: no upload pending for the instance, and the node's own recent report says
no client session is open while it refuses new ones. `--wait` re-checks every 10 seconds, and
gives up if maintenance is turned off. Parked uploads never drain on their own: run `uploader
resolve` on that node. Before stopping the node, also check its relay queue with `relay stats`
on it. All reads go to the primary database.

---

## 19. health

### health status

Shows the component health that running servers record in the database: an overall status, the
number of healthy, degraded and unhealthy components (for example `database`, `s3_storage` and
circuit breakers), and failures.

| Flag | Default | Meaning |
|---|---|---|
| `--hostname` | all | Only this server. |
| `--component` | all | Only this component. |
| `--detailed` | `false` | Include each component's metadata. |
| `--json` | `false` | Print JSON. |
| `--backends` | `false` | Instead, show the proxies' backend health from the Admin API (`GET /admin/proxy/backends`), which needs `[admin_cli]` and no database. Backends in maintenance are marked. `--json` works with it. |

Health checks and what to alert on are covered in [METRICS.md](METRICS.md).

---

## 20. relay

Reads and edits the disk relay queue of **this host**. The queue holds outgoing redirect and
vacation messages; see [RELAY.md](RELAY.md). The commands work only when `[relay] type` is set,
and use `[relay.queue] path` (default `/var/spool/sora/relay`). Each message is a `<id>.json`
metadata file and a `<id>.msg` body in one of `pending/`, `processing/` or `failed/`.

| Subcommand | Flags | What it does |
|---|---|---|
| `stats` | | Counts messages in each queue. Reports a queue the server has not created yet, and does not create it. |
| `list` | `--queue` (default `pending`), `--limit` (default `100`) | Lists messages: ID, type, sender, recipient, attempts, queued time, next retry. |
| `show` | `--id` (required), `--queue` (default `pending`) | Prints a message's metadata, error history and body. |
| `delete` | `--id` (required; `all` for every message), `--queue` (default `failed`), `--confirm` (required) | Deletes the message files. No undo. |
| `requeue` | `--id` (required; `all` for every failed message), `--confirm` (required) | Moves messages from `failed/` to `pending/`, with attempts reset and errors cleared, ready for the next worker run. |

`--queue` is `pending`, `processing` or `failed`. `--confirm` does not prompt; without it,
`delete` and `requeue` refuse.

**Working next to a running server.** The commands and the server's relay worker take turns on
each message:

- On Linux and macOS, `requeue`, `delete`, the worker and crash recovery each take a lock on the
  message (an advisory lock on the spool's filesystem). A message the worker holds is reported as
  `busy`, however old its files are; try again later.
- `delete --id all` deletes only the messages it can lock. It leaves busy messages, and Sieve
  redirects whose delivery has not finished (`<id>.held`), alone. The count it prints is the
  number of messages it deleted.
- `requeue` records in a journal on disk what it is doing, so a requeue interrupted by a crash is
  either rolled back or completed by the queue's crash recovery (when the worker starts, or when
  the message is next touched). Pairs of `.requeuing-*` files
  that an older build left without a journal are kept and reported, for you to inspect by hand.
- Upgrade every server and every `sora-admin` that uses a spool before you rely on this: older
  binaries ignore the locks. Keep the spool on a filesystem that supports advisory locks and
  directory fsync, and do not edit its files by hand while the worker runs.

Delivery through the relay is at least once: the relay can accept a message just before a crash
stops Sora from recording it as sent, and Sora then sends it again.

---

## 21. tls

Manages the Let's Encrypt certificates that Sora keeps in S3 when `[tls.letsencrypt]` is
configured; see [TLS.md](TLS.md). These commands use the `[tls.letsencrypt.s3]` bucket
settings (endpoint default `s3.amazonaws.com`), not `[s3]`, and need no database. Certificates
are stored under `autocert/` with hashed names; the local mirror is `--cache-dir`, which
defaults to `[tls.letsencrypt] fallback_dir`, or `/var/lib/sora/certs`.

| Subcommand | Flags | What it does |
|---|---|---|
| `list` (or `ls`) | `--cache-dir`, `--details`, `--json` | Lists certificates in S3: domain, type (ECDSA or RSA), expiry, whether this host has a local copy, and the S3 key. `--details` adds issuer, serial and algorithms and shows full keys. |
| `delete` (or `del`, `rm`) | `--domain` or `--key`, `--cache-dir`, `--dry-run` | Deletes a certificate from S3 (see the notes below for the local mirror). No prompt. |
| `clean` | `--cache-dir`, `--dry-run`, `--force` | Deletes expired certificates from S3 and the local mirror, after a `[y/N]` prompt unless `--force`. |
| `cache` (or `sync`) | `--cache-dir`, `--domain`, `--force` | Downloads the certificates of `[tls.letsencrypt] domains` (or only `--domain`) from S3 into the local mirror, both ECDSA and RSA. Expired ones are skipped. Existing files are kept unless `--force`. |

S3 keys are hashes of the certificate names, so `list` names a certificate by matching the key
against the domains in `[tls.letsencrypt] domains`. A certificate of a domain that is no longer
configured is shown by the first 16 characters of its hash.

Before you use `delete` or `clean`, upgrade every Sora server and `sora-admin` that writes the
bucket or a local certificate directory: older binaries ignore the certificate state and can
overwrite a deletion barrier, and nothing detects them for you
([TLS.md](TLS.md#upgrading-from-a-version-without-certificate-state)).

Notes on `delete`:

- Give exactly one of `--domain` and `--key`.
- `--domain` covers both the ECDSA and the RSA certificate of the domain, also one that is not in
  S3 yet (a node may hold a copy it has not stored). It also removes this host's local copies,
  but keeps one that was renewed while the command ran.
- `--key` takes the full S3 key as `tls list --details` shows it (`autocert/cert-...`). An
  abbreviated key, or one ending in `...`, must match exactly one certificate. ACME account keys
  and Sora's own state objects are never selected. `--key` leaves this host's local directory
  alone.
- Both forms put a **deletion barrier** in place of the S3 object: an entry with no certificate
  and no key that stops every node from storing the deleted certificate, or a copy taken before
  the deletion, again. A certificate ordered afterwards is stored as usual
  ([TLS.md](TLS.md#certificate-state-in-s3)). Keep the barriers: do not let a bucket lifecycle
  rule or a restore of old object versions remove them.
- Nodes drop their local copies at their next sync, but keep serving a certificate they hold in
  memory until they restart. A deletion is not a revocation at Let's Encrypt
  ([TLS.md](TLS.md#what-a-deletion-reaches)). To get a new certificate on every node, follow
  [Replacing a certificate](TLS.md#replacing-a-certificate).

Notes on `clean`:

- `clean` replaces an expired certificate with an empty entry, and only if the object is still
  the one it read, so a certificate renewed while it runs is kept. A valid certificate that a
  node renewed while it could not reach S3 can still be stored afterwards.
- On a bucket that keeps object versions (Backblaze B2 buckets always do), `clean` also deletes
  the old versions that hold expired certificates. This needs the right to list and delete
  object versions (`s3:ListBucketVersions` and `s3:DeleteObjectVersion` on AWS). If it fails
  partway, the next `clean` finishes the work.
- In the local directory, `clean` removes only the expired file it read; a valid replacement
  written meanwhile stays.
- A certificate next to a deletion timestamp from an older version cannot be dated, and `clean`
  does not settle it: run `tls delete --domain` for it once every writer is upgraded.

`delete` and `clean` change objects only with conditional requests (`If-Match` with the ETag
they read). A store that returns no ETag, or refuses conditional requests, makes them fail; they
never fall back to an unconditional write.

**Private files in the local directory.** Sora keeps its state, locks and temporary files in the
local certificate directory under names that start with `.sora-`, and never serves them. A local
copy it cannot prove safe behind a deletion barrier is moved to a quarantine there instead of
being served. A quarantined file may hold the only copy of a private key; it never expires, and
neither `delete` nor `clean` removes it. Remove such files yourself once you no longer need them
([TLS.md](TLS.md#the-local-fallback-directory)).

`cache` writes a new certificate with mode `0600` and a replacement with the mode of the file
it replaces. When the directory belongs to another user, as the server's directory does when
you run `cache` as root, each file it writes is given to that user; otherwise a replacement
keeps the owner of the file it replaces. A missing directory is created with mode `0700`, as
the server creates it, and given to the owner of the directory it is created in: for the
default `/var/lib/sora/certs`, the owner of `/var/lib/sora`, the server's user under
`dist/sora.service`. A directory created in a sticky directory such as `/tmp` stays yours.

`cache` counts a certificate that is not in S3 under `Not found` and goes on: a configured
domain may not have been issued yet, and the RSA certificate exists only once a client has
asked for one. With `--domain`, it exits `1` when neither certificate of that domain is in S3,
as `delete --domain` does. A certificate that cannot be downloaded, does not parse, or cannot
be written exits `1` as well; the others are still cached.

---

## 22. config

Checks and prints a config file. These subcommands read only the file.

| Subcommand | Flags | What it does |
|---|---|---|
| `validate` | | Checks the file as `sora` checks it before it starts any service. Exits `1` on errors, `0` otherwise (warnings included). |
| `dump` | `--format` (`toml` or `json`, default `toml`), `--mask-secrets` (default `true`) | Prints the configuration as loaded, with defaults applied. |

`config` reads `--config` itself, after the other commands' loader is skipped, so
`sora-admin config --help` works without a config file, and a file that does not load is
reported by `validate` instead of stopping the tool.

### config validate

`validate` loads the file with the server's loader, which warns about unknown and duplicate keys,
then runs the checks of [CONFIGURATION.md section 4](CONFIGURATION.md#4-checks-at-startup):

- It checks only what this node would run. For example, `[uploader]`, `[cleanup]` and
  `[local_cache]` are checked when the file has a mail backend (`imap`, `lmtp`, `pop3`), and
  `[database]` when some server uses the database.
- It reports every problem it finds, each on a `[FAIL]` line, not only the first.
- It prints, as `[WARN]` lines, the warnings start-up logs about settings that will not do what
  they say on this node: Sieve extensions the engine does not support, broad
  `trusted_networks`, `[[server]]` keys the server type ignores, values start-up cannot parse
  and replaces with the default, and the others listed in section 4.
- When the file is valid it prints `[OK] Configuration is valid!` and the servers.

It connects to nothing and does not look at the node's disk. A clean result does not prove that
the database, S3, the certificate store or a remote lookup can be reached.

`--mask-secrets` masks the database passwords, `[s3]` access key, secret key and encryption key,
the `[tls]` certificate and key paths, the Let's Encrypt S3 keys, `[cluster] secret_key`,
`[admin_cli] api_key`, `[relay] auth_token`, `[spam_training] auth_token`, and the `api_key`,
`jwt_secret`, `master_password`, `master_sasl_password` and remote lookup `auth_token` of each
`[[server]]`.

In every other setting that holds a URL, such as `[relay] http_url`, `[spam_training] endpoint`
or the remote lookup `url`, it masks the userinfo and the value of each query parameter, and keeps
the scheme, host, port, path, fragment and parameter names. The remote lookup `$email` and `$ip`
placeholders are shown. A query component that may be a bare token is masked whole, name
included: one without `=`, and one whose value is empty or only `=` signs, as a base64 token
ending in `=` padding looks like a name with such a value. A URL with userinfo or a query that
does not parse is masked whole. The server's log lines and errors show these endpoints masked the
same way. `--mask-secrets=false` prints every value as configured.

See [CONFIGURATION.md](CONFIGURATION.md) for the file itself.

---

## 23. migrate

Applies and reverts the database schema migrations built into the binary
([db/migrations/](../db/migrations/)). See [DATABASE.md](DATABASE.md) for how migrations fit into
upgrades.

| Subcommand | Flags | What it does |
|---|---|---|
| `up` | | Applies every pending migration. |
| `down` | `--limit N` (default `1`, at least 1), `--all` | Reverts the last N migrations, or with `--all` every migration after 000001. 000001, the initial schema, is never reverted: a `--limit` that reaches it is refused. Refuses a dirty database. No prompt. |
| `version` | | Prints the current version and whether it is dirty. Safe while servers run: a plain read of `schema_migrations`, no lock. |
| `force VERSION` | | Records VERSION as the current version and clears the dirty flag, without running anything. |

- Stop the Sora servers before `up`, `down` and `force`. These three take the migration leader
  lock, and refuse to run while a starting server holds it.
- `down` runs the reverse migrations, which drop tables and columns and the data in them. Take a
  backup first.
- `force` is for a dirty state after a failed migration: fix the schema by hand, then force the
  version that matches it.
- `migrate` connects to the first host of `[database.write] hosts` with `port`, `user`,
  `password`, `name` and `tls`, with the server's port rules: a port in the host entry wins, and
  `port` defaults to `5432`.

---

## 24. version and help

```sh
sora-admin version      # also -v and --version
sora-admin help         # also --help and -h
```

`version` prints `sora-admin version VERSION (commit: COMMIT, built at: DATE)`, set at build
time. Neither needs a config file.

---

## 25. Destructive commands at a glance

| Command | What it removes | Undo | Confirmation |
|---|---|---|---|
| `accounts delete` | Soft-deletes the account. | `accounts restore` within `[cleanup] grace_period`. | `--confirm` flag required. |
| `accounts delete --purge` | The account, its mailboxes, messages, S3 objects, search index, credentials. | None. | `--confirm` flag required. |
| `accounts purge-domain` | Every account with its primary address in the domain, as above, and the domain's remaining aliases. | None. | `--confirm` flag required. |
| `credentials delete` | One alias. | Add it again. | None. |
| `mailbox delete` | The mailbox; its messages after the grace period. | None for the mailbox. | `--confirm` flag required. |
| `mailbox delete --purge` | Expunges the messages at once, then deletes the mailbox. | `messages restore` within the grace period. | `--confirm` flag required. |
| `sieve delete` | One script, also the active one. | None. | None. |
| `acl revoke` | One ACL entry. | `acl grant` again. | None. |
| `verify s3 --fix-orphaned` | S3 objects that no message uses, expunged or not. | None. | None; try `--dry-run` first. |
| `verify s3 --fix-missing` | Sets `uploaded = false` on messages with no object. | None. | None; try `--dry-run` first. |
| `verify body-deletions --reconcile` | Body keys that nothing needs, and the deletion intent. | None. | `--storage-drained` flag required. |
| `import rekey --delete-old-objects` | Old SHA-256-keyed objects that nothing references any more. | None. | None; try `--dry-run` first. |
| `uploader resolve` | `[DELETE]`: message rows whose body is in neither S3 nor the spool. | None. | None; try `--dry-run` first. |
| `cache purge` | The local cache of this host. | Refills from S3. | `(y/N)` prompt unless `--confirm`. |
| `relay delete` | Queued relay messages. | None. | `--confirm` flag required. |
| `tls delete` | A certificate in S3, replaced by a deletion barrier (with `--domain`, also this host's local copy). | Let's Encrypt issues a new one. | None. |
| `tls clean` | Expired certificates. | None needed. | `[y/N]` prompt unless `--force`. |
| `migrate down` | Schema objects and their data. | `migrate up` restores the schema, not the data. | None. |
| `connections kick` | Open sessions (users can log in again). | Not applicable. | `(y/N)` prompt unless `--confirm` or `-y`. |
