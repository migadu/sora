# Sora Shared Mailboxes

A shared mailbox is a folder that several users of the same domain can open, for example a team
inbox. Sora implements sharing with a shared IMAP namespace (RFC 2342) and access control lists,
ACLs (RFC 4314): each shared folder lists who may do what with it. Sharing is supported and
**off by default**. This document covers how to turn it on, how shared folders are named and
created, the rights and the commands that manage them, the same-domain rule, and how sharing
affects flags, delivery, search and storage. It is for operators and for contributors.

## Contents

1. [How sharing works](#1-how-sharing-works)
2. [Turning sharing on](#2-turning-sharing-on)
3. [The shared namespace](#3-the-shared-namespace)
4. [Creating shared mailboxes](#4-creating-shared-mailboxes)
5. [Rights](#5-rights)
6. [Managing access](#6-managing-access)
7. [The same-domain rule and "anyone"](#7-the-same-domain-rule-and-anyone)
8. [What each command needs](#8-what-each-command-needs)
9. [Sharing and the rest of Sora](#9-sharing-and-the-rest-of-sora)
10. [Configuration reference](#10-configuration-reference)
11. [Code map](#11-code-map)

---

## 1. How sharing works

- Every shared mailbox has one **owner**, an account. Its messages are stored under that account.
- It lives in the **shared namespace**: its name starts with a prefix, `Shared/` by default, for
  example `Shared/Sales`. Every user who may see it sees it under that same name.
- Its **ACL** lists identifiers (a user's address, or `anyone`) and the rights each has, such as
  `lrs` (see, read, mark read).
- The owner always holds every right, whatever the ACL says.
- Users can be given rights only on mailboxes in the shared namespace, and only if they are in the
  owner's domain. Personal folders cannot be shared, and there is no "other users" namespace.

```mermaid
flowchart LR
    O[owner@example.com] -- owns, all rights --> M["Shared/Sales"]
    B[bob@example.com] -- "ACL: lrswi" --> M
    A["anyone (example.com)"] -- "ACL: lr" --> M
    X[eve@example.net] -. "refused: other domain" .-> M
```

---

## 2. Turning sharing on

```toml
[shared_mailboxes]
enabled = true
namespace_prefix = "Shared/"
```

Restart Sora after changing this section. A reload (`SIGHUP`) logs
`Config reload: [shared_mailboxes] changed but requires restart to take effect` and changes nothing.

With sharing on:

- `NAMESPACE` lists the prefix as the shared namespace.
- `CREATE` of a name under the prefix makes a shared mailbox (if allowed, see
  [section 4](#4-creating-shared-mailboxes)).
- The rules for the namespace root and for renames apply ([section 3](#3-the-shared-namespace)).

The IMAP `ACL` capability and the ACL commands are always there, whether or not sharing is on.
`MYRIGHTS` and `GETACL` also work on personal folders, where they report the owner with every right.

### Before you turn it on

The prefix is matched without regard to case. Folders users already have under it (`Shared`,
`shared/Old`, ...) fall inside the namespace without being shared. A personal folder named exactly
like the root (`Shared`) can no longer be selected, and personal folders under the prefix can be
renamed out of the namespace but not within it. Count them first (for the default prefix):

```sql
SELECT count(*), count(DISTINCT account_id) FROM mailboxes
 WHERE deleted_at IS NULL AND NOT COALESCE(is_shared, FALSE)
   AND (LOWER(name) = 'shared' OR LOWER(name) LIKE 'shared/%');
```

### Turning it off again

Sora does not remove shared mailboxes or their ACLs when you set `enabled = false`. `NAMESPACE`
stops listing the prefix and new folders under it become personal folders, but existing shared
mailboxes stay visible and usable for the users who have rights on them.

---

## 3. The shared namespace

- The prefix is `namespace_prefix`, default `Shared/`. Sora refuses to start with an empty prefix
  while sharing is on.
- A name is in the namespace when it starts with the prefix, or equals the prefix without its
  trailing `/` (the root, `Shared`). Case does not matter. A folder such as `SharedNotes` is an
  ordinary personal folder.
- **The root is a container.** `CREATE Shared` is refused with
  `NO [CANNOT] Cannot create the shared namespace root directly...`, and `SELECT Shared` with
  `NO [CANNOT] The shared namespace root cannot be selected...`. When the root exists as a parent
  and has children, `LIST` marks it `\Noselect`.
- **Whether a mailbox is shared is fixed when it is created.** `RENAME` cannot move a mailbox into
  or out of the namespace: `NO [CANNOT] Mailboxes cannot be moved into or out of the shared namespace`.
  The one exception is a personal folder that already sat under the prefix: it may be renamed out.
- A shared mailbox's owner domain is the domain of the owner's primary address when the mailbox is
  created.
- Names are unique per owner, so a user can see a folder of their own and a shared folder with the
  same name. Their own folder wins, in `LIST` and in every command.

---

## 4. Creating shared mailboxes

### By an administrator

```sh
sora-admin mailbox create --config /etc/sora/config.toml \
  --email owner@example.com --mailbox "Shared/Sales"
```

The account given with `--email` becomes the owner. This works whatever `allow_user_create` says,
as long as sharing is enabled in the config file you pass. Missing parent folders are created too.
See [ADMIN_CLI.md](ADMIN_CLI.md).

### By users over IMAP

With `allow_user_create = true`, a user can `CREATE Shared/Projects` and becomes its owner.

With `allow_user_create = false` (the default), a user's `CREATE` (or a `RENAME` that would create
a folder) of a new top-level shared folder is refused with
`NO [NOPERM] Only administrators can create shared mailboxes`.

Either way, a user who holds the create right (`k`) on an existing shared folder may create
folders below it. The new folder belongs to the owner of that hierarchy, not to the user who
created it.

### Other paths create personal folders

The User API never creates shared folders; a folder it creates under the prefix is a personal
folder. Sieve `fileinto :create` never creates a folder in the shared namespace.

### The initial ACL

- A new shared folder **under a shared parent** copies the parent's ACL entries at that moment.
  Later changes to the parent do not flow down.
- A new shared folder **with no shared parent** gets one entry: the creator's primary address with
  `default_rights` (default `lrswipkxtea`). Because the creator is also the owner, and the owner
  always holds every right, this entry does not limit anyone. Grant rights to other users
  explicitly.

---

## 5. Rights

| Right | Name | Allows |
|---|---|---|
| `l` | lookup | Seeing the folder in `LIST`. |
| `r` | read | `SELECT`, `EXAMINE`, `STATUS`, `FETCH`, `SEARCH`, `GETMETADATA`; copying messages out. |
| `s` | seen | Setting and clearing `\Seen`, including the implicit `\Seen` a `FETCH` sets. |
| `w` | write | Setting and clearing every flag and keyword except `\Seen` and `\Deleted`; `SETMETADATA` of `/shared` entries. |
| `i` | insert | `APPEND`, `COPY` and `MOVE` into the folder; Sieve `fileinto` into it. |
| `p` | post | Stored and shown, but Sora does not use it: there is no address that delivers into a folder. |
| `k` | create | Creating folders below this one; also needed on the new parent when renaming into it. |
| `x` | delete | `DELETE` and `RENAME` of the folder. |
| `t` | delete messages | Setting and clearing `\Deleted`; with `e`, moving messages out. |
| `e` | expunge | `EXPUNGE`; with `t`, moving messages out. |
| `a` | administer | `GETACL`, `SETACL`, `DELETEACL`, `LISTRIGHTS`. |

- A user's effective rights are their own entry **plus** the `anyone` entry, if they are in the
  owner's domain. `MYRIGHTS` reports that union.
- Sora advertises `RIGHTS=kxte`.
- For older clients written for RFC 2086, `SETACL` accepts the obsolete rights `c` (meaning `k`
  and `x`) and `d` (meaning `t` and `e`), and answers to `GETACL`, `MYRIGHTS` and `LISTRIGHTS`
  include them where they apply.
- There are no negative rights. An identifier that starts with `-` is refused with `BAD`.

---

## 6. Managing access

### Over IMAP

Users manage access with the RFC 4314 commands. All of them except `MYRIGHTS` need the `a` right
on the folder (the owner has it).

```text
a1 SETACL "Shared/Sales" bob@example.com lrswi
a2 SETACL "Shared/Sales" bob@example.com +t
a3 GETACL "Shared/Sales"
a4 LISTRIGHTS "Shared/Sales" bob@example.com
a5 MYRIGHTS "Shared/Sales"
a6 DELETEACL "Shared/Sales" bob@example.com
```

- `SETACL` replaces the identifier's rights, or adds (`+`) or removes (`-`) the given ones.
- `DELETEACL` removes the entry. Removing an entry that is not there succeeds.
- The identifier may be any address of the user, an alias included. Sora stores the entry under
  the user's primary address, and `GETACL` lists it that way, so one user always has one entry.
- `GETACL` lists every entry and the owner, with every right.
- `LISTRIGHTS` for the owner reports every right as always granted. For anyone else who can be
  granted rights, it offers each right separately. It offers nothing for a user who cannot be
  granted rights (another domain, or `anyone` while it is disabled).
- A user with the `a` right can manage the ACL like the owner, including taking rights away from
  their own entry, `a` included. A user without `a` cannot change any entry, not even their own.

Answers that refuse a change:

| Situation | Answer |
|---|---|
| The folder is not in the shared namespace | `NO [CANNOT] Only mailboxes in the shared namespace can be shared` |
| The user is in another domain | `NO [CANNOT] Mailboxes can only be shared with users in the same domain` |
| The identifier is the owner | `NO [CANNOT] The mailbox owner always holds every right` |
| `anyone` while `allow_anyone_identifier = false` | `NO [CANNOT] Sharing with "anyone" is disabled on this server` |
| No such user in the owner's domain | `NO [NONEXISTENT] user '...' does not exist` |
| No such folder | `NO [NONEXISTENT] mailbox '...' does not exist` |
| The caller lacks `a` | `NO [NOPERM] You do not have permission to modify ACL for this mailbox` |
| An unknown right letter | `BAD [CLIENTBUG] The <x> right is not supported` |
| An uppercase right letter | `BAD [CLIENTBUG] Uppercase rights are not allowed` |
| An empty identifier, or one with control characters or a leading `-` | `BAD [CLIENTBUG] Invalid ACL identifier` |

Taking rights away always works, even from a user who could no longer be granted them (deleted, or
moved to another domain).

### With `sora-admin`

```sh
sora-admin acl grant --config /etc/sora/config.toml \
  --email owner@example.com --mailbox "Shared/Sales" --user bob@example.com --rights lrs
sora-admin acl list --config /etc/sora/config.toml \
  --email owner@example.com --mailbox "Shared/Sales"
sora-admin acl revoke --config /etc/sora/config.toml \
  --email owner@example.com --mailbox "Shared/Sales" --user bob@example.com
```

`--email` is the owner. `--identifier` and `--user` are the same flag; use `--identifier anyone`
for the domain-wide entry. `grant` replaces the user's rights. `revoke` fails when there is no
such entry. See [ADMIN_CLI.md](ADMIN_CLI.md).

### With the Admin API

| Request | Body or query | Effect |
|---|---|---|
| `POST /admin/mailboxes/acl/grant` | `{"owner": "...", "mailbox": "...", "identifier": "...", "rights": "..."}` | Replaces the identifier's rights. |
| `POST /admin/mailboxes/acl/revoke` | `{"owner": "...", "mailbox": "...", "identifier": "..."}` | Removes the entry. Succeeds when there is none. |
| `GET /admin/mailboxes/acl` | `?owner=...&mailbox=...` | `{"mailbox": "...", "owner": "...", "acls": [{"identifier": "...", "rights": "..."}]}` |

A refused change answers `400`; an owner, folder or user that does not exist answers `404`. Details
and authentication are in [ADMIN_API.md](ADMIN_API.md).

The admin tools follow the same rules as IMAP: shared namespace only, same domain, and the
`anyone` setting. They read that setting from the `[shared_mailboxes]` section of the config they
run with, whether or not that section has `enabled = true`.

---

## 7. The same-domain rule and "anyone"

Sharing never crosses domains:

- A user can be granted rights only if the domain of their **primary** address is the folder's
  owner domain. An alias in the owner's domain is not enough when the primary address is
  elsewhere.
- Sora checks the domain written in the identifier before it looks the address up, so a refusal
  never tells whether an address in another domain exists.

`anyone` is the RFC 4314 identifier for "every user". In Sora it means every user whose primary
address is in the owner's domain. Use it for folders the whole domain should see.

Granting rights to `anyone` needs `allow_anyone_identifier = true` (default `false`). With it off,
`SETACL ... anyone` is refused, the Admin API answers `400`, and `LISTRIGHTS` offers nothing for
`anyone`. Grants made while it was on keep working until you reduce or remove them, which is
always allowed.

---

## 8. What each command needs

| Command | Rights needed |
|---|---|
| `LIST` shows the folder | `l` |
| `SELECT`, `EXAMINE`, `STATUS` (also `LIST ... RETURN (STATUS)`) | `r` |
| `FETCH` that sets `\Seen` implicitly | `r`, and `s` for the flag to be set; without `s` the message stays unread |
| `STORE` | `s` for `\Seen`, `t` for `\Deleted`, `w` for every other flag. Flags the user may not change are left alone; the command fails only if none of the named flags may be changed. |
| `APPEND` into the folder | `i` |
| `COPY` into the folder | `i`. Flags the user could not set themselves are not copied. |
| `MOVE` | `i` on the destination, `t` and `e` on the source |
| `EXPUNGE` | `e` |
| `CREATE` below the folder | `k` on the nearest existing ancestor |
| `DELETE` | `x` |
| `RENAME` | `x` on the folder, `k` on the new parent |
| `GETMETADATA` | `r` |
| `SETMETADATA` | `w` for `/shared` entries, `l` for `/private` entries |
| `GETACL`, `SETACL`, `DELETEACL`, `LISTRIGHTS` | `a` |
| `MYRIGHTS` | none |

`SELECT` opens the folder read-only when the user holds none of `i`, `e`, `s`, `t` and `w`.
`PERMANENTFLAGS` lists only the flags the user may change.

---

## 9. Sharing and the rest of Sora

### Flags are shared

Sora stores flags once per message, not once per user. When one user reads a message in a shared
folder, it is read for everyone; the same goes for `\Flagged`, `\Deleted` and keywords. The `s`,
`t` and `w` rights decide who may change them.

### Storage and statistics

A message in a shared folder belongs to the folder's owner. Its body is stored in S3 under the
owner's account, whoever appended, copied, moved or filed it there. It counts in the owner's
message counts, as shown by `sora-admin` and the Admin API. Sora has no storage quota to enforce.

When the owner's account is deleted and purged, the shared folders it owns are deleted with it,
messages included. Give shared folders an owner account that outlives any one person. Account
deletion is described in [STORAGE.md](STORAGE.md).

### Delivery and Sieve

A shared folder has no address of its own; LMTP always delivers to a user's account. A user's Sieve
script can file into a shared folder with `fileinto "Shared/Sales"` if the user has the `i` right.
Without it, the message goes to the user's own INBOX and Sora logs
`fileinto denied: no insert right on shared mailbox, delivering to INBOX`. `fileinto :create` with
an existing shared folder's name files into that folder, exactly as without `:create`
([SIEVE.md](SIEVE.md#5-what-each-action-does)).

### Search

Search in a shared folder works as in any folder for a user with `r`. Body search uses the owner's
full-text index, because the messages are the owner's. See [SEARCH.md](SEARCH.md).

### Spam training

Spam training follows the `\Junk` and `\Trash` special-use attributes, not folder names, so moves
into a shared folder such as `Shared/Junk` are not reported unless it carries `\Junk`
([RELAY.md](RELAY.md#7-spam-training)).

---

## 10. Configuration reference

### `[shared_mailboxes]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | Turns sharing on. |
| `namespace_prefix` | string | `"Shared/"` | The prefix of the shared namespace: `Shared/` covers the root `Shared` and the names under `Shared/`. Must not be empty while sharing is on. |
| `allow_user_create` | bool | `false` | Lets users create top-level shared folders over IMAP. Off: only `sora-admin mailbox create` can. |
| `allow_anyone_identifier` | bool | `false` | Lets rights be granted to `anyone` (every user of the owner's domain). |
| `default_rights` | string | `"lrswipkxtea"` | Rights stored as the creator's entry on a new top-level shared folder. Has no practical effect, since the creator is the owner ([section 4](#4-creating-shared-mailboxes)). |

All keys are read at startup. Sora checks `namespace_prefix` at startup; it does not validate
`default_rights`.

```toml
[shared_mailboxes]
enabled = true
namespace_prefix = "Shared/"
allow_user_create = false
allow_anyone_identifier = false
```

---

## 11. Code map

| What | Where |
|---|---|
| `[shared_mailboxes]` and the namespace test (`InNamespace`) | [config/config.go](../config/config.go) |
| ACL storage, grant and revoke rules, the same-domain checks | [db/acl.go](../db/acl.go) |
| The `has_mailbox_right` SQL function | [db/migrations/000001_initial_schema.up.sql](../db/migrations/000001_initial_schema.up.sql) |
| Creating shared folders, ACL inheritance, `default_rights` | [db/mailbox.go](../db/mailbox.go) (`CreateMailbox`) |
| Which folders a user sees | [db/mailbox.go](../db/mailbox.go) (`GetMailboxes`, `GetMailboxByName`) |
| IMAP ACL commands | [server/imap/cmd_acl.go](../server/imap/cmd_acl.go) |
| Per-flag right checks | [server/imap/acl_flags.go](../server/imap/acl_flags.go) |
| `NAMESPACE`, `CREATE`, `RENAME`, `SELECT` rules | [server/imap/namespaces.go](../server/imap/namespaces.go), [server/imap/create.go](../server/imap/create.go), [server/imap/rename.go](../server/imap/rename.go), [server/imap/select.go](../server/imap/select.go) |
| The ACL service used by `sora-admin` and the Admin API | [server/aclservice/service.go](../server/aclservice/service.go) |
| `sora-admin acl` | [cmd/sora-admin/acl.go](../cmd/sora-admin/acl.go) |
| Admin API endpoints | [server/adminapi/acl.go](../server/adminapi/acl.go) |
| Delivery into shared folders | [server/lmtp/session.go](../server/lmtp/session.go) (`saveMessageToMailbox`), [server/delivery/delivery.go](../server/delivery/delivery.go) (`resolveOwnedTarget`) |
