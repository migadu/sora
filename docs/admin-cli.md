# Admin CLI (`sora-admin`)

`sora-admin` is a powerful command-line tool for managing your Sora instance. It connects to the same database and uses the same configuration file as the main `sora` server.

All commands require the `-config` flag to specify the path to your `config.toml` file.

```bash
./sora-admin -config /path/to/config.toml <command> [arguments]
```

## Common Commands

### `migrate`

Manages database schema migrations. This is essential for initial setup and for upgrades.

```bash
# Apply all pending migrations
./sora-admin -config ... migrate up

# Roll back the last migration
./sora-admin -config ... migrate down

# Check the current migration status
./sora-admin -config ... migrate status
```

### `account`

Manages user accounts.

```bash
# Create a new account
./sora-admin -config ... account create <email>

# Delete an account
./sora-admin -config ... account delete <email>
```

### `credential`

Manages user credentials.

```bash
# Set a password for an account (will prompt for password)
./sora-admin -config ... credential set <email>

# You can specify the password hashing scheme (defaults to bcrypt)
./sora-admin -config ... credential set <email> --scheme SSHA512
```

### `import-maildir` and `export-maildir`

Tools for migrating mail data to and from the standard Maildir format. This is extremely useful for migrating from other mail systems like Dovecot or Courier.

```bash
# Import mail for a user from a Maildir path
./sora-admin -config ... import-maildir --email user@example.com --path /path/to/maildir

# Export a user's mail to a Maildir path
./sora-admin -config ... export-maildir --email user@example.com --path /path/to/export
```

### `import rekey`

Older versions of the maildir importer stored message bodies under their SHA-256 digest, where every other path uses the BLAKE3 digest. That mail reads fine, but `verify s3 --deep` and `verify hash` flag it (as stored under its SHA-256 digest), it never deduplicates with other copies, and a non-incremental re-import adds every message again. `import rekey` downloads each of an account's bodies and moves every SHA-256-keyed one to its BLAKE3 key: it writes the object under the new key, moves the message and full-text search rows, and deletes the old object once nothing references it. It is idempotent and can be resumed with `--start-after`.

```bash
# Report what would change
./sora-admin -config ... import rekey --email user@example.com --dry-run

# Re-key the account's bodies
./sora-admin -config ... import rekey --email user@example.com
```

### `restore`

Restores soft-deleted messages for a user or the entire system. Messages are soft-deleted when expunged and are kept for the duration of the `cleanup.grace_period`.

```bash
# Restore all soft-deleted messages for a specific user
./sora-admin -config ... restore --email user@example.com
```

### `backends`

Puts a backend in maintenance: proxies stop sending it new traffic while it finishes its own uploads, after which it is safe to stop. After `[backend_maintenance] refuse_after` (default 30s) the backend also refuses new sessions itself, however they reach it. `--wait` returns once the backend has nothing pending and reports that it refuses new client sessions and has none left (IMAP or POP3 logged in, LMTP transaction, Admin API delivery). See [Taking a backend out of service](deployment.md#taking-a-backend-out-of-service).

```bash
./sora-admin -config ... backends maintenance on --host storage2.example.com --reason "disk swap" --wait
./sora-admin -config ... backends status
./sora-admin -config ... backends maintenance off --host storage2.example.com
```

### `health-status`

Checks the health of the system's components (Database, S3) and reports the status.

```bash
./sora-admin -config ... health-status
```

### `config dump`

Dumps the fully resolved configuration, including defaults and environment variable overrides, to standard output. This is useful for debugging configuration issues.

```bash
./sora-admin -config ... config dump
```
