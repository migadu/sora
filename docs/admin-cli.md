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

### `restore`

Restores soft-deleted messages for a user or the entire system. Messages are soft-deleted when expunged and are kept for the duration of the `cleanup.grace_period`.

```bash
# Restore all soft-deleted messages for a specific user
./sora-admin -config ... restore --email user@example.com
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
