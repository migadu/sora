package db

import (
	"context"
	"errors"
	"io/fs"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMetadataScopeRootEntriesDroppedOnUpgrade covers METADATA rows stored
// under the scope roots /private/ and /shared/ before IMAP refused them. RFC 5464
// §3.2: an entry name "MUST NOT end with a "/" character", and "Invalid entry
// names result in a BAD response in any IMAP command in which they are used", so
// no command can read or delete such a row any more, yet it counted toward the
// account's entry and size limits.
//
// The schema of 000064 holds the rows as an older binary stored them, and
// NewDatabaseFromConfig then runs the pending migrations through Sora's own
// migration driver, as a starting server does. Only the scope-root rows may go,
// in either scope, and the limits must count only the entries a client can name.
//
// Runs against the dedicated migration test database (see migrationTestDBName).
func TestMetadataScopeRootEntriesDroppedOnUpgrade(t *testing.T) {
	skipDatabaseTestInShortMode(t)
	ctx := context.Background()

	old, err := NewDatabaseFromConfig(ctx, makeTestDBConfig(t), false)
	require.NoError(t, err)
	_, err = old.WritePool.Exec(ctx, "DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
	old.Close()
	require.NoError(t, err)
	migrations, err := fs.Sub(MigrationsFS, "migrations")
	require.NoError(t, err)
	source, err := iofs.New(migrations, ".")
	require.NoError(t, err)
	m, err := migrate.NewWithSourceInstance("iofs", source, migrationTestConnStr(t))
	require.NoError(t, err)
	require.NoError(t, m.Migrate(64))
	srcErr, dbErr := m.Close()
	require.NoError(t, errors.Join(srcErr, dbErr))

	// What an older binary stored for SETMETADATA "" (/private/ "x"),
	// SETMETADATA "" (/shared/ "yy") and SETMETADATA INBOX (/shared/ "m"), next
	// to one valid entry in each scope.
	old, err = NewDatabaseFromConfig(ctx, makeTestDBConfig(t), false)
	require.NoError(t, err)
	var accountID, inboxID int64
	require.NoError(t, old.WritePool.QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING id`).Scan(&accountID))
	require.NoError(t, old.WritePool.QueryRow(ctx, `INSERT INTO mailboxes (account_id, name, uid_validity, subscribed, path)
		VALUES ($1, 'INBOX', 1, true, '') RETURNING id`, accountID).Scan(&inboxID))
	_, err = old.WritePool.Exec(ctx, `INSERT INTO metadata (account_id, mailbox_id, entry_name, entry_value) VALUES
		($1, NULL, '/private/', 'x'),
		($1, NULL, '/shared/', 'yy'),
		($1, NULL, '/private/other', 'o'),
		($1, $2, '/shared/', 'm'),
		($1, $2, '/private/comment', 'c')`, accountID, inboxID)
	old.Close()
	require.NoError(t, err)

	database, err := NewDatabaseFromConfig(ctx, makeTestDBConfig(t), true)
	require.NoError(t, err)
	t.Cleanup(database.Close)
	tx, err := database.WritePool.Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	stored := func() []string {
		rows, err := tx.Query(ctx, `SELECT (CASE WHEN mailbox_id IS NULL THEN 'server ' ELSE 'INBOX ' END) || entry_name
			FROM metadata WHERE account_id = $1`, accountID)
		require.NoError(t, err)
		names, err := pgx.CollectRows(rows, pgx.RowTo[string])
		require.NoError(t, err)
		return names
	}
	assert.ElementsMatch(t, []string{"server /private/other", "INBOX /private/comment"}, stored(),
		"no row may stay stored under a scope root, which no command can name")

	// The issue's step 4: one server entry a client can name, at
	// max_entries_per_server = 2, leaves room for one more.
	assert.NoError(t, database.SetMetadata(ctx, tx, accountID, nil,
		map[string]*[]byte{"/private/new": bytePtr([]byte("y"))}, &MetadataLimits{MaxEntriesPerServer: 2}),
		"an entry no command can name must not take an entry slot")

	// The values a client can name total 3 bytes (o, c, y): growing one of them
	// by a byte fits max_total_size = 4.
	assert.NoError(t, database.SetMetadata(ctx, tx, accountID, nil,
		map[string]*[]byte{"/private/other": bytePtr([]byte("oo"))}, &MetadataLimits{MaxTotalSize: 4}),
		"a value no command can name must not count toward max_total_size")
}
