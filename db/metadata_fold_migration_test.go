package db

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/require"
)

// TestMetadataFoldEntryNamesMigration covers METADATA rows stored before IMAP
// folded entry names to lower case. The server now folds every name before it
// reads or writes, and entry_name compares case-sensitively, so a row such as
// /private/Comment could not be read or deleted any more but still counted toward
// the limits. The migration folds the stored names and, where two rows of one
// account and scope fold to the same name, keeps the most recently updated one.
//
// It runs the migration on a copy of the metadata table in its own schema, so
// the rows of other tests are not touched.
func TestMetadataFoldEntryNamesMigration(t *testing.T) {
	if testing.Short() {
		t.Skip("requires PostgreSQL")
	}
	database := setupTestDatabase(t)
	t.Cleanup(database.Close)
	ctx := context.Background()

	files, err := filepath.Glob("migrations/*_metadata_fold_entry_names.up.sql")
	require.NoError(t, err)
	require.Len(t, files, 1, "no migration folds the stored METADATA entry names")
	up, err := os.ReadFile(files[0])
	require.NoError(t, err)

	conn, err := database.GetWritePool().Acquire(ctx)
	require.NoError(t, err)
	schema := fmt.Sprintf("metadata_fold_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{schema}.Sanitize()
	t.Cleanup(func() {
		_, _ = conn.Exec(ctx, "RESET search_path")
		_, _ = conn.Exec(ctx, "DROP SCHEMA IF EXISTS "+quoted+" CASCADE")
		conn.Release()
	})
	// The copy keeps the unique constraint and the server-scope partial unique
	// index, which the folded names must satisfy, and drops the foreign keys.
	_, err = conn.Exec(ctx, "CREATE SCHEMA "+quoted)
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "CREATE TABLE "+quoted+".metadata (LIKE metadata INCLUDING ALL)")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SET search_path = "+quoted)
	require.NoError(t, err)

	const (
		acctA = int64(9_124_000_001)
		acctB = int64(9_124_000_002)
		mbx1  = int64(9_124_000_101)
		mbx2  = int64(9_124_000_102)
	)
	now := time.Now().UTC().Truncate(time.Microsecond)
	newer, older, oldest := now.Add(-time.Hour), now.Add(-2*time.Hour), now.Add(-3*time.Hour)

	type row struct {
		account int64
		mailbox *int64
		name    string
		value   string
		updated time.Time
	}
	m1, m2 := mbx1, mbx2
	rows := []row{
		// No folded twin: renamed in place.
		{acctA, nil, "/private/Comment", "only", older},
		// Twin is newer: the lower-case row stays.
		{acctA, nil, "/private/Vendor/Example/Theme", "old-upper", older},
		{acctA, nil, "/private/vendor/example/theme", "new-lower", newer},
		// Upper-case row is the newest of three: it stays, under the folded name.
		{acctA, nil, "/shared/Admin", "new-upper", newer},
		{acctA, nil, "/shared/admin", "old-lower", older},
		{acctA, nil, "/shared/ADMIN", "oldest-upper", oldest},
		// Same updated_at: the row inserted last (highest id) stays.
		{acctA, nil, "/private/Tie", "first", older},
		{acctA, nil, "/private/TIE", "second", older},
		// Already folded: untouched.
		{acctA, nil, "/private/untouched", "same", older},
		// Mailbox scope folds per mailbox, apart from server scope and each other.
		{acctA, &m1, "/private/Comment", "mbx1", older},
		{acctA, &m2, "/private/comment", "mbx2-lower", newer},
		{acctA, &m2, "/private/Comment", "mbx2-upper", older},
		// Another account's row of the same name is its own.
		{acctB, nil, "/private/Comment", "b", newer},
	}
	for _, r := range rows {
		_, err := conn.Exec(ctx, `INSERT INTO metadata (account_id, mailbox_id, entry_name, entry_value, updated_at)
			VALUES ($1, $2, $3, $4, $5)`, r.account, r.mailbox, r.name, []byte(r.value), r.updated)
		require.NoError(t, err)
	}

	_, err = conn.Exec(ctx, string(up))
	require.NoError(t, err)

	stored := func(t *testing.T) map[string]string {
		t.Helper()
		got := map[string]string{}
		res, err := conn.Query(ctx, `SELECT account_id, COALESCE(mailbox_id, 0), entry_name, entry_value, updated_at FROM metadata`)
		require.NoError(t, err)
		defer res.Close()
		for res.Next() {
			var account, mailbox int64
			var name string
			var value []byte
			var updated time.Time
			require.NoError(t, res.Scan(&account, &mailbox, &name, &value, &updated))
			got[fmt.Sprintf("%d|%d|%s", account, mailbox, name)] = fmt.Sprintf("%s@%s", value, updated.UTC().Format(time.RFC3339Nano))
		}
		require.NoError(t, res.Err())
		return got
	}
	at := func(value string, updated time.Time) string {
		return value + "@" + updated.Format(time.RFC3339Nano)
	}
	key := func(account, mailbox int64, name string) string {
		return fmt.Sprintf("%d|%d|%s", account, mailbox, name)
	}
	want := map[string]string{
		key(acctA, 0, "/private/comment"):              at("only", older),
		key(acctA, 0, "/private/vendor/example/theme"): at("new-lower", newer),
		key(acctA, 0, "/shared/admin"):                 at("new-upper", newer),
		key(acctA, 0, "/private/tie"):                  at("second", older),
		key(acctA, 0, "/private/untouched"):            at("same", older),
		key(acctA, mbx1, "/private/comment"):           at("mbx1", older),
		key(acctA, mbx2, "/private/comment"):           at("mbx2-lower", newer),
		key(acctB, 0, "/private/comment"):              at("b", newer),
	}
	require.Equal(t, want, stored(t), "stored names must be folded, one row per folded name and scope, updated_at kept")

	// Running it again changes nothing (an operator may have run it by hand).
	_, err = conn.Exec(ctx, string(up))
	require.NoError(t, err)
	require.Equal(t, want, stored(t))

	// The issue's steps, through the db layer the IMAP commands use.
	tx, err := conn.Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	got, err := database.GetMetadata(ctx, tx, acctA, nil, []string{"/private/comment"}, nil)
	require.NoError(t, err)
	require.Contains(t, got.Entries, "/private/comment")
	require.Equal(t, "only", string(*got.Entries["/private/comment"]))

	got, err = database.GetMetadata(ctx, tx, acctA, nil, []string{"/private"}, &imap.GetMetadataOptions{Depth: imap.GetMetadataDepthInfinity})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"/private/comment", "/private/vendor/example/theme", "/private/tie", "/private/untouched"}, keysOf(got.Entries))

	// Account A has 5 server entries; writing one of them at a limit of 5 is an
	// overwrite, not a new entry, so it is not TOOMANY.
	limits := &MetadataLimits{MaxEntriesPerServer: 5}
	require.NoError(t, database.SetMetadata(ctx, tx, acctA, nil, map[string]*[]byte{"/private/comment": bytePtr([]byte("y"))}, limits))
	var count int
	require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM metadata WHERE account_id = $1 AND mailbox_id IS NULL`, acctA).Scan(&count))
	require.Equal(t, 5, count)

	// Deleting it removes the only row of that name.
	require.NoError(t, database.SetMetadata(ctx, tx, acctA, nil, map[string]*[]byte{"/private/comment": nil}, limits))
	require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM metadata WHERE account_id = $1 AND mailbox_id IS NULL
		AND lower(entry_name) = '/private/comment'`, acctA).Scan(&count))
	require.Zero(t, count)
}

func keysOf(m map[string]*[]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
