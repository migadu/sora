package db

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMetadataServerScope_NoDuplicateRows is a regression test for audit finding H6
// (2026-07-01 IMAP command-correctness audit).
//
// SetMetadata uses `INSERT ... ON CONFLICT (account_id, mailbox_id, entry_name)
// DO UPDATE`. Server-scope entries have mailbox_id = NULL, and the backing
// constraint `metadata_unique_entry UNIQUE(account_id, mailbox_id, entry_name)`
// treats NULLs as distinct on PostgreSQL (default NULLS DISTINCT; PG14 has no
// NULLS NOT DISTINCT option). So ON CONFLICT never fires for server metadata and
// every SET inserts a brand-new row instead of replacing the existing value.
//
// TestMetadataUpdate passes despite this because it only reads a value back via a
// map; this test asserts the physical invariant it misses.
//
// Expected: exactly ONE row per server-scope (account_id, entry_name).
// Actual   (bug): one row per SET (here, 3).
//
// Fix: add a partial unique index `... WHERE mailbox_id IS NULL` (and a matching
// one WHERE mailbox_id IS NOT NULL) and target the right index per scope.
func TestMetadataServerScope_NoDuplicateRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}

	db := setupTestDatabase(t)
	ctx := context.Background()

	accountID := createTestAccount(t, db, "test-serverdup@example.com", "password")
	const entryName = "/private/vendor/duptest"

	set := func(val string) {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		require.NoError(t, db.SetMetadata(ctx, tx, accountID, nil,
			map[string]*[]byte{entryName: bytePtr([]byte(val))}, nil))
		require.NoError(t, tx.Commit(ctx))
	}

	set("first")
	set("second")
	set("third")

	var count int
	err := db.GetReadPool().QueryRow(ctx,
		`SELECT COUNT(*) FROM metadata WHERE account_id = $1 AND mailbox_id IS NULL AND entry_name = $2`,
		accountID, entryName).Scan(&count)
	require.NoError(t, err)

	if count != 1 {
		t.Errorf("REGRESSION: server-scope SETMETADATA created %d physical rows for %q, expected 1. "+
			"UNIQUE(account_id, mailbox_id, entry_name) does not dedupe NULL mailbox_id (NULLS DISTINCT), "+
			"so ON CONFLICT never fires. Add a partial unique index WHERE mailbox_id IS NULL.",
			count, entryName)
	}
}
