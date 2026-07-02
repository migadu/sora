package db

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func subNames(t *testing.T, db *Database, ctx context.Context, accountID int64) []string {
	t.Helper()
	names, err := db.GetSubscribedMailboxNames(ctx, accountID)
	require.NoError(t, err)
	sort.Strings(names)
	return names
}

// TestSubscriptions_NameBased exercises the name-based subscription store:
// idempotent + case-insensitive subscribe/unsubscribe, listing, and rename that
// moves both the exact name and its descendants while clearing destination
// collisions.
func TestSubscriptions_NameBased(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}
	db := setupTestDatabase(t)
	ctx := context.Background()
	accountID := createTestAccount(t, db, fmt.Sprintf("test-subs-%d@example.com", time.Now().UnixNano()), "password")

	tx := func(fn func(tx pgx.Tx) error) {
		t.Helper()
		wtx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer wtx.Rollback(ctx)
		require.NoError(t, fn(wtx))
		require.NoError(t, wtx.Commit(ctx))
	}

	// Subscribe some names, including a nonexistent one and a hierarchy.
	tx(func(t2 pgx.Tx) error { return db.Subscribe(ctx, t2, accountID, "Work") })
	tx(func(t2 pgx.Tx) error { return db.Subscribe(ctx, t2, accountID, "Work/Reports") })
	tx(func(t2 pgx.Tx) error { return db.Subscribe(ctx, t2, accountID, "Work/Reports/2026") })
	tx(func(t2 pgx.Tx) error { return db.Subscribe(ctx, t2, accountID, "Ghost") })

	// Idempotent + case-insensitive: re-subscribing "work" must not add a row.
	tx(func(t2 pgx.Tx) error { return db.Subscribe(ctx, t2, accountID, "work") })

	require.Equal(t, []string{"Ghost", "Work", "Work/Reports", "Work/Reports/2026"},
		subNames(t, db, ctx, accountID))

	// Rename Work -> Personal: moves the exact name AND all descendants.
	tx(func(t2 pgx.Tx) error { return db.RenameSubscriptions(ctx, t2, accountID, "Work", "Personal", "/") })
	require.Equal(t, []string{"Ghost", "Personal", "Personal/Reports", "Personal/Reports/2026"},
		subNames(t, db, ctx, accountID))

	// Rename into an occupied destination namespace clears the collision first.
	tx(func(t2 pgx.Tx) error { return db.Subscribe(ctx, t2, accountID, "Personal") }) // no-op, already there
	tx(func(t2 pgx.Tx) error { return db.Subscribe(ctx, t2, accountID, "Ghost/Old") })
	tx(func(t2 pgx.Tx) error { return db.RenameSubscriptions(ctx, t2, accountID, "Personal", "Ghost", "/") })
	// Old "Ghost" + "Ghost/Old" destination entries are dropped, then Personal* moved in.
	require.Equal(t, []string{"Ghost", "Ghost/Reports", "Ghost/Reports/2026"},
		subNames(t, db, ctx, accountID))

	// Unsubscribe is case-insensitive and idempotent.
	tx(func(t2 pgx.Tx) error { return db.Unsubscribe(ctx, t2, accountID, "GHOST") })
	tx(func(t2 pgx.Tx) error { return db.Unsubscribe(ctx, t2, accountID, "GHOST") }) // no-op
	require.Equal(t, []string{"Ghost/Reports", "Ghost/Reports/2026"},
		subNames(t, db, ctx, accountID))
}
