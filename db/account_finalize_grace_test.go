package db

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// An account soft-deleted a moment ago must not be eligible for final (irreversible)
// deletion until the cleanup grace period has elapsed, whatever its message count —
// otherwise `accounts restore` cannot undo a mistaken delete of an empty account. And
// an account restored between the scan and the finalize must survive the finalize.
func TestAccountFinalizeHonoursGraceAndRestore(t *testing.T) {
	if testing.Short() {
		t.Skip("database integration test")
	}
	db, accountID, _ := setupMessageTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	var email string
	require.NoError(t, db.GetWritePool().QueryRow(ctx,
		`SELECT address FROM credentials WHERE account_id = $1 AND primary_identity`, accountID).Scan(&email))

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.DeleteAccount(ctx, tx, email))
	require.NoError(t, tx.Commit(ctx))

	contains := func(ids []int64) bool {
		for _, id := range ids {
			if id == accountID {
				return true
			}
		}
		return false
	}

	// Inside the grace period: not a candidate, however empty the account is.
	ids, err := db.GetDanglingAccountsForFinalDeletion(ctx, 100000, time.Now().Add(-14*24*time.Hour))
	require.NoError(t, err)
	require.False(t, contains(ids), "an account soft-deleted seconds ago must wait out the grace period")

	// Past the grace period: a candidate.
	ids, err = db.GetDanglingAccountsForFinalDeletion(ctx, 100000, time.Now().Add(time.Minute))
	require.NoError(t, err)
	require.True(t, contains(ids), "an empty account past the grace period is finalized")

	// Restored between the scan and the finalize: the finalize must leave it alone.
	_, err = db.GetWritePool().Exec(ctx, `UPDATE accounts SET deleted_at = NULL WHERE id = $1`, accountID)
	require.NoError(t, err)
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	n, err := db.FinalizeAccountDeletions(ctx, tx2, []int64{accountID})
	require.NoError(t, err)
	require.NoError(t, tx2.Commit(ctx))
	require.Equal(t, int64(0), n, "a restored account must not be finalized")
	var stillThere bool
	require.NoError(t, db.GetWritePool().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM accounts WHERE id = $1)`, accountID).Scan(&stillThere))
	require.True(t, stillThere)
}
