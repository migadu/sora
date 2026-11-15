package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateMailbox_DuplicateNameKeepsTransactionUsable: a name that is taken is
// reported as consts.ErrDBUniqueViolation without aborting the caller's
// transaction, so a caller that tolerates the duplicate can read the existing
// mailbox back and go on in the same transaction (issue #1396).
func TestCreateMailbox_DuplicateNameKeepsTransactionUsable(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()
	accountID := createTestAccount(t, db, fmt.Sprintf("create-dup-tx-%d@example.com", time.Now().UnixNano()), "password123")
	require.NoError(t, db.CreateMailboxForUser(ctx, accountID, "Alpha"))

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(context.Background())

	// Names are case-insensitive, so a case variant is the same name.
	err = db.CreateMailbox(ctx, tx, accountID, "ALPHA", nil)
	require.ErrorIs(t, err, consts.ErrDBUniqueViolation)

	var id int64
	err = tx.QueryRow(ctx, `SELECT id FROM mailboxes WHERE account_id = $1 AND LOWER(name) = 'alpha' AND deleted_at IS NULL`, accountID).Scan(&id)
	require.NoError(t, err, "the transaction must still be usable after a duplicate name")
	require.NoError(t, db.CreateMailbox(ctx, tx, accountID, "Alpha/Beta", &id))
	require.NoError(t, tx.Commit(ctx))

	child, err := db.GetMailboxByName(ctx, accountID, "Alpha/Beta")
	require.NoError(t, err)
	assert.Equal(t, "Alpha/Beta", child.Name)
	assertMailboxTreeConsistent(t, db, accountID)
}

// TestCreateMailboxForUser_ParentCreatedConcurrently is issue #1396: a missing
// ancestor that another transaction creates while CreateMailboxForUser creates it
// too must be read back and used as the parent, not fail the call with
// "current transaction is aborted" (SQLSTATE 25P02).
func TestCreateMailboxForUser_ParentCreatedConcurrently(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()
	accountID := createTestAccount(t, db, fmt.Sprintf("create-parent-race-%d@example.com", time.Now().UnixNano()), "password123")

	// The other creator of "Alpha", done but not committed.
	txOther, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer txOther.Rollback(context.Background())
	otherPID := backendPID(t, txOther)
	require.NoError(t, db.CreateMailbox(ctx, txOther, accountID, "Alpha", nil))

	// Its lookup of "Alpha" sees nothing, so it inserts "Alpha" too and waits on
	// the unique index for the other transaction.
	done := make(chan error, 1)
	go func() { done <- db.CreateMailboxForUser(ctx, accountID, "Alpha/Beta") }()
	finished, result := blockedOrDone(t, db, otherPID, done)
	require.False(t, finished, "CreateMailboxForUser did not wait for the other creator of Alpha: %v", result)

	require.NoError(t, txOther.Commit(ctx))
	select {
	case err = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("CreateMailboxForUser did not return after the other creator committed")
	}
	require.NoError(t, err, "a parent created concurrently must be read back and used")

	alpha, err := db.GetMailboxByName(ctx, accountID, "Alpha")
	require.NoError(t, err)
	assert.True(t, alpha.HasChildren, "Alpha/Beta must be linked below the other transaction's Alpha")
	_, err = db.GetMailboxByName(ctx, accountID, "Alpha/Beta")
	require.NoError(t, err)
	assertMailboxTreeConsistent(t, db, accountID)
}
