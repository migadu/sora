package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestListMessagesForPOP3_Limit verifies the pre-materialization row cap: when a
// positive limit is passed, ListMessagesForPOP3 returns at most that many rows
// (so a huge mailbox is bounded at fetch time instead of being fully materialized
// before the POP3 session-memory charge rejects it); limit <= 0 means unlimited.
func TestListMessagesForPOP3_Limit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}
	db := setupTestDatabase(t)
	ctx := context.Background()
	accountID := createTestAccount(t, db, fmt.Sprintf("test-pop3-limit-%d@example.com", time.Now().UnixNano()), "password")

	// Create INBOX and fetch its ID.
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.CreateMailbox(ctx, tx, accountID, "INBOX", nil))
	require.NoError(t, tx.Commit(ctx))

	mailbox, err := db.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)

	// Insert N messages.
	const total = 5
	mtx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	for i := 1; i <= total; i++ {
		insertTestMessageWithUIDForTrigger(t, db, ctx, mtx, accountID, mailbox.ID, "INBOX", uint32(i), nil)
	}
	require.NoError(t, mtx.Commit(ctx))

	get := func(limit int) int {
		msgs, err := db.ListMessagesForPOP3(ctx, mailbox.ID, limit)
		require.NoError(t, err)
		return len(msgs)
	}

	require.Equal(t, total, get(0), "limit 0 = unlimited")
	require.Equal(t, total, get(-1), "negative limit = unlimited")
	require.Equal(t, total, get(total+10), "limit above count returns all")
	require.Equal(t, 3, get(3), "limit below count truncates the fetch")
	require.Equal(t, 1, get(1), "limit of 1 returns a single row")
}
