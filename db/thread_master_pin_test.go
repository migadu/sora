package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/require"
)

func TestThreadHonoursMasterDBPin(t *testing.T) {
	if testing.Short() {
		t.Skip("requires PostgreSQL")
	}
	master := setupTestDatabase(t)
	defer master.Close()
	ctx := context.Background()
	tx, err := master.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	accountID, err := master.CreateAccount(ctx, tx, CreateAccountRequest{
		Email:    fmt.Sprintf("thread_pin_%d@example.com", time.Now().UnixNano()),
		Password: "password", IsPrimary: true, HashType: "bcrypt",
	})
	require.NoError(t, err)
	require.NoError(t, master.CreateMailbox(ctx, tx, accountID, "INBOX", nil))
	require.NoError(t, tx.Commit(ctx))
	mailbox, err := master.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)

	schema := fmt.Sprintf("thread_pin_replica_%d", time.Now().UnixNano())
	_, err = master.GetWritePool().Exec(ctx, "CREATE SCHEMA "+schema)
	require.NoError(t, err)
	defer master.GetWritePool().Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
	for _, table := range []string{"messages", "message_state"} {
		_, err = master.GetWritePool().Exec(ctx, fmt.Sprintf("CREATE TABLE %s.%s AS SELECT * FROM public.%s WHERE false", schema, table, table))
		require.NoError(t, err)
	}
	replica := newLaggingReplicaPool(t, ctx, schema)
	defer replica.Close()
	split := &Database{WritePool: master.GetWritePool(), ReadPool: replica}
	tx, err = master.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	insertTestMessageWithUIDForPoll(t, master, ctx, tx, accountID, mailbox.ID, "INBOX", 101, nil)
	require.NoError(t, tx.Commit(ctx))

	unpinned, err := split.GetMessagesForThreading(ctx, mailbox.ID, accountID, &imap.SearchCriteria{}, true, false, 10)
	require.NoError(t, err)
	require.Empty(t, unpinned, "control: replica must lag")
	pinnedCtx := context.WithValue(ctx, consts.UseMasterDBKey, true)
	pinned, err := split.GetMessagesForThreading(pinnedCtx, mailbox.ID, accountID, &imap.SearchCriteria{}, true, false, 10)
	require.NoError(t, err)
	require.Len(t, pinned, 1, "THREAD must read its own writes when pinned to master")
	require.Equal(t, imap.UID(101), pinned[0].UID)
}
