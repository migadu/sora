package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReadHelpersHonorMasterDBPin covers read helpers whose callers pass a
// master-pinned context (SELECT, poll and ManageSieve after a write). Each one
// must read from the write pool when the context carries consts.UseMasterDBKey.
// The read pool is a lagging replica (see newLaggingReplicaPool) that has none
// of the rows the master holds.
func TestReadHelpersHonorMasterDBPin(t *testing.T) {
	if testing.Short() {
		t.Skip("requires PostgreSQL")
	}
	master := setupTestDatabase(t)
	t.Cleanup(master.Close)
	ctx := context.Background()
	accountID, mailboxID := setupAccountWithInbox(t, master, ctx, fmt.Sprintf("readpin%d@example.com", time.Now().UnixNano()))

	tx, err := master.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	insertTestMessageWithUIDForPoll(t, master, ctx, tx, accountID, mailboxID, "INBOX", 101, []imap.Flag{"PinKeyword"})
	script, err := master.CreateScript(ctx, tx, accountID, "pinned", "keep;")
	require.NoError(t, err)
	require.NoError(t, master.SetScriptActive(ctx, tx, script.ID, accountID, true))
	require.NoError(t, tx.Commit(ctx))

	// lagging returns a database whose read pool sees empty copies of the given tables.
	lagging := func(t *testing.T, emptyTables ...string) *Database {
		t.Helper()
		schema := fmt.Sprintf("read_pin_replica_%d", time.Now().UnixNano())
		_, err := master.GetWritePool().Exec(ctx, "CREATE SCHEMA "+schema)
		require.NoError(t, err)
		t.Cleanup(func() { _, _ = master.GetWritePool().Exec(ctx, "DROP SCHEMA "+schema+" CASCADE") })
		for _, table := range emptyTables {
			_, err := master.GetWritePool().Exec(ctx, fmt.Sprintf("CREATE TABLE %s.%s AS SELECT * FROM public.%s WHERE false", schema, table, table))
			require.NoError(t, err)
		}
		replica := newLaggingReplicaPool(t, ctx, schema)
		t.Cleanup(replica.Close)
		return &Database{WritePool: master.GetWritePool(), ReadPool: replica}
	}
	pinned := context.WithValue(ctx, consts.UseMasterDBKey, true)

	t.Run("CountMessagesGreaterThanUID", func(t *testing.T) {
		split := lagging(t, "messages")
		stale, err := split.CountMessagesGreaterThanUID(ctx, mailboxID, 0)
		require.NoError(t, err)
		require.Zero(t, stale, "control: replica must lag")
		got, err := split.CountMessagesGreaterThanUID(pinned, mailboxID, 0)
		require.NoError(t, err)
		assert.Equal(t, uint32(1), got)
	})

	t.Run("GetUniqueCustomFlagsForMailbox cache", func(t *testing.T) {
		split := lagging(t, "mailbox_stats")
		stale, err := split.GetUniqueCustomFlagsForMailbox(ctx, mailboxID)
		require.NoError(t, err)
		require.Empty(t, stale, "control: replica must lag")
		got, err := split.GetUniqueCustomFlagsForMailbox(pinned, mailboxID)
		require.NoError(t, err)
		assert.Equal(t, []string{"PinKeyword"}, got)
	})

	t.Run("GetUniqueCustomFlagsForMailbox full scan", func(t *testing.T) {
		// A NULL cache sends the helper to its full scan of message_state.
		_, err := master.GetWritePool().Exec(ctx, "UPDATE mailbox_stats SET custom_flags_cache = NULL WHERE mailbox_id = $1", mailboxID)
		require.NoError(t, err)
		split := lagging(t, "messages", "message_state")
		stale, err := split.GetUniqueCustomFlagsForMailbox(ctx, mailboxID)
		require.NoError(t, err)
		require.Empty(t, stale, "control: replica must lag")
		got, err := split.GetUniqueCustomFlagsForMailbox(pinned, mailboxID)
		require.NoError(t, err)
		assert.Equal(t, []string{"PinKeyword"}, got)
	})

	t.Run("sieve scripts", func(t *testing.T) {
		split := lagging(t, "sieve_scripts")

		t.Run("GetUserScripts", func(t *testing.T) {
			stale, err := split.GetUserScripts(ctx, accountID)
			require.NoError(t, err)
			require.Empty(t, stale, "control: replica must lag")
			got, err := split.GetUserScripts(pinned, accountID)
			require.NoError(t, err)
			require.Len(t, got, 1)
			assert.Equal(t, "pinned", got[0].Name)
		})
		t.Run("GetScript", func(t *testing.T) {
			_, err := split.GetScript(ctx, script.ID, accountID)
			require.Error(t, err, "control: replica must lag")
			got, err := split.GetScript(pinned, script.ID, accountID)
			require.NoError(t, err)
			assert.Equal(t, "pinned", got.Name)
		})
		t.Run("GetActiveScript", func(t *testing.T) {
			_, err := split.GetActiveScript(ctx, accountID)
			require.ErrorIs(t, err, consts.ErrDBNotFound, "control: replica must lag")
			got, err := split.GetActiveScript(pinned, accountID)
			require.NoError(t, err)
			assert.Equal(t, "pinned", got.Name)
		})
		t.Run("GetScriptByName", func(t *testing.T) {
			_, err := split.GetScriptByName(ctx, "pinned", accountID)
			require.ErrorIs(t, err, consts.ErrDBNotFound, "control: replica must lag")
			got, err := split.GetScriptByName(pinned, "pinned", accountID)
			require.NoError(t, err)
			assert.Equal(t, script.ID, got.ID)
		})
	})
}
