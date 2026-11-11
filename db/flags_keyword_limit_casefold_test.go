package db

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/require"
)

// AddMessageFlagsBatch must enforce the per-message keyword cap itself, inside
// the locked transaction: the IMAP layer's pre-check runs on an unlocked
// snapshot, so a concurrent writer can fill the message before the lock is
// taken. The caller then needs consts.ErrTooManyKeywords (NO [LIMIT]), not a
// raw max_custom_flags_check violation (NO [SERVERBUG]).
func TestAddMessageFlagsBatchEnforcesKeywordLimit(t *testing.T) {
	db, _, mailboxID, uids := setupBatchFlagTestDatabase(t, 2)
	defer db.Close()
	ctx := context.Background()

	full := make([]imap.Flag, 0, MaxCustomKeywordsPerMessage)
	for i := 0; i < MaxCustomKeywordsPerMessage; i++ {
		full = append(full, imap.Flag(fmt.Sprintf("kw%02d", i)))
	}
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = db.SetMessageFlagsBatch(ctx, tx, uids[:1], mailboxID, full)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	// The message is already at the cap, as if a concurrent STORE had won the
	// race after this STORE's pre-check.
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = db.AddMessageFlagsBatch(ctx, tx, uids, mailboxID, []imap.Flag{"onetoomany"})
	_ = tx.Rollback(ctx)
	require.ErrorIs(t, err, consts.ErrTooManyKeywords)

	// Re-adding a keyword the message already has (in another case) stays legal.
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = db.AddMessageFlagsBatch(ctx, tx, uids[:1], mailboxID, []imap.Flag{"KW00", imap.FlagSeen})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
}

// UpdateMessageFlags must treat keywords case-insensitively (RFC 9051 §2.3.2)
// against the message's own keywords, even when mailbox_stats.custom_flags_cache
// does not list them.
func TestUpdateMessageFlagsFoldsCaseWithoutKeywordCache(t *testing.T) {
	db, accountID, mailboxID, uids := setupBatchFlagTestDatabase(t, 2)
	defer db.Close()
	ctx := context.Background()

	customFlags := func(messageID int64) []string {
		var raw []byte
		require.NoError(t, db.GetWritePool().QueryRow(ctx,
			`SELECT custom_flags FROM message_state WHERE message_id = $1`, messageID).Scan(&raw))
		var out []string
		require.NoError(t, json.Unmarshal(raw, &out))
		return out
	}
	// A message tagged "Work" in a mailbox whose keyword cache is empty.
	prepare := func(t *testing.T, uid imap.UID) int64 {
		var messageID int64
		require.NoError(t, db.GetWritePool().QueryRow(ctx,
			`SELECT id FROM messages WHERE mailbox_id = $1 AND uid = $2`, mailboxID, int64(uid)).Scan(&messageID))
		require.NoError(t, db.UpdateMessageFlags(ctx, accountID, messageID, []string{"Work"}, nil))
		require.Equal(t, []string{"Work"}, customFlags(messageID))
		_, err := db.GetWritePool().Exec(ctx,
			`UPDATE mailbox_stats SET custom_flags_cache = NULL WHERE mailbox_id = $1`, mailboxID)
		require.NoError(t, err)
		return messageID
	}

	t.Run("add", func(t *testing.T) {
		messageID := prepare(t, uids[0])
		require.NoError(t, db.UpdateMessageFlags(ctx, accountID, messageID, []string{"work"}, nil))
		require.Equal(t, []string{"Work"}, customFlags(messageID), "adding a case variant must not create a second keyword")
	})
	t.Run("remove", func(t *testing.T) {
		messageID := prepare(t, uids[1])
		require.NoError(t, db.UpdateMessageFlags(ctx, accountID, messageID, nil, []string{"work"}))
		require.Empty(t, customFlags(messageID), "removal must match the stored keyword regardless of case")
	})
}
