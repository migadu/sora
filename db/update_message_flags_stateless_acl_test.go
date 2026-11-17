package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/require"
)

// TestUpdateMessageFlags_StatelessSharedMailboxWithoutWriteRight proves that when a
// shared-mailbox grantee lacks the 'w' right (!mayWrite) — e.g. 'lrs' setting \Seen or
// 'lrst' setting \Deleted — UpdateMessageFlags on a historical live message missing its
// message_state row initializes message_state with custom_flags = '[]'::jsonb (not JSON
// scalar 'null'::jsonb, which violated max_custom_flags_check with SQLSTATE 22023),
// applies the permitted system flag, ignores unpermitted keywords, and keeps
// mailbox_stats.unseen_count and highest_modseq accurate.
func TestUpdateMessageFlags_StatelessSharedMailboxWithoutWriteRight(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()

	baseCtx := context.Background()
	sharedCtx := context.WithValue(baseCtx, consts.ConfigContextKey, &config.Config{
		SharedMailboxes: config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: "Shared/"},
	})

	ts := time.Now().UnixNano()
	domain := fmt.Sprintf("stateless-acl-%d.example.com", ts)

	ownerID, _ := setupAccountWithInbox(t, db, baseCtx, "owner@"+domain)
	seenEmail := "seen-only@" + domain
	seenID, _ := setupAccountWithInbox(t, db, baseCtx, seenEmail)
	deleteEmail := "delete-only@" + domain
	deleteID, _ := setupAccountWithInbox(t, db, baseCtx, deleteEmail)
	readOnlyEmail := "read-only@" + domain
	readOnlyID, _ := setupAccountWithInbox(t, db, baseCtx, readOnlyEmail)

	const mboxName = "Shared/StatelessACL"
	tx, err := db.GetWritePool().Begin(sharedCtx)
	require.NoError(t, err)
	defer tx.Rollback(baseCtx)
	require.NoError(t, db.CreateMailbox(sharedCtx, tx, ownerID, mboxName, nil))
	require.NoError(t, tx.Commit(sharedCtx))

	mbox, err := db.GetMailboxByName(sharedCtx, ownerID, mboxName)
	require.NoError(t, err)

	require.NoError(t, db.GrantMailboxAccessByIdentifier(sharedCtx, ownerID, seenEmail, mboxName, "lrs"))
	require.NoError(t, db.GrantMailboxAccessByIdentifier(sharedCtx, ownerID, deleteEmail, mboxName, "lrst"))
	require.NoError(t, db.GrantMailboxAccessByIdentifier(sharedCtx, ownerID, readOnlyEmail, mboxName, "lr"))

	seq := 0
	insertStateless := func(t *testing.T) int64 {
		t.Helper()
		seq++
		now := time.Now()
		hash := fmt.Sprintf("%064x", ts+int64(seq))
		var msgID int64
		inTx(t, db, func(tx pgx.Tx) {
			var insErr error
			msgID, _, insErr = db.InsertMessage(baseCtx, tx, &InsertMessageOptions{
				AccountID:     ownerID,
				MailboxID:     mbox.ID,
				MailboxName:   mboxName,
				S3Domain:      domain,
				S3Localpart:   "owner",
				ContentHash:   hash,
				MessageID:     fmt.Sprintf("<stateless-%d-%d@example.com>", ts, seq),
				InternalDate:  now,
				Size:          512,
				Subject:       fmt.Sprintf("stateless-%d", seq),
				PlaintextBody: "body",
				SentDate:      now,
			}, PendingUpload{AccountID: ownerID, ContentHash: hash, InstanceID: "test-node", Size: 512, CreatedAt: now, UpdatedAt: now})
			require.NoError(t, insErr)
		})
		_, err := db.GetWritePool().Exec(baseCtx, `DELETE FROM message_state WHERE message_id = $1`, msgID)
		require.NoError(t, err)
		return msgID
	}

	readMailboxStats := func(t *testing.T) (unseen int64, actualUnseen int64, highestModSeq int64) {
		t.Helper()
		require.NoError(t, db.GetWritePool().QueryRow(baseCtx,
			`SELECT unseen_count, `+liveUnseenCount("$1")+`, highest_modseq FROM mailbox_stats WHERE mailbox_id = $1`,
			mbox.ID,
		).Scan(&unseen, &actualUnseen, &highestModSeq))
		return unseen, actualUnseen, highestModSeq
	}

	readMessageState := func(t *testing.T, msgID int64) (flags int, customJSON string, customType string, updatedModSeq int64, initialModSeq *int64) {
		t.Helper()
		require.NoError(t, db.GetWritePool().QueryRow(baseCtx, `
			SELECT flags, custom_flags::text, jsonb_typeof(custom_flags), updated_modseq, initial_modseq
			FROM message_state
			WHERE message_id = $1
		`, msgID).Scan(&flags, &customJSON, &customType, &updatedModSeq, &initialModSeq))
		return flags, customJSON, customType, updatedModSeq, initialModSeq
	}

	t.Run("lrs grantee setting Seen on stateless message seeds empty array custom_flags", func(t *testing.T) {
		msgID := insertStateless(t)
		_, _, beforeModSeq := readMailboxStats(t)

		err := db.UpdateMessageFlags(baseCtx, seenID, msgID, []string{`\Seen`, "UnauthorizedKeyword"}, nil)
		require.NoError(t, err)

		flags, customJSON, customType, updatedModSeq, initialModSeq := readMessageState(t, msgID)
		require.Equal(t, FlagSeen, flags)
		require.Equal(t, "array", customType)
		require.Equal(t, "[]", customJSON)
		require.Greater(t, updatedModSeq, beforeModSeq)
		require.Nil(t, initialModSeq)

		unseen, actualUnseen, highestModSeq := readMailboxStats(t)
		require.Equal(t, int64(0), unseen)
		require.Equal(t, actualUnseen, unseen)
		require.Equal(t, updatedModSeq, highestModSeq)

		msg, err := db.GetMessageByID(baseCtx, seenID, msgID)
		require.NoError(t, err)
		require.Equal(t, []string{`\Seen`}, msg.Flags)
		require.Empty(t, msg.CustomFlags)
	})

	t.Run("lrst grantee setting Deleted on stateless message seeds state and counts unseen", func(t *testing.T) {
		msgID := insertStateless(t)
		_, _, beforeModSeq := readMailboxStats(t)

		err := db.UpdateMessageFlags(baseCtx, deleteID, msgID, []string{`\Deleted`}, nil)
		require.NoError(t, err)

		flags, customJSON, customType, updatedModSeq, initialModSeq := readMessageState(t, msgID)
		require.Equal(t, FlagDeleted, flags)
		require.Equal(t, "array", customType)
		require.Equal(t, "[]", customJSON)
		require.Greater(t, updatedModSeq, beforeModSeq)
		require.Nil(t, initialModSeq)

		unseen, actualUnseen, highestModSeq := readMailboxStats(t)
		require.Equal(t, int64(1), unseen, "message marked \\Deleted without \\Seen remains unseen")
		require.Equal(t, actualUnseen, unseen)
		require.Equal(t, updatedModSeq, highestModSeq)

		msg, err := db.GetMessageByID(baseCtx, deleteID, msgID)
		require.NoError(t, err)
		require.Equal(t, []string{`\Deleted`}, msg.Flags)
		require.Empty(t, msg.CustomFlags)
	})

	t.Run("lr grantee rejected with ErrNotPermitted leaves missing state untouched", func(t *testing.T) {
		msgID := insertStateless(t)

		err := db.UpdateMessageFlags(baseCtx, readOnlyID, msgID, []string{`\Seen`}, nil)
		require.ErrorIs(t, err, consts.ErrNotPermitted)

		var exists bool
		require.NoError(t, db.GetWritePool().QueryRow(baseCtx,
			`SELECT EXISTS (SELECT 1 FROM message_state WHERE message_id = $1)`, msgID,
		).Scan(&exists))
		require.False(t, exists, "rejected flag write must not initialize missing message_state")
	})
}
