package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/require"
)

// TestFlagWritersCreateMissingMessageState proves that online flag updates — IMAP batch
// STORE (Set/Add/RemoveMessageFlagsBatch), single-message flag helpers
// (Set/Add/RemoveMessageFlags), and User API PATCH/DELETE (UpdateMessageFlags) — create
// the missing message_state row on demand and keep unseen_count accurate when mutating a
// historical live message that has no message_state row (#1151).
func TestFlagWritersCreateMissingMessageState(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	ts := time.Now().UnixNano()
	var accountID int64
	inTx(t, db, func(tx pgx.Tx) {
		var err error
		accountID, err = db.CreateAccount(ctx, tx, CreateAccountRequest{
			Email:    fmt.Sprintf("flag_writers_stateless_%d@example.com", ts),
			Password: "password", IsPrimary: true, HashType: "bcrypt",
		})
		require.NoError(t, err)
		require.NoError(t, db.CreateMailbox(ctx, tx, accountID, "INBOX", nil))
	})
	inbox, err := db.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)

	seq := 0
	insertStateless := func(t *testing.T) (id int64, uid imap.UID) {
		t.Helper()
		seq++
		hash := fmt.Sprintf("stateless-flag-%d-%d", ts, seq)
		var rawUID int64
		inTx(t, db, func(tx pgx.Tx) {
			var insErr error
			id, rawUID, insErr = db.InsertMessage(ctx, tx, &InsertMessageOptions{
				AccountID: accountID, MailboxID: inbox.ID, MailboxName: inbox.Name,
				S3Domain: "example.com", S3Localpart: "user",
				ContentHash: hash, MessageID: "<" + hash + "@example.com>",
				InternalDate: time.Now(), Size: 512,
				Subject: "stateless", PlaintextBody: "body", SentDate: time.Now(),
			}, PendingUpload{AccountID: accountID, ContentHash: hash})
			require.NoError(t, insErr)
		})
		_, err := db.GetWritePool().Exec(ctx, `DELETE FROM message_state WHERE message_id = $1`, id)
		require.NoError(t, err)
		return id, imap.UID(rawUID)
	}

	t.Run("batch flag writers (IMAP STORE)", func(t *testing.T) {
		_, uidAdd := insertStateless(t)
		inTx(t, db, func(tx pgx.Tx) {
			res, err := db.AddMessageFlagsBatch(ctx, tx, []imap.UID{uidAdd}, inbox.ID, []imap.Flag{imap.FlagSeen, "Work"})
			require.NoError(t, err)
			require.Len(t, res, 1)
			require.ElementsMatch(t, []imap.Flag{imap.FlagSeen, "Work"}, res[0].Flags)
		})

		_, uidSet := insertStateless(t)
		inTx(t, db, func(tx pgx.Tx) {
			res, err := db.SetMessageFlagsBatch(ctx, tx, []imap.UID{uidSet}, inbox.ID, []imap.Flag{imap.FlagFlagged})
			require.NoError(t, err)
			require.Len(t, res, 1)
			require.Equal(t, []imap.Flag{imap.FlagFlagged}, res[0].Flags)
		})

		idRem, uidRem := insertStateless(t)
		inTx(t, db, func(tx pgx.Tx) {
			res, err := db.RemoveMessageFlagsBatch(ctx, tx, []imap.UID{uidRem}, inbox.ID, []imap.Flag{imap.FlagSeen})
			require.NoError(t, err)
			require.Empty(t, res, "no-op removal does not bump modseq (RFC 7162 §3.1)")
		})
		var seeded bool
		require.NoError(t, db.GetWritePool().QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM message_state WHERE message_id = $1)`, idRem).Scan(&seeded))
		require.True(t, seeded, "RemoveMessageFlagsBatch must still seed the missing message_state row")
	})

	t.Run("rejected conditional writers leave missing state untouched", func(t *testing.T) {
		for _, mode := range []string{"add", "set", "remove"} {
			t.Run(mode, func(t *testing.T) {
				id, uid := insertStateless(t)
				inTx(t, db, func(tx pgx.Tx) {
					var results []BatchFlagUpdateResult
					var err error
					switch mode {
					case "add":
						results, err = db.AddMessageFlagsBatch(ctx, tx, []imap.UID{uid}, inbox.ID, []imap.Flag{imap.FlagSeen}, 0)
					case "set":
						results, err = db.SetMessageFlagsBatch(ctx, tx, []imap.UID{uid}, inbox.ID, []imap.Flag{imap.FlagSeen}, 0)
					case "remove":
						results, err = db.RemoveMessageFlagsBatch(ctx, tx, []imap.UID{uid}, inbox.ID, []imap.Flag{imap.FlagSeen}, 0)
					}
					require.NoError(t, err)
					require.Len(t, results, 1)
					require.True(t, results[0].PreconditionFailed)
				})
				var present bool
				require.NoError(t, db.GetWritePool().QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM message_state WHERE message_id=$1)`, id).Scan(&present))
				require.False(t, present, "UNCHANGEDSINCE rejection must not initialize historical state")
			})
		}
	})

	t.Run("single-message flag writers", func(t *testing.T) {
		_, uidAdd := insertStateless(t)
		inTx(t, db, func(tx pgx.Tx) {
			flags, modSeq, err := db.AddMessageFlags(ctx, tx, uidAdd, inbox.ID, []imap.Flag{imap.FlagFlagged, "Tag1"})
			require.NoError(t, err)
			require.Positive(t, modSeq)
			require.ElementsMatch(t, []imap.Flag{imap.FlagFlagged, "Tag1"}, flags)
		})

		_, uidSet := insertStateless(t)
		inTx(t, db, func(tx pgx.Tx) {
			flags, modSeq, err := db.SetMessageFlags(ctx, tx, uidSet, inbox.ID, []imap.Flag{imap.FlagSeen})
			require.NoError(t, err)
			require.Positive(t, modSeq)
			require.Equal(t, []imap.Flag{imap.FlagSeen}, flags)
		})

		_, uidRem := insertStateless(t)
		inTx(t, db, func(tx pgx.Tx) {
			flags, modSeq, err := db.RemoveMessageFlags(ctx, tx, uidRem, inbox.ID, []imap.Flag{imap.FlagSeen})
			require.NoError(t, err)
			require.Positive(t, modSeq)
			require.Empty(t, flags)
		})
	})

	t.Run("User API UpdateMessageFlags", func(t *testing.T) {
		idUserAPI, _ := insertStateless(t)
		err := db.UpdateMessageFlags(ctx, accountID, idUserAPI, []string{`\Seen`, "Important"}, nil)
		require.NoError(t, err)

		msg, err := db.GetMessageByID(ctx, accountID, idUserAPI)
		require.NoError(t, err)
		require.Equal(t, []string{`\Seen`}, msg.Flags)
		require.Equal(t, []string{"Important"}, msg.CustomFlags)
	})
}
