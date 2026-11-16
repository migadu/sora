package db

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func insertRestoreCustomTestMessage(
	t *testing.T,
	db *Database,
	accountID, mailboxID int64,
	mailboxName, subject, messageID, contentHash, deliveryHash string,
	flags []imap.Flag,
) (int64, imap.UID) {
	t.Helper()
	ctx := context.Background()

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	now := time.Now()
	options := &InsertMessageOptions{
		AccountID:     accountID,
		MailboxID:     mailboxID,
		MailboxName:   mailboxName,
		S3Domain:      "example.com",
		S3Localpart:   "test",
		ContentHash:   contentHash,
		MessageID:     messageID,
		DeliveryHash:  deliveryHash,
		Flags:         flags,
		InternalDate:  now,
		Size:          512,
		Subject:       subject,
		PlaintextBody: fmt.Sprintf("Test message body for %s", subject),
		SentDate:      now.Add(-time.Hour),
		InReplyTo:     []string{},
	}

	upload := PendingUpload{
		AccountID:   accountID,
		ContentHash: contentHash,
		InstanceID:  "test-instance",
		Size:        512,
		Attempts:    0,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	msgID, uid, err := db.InsertMessage(ctx, tx, options, upload)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	return msgID, imap.UID(uid)
}

func readMailboxCustomFlagsCache(t *testing.T, db *Database, mailboxID int64) []string {
	t.Helper()
	var raw []byte
	err := db.GetReadPool().QueryRow(context.Background(),
		`SELECT custom_flags_cache FROM mailbox_stats WHERE mailbox_id = $1`, mailboxID).Scan(&raw)
	require.NoError(t, err)
	if len(raw) == 0 {
		return []string{}
	}
	var out []string
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

func readMessageCustomFlags(t *testing.T, db *Database, messageID int64) []string {
	t.Helper()
	var raw []byte
	err := db.GetReadPool().QueryRow(context.Background(),
		`SELECT custom_flags FROM message_state WHERE message_id = $1`, messageID).Scan(&raw)
	require.NoError(t, err)
	var out []string
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

func searchUIDs(t *testing.T, db *Database, mailboxID, accountID int64, criteria *imap.SearchCriteria) []imap.UID {
	t.Helper()
	res, err := db.SearchMessagesWithCriteria(context.Background(), mailboxID, accountID, criteria, 0, 100)
	require.NoError(t, err)
	uids := make([]imap.UID, 0, len(res))
	for _, r := range res {
		uids = append(uids, r.UID)
	}
	return uids
}

// Keyword identity is case-insensitive per RFC 9051 §2.3.2. Every other path that puts
// a message into a mailbox (InsertMessage, InsertMessagesBatch, CopyMessages, MoveMessages)
// folds custom keywords onto the destination mailbox's canonical case so that
// mailbox_stats.custom_flags_cache holds a single case per keyword and SEARCH KEYWORD /
// SEARCH UNKEYWORD / STORE -FLAGS match every message carrying that keyword.
func TestRestoreMessages_FoldsCustomFlagsOntoTargetMailboxCanonicalCase(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, testEmail, _, _ := setupRestoreTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	t.Run("folds onto existing canonical case in recreated mailbox", func(t *testing.T) {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		require.NoError(t, db.CreateMailbox(ctx, tx, accountID, "Archive", nil))
		require.NoError(t, tx.Commit(ctx))

		oldArchive, err := db.GetMailboxByName(ctx, accountID, "Archive")
		require.NoError(t, err)

		oldMsgID, _ := insertRestoreCustomTestMessage(
			t, db, accountID, oldArchive.ID, "Archive",
			"Old archived message", "<restore-kw-old@example.com>", "hash_restore_kw_old", "",
			[]imap.Flag{imap.FlagSeen, imap.Flag("$important")},
		)

		// Purge the old Archive mailbox: its messages become expunged orphans with
		// mailbox_path = "Archive" and message_state.custom_flags = ["$important"].
		tx, err = db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		require.NoError(t, db.DeleteMailbox(ctx, tx, oldArchive.ID, accountID))
		require.NoError(t, tx.Commit(ctx))

		// Recreate Archive and establish "$Important" as its canonical case.
		tx, err = db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		require.NoError(t, db.CreateMailbox(ctx, tx, accountID, "Archive", nil))
		require.NoError(t, tx.Commit(ctx))

		newArchive, err := db.GetMailboxByName(ctx, accountID, "Archive")
		require.NoError(t, err)

		_, liveUID := insertRestoreCustomTestMessage(
			t, db, accountID, newArchive.ID, "Archive",
			"New archived message", "<restore-kw-live@example.com>", "hash_restore_kw_live", "",
			[]imap.Flag{imap.FlagSeen, imap.Flag("$Important")},
		)
		require.Equal(t, []string{"$Important"}, readMailboxCustomFlagsCache(t, db, newArchive.ID))

		// Restore the message from the purged Archive incarnation into the recreated Archive.
		tx, err = db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		restored, err := db.RestoreMessages(ctx, tx, RestoreMessagesParams{
			Email:      testEmail,
			MessageIDs: []int64{oldMsgID},
		})
		require.NoError(t, err)
		require.Equal(t, int64(1), restored)
		require.NoError(t, tx.Commit(ctx))

		restoredID := restoredCopyID(t, db, oldMsgID)
		var restoredUID imap.UID
		require.NoError(t, db.GetReadPool().QueryRow(ctx,
			`SELECT uid FROM messages WHERE id = $1`, restoredID).Scan(&restoredUID))

		assert.Equal(t, []string{"$Important"}, readMessageCustomFlags(t, db, restoredID),
			"restored message must fold its keyword onto target mailbox's canonical case")
		assert.Equal(t, []string{"$Important"}, readMailboxCustomFlagsCache(t, db, newArchive.ID),
			"custom_flags_cache must contain only the single canonical keyword case")

		assert.ElementsMatch(t, []imap.UID{liveUID, restoredUID},
			searchUIDs(t, db, newArchive.ID, accountID, &imap.SearchCriteria{Flag: []imap.Flag{"$important"}}),
			"SEARCH KEYWORD $important must match both the existing and restored messages")
		assert.Empty(t,
			searchUIDs(t, db, newArchive.ID, accountID, &imap.SearchCriteria{NotFlag: []imap.Flag{"$important"}}),
			"SEARCH UNKEYWORD $important must match neither message")

		// UID STORE -FLAGS ($important) must cleanly remove the keyword from the restored message.
		txRem, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer txRem.Rollback(ctx)
		updatedFlags, _, err := db.RemoveMessageFlags(ctx, txRem, restoredUID, newArchive.ID, []imap.Flag{"$important"})
		require.NoError(t, err)
		require.NoError(t, txRem.Commit(ctx))

		assert.Equal(t, []imap.Flag{imap.FlagSeen}, updatedFlags,
			"RemoveMessageFlags with $important must remove the folded keyword cleanly")
		assert.Empty(t, readMessageCustomFlags(t, db, restoredID))
	})

	t.Run("folds intra-batch keywords onto one canonical case in freshly recreated mailbox", func(t *testing.T) {
		const mboxName = "ArchiveBatch"

		// Incarnation 1 holds M1 with ["$Important", "Work"], then is purged.
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		require.NoError(t, db.CreateMailbox(ctx, tx, accountID, mboxName, nil))
		require.NoError(t, tx.Commit(ctx))
		inc1, err := db.GetMailboxByName(ctx, accountID, mboxName)
		require.NoError(t, err)

		m1ID, _ := insertRestoreCustomTestMessage(
			t, db, accountID, inc1.ID, mboxName,
			"Batch M1", "<restore-kw-batch-1@example.com>", "hash_restore_kw_batch_1", "",
			[]imap.Flag{imap.FlagSeen, imap.Flag("$Important"), imap.Flag("Work")},
		)
		tx, err = db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		require.NoError(t, db.DeleteMailbox(ctx, tx, inc1.ID, accountID))
		require.NoError(t, tx.Commit(ctx))

		// Incarnation 2 holds M2 with ["$important", "WORK"], then is purged too.
		tx, err = db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		require.NoError(t, db.CreateMailbox(ctx, tx, accountID, mboxName, nil))
		require.NoError(t, tx.Commit(ctx))
		inc2, err := db.GetMailboxByName(ctx, accountID, mboxName)
		require.NoError(t, err)

		m2ID, _ := insertRestoreCustomTestMessage(
			t, db, accountID, inc2.ID, mboxName,
			"Batch M2", "<restore-kw-batch-2@example.com>", "hash_restore_kw_batch_2", "",
			[]imap.Flag{imap.FlagSeen, imap.Flag("$important"), imap.Flag("WORK")},
		)
		tx, err = db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		require.NoError(t, db.DeleteMailbox(ctx, tx, inc2.ID, accountID))
		require.NoError(t, tx.Commit(ctx))

		// Restore both together into a freshly recreated ArchiveBatch.
		mailboxFilter := mboxName
		tx, err = db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		restored, err := db.RestoreMessages(ctx, tx, RestoreMessagesParams{
			Email:       testEmail,
			MailboxPath: &mailboxFilter,
		})
		require.NoError(t, err)
		require.Equal(t, int64(2), restored)
		require.NoError(t, tx.Commit(ctx))

		recreated, err := db.GetMailboxByName(ctx, accountID, mboxName)
		require.NoError(t, err)

		r1ID := restoredCopyID(t, db, m1ID)
		r2ID := restoredCopyID(t, db, m2ID)
		var r1UID, r2UID imap.UID
		require.NoError(t, db.GetReadPool().QueryRow(ctx, `SELECT uid FROM messages WHERE id = $1`, r1ID).Scan(&r1UID))
		require.NoError(t, db.GetReadPool().QueryRow(ctx, `SELECT uid FROM messages WHERE id = $1`, r2ID).Scan(&r2UID))

		r1Flags := readMessageCustomFlags(t, db, r1ID)
		r2Flags := readMessageCustomFlags(t, db, r2ID)
		assert.Equal(t, []string{"$Important", "Work"}, r1Flags)
		assert.Equal(t, r1Flags, r2Flags, "both restored messages must share one canonical case per keyword")
		assert.Equal(t, []string{"$Important", "Work"}, readMailboxCustomFlagsCache(t, db, recreated.ID),
			"custom_flags_cache must have no case duplicates")

		assert.ElementsMatch(t, []imap.UID{r1UID, r2UID},
			searchUIDs(t, db, recreated.ID, accountID, &imap.SearchCriteria{Flag: []imap.Flag{"$important"}}))
		assert.ElementsMatch(t, []imap.UID{r1UID, r2UID},
			searchUIDs(t, db, recreated.ID, accountID, &imap.SearchCriteria{Flag: []imap.Flag{"work"}}))
	})
}

// Headerless MTA deliveries receive a fresh synthetic timestamp-based message_id on each
// delivery attempt ("<%d@%s>") and rely on delivery_hash to deduplicate redeliveries per
// mailbox. Because RestoreMessages carries delivery_hash onto restored rows, its target-
// mailbox duplicate check must also suppress duplicates matching delivery_hash in that
// target mailbox.
func TestRestoreMessages_SkipsDuplicateByDeliveryHash(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, testEmail, inboxID, _ := setupRestoreTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.CreateMailbox(ctx, tx, accountID, "Archive", nil))
	require.NoError(t, tx.Commit(ctx))
	archive, err := db.GetMailboxByName(ctx, accountID, "Archive")
	require.NoError(t, err)

	t.Run("skips expunged attempt when redelivered copy with same delivery_hash is live in target mailbox", func(t *testing.T) {
		expungedAttemptID, expungedUID := insertRestoreCustomTestMessage(
			t, db, accountID, inboxID, "INBOX",
			"Headerless delivery attempt 1", "<attempt1@INBOX>", "hash_dh_live_1", "dh-live",
			[]imap.Flag{imap.FlagSeen},
		)
		expungeMessage(t, db, inboxID, expungedUID)

		// Second MTA attempt of the same headerless message is now live in INBOX under a
		// different synthetic Message-ID and per-attempt content_hash, but the same delivery_hash.
		_, _ = insertRestoreCustomTestMessage(
			t, db, accountID, inboxID, "INBOX",
			"Headerless delivery attempt 2", "<attempt2@INBOX>", "hash_dh_live_2", "dh-live",
			[]imap.Flag{imap.FlagSeen},
		)

		// An expunged copy in a DIFFERENT mailbox (Archive) with the same delivery_hash must
		// still be restorable, because duplicate suppression is scoped per target mailbox.
		archiveAttemptID, archiveUID := insertRestoreCustomTestMessage(
			t, db, accountID, archive.ID, "Archive",
			"Headerless delivery in Archive", "<attempt1@Archive>", "hash_dh_live_archive", "dh-live",
			[]imap.Flag{imap.FlagSeen},
		)
		expungeMessage(t, db, archive.ID, archiveUID)

		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		restoredInbox, err := db.RestoreMessages(ctx, tx, RestoreMessagesParams{
			Email:      testEmail,
			MessageIDs: []int64{expungedAttemptID},
		})
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))

		assert.Zero(t, restoredInbox, "expunged attempt must be skipped when same delivery_hash is already live in INBOX")
		requireNotRestored(t, db, expungedAttemptID)

		var liveInbox int
		require.NoError(t, db.GetReadPool().QueryRow(ctx,
			`SELECT COUNT(*) FROM messages WHERE mailbox_id = $1 AND delivery_hash = $2 AND expunged_at IS NULL`,
			inboxID, "dh-live").Scan(&liveInbox))
		assert.Equal(t, 1, liveInbox, "INBOX must retain only the single live copy")

		tx2, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx2.Rollback(ctx)
		restoredArchive, err := db.RestoreMessages(ctx, tx2, RestoreMessagesParams{
			Email:      testEmail,
			MessageIDs: []int64{archiveAttemptID},
		})
		require.NoError(t, err)
		require.NoError(t, tx2.Commit(ctx))

		assert.Equal(t, int64(1), restoredArchive, "live copy in INBOX must not block restoring into Archive")
	})

	t.Run("restores only one of two expunged attempts sharing delivery_hash in one batch", func(t *testing.T) {
		attempt1ID, attempt1UID := insertRestoreCustomTestMessage(
			t, db, accountID, inboxID, "INBOX",
			"Headerless pair attempt 1", "<pair-attempt1@INBOX>", "hash_dh_pair_1", "dh-pair",
			[]imap.Flag{imap.FlagSeen},
		)
		expungeMessage(t, db, inboxID, attempt1UID)

		attempt2ID, attempt2UID := insertRestoreCustomTestMessage(
			t, db, accountID, inboxID, "INBOX",
			"Headerless pair attempt 2", "<pair-attempt2@INBOX>", "hash_dh_pair_2", "dh-pair",
			[]imap.Flag{imap.FlagSeen},
		)
		expungeMessage(t, db, inboxID, attempt2UID)

		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		restored, err := db.RestoreMessages(ctx, tx, RestoreMessagesParams{
			Email:      testEmail,
			MessageIDs: []int64{attempt1ID, attempt2ID},
		})
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))

		assert.Equal(t, int64(1), restored, "only the first attempt should be restored; the duplicate attempt must be skipped")

		var livePair int
		require.NoError(t, db.GetReadPool().QueryRow(ctx,
			`SELECT COUNT(*) FROM messages WHERE mailbox_id = $1 AND delivery_hash = $2 AND expunged_at IS NULL`,
			inboxID, "dh-pair").Scan(&livePair))
		assert.Equal(t, 1, livePair, "INBOX must hold exactly one live copy for dh-pair after batch restore")
	})
}
