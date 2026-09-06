package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/stretchr/testify/require"
)

// The S3 key of a body is per row (s3_domain/s3_localpart recorded at insert time), and
// one account's rows may carry different keys: the primary address at the time each row
// was written, or the address an import ran under. Every path that creates a row must
// therefore either keep the key of the row whose object it reuses, or write the object
// under the new key first. These tests pin the same-account paths that once assumed
// "same account ⇒ same key" and produced rows marked uploaded with no object behind them
// (read as an empty body forever).

// keyTestSeedUploaded inserts a message whose body is "in S3" under the key
// example.com/test/<hash> and returns its UID, key localpart and hash.
func keyTestSeedUploaded(t *testing.T, db *Database, accountID, mailboxID int64, messageID string) (imap.UID, string, string) {
	t.Helper()
	ctx := context.Background()
	msgID := insertTestMessage(t, db, accountID, mailboxID, "INBOX", "seed", messageID)
	_, err := db.GetWritePool().Exec(ctx, `UPDATE messages SET uploaded = TRUE WHERE id = $1`, msgID)
	require.NoError(t, err)
	_, err = db.GetWritePool().Exec(ctx, `DELETE FROM pending_uploads WHERE account_id = $1`, accountID)
	require.NoError(t, err)
	var uid imap.UID
	var localpart, hash string
	require.NoError(t, db.GetWritePool().QueryRow(ctx,
		`SELECT uid, s3_localpart, content_hash FROM messages WHERE id = $1`, msgID).Scan(&uid, &localpart, &hash))
	return uid, localpart, hash
}

func keyTestMailbox(t *testing.T, db *Database, accountID int64, name string) *DBMailbox {
	t.Helper()
	ctx := context.Background()
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.CreateMailbox(ctx, tx, accountID, name, nil))
	require.NoError(t, tx.Commit(ctx))
	mb, err := db.GetMailboxByName(ctx, accountID, name)
	require.NoError(t, err)
	return mb
}

func keyTestPendingRows(t *testing.T, db *Database, accountID int64) int {
	t.Helper()
	var n int
	require.NoError(t, db.GetWritePool().QueryRow(context.Background(),
		`SELECT COUNT(*) FROM pending_uploads WHERE account_id = $1`, accountID).Scan(&n))
	return n
}

// A same-account COPY keeps the source row's key even when the caller (an IMAP session
// whose primary address has since changed) passes a different one.
func TestCopyMessagesKeepsSourceS3KeyForSameAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("database integration test")
	}
	db, accountID, inboxID := setupMessageTestDatabase(t)
	defer db.Close()
	ctx := context.Background()
	archive := keyTestMailbox(t, db, accountID, "Archive")
	srcUID, srcLocalpart, _ := keyTestSeedUploaded(t, db, accountID, inboxID, "<copy-key@example.com>")

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	uids := []imap.UID{srcUID}
	_, newIDs, err := db.CopyMessages(ctx, tx, &uids, inboxID, archive.ID, accountID, "example.com", "renamed", "test-instance")
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	require.Len(t, newIDs, 1)

	var localpart string
	var uploaded bool
	require.NoError(t, db.GetWritePool().QueryRow(ctx,
		`SELECT s3_localpart, uploaded FROM messages WHERE id = $1`, newIDs[0]).Scan(&localpart, &uploaded))
	require.Equal(t, srcLocalpart, localpart, "the copy must point at the key the object was uploaded under")
	require.True(t, uploaded, "the copy inherits uploaded=TRUE, which is only valid under the source key")
}

// A same-account MOVE keeps the source row's key: after the move it is the only live
// reference to the object.
func TestMoveMessagesKeepsSourceS3KeyForSameAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("database integration test")
	}
	db, accountID, inboxID := setupMessageTestDatabase(t)
	defer db.Close()
	ctx := context.Background()
	archive := keyTestMailbox(t, db, accountID, "Archive")
	srcUID, srcLocalpart, hash := keyTestSeedUploaded(t, db, accountID, inboxID, "<move-key@example.com>")

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	uids := []imap.UID{srcUID}
	uidMap, err := db.MoveMessages(ctx, tx, &uids, inboxID, archive.ID, accountID, "example.com", "renamed", "test-instance")
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	require.Len(t, uidMap, 1)

	var localpart string
	var uploaded bool
	require.NoError(t, db.GetWritePool().QueryRow(ctx,
		`SELECT s3_localpart, uploaded FROM messages WHERE account_id = $1 AND content_hash = $2 AND expunged_at IS NULL`,
		accountID, hash).Scan(&localpart, &uploaded))
	require.Equal(t, srcLocalpart, localpart, "the moved row must keep the key the object lives under")
	require.True(t, uploaded)
}

// Insert-time dedup is key-qualified: identical bytes arriving under a different key
// are not "already uploaded" — the row stays unuploaded and a pending upload is queued
// so the uploader writes the object under the new key.
func TestInsertMessageDedupIsKeyQualified(t *testing.T) {
	if testing.Short() {
		t.Skip("database integration test")
	}
	db, accountID, inboxID := setupMessageTestDatabase(t)
	defer db.Close()
	ctx := context.Background()
	archive := keyTestMailbox(t, db, accountID, "Archive")
	_, srcLocalpart, hash := keyTestSeedUploaded(t, db, accountID, inboxID, "<dedup-key@example.com>")
	require.Equal(t, 0, keyTestPendingRows(t, db, accountID))

	insert := func(localpart, messageID string) (string, bool) {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		now := time.Now()
		opts := &InsertMessageOptions{
			AccountID: accountID, MailboxID: archive.ID, MailboxName: archive.Name,
			S3Domain: "example.com", S3Localpart: localpart,
			ContentHash: hash, MessageID: messageID,
			Flags: []imap.Flag{}, InternalDate: now, Size: 512, Subject: "identical bytes",
			PlaintextBody: "x", SentDate: now, InReplyTo: []string{},
		}
		upload := PendingUpload{AccountID: accountID, ContentHash: hash, InstanceID: "test-instance", Size: 512, CreatedAt: now, UpdatedAt: now}
		id, _, err := db.InsertMessage(ctx, tx, opts, upload)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		var gotLocalpart string
		var uploaded bool
		require.NoError(t, db.GetWritePool().QueryRow(ctx,
			`SELECT s3_localpart, uploaded FROM messages WHERE id = $1`, id).Scan(&gotLocalpart, &uploaded))
		return gotLocalpart, uploaded
	}

	// Same key: deduplicated, no upload needed.
	_, uploaded := insert(srcLocalpart, "<dedup-same-key@example.com>")
	require.True(t, uploaded, "same key ⇒ the object is there ⇒ dedup applies")
	require.Equal(t, 0, keyTestPendingRows(t, db, accountID))

	// Different key: no object under it yet, so the row must go through the uploader.
	_, uploaded = insert("renamed", "<dedup-other-key@example.com>")
	require.False(t, uploaded, "a different key has no object yet; dedup must not apply")
	require.Equal(t, 1, keyTestPendingRows(t, db, accountID), "a pending upload must be queued for the new key")
}

// CompleteS3Upload marks only the rows whose key was written (or already has a live
// uploaded sibling) and keeps the pending row while any row still lacks its object.
func TestCompleteS3UploadIsKeyQualified(t *testing.T) {
	if testing.Short() {
		t.Skip("database integration test")
	}
	db, accountID, inboxID := setupMessageTestDatabase(t)
	defer db.Close()
	ctx := context.Background()
	archive := keyTestMailbox(t, db, accountID, "Archive")

	// Two unuploaded rows for one hash under two keys, sharing one pending row.
	idA := insertTestMessage(t, db, accountID, inboxID, "INBOX", "key A", "<complete-a@example.com>")
	idB := insertTestMessage(t, db, accountID, archive.ID, archive.Name, "key B", "<complete-b@example.com>")
	var hash, hashB string
	require.NoError(t, db.GetWritePool().QueryRow(ctx, `SELECT content_hash FROM messages WHERE id = $1`, idA).Scan(&hash))
	require.NoError(t, db.GetWritePool().QueryRow(ctx, `SELECT content_hash FROM messages WHERE id = $1`, idB).Scan(&hashB))
	// Put B on the same hash as A under a second key; its own pending row goes with it.
	_, err := db.GetWritePool().Exec(ctx, `UPDATE messages SET content_hash = $1, s3_localpart = 'other' WHERE id = $2`, hash, idB)
	require.NoError(t, err)
	_, err = db.GetWritePool().Exec(ctx, `DELETE FROM pending_uploads WHERE account_id = $1 AND content_hash = $2`, accountID, hashB)
	require.NoError(t, err)
	require.Equal(t, 1, keyTestPendingRows(t, db, accountID))

	uploadedOf := func(id int64) bool {
		var u bool
		require.NoError(t, db.GetWritePool().QueryRow(ctx, `SELECT uploaded FROM messages WHERE id = $1`, id).Scan(&u))
		return u
	}
	complete := func(written []string) {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		require.NoError(t, db.CompleteS3Upload(ctx, tx, hash, accountID, written))
		require.NoError(t, tx.Commit(ctx))
	}

	// Only key A was written: A is done, B is not, and the pending row survives so the
	// next lease writes B (PendingUploadKeys lists exactly that key).
	complete([]string{fmt.Sprintf("example.com/test/%s", hash)})
	require.True(t, uploadedOf(idA))
	require.False(t, uploadedOf(idB), "a row whose key was not written must not be marked uploaded")
	require.Equal(t, 1, keyTestPendingRows(t, db, accountID), "the pending row stays while a key is still missing")
	keys, err := db.PendingUploadKeys(ctx, hash, accountID)
	require.NoError(t, err)
	require.Equal(t, []string{fmt.Sprintf("example.com/other/%s", hash)}, keys)

	// Key B written: everything is done and the pending row goes.
	complete([]string{fmt.Sprintf("example.com/other/%s", hash)})
	require.True(t, uploadedOf(idB))
	require.Equal(t, 0, keyTestPendingRows(t, db, accountID))
}

// A row whose key already has a live uploaded sibling is finalized from that sibling
// even when nothing was written in this pass — the state a dedup that ran just before
// an in-flight upload finalized leaves behind, which must not lease forever.
func TestCompleteS3UploadMarksFromLiveSibling(t *testing.T) {
	if testing.Short() {
		t.Skip("database integration test")
	}
	db, accountID, inboxID := setupMessageTestDatabase(t)
	defer db.Close()
	ctx := context.Background()
	archive := keyTestMailbox(t, db, accountID, "Archive")

	_, _, hash := keyTestSeedUploaded(t, db, accountID, inboxID, "<sibling-live@example.com>")
	// Same key, same hash, not yet marked, with a re-armed pending row.
	late := insertTestMessage(t, db, accountID, archive.ID, archive.Name, "late", "<sibling-late@example.com>")
	_, err := db.GetWritePool().Exec(ctx, `UPDATE messages SET content_hash = $1, uploaded = FALSE WHERE id = $2`, hash, late)
	require.NoError(t, err)
	_, err = db.GetWritePool().Exec(ctx, `DELETE FROM pending_uploads WHERE account_id = $1`, accountID)
	require.NoError(t, err)
	_, err = db.GetWritePool().Exec(ctx,
		`INSERT INTO pending_uploads (instance_id, content_hash, size, created_at, account_id) VALUES ('test-instance', $1, 512, now(), $2)`, hash, accountID)
	require.NoError(t, err)

	keys, err := db.PendingUploadKeys(ctx, hash, accountID)
	require.NoError(t, err)
	require.Empty(t, keys, "nothing to write: the key already has a live uploaded row")

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.CompleteS3Upload(ctx, tx, hash, accountID, nil))
	require.NoError(t, tx.Commit(ctx))

	var uploaded bool
	require.NoError(t, db.GetWritePool().QueryRow(ctx, `SELECT uploaded FROM messages WHERE id = $1`, late).Scan(&uploaded))
	require.True(t, uploaded, "the live sibling proves the object; the late row must be finalized from it")
	require.Equal(t, 0, keyTestPendingRows(t, db, accountID), "and the pending row must not be leased again")
}
