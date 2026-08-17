//go:build integration

package resilient_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// restoreFixture inserts one message into mailboxID and returns its row id and uid.
func restoreFixture(t *testing.T, rdb *resilient.ResilientDatabase, accountID, mailboxID int64, mailboxName, messageID string) (int64, imap.UID) {
	t.Helper()
	ctx := context.Background()
	tx, err := rdb.BeginTxWithRetry(ctx, pgx.TxOptions{})
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	now := time.Now()
	opts := &db.InsertMessageOptions{
		AccountID:     accountID,
		MailboxID:     mailboxID,
		MailboxName:   mailboxName,
		S3Domain:      "example.com",
		S3Localpart:   "restore",
		ContentHash:   "hash-" + messageID,
		MessageID:     messageID,
		Flags:         []imap.Flag{imap.FlagSeen},
		InternalDate:  now,
		Size:          256,
		Subject:       "restore " + messageID,
		PlaintextBody: "body",
		SentDate:      now,
		InReplyTo:     []string{},
	}
	upload := db.PendingUpload{AccountID: accountID, ContentHash: opts.ContentHash, InstanceID: "test", Size: 256, CreatedAt: now, UpdatedAt: now}
	id, uid, err := rdb.GetDatabase().InsertMessage(ctx, tx, opts, upload)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	return id, imap.UID(uid)
}

func expungeFixture(t *testing.T, rdb *resilient.ResilientDatabase, mailboxID int64, uid imap.UID) {
	t.Helper()
	ctx := context.Background()
	tx, err := rdb.BeginTxWithRetry(ctx, pgx.TxOptions{})
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	_, err = rdb.GetDatabase().ExpungeMessageUIDs(ctx, tx, mailboxID, uid)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
}

func liveCount(t *testing.T, rdb *resilient.ResilientDatabase, mailboxID int64) int {
	t.Helper()
	var n int
	err := rdb.GetDatabase().GetReadPool().QueryRow(context.Background(),
		"SELECT COUNT(*) FROM messages WHERE mailbox_id = $1 AND expunged_at IS NULL", mailboxID).Scan(&n)
	require.NoError(t, err)
	return n
}

// TestRestoreMessagesWithRetry_Chunked verifies that a restore larger than one chunk is
// fully restored across several transactions, that a duplicate tombstone straddling a
// chunk boundary yields exactly one live copy, that re-running is a no-op, and that the
// restored messages get UIDs in arrival order.
func TestRestoreMessagesWithRetry_Chunked(t *testing.T) {
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)
	inbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	require.NoError(t, err)

	since := time.Now().Add(-time.Minute)

	// 7 distinct messages + 1 duplicate tombstone of the first Message-ID = 8 tombstones.
	const n = 7
	ids := make([]int64, 0, n+1)
	for i := 0; i < n; i++ {
		id, uid := restoreFixture(t, rdb, accountID, inbox.ID, "INBOX", fmt.Sprintf("<chunk-%d-%d@example.com>", i, time.Now().UnixNano()))
		ids = append(ids, id)
		expungeFixture(t, rdb, inbox.ID, uid)
	}
	var firstMessageID string
	require.NoError(t, rdb.GetDatabase().GetReadPool().QueryRow(ctx, "SELECT message_id FROM messages WHERE id = $1", ids[0]).Scan(&firstMessageID))
	dupID, dupUID := restoreFixture(t, rdb, accountID, inbox.ID, "INBOX", firstMessageID)
	expungeFixture(t, rdb, inbox.ID, dupUID)
	ids = append(ids, dupID)

	require.Equal(t, 0, liveCount(t, rdb, inbox.ID), "all fixtures are tombstones before restore")

	// Chunk size 3 over 8 candidates → 3 transactions (3,3,2); the duplicate pair
	// (ids[0] and dupID) is guaranteed to be split across chunks by the arrival-order sort.
	restored, err := rdb.RestoreMessagesChunkedForTest(ctx, db.RestoreMessagesParams{Email: account.Email, Since: &since}, 3)
	require.NoError(t, err)
	assert.Equal(t, int64(n), restored, "every distinct message restored, the duplicate tombstone skipped")
	assert.Equal(t, n, liveCount(t, rdb, inbox.ID))

	var liveDup int
	require.NoError(t, rdb.GetDatabase().GetReadPool().QueryRow(ctx,
		"SELECT COUNT(*) FROM messages WHERE mailbox_id = $1 AND message_id = $2 AND expunged_at IS NULL", inbox.ID, firstMessageID).Scan(&liveDup))
	assert.Equal(t, 1, liveDup, "a duplicate tombstone across a chunk boundary must not produce a second live copy")

	// New UIDs follow arrival order (internal_date, id) — ids were inserted in order.
	rows, err := rdb.GetDatabase().GetReadPool().Query(ctx,
		"SELECT id FROM messages WHERE mailbox_id = $1 AND expunged_at IS NULL ORDER BY uid", inbox.ID)
	require.NoError(t, err)
	var byUID []int64
	for rows.Next() {
		var id int64
		require.NoError(t, rows.Scan(&id))
		byUID = append(byUID, id)
	}
	rows.Close()
	assert.Equal(t, ids[:n], byUID, "restored UIDs must be assigned in arrival order")

	// Idempotent: nothing left to restore (the remaining tombstone is skipped: live copy exists).
	restored, err = rdb.RestoreMessagesChunkedForTest(ctx, db.RestoreMessagesParams{Email: account.Email, Since: &since}, 3)
	require.NoError(t, err)
	assert.Equal(t, int64(0), restored)
	assert.Equal(t, n, liveCount(t, rdb, inbox.ID))
}

// TestRestoreMessagesWithRetry_PartialProgressSurvivesFailure verifies the contract the
// CLI/API rely on: when a later chunk fails, the chunks committed before it stay
// restored and the returned count says how many, so the operator can re-run.
func TestRestoreMessagesWithRetry_PartialProgressSurvivesFailure(t *testing.T) {
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)
	inbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	require.NoError(t, err)

	since := time.Now().Add(-time.Minute)

	// Two restorable tombstones, then one that cannot be restored: a row without a
	// recorded mailbox_path (sorts last, so it lands in the final chunk on its own).
	var uids []imap.UID
	var poisonID int64
	for i := 0; i < 3; i++ {
		id, uid := restoreFixture(t, rdb, accountID, inbox.ID, "INBOX", fmt.Sprintf("<partial-%d-%d@example.com>", i, time.Now().UnixNano()))
		uids = append(uids, uid)
		if i == 2 {
			poisonID = id
		}
	}
	for _, uid := range uids {
		expungeFixture(t, rdb, inbox.ID, uid)
	}
	_, err = rdb.GetDatabase().GetWritePool().Exec(ctx, "UPDATE messages SET mailbox_path = NULL WHERE id = $1", poisonID)
	require.NoError(t, err)

	restored, err := rdb.RestoreMessagesChunkedForTest(ctx, db.RestoreMessagesParams{Email: account.Email, Since: &since}, 1)
	require.Error(t, err, "the unrestorable row must surface as an error")
	assert.Contains(t, err.Error(), fmt.Sprintf("message %d has no recorded mailbox path", poisonID))
	assert.Contains(t, err.Error(), "restore stopped at candidates 3-3 of 3 after restoring 2")
	assert.Equal(t, int64(2), restored, "count reports the messages restored before the failure")
	assert.Equal(t, 2, liveCount(t, rdb, inbox.ID), "chunks committed before the failure stay restored")
}

// TestRestoreMessagesWithRetry_NotBoundedByWriteTimeout pins the fix for the production
// failure "failed to restore message_state for message N: timeout: context deadline
// exceeded": a restore of many messages must not run inside one transaction bounded by
// write_timeout. With write_timeout deliberately tiny, a 500-message restore (several
// thousand statements) can only succeed if it is split into chunks that each get the
// admin timeout — which is exactly what the chunked implementation does.
func TestRestoreMessagesWithRetry_NotBoundedByWriteTimeout(t *testing.T) {
	dbName := os.Getenv("SORA_TEST_DB_NAME")
	if dbName == "" {
		dbName = "sora_test_db"
	}
	cfg := &config.DatabaseConfig{
		WriteTimeout: "50ms", // far below what a 500-message restore needs in one transaction
		Write: &config.DatabaseEndpointConfig{
			Hosts: []string{"localhost"}, Port: "5432", User: "postgres", Name: dbName,
		},
	}
	rdb, err := resilient.NewResilientDatabase(context.Background(), cfg, true, true)
	require.NoError(t, err)
	t.Cleanup(rdb.Close)

	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)
	inbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	require.NoError(t, err)

	const n = 500
	since := time.Now().Add(-time.Minute)
	uids := make([]imap.UID, 0, n)
	for i := 0; i < n; i++ {
		_, uid := restoreFixture(t, rdb, accountID, inbox.ID, "INBOX", fmt.Sprintf("<bulk-%d-%d@example.com>", i, time.Now().UnixNano()))
		uids = append(uids, uid)
	}
	tx, err := rdb.BeginTxWithRetry(ctx, pgx.TxOptions{})
	require.NoError(t, err)
	_, err = rdb.GetDatabase().ExpungeMessageUIDs(ctx, tx, inbox.ID, uids...)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	require.Equal(t, 0, liveCount(t, rdb, inbox.ID))

	restored, err := rdb.RestoreMessagesWithRetry(ctx, db.RestoreMessagesParams{Email: account.Email, Since: &since})
	require.NoError(t, err, "a large restore must not be bounded by a single write_timeout")
	assert.Equal(t, int64(n), restored)
	assert.Equal(t, n, liveCount(t, rdb, inbox.ID))
}
