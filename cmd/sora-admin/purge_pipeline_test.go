//go:build integration
// +build integration

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/stretchr/testify/require"
)

// These tests pin what a purge must leave behind: nothing at all when it succeeds, and a
// soft-deleted account that still has its credentials when it does not, so that running it
// again (or the cleaner, after the grace period) finishes the job.

// TestAccountPurgeWithMessageNotYetUploaded purges an account holding a message whose body
// has not reached S3 yet. messages.account_id is ON DELETE RESTRICT, so a purge that only
// reaps uploaded rows cannot delete the account row; if it deleted the credentials first,
// the account is left behind with no address to find it by.
func TestAccountPurgeWithMessageNotYetUploaded(t *testing.T) {
	ctx := context.Background()
	rdb := setupPurgeTestDatabase(t)
	defer rdb.Close()
	s3Storage := createPurgeTestS3Storage(t)
	cfg := createPurgeTestConfig(t)

	email := fmt.Sprintf("test-purge-pending-%d@example.com", time.Now().UnixNano())
	createPurgeTestAccount(t, rdb, email, "password123")
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, email)
	require.NoError(t, err)

	createPurgeTestMessages(t, ctx, rdb, s3Storage, accountID, email, 2)
	insertPurgeTestMessage(t, ctx, rdb, s3Storage, accountID, email, "pending", false)

	require.NoError(t, purgeAccountWithStorage(ctx, cfg, rdb, accountID, email, s3Storage))

	requireAccountGone(t, ctx, rdb, accountID, email)
	require.Equal(t, 0, countS3ObjectsForAccount(t, s3Storage, email), "no S3 object may outlive the account")
}

// TestAccountPurgeRemovesSearchIndex: messages_fts_v2 has no foreign key to accounts, so
// nothing removes an account's search vectors unless the purge does.
func TestAccountPurgeRemovesSearchIndex(t *testing.T) {
	ctx := context.Background()
	rdb := setupPurgeTestDatabase(t)
	defer rdb.Close()
	s3Storage := createPurgeTestS3Storage(t)
	cfg := createPurgeTestConfig(t)

	email := fmt.Sprintf("test-purge-fts-%d@example.com", time.Now().UnixNano())
	createPurgeTestAccount(t, rdb, email, "password123")
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, email)
	require.NoError(t, err)

	insertPurgeTestMessage(t, ctx, rdb, s3Storage, accountID, email, "indexed-1", true)
	insertPurgeTestMessage(t, ctx, rdb, s3Storage, accountID, email, "indexed-2", true)
	require.Equal(t, 2, countAccountRows(t, ctx, rdb, "messages_fts_v2", accountID), "precondition: the messages are indexed")

	require.NoError(t, purgeAccountWithStorage(ctx, cfg, rdb, accountID, email, s3Storage))

	requireAccountGone(t, ctx, rdb, accountID, email)
	require.Equal(t, 0, countAccountRows(t, ctx, rdb, "messages_fts_v2", accountID), "search vectors must go with the account")
}

// TestAccountPurgeFailureLeavesAccountRetryable: when S3 refuses the deletes, the purge
// fails, the account stays out of service and findable, and a second run completes it.
func TestAccountPurgeFailureLeavesAccountRetryable(t *testing.T) {
	ctx := context.Background()
	rdb := setupPurgeTestDatabase(t)
	defer rdb.Close()
	s3Storage := createPurgeTestS3Storage(t)
	cfg := createPurgeTestConfig(t)

	email := fmt.Sprintf("test-purge-retry-%d@example.com", time.Now().UnixNano())
	createPurgeTestAccount(t, rdb, email, "password123")
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, email)
	require.NoError(t, err)
	createPurgeTestMessages(t, ctx, rdb, s3Storage, accountID, email, 3)

	broken := &failingDeleteStorage{objectStorage: s3Storage}
	require.Error(t, purgeAccountWithStorage(ctx, cfg, rdb, accountID, email, broken))

	stillThere, err := rdb.GetAccountIDByEmailWithRetry(ctx, email)
	require.NoError(t, err, "a failed purge must leave the account findable by its address")
	require.Equal(t, accountID, stillThere)
	var deleted, marked bool
	require.NoError(t, rdb.QueryRowWithRetry(ctx, `SELECT deleted_at IS NOT NULL, purge_requested_at IS NOT NULL FROM accounts WHERE id = $1`, accountID).Scan(&deleted, &marked))
	require.True(t, deleted, "a failed purge must leave the account out of service")
	require.True(t, marked, "a failed purge must leave the account marked, so the server's purge worker finishes it")

	require.NoError(t, purgeAccountWithStorage(ctx, cfg, rdb, accountID, email, s3Storage))
	requireAccountGone(t, ctx, rdb, accountID, email)
	require.Equal(t, 0, countS3ObjectsForAccount(t, s3Storage, email))
}

// failingDeleteStorage refuses every delete, like a provider rejecting the credentials.
type failingDeleteStorage struct {
	objectStorage
}

func (f *failingDeleteStorage) Delete(key string) error {
	return errors.New("403 AccessDenied")
}

// insertPurgeTestMessage adds one INBOX message with a plaintext body (so it is staged for
// search). uploaded=true also writes its body to S3 and marks the row uploaded, the state
// the uploader leaves; uploaded=false leaves it queued, as delivery does.
func insertPurgeTestMessage(t *testing.T, ctx context.Context, rdb *resilient.ResilientDatabase, s3Storage objectStorage, accountID int64, email, tag string, uploaded bool) {
	t.Helper()

	mailbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	require.NoError(t, err)
	parts := splitPurgeEmail(email)
	require.Len(t, parts, 2)

	body := []byte(fmt.Sprintf("Subject: %s\r\n\r\nbody of %s", tag, tag))
	contentHash := fmt.Sprintf("hash-%d-%s", accountID, tag)
	s3Key := fmt.Sprintf("%s/%s/%s", parts[1], parts[0], contentHash)
	if uploaded {
		require.NoError(t, s3Storage.Put(s3Key, bytes.NewReader(body), int64(len(body))))
	}

	var bs imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain"}
	hostname, _ := os.Hostname()
	msgID, _, err := rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
		AccountID:     accountID,
		MailboxID:     mailbox.ID,
		MailboxName:   "INBOX",
		S3Domain:      parts[1],
		S3Localpart:   parts[0],
		ContentHash:   contentHash,
		MessageID:     fmt.Sprintf("<%s-%d@example.com>", tag, accountID),
		InternalDate:  time.Now(),
		Size:          int64(len(body)),
		PlaintextBody: "body of " + tag,
		BodyStructure: &bs,
	}, db.PendingUpload{InstanceID: hostname, ContentHash: contentHash, Size: int64(len(body)), AccountID: accountID})
	require.NoError(t, err)

	if uploaded {
		_, err = rdb.ExecWithRetry(ctx, `UPDATE messages SET uploaded = TRUE WHERE id = $1`, msgID)
		require.NoError(t, err)
		_, err = rdb.ExecWithRetry(ctx, `DELETE FROM pending_uploads WHERE account_id = $1 AND content_hash = $2`, accountID, contentHash)
		require.NoError(t, err)
	}
}

// countAccountRows counts a table's rows for an account. table is a test constant.
func countAccountRows(t *testing.T, ctx context.Context, rdb *resilient.ResilientDatabase, table string, accountID int64) int {
	t.Helper()
	column := "account_id"
	if table == "accounts" {
		column = "id"
	}
	var n int
	require.NoError(t, rdb.QueryRowWithRetry(ctx, `SELECT count(*) FROM `+table+` WHERE `+column+` = $1`, accountID).Scan(&n))
	return n
}

// requireAccountGone asserts that no row of any kind is left for the account.
func requireAccountGone(t *testing.T, ctx context.Context, rdb *resilient.ResilientDatabase, accountID int64, email string) {
	t.Helper()
	for _, table := range []string{"accounts", "credentials", "messages", "mailboxes", "pending_uploads", "sieve_scripts", "messages_fts_v2"} {
		require.Equal(t, 0, countAccountRows(t, ctx, rdb, table, accountID), "%s rows left for purged account", table)
	}
	result, err := rdb.AccountExistsWithRetry(ctx, email)
	require.NoError(t, err)
	require.False(t, result.Exists)
}

// TestDomainPurgeResumesAccountLeftOutOfService: a purge that failed leaves its account
// soft-deleted. Re-running the domain purge has to pick that account up again, not take
// it for already purged.
func TestDomainPurgeResumesAccountLeftOutOfService(t *testing.T) {
	ctx := context.Background()
	rdb := setupPurgeTestDatabase(t)
	defer rdb.Close()
	s3Storage := createPurgeTestS3Storage(t)
	cfg := createPurgeTestConfig(t)

	domain := fmt.Sprintf("purge-resume-%d.example.com", time.Now().UnixNano())
	var emails []string
	var ids []int64
	for i := 0; i < 2; i++ {
		email := fmt.Sprintf("user%d@%s", i, domain)
		createPurgeTestAccount(t, rdb, email, "password123")
		id, err := rdb.GetAccountIDByEmailWithRetry(ctx, email)
		require.NoError(t, err)
		createPurgeTestMessages(t, ctx, rdb, s3Storage, id, email, 2)
		emails = append(emails, email)
		ids = append(ids, id)
	}
	// What an earlier, failed purge of the first account left behind.
	require.NoError(t, rdb.DeleteAccountWithRetry(ctx, emails[0]))

	require.NoError(t, purgeDomainWithStorage(ctx, cfg, rdb, domain, s3Storage))

	for i, email := range emails {
		requireAccountGone(t, ctx, rdb, ids[i], email)
		require.Equal(t, 0, countS3ObjectsForAccount(t, s3Storage, email), "S3 objects left for %s", email)
	}
}

// TestAccountPurgeWaitsForServerPurgeWorker: once the account is marked, a server's purge
// worker may already be purging it and hold its lock. The command must not run a second
// purge alongside; it waits for the worker and reports the outcome.
func TestAccountPurgeWaitsForServerPurgeWorker(t *testing.T) {
	ctx := context.Background()
	rdb := setupPurgeTestDatabase(t)
	defer rdb.Close()
	s3Storage := createPurgeTestS3Storage(t)
	cfg := createPurgeTestConfig(t)

	email := fmt.Sprintf("test-purge-held-%d@example.com", time.Now().UnixNano())
	createPurgeTestAccount(t, rdb, email, "password123")
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, email)
	require.NoError(t, err)
	createPurgeTestMessages(t, ctx, rdb, s3Storage, accountID, email, 2)

	// What a purge worker mid-purge looks like from outside: the account's lock is held.
	tx, err := rdb.BeginTxWithRetry(ctx, pgx.TxOptions{})
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, db.AccountPurgeLockID(accountID))
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() { done <- purgeAccountWithStorage(ctx, cfg, rdb, accountID, email, s3Storage) }()
	select {
	case err := <-done:
		_ = tx.Rollback(ctx)
		t.Fatalf("the command returned (%v) while a purge worker held the account", err)
	case <-time.After(2 * time.Second):
	}
	require.Equal(t, 1, countAccountRows(t, ctx, rdb, "accounts", accountID), "the command purged the account under the worker's lock")

	require.NoError(t, tx.Rollback(ctx))
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(30 * time.Second):
		t.Fatal("the command did not finish once the lock was released")
	}
	requireAccountGone(t, ctx, rdb, accountID, email)
}

// TestAccountPurgeFollowsTheAddress: the address decides which account is purged. If the
// id the caller resolved earlier no longer matches (the address moved to another account
// in between), the account behind the address is the one taken out of service and purged,
// and the account the stale id named is left alone.
func TestAccountPurgeFollowsTheAddress(t *testing.T) {
	ctx := context.Background()
	rdb := setupPurgeTestDatabase(t)
	defer rdb.Close()
	s3Storage := createPurgeTestS3Storage(t)
	cfg := createPurgeTestConfig(t)

	stamp := time.Now().UnixNano()
	emailA := fmt.Sprintf("test-purge-stale-a-%d@example.com", stamp)
	emailB := fmt.Sprintf("test-purge-stale-b-%d@example.com", stamp)
	alias := fmt.Sprintf("test-purge-stale-x-%d@example.com", stamp)
	createPurgeTestAccount(t, rdb, emailA, "password123")
	createPurgeTestAccount(t, rdb, emailB, "password123")
	idA, err := rdb.GetAccountIDByEmailWithRetry(ctx, emailA)
	require.NoError(t, err)
	idB, err := rdb.GetAccountIDByEmailWithRetry(ctx, emailB)
	require.NoError(t, err)
	createPurgeTestMessages(t, ctx, rdb, s3Storage, idB, emailB, 2)

	// The alias was A's when the caller resolved it, and B's by the time the purge ran.
	require.NoError(t, rdb.AddCredentialWithRetry(ctx, db.AddCredentialRequest{AccountID: idA, NewEmail: alias, NewPassword: "password123", NewHashType: "bcrypt"}))
	_, err = rdb.ExecWithRetry(ctx, `UPDATE credentials SET account_id = $1 WHERE LOWER(address) = LOWER($2)`, idB, alias)
	require.NoError(t, err)

	require.NoError(t, purgeAccountWithStorage(ctx, cfg, rdb, idA, alias, s3Storage))

	requireAccountGone(t, ctx, rdb, idB, emailB)
	var deletedA bool
	require.NoError(t, rdb.QueryRowWithRetry(ctx, `SELECT deleted_at IS NOT NULL FROM accounts WHERE id = $1`, idA).Scan(&deletedA))
	require.False(t, deletedA, "the account the stale id named must be left in service")
}
