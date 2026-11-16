//go:build integration

package cleaner

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Rows of different accounts can point at one S3 object. A row's key is
// <s3_domain>/<s3_localpart>/<hash>, from the address its account had when the row was
// written, and addresses move between accounts: once one has, a cross-account COPY into a
// mailbox of the new owner reuses the object stored under the address, and a delivery or
// an import of the same bytes writes the same key. These tests run the cleaner's S3 phase
// and the account purge against a live database, with an S3 that records the keys it is
// asked to delete.

const sharedObjectGrace = 24 * time.Hour

// keyRecorder is an S3 on which every delete succeeds; it records the keys.
type keyRecorder struct{ keys []string }

func (r *keyRecorder) DeleteBulkWithRetry(_ context.Context, keys []string) map[string]error {
	r.keys = append(r.keys, keys...)
	return nil
}

// sharedObject is one object, example.com/<localpart>/<hash>, and two accounts: a, whose
// address the object was stored under, and b, the account the address moved to.
type sharedObject struct {
	rdb       *resilient.ResilientDatabase
	hash      string
	localpart string
	key       string
	emailA    string
	a, b      int64
	inboxA    int64
	inboxB    int64
	uid       int
}

func newSharedObject(t *testing.T) *sharedObject {
	t.Helper()
	ctx := context.Background()
	name := os.Getenv("SORA_TEST_DB_NAME")
	if name == "" {
		name = "sora_test_db"
	}
	rdb, err := resilient.NewResilientDatabase(ctx, &config.DatabaseConfig{
		Write: &config.DatabaseEndpointConfig{Hosts: []string{"localhost"}, Port: "5432", User: "postgres", Name: name},
	}, false, true)
	require.NoError(t, err, "test database %s", name)
	t.Cleanup(rdb.Close)

	stamp := time.Now().UnixNano()
	o := &sharedObject{
		rdb:       rdb,
		hash:      fmt.Sprintf("shared-%d", stamp),
		localpart: fmt.Sprintf("moved-%d", stamp),
		emailA:    fmt.Sprintf("shared-a-%d@example.com", stamp),
	}
	o.key = helpers.NewS3Key("example.com", o.localpart, o.hash)
	o.a, o.inboxA = o.newAccount(t, o.emailA)
	o.b, o.inboxB = o.newAccount(t, fmt.Sprintf("shared-b-%d@example.com", stamp))
	return o
}

func (o *sharedObject) newAccount(t *testing.T, email string) (accountID, inboxID int64) {
	t.Helper()
	ctx := context.Background()
	accountID, err := o.rdb.CreateAccountWithRetry(ctx, db.CreateAccountRequest{Email: email, Password: "password", IsPrimary: true, HashType: "bcrypt"})
	require.NoError(t, err)
	require.NoError(t, o.rdb.CreateDefaultMailboxesWithRetry(ctx, accountID))
	inbox, err := o.rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	require.NoError(t, err)
	return accountID, inbox.ID
}

// addRow stores a message of the account in its INBOX under example.com/<localpart>/<hash>.
// A zero expungedAt leaves it live.
func (o *sharedObject) addRow(t *testing.T, accountID, inboxID int64, localpart string, uploaded bool, expungedAt time.Time) {
	t.Helper()
	o.uid++
	var expunged any
	if !expungedAt.IsZero() {
		expunged = expungedAt
	}
	_, err := o.rdb.ExecWithRetry(context.Background(), `
		WITH inserted AS (
			INSERT INTO messages (account_id, mailbox_id, uid, content_hash, sent_date, internal_date, size, uploaded, s3_domain, s3_localpart, message_id, body_structure, recipients_json, created_modseq, expunged_at, expunged_modseq)
			VALUES ($1, $2, $3, $4, now(), now(), 100, $5, 'example.com', $6, $7, 'body', '[]', nextval('messages_modseq'), $8::timestamptz,
			        CASE WHEN $8::timestamptz IS NULL THEN NULL ELSE nextval('messages_modseq') END)
			RETURNING id, mailbox_id
		)
		INSERT INTO message_state (message_id, mailbox_id, flags)
		SELECT id, mailbox_id, 0 FROM inserted
	`, accountID, inboxID, o.uid, o.hash, uploaded, localpart, fmt.Sprintf("<%s-%d@example.com>", o.hash, o.uid), expunged)
	require.NoError(t, err)
}

// rows counts the account's message rows of the object's hash.
func (o *sharedObject) rows(t *testing.T, accountID int64) int {
	t.Helper()
	var n int
	require.NoError(t, o.rdb.QueryRowWithRetry(context.Background(),
		`SELECT count(*) FROM messages WHERE account_id = $1 AND content_hash = $2`, accountID, o.hash).Scan(&n))
	return n
}

// candidate is the cleaner's candidate for the account's rows under the object's key.
func (o *sharedObject) candidate(accountID int64) db.UserScopedObjectForCleanup {
	return db.UserScopedObjectForCleanup{AccountID: accountID, ContentHash: o.hash, S3Domain: "example.com", S3Localpart: o.localpart}
}

func (o *sharedObject) reap(t *testing.T, s3 *keyRecorder, candidates ...db.UserScopedObjectForCleanup) {
	t.Helper()
	_, _, err := reapS3Objects(context.Background(), o.rdb, s3, sharedObjectGrace, candidates)
	require.NoError(t, err)
}

// A's rows under the key are expunged past the grace period, B's row under it is live.
// The cleaner deletes A's rows, and must leave the object B reads.
func TestCleanerKeepsAnObjectAnotherAccountStillReads(t *testing.T) {
	o := newSharedObject(t)
	o.addRow(t, o.a, o.inboxA, o.localpart, true, time.Now().Add(-2*sharedObjectGrace))
	o.addRow(t, o.b, o.inboxB, o.localpart, true, time.Time{})

	s3 := &keyRecorder{}
	o.reap(t, s3, o.candidate(o.a))

	assert.NotContains(t, s3.keys, o.key, "the object another account's live row reads was deleted")
	assert.Equal(t, 0, o.rows(t, o.a), "the account's expunged rows go even though the object stays")
	assert.Equal(t, 1, o.rows(t, o.b), "the other account's row must stay")
}

// B's rows under the key are expunged past the grace period as well, but B's candidate
// is not in this batch. The object stays for B's rows, and goes with them.
func TestCleanerLeavesASharedObjectToItsLastAccount(t *testing.T) {
	o := newSharedObject(t)
	o.addRow(t, o.a, o.inboxA, o.localpart, true, time.Now().Add(-2*sharedObjectGrace))
	o.addRow(t, o.b, o.inboxB, o.localpart, true, time.Now().Add(-2*sharedObjectGrace))

	s3 := &keyRecorder{}
	o.reap(t, s3, o.candidate(o.a))
	assert.NotContains(t, s3.keys, o.key, "the object was deleted while another account's rows still point at it")
	assert.Equal(t, 0, o.rows(t, o.a), "the account's expunged rows go even though the object stays")
	require.Equal(t, 1, o.rows(t, o.b))

	o.reap(t, s3, o.candidate(o.b))
	assert.Contains(t, s3.keys, o.key, "the object goes with the last rows that point at it")
	assert.Equal(t, 0, o.rows(t, o.b))
}

// Both accounts are done with the object and both candidates are in one batch: the object
// is deleted once, and the rows of both accounts go.
func TestCleanerDeletesAnObjectEveryAccountIsDoneWith(t *testing.T) {
	o := newSharedObject(t)
	o.addRow(t, o.a, o.inboxA, o.localpart, true, time.Now().Add(-2*sharedObjectGrace))
	o.addRow(t, o.b, o.inboxB, o.localpart, true, time.Now().Add(-2*sharedObjectGrace))

	s3 := &keyRecorder{}
	o.reap(t, s3, o.candidate(o.a), o.candidate(o.b))

	assert.Equal(t, []string{o.key}, s3.keys, "one delete of the object")
	assert.Equal(t, 0, o.rows(t, o.a), "rows of the first account under the key were left")
	assert.Equal(t, 0, o.rows(t, o.b), "rows of the second account under the key were left")
}

// Another account has an upload of the body pending. It writes the keys of that account's
// rows, which can be this key by the time it writes, so nothing is deleted this cycle.
func TestCleanerWaitsForAnotherAccountsUploadOfTheBody(t *testing.T) {
	o := newSharedObject(t)
	o.addRow(t, o.a, o.inboxA, o.localpart, true, time.Now().Add(-2*sharedObjectGrace))
	o.addRow(t, o.b, o.inboxB, "elsewhere", false, time.Time{})
	_, err := o.rdb.ExecWithRetry(context.Background(),
		`INSERT INTO pending_uploads (account_id, instance_id, content_hash, size) VALUES ($1, 'other-node', $2, 100)`, o.b, o.hash)
	require.NoError(t, err)

	s3 := &keyRecorder{}
	o.reap(t, s3, o.candidate(o.a))

	assert.NotContains(t, s3.keys, o.key, "the object was deleted while another account's upload of the body was pending")
	assert.Equal(t, 1, o.rows(t, o.a), "the rows stay until the upload is done")
}

// Purging A must not take the object B reads, and must still finish: A's rows under the
// key go, and A with them.
func TestPurgeKeepsAnObjectAnotherAccountStillReads(t *testing.T) {
	o := newSharedObject(t)
	ctx := context.Background()
	o.addRow(t, o.a, o.inboxA, o.localpart, true, time.Time{})
	o.addRow(t, o.b, o.inboxB, o.localpart, true, time.Time{})

	purged, _, err := o.rdb.RequestAccountPurgeWithRetry(ctx, o.emailA)
	require.NoError(t, err)
	require.Equal(t, o.a, purged)

	s3 := &keyRecorder{}
	_, err = PurgeAccount(ctx, o.rdb, s3, o.a, "global-hash-v1")
	require.NoError(t, err)

	assert.NotContains(t, s3.keys, o.key, "the purge deleted the object another account's live row reads")
	var accounts int
	require.NoError(t, o.rdb.QueryRowWithRetry(ctx, `SELECT count(*) FROM accounts WHERE id = $1`, o.a).Scan(&accounts))
	assert.Equal(t, 0, accounts, "the purged account must be gone")
	assert.Equal(t, 1, o.rows(t, o.b), "the other account's row must stay")
}
