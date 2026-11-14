package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// One S3 object can be the body of rows of several accounts: a row's key is the address its
// account had when the row was written (s3_domain/s3_localpart), so an address that moved to
// another account brings that account's new rows onto the keys of the mail stored under it.
// A delete of the object and a claim of it must therefore exclude each other whichever
// accounts they act for (#557).
//
// Here the cleaner deletes accountID's orphan, its re-check done, and another account's
// delivery of the same body (a row under the same key and a pending upload) commits while
// the S3 DELETE may still be in flight. That upload must not pass the write gate until the
// delete is over: written now, the DELETE would remove it under its live row.
func TestS3OrphanDeleteKeepsOutAnotherAccountsUpload(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	database, _, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer database.Close()
	ctx := context.Background()
	suffix := time.Now().UnixNano()

	otherID := createTestAccount(t, database, fmt.Sprintf("s3lock-other-%d@example.com", suffix), "password")
	otherMailboxID := createTestMailbox(t, database, otherID, "INBOX")
	hash := fmt.Sprintf("s3lock_accounts_%d", suffix)
	localpart := fmt.Sprintf("moved-%d", suffix)

	insertKeyedMessage(t, database, accountID, mailboxID, 300, hash, localpart, true, time.Now().Add(-24*time.Hour))
	orphan := UserScopedObjectForCleanup{AccountID: accountID, ContentHash: hash, S3Domain: "example.com", S3Localpart: localpart}

	var gate S3WriteGate
	require.NoError(t, database.ExecuteWithLockedS3Orphans(ctx, []UserScopedObjectForCleanup{orphan}, time.Hour,
		func(ctx context.Context, orphans []UserScopedObjectForCleanup) error {
			require.Equal(t, []UserScopedObjectForCleanup{orphan}, orphans)
			// The S3 DELETE runs here. The other account's delivery commits meanwhile.
			insertKeyedMessage(t, database, otherID, otherMailboxID, 1, hash, localpart, false, time.Time{})
			pendingID := createPendingUpload(t, database, otherID, "other-instance", hash, 0, time.Time{}, 100)
			var err error
			gate, err = database.PassS3WriteGate(ctx, pendingID, otherID, hash, gateTestOwner, gateTestLease)
			return err
		}))
	assert.Equal(t, S3WriteBusy, gate, "another account's upload of the body was let write while its delete was in flight")
}
