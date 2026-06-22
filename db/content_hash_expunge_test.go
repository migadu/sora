package db

import (
	"context"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetMessagesByContentHash_IncludesExpunged verifies that content-hash lookup
// returns expunged (soft-deleted) messages with Expunged=true, rather than hiding
// them. This is what lets `verify` distinguish a message that is merely pending
// two-phase cleanup from a genuine orphan.
func TestGetMessagesByContentHash_IncludesExpunged(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupMessageTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	now := time.Now()
	const contentHash = "b97a6e89b97a6e89b97a6e89b97a6e89b97a6e89b97a6e89b97a6e89b97a6e89"

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)

	bodyStructure := imap.BodyStructure(&imap.BodyStructureSinglePart{
		Type: "text", Subtype: "plain", Encoding: "7bit", Size: 64,
	})
	_, uid, err := db.InsertMessage(ctx, tx,
		&InsertMessageOptions{
			AccountID:     accountID,
			MailboxID:     mailboxID,
			MailboxName:   "INBOX",
			S3Domain:      "example.com",
			S3Localpart:   "test",
			ContentHash:   contentHash,
			MessageID:     "<expunge-test@example.com>",
			Flags:         []imap.Flag{},
			InternalDate:  now,
			Size:          64,
			Subject:       "Expunge test",
			PlaintextBody: "body",
			SentDate:      now,
			BodyStructure: &bodyStructure,
		},
		PendingUpload{AccountID: accountID, ContentHash: contentHash, InstanceID: "test-instance", Size: 64},
	)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	// Live message: returned, not expunged.
	msgs, err := db.GetMessagesByContentHash(ctx, accountID, contentHash)
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	assert.False(t, msgs[0].Expunged, "freshly inserted message must not be reported expunged")

	// Expunge it (soft delete), then it must STILL be returned, flagged Expunged.
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = db.ExpungeMessageUIDs(ctx, tx2, mailboxID, imap.UID(uid))
	require.NoError(t, err)
	require.NoError(t, tx2.Commit(ctx))

	msgs, err = db.GetMessagesByContentHash(ctx, accountID, contentHash)
	require.NoError(t, err)
	require.Len(t, msgs, 1, "expunged message must still be returned (not treated as an orphan)")
	assert.True(t, msgs[0].Expunged, "expunged message must be reported with Expunged=true")
}
