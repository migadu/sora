package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFTSBatchInsertSkipsIndexUnderDefaultConfig proves that the maildir importer's
// batch insert path (InsertMessagesFromImporterBatch -> InsertMessagesBatch) creates
// NO messages_fts row under the DEFAULT configuration (fts_retention unset => 0 =>
// "keep FTS forever"), while the single-message path (InsertMessageFromImporter)
// with the exact same zero FTSRetention DOES create one.
//
// The single-message path guards the FTS insert with:
//
//	if FTSRetention == 0 || SentDate.IsZero() || !SentDate.Before(now-FTSRetention) { insert }
//
// The batch path inverts the FTSRetention==0 clause onto the SKIP side:
//
//	if FTSRetention == 0 || (!SentDate.IsZero() && SentDate.Before(now-FTSRetention)) { skip }
//
// so "no retention limit" is read as "never index".
func TestFTSBatchInsertSkipsIndexUnderDefaultConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database, _, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer database.Close()

	ctx := context.Background()
	stamp := time.Now().UnixNano()

	const batchToken = "zzbatchftstokenzz"
	const singleToken = "zzsingleftstokenzz"

	batchHash := fmt.Sprintf("batchhash_%d", stamp)
	singleHash := fmt.Sprintf("singlehash_%d", stamp)

	bs := imap.BodyStructure(&imap.BodyStructureSinglePart{Type: "text", Subtype: "plain", Size: 100})
	sentDate := time.Now().Add(-24 * time.Hour)

	// Options are built exactly as cmd/sora-admin/importer.go:1827-1870 builds them
	// for the batch import path: note that FTSRetention is NOT set (zero value),
	// which is also what the default config yields (fts_retention unset => keep forever).
	newOpts := func(hash, msgID, token string, uid uint32) *InsertMessageOptions {
		return &InsertMessageOptions{
			AccountID:     accountID,
			MailboxID:     mailboxID,
			MailboxName:   "INBOX",
			S3Domain:      "example.com",
			S3Localpart:   fmt.Sprintf("lp-%d", uid),
			ContentHash:   hash,
			MessageID:     msgID,
			Flags:         []imap.Flag{imap.FlagSeen},
			InternalDate:  sentDate,
			Size:          1024,
			Subject:       "importer fts probe",
			PlaintextBody: "hello world " + token + " end of body",
			SentDate:      sentDate,
			BodyStructure: &bs,
			Recipients: []helpers.Recipient{
				{Name: "Sender", EmailAddress: "sender@example.com", AddressType: "from"},
				{Name: "Rcpt", EmailAddress: "rcpt@example.com", AddressType: "to"},
			},
			// FTSRetention intentionally left at its zero value (default config).
		}
	}

	// --- Path A: BATCH insert (what the maildir importer actually uses) ---
	batchOpt := newOpts(batchHash, fmt.Sprintf("<batch-%d@test>", stamp), batchToken, 1)
	txA, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, _, insertedHashes, err := database.InsertMessagesFromImporterBatch(ctx, txA, []*InsertMessageOptions{batchOpt})
	require.NoError(t, err, "batch insert must succeed")
	require.NoError(t, txA.Commit(ctx))
	require.Equal(t, []string{batchHash}, insertedHashes, "batch must report the message as inserted")

	// --- Path B: SINGLE insert, identical zero FTSRetention (control) ---
	singleOpt := newOpts(singleHash, fmt.Sprintf("<single-%d@test>", stamp), singleToken, 2)
	txB, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, _, err = database.InsertMessageFromImporter(ctx, txB, singleOpt)
	require.NoError(t, err, "single insert must succeed")
	require.NoError(t, txB.Commit(ctx))

	countFTS := func(hash string) int {
		var n int
		require.NoError(t, database.GetReadPool().QueryRow(ctx,
			"SELECT COUNT(*) FROM messages_fts WHERE content_hash = $1", hash).Scan(&n))
		return n
	}
	countMessages := func(hash string) int {
		var n int
		require.NoError(t, database.GetReadPool().QueryRow(ctx,
			"SELECT COUNT(*) FROM messages WHERE content_hash = $1", hash).Scan(&n))
		return n
	}

	// Both messages really landed in `messages` — this is not an insert failure.
	require.Equal(t, 1, countMessages(batchHash), "batch message row must exist in messages")
	require.Equal(t, 1, countMessages(singleHash), "single message row must exist in messages")

	// Control: the single-insert path indexes correctly with the SAME zero FTSRetention.
	require.Equal(t, 1, countFTS(singleHash),
		"CONTROL: single-message path must create a messages_fts row with FTSRetention=0")

	// RED assertion: the batch path creates no messages_fts row at all.
	assert.Equal(t, 1, countFTS(batchHash),
		"batch-inserted message has NO messages_fts row (FTSRetention==0 is treated as 'skip FTS' "+
			"in InsertMessagesBatch, the inverse of InsertMessageFromImporter)")

	// --- User-visible consequence: body search cannot find the batch-imported message ---
	// Drain the FTS queue so staged text_body rows get their tsvector. ProcessFTSBatch
	// takes the oldest rows first, so a backlog left by earlier tests in the same run
	// would otherwise absorb the batch before it reaches these two messages.
	for {
		txC, err := database.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		processed, err := database.ProcessFTSBatch(ctx, txC, 500)
		require.NoError(t, err)
		require.NoError(t, txC.Commit(ctx))
		if processed == 0 {
			break
		}
	}

	search := func(token string) int {
		results, err := database.SearchMessagesWithCriteria(ctx, mailboxID,
			&imap.SearchCriteria{Body: []string{token}}, 0)
		require.NoError(t, err)
		return len(results)
	}

	require.Equal(t, 1, search(singleToken),
		"CONTROL: BODY search must find the single-inserted message")
	assert.Equal(t, 1, search(batchToken),
		"BODY search finds nothing for the batch-imported message: imported mail is permanently unsearchable")
}
