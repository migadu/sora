package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Before shared mailbox ownership landed (June 2026), a message that someone other than the
// owner added to a shared mailbox (APPEND, COPY, MOVE, Sieve fileinto) was stored with THAT
// person's messages.account_id. No migration rewrote those rows. Searches are scoped to the
// mailbox owner, so:
//
//   - no query on messages may filter on m.account_id (mailbox_id already scopes it), or
//     such messages vanish from THREAD, TEXT and seqnum searches while SEARCH ALL still
//     lists them;
//   - their FTS rows must be keyed on the mailbox owner, by the sweep's
//     notion of "still referenced", or body search can never find them.
func TestLegacySharedMailboxMessagesStaySearchable(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, ownerID, mailboxID := setupCleanerTestDatabase(t)
	t.Cleanup(db.Close) // registered first, so it runs after every other cleanup

	ctx := context.Background()
	ts := time.Now().UnixNano()

	var appenderID int64
	require.NoError(t, db.GetWritePool().QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING id`).Scan(&appenderID))

	legacyHash := fmt.Sprintf("legacy_shared_%d", ts)
	ownerHash := fmt.Sprintf("owner_shared_%d", ts)

	insert := func(accountID int64, uid int, hash, subject string) int64 {
		t.Helper()
		var id int64
		require.NoError(t, db.GetWritePool().QueryRow(ctx, `
			WITH inserted AS (
				INSERT INTO messages (account_id, mailbox_id, uid, content_hash, subject, subject_sort,
				                      sent_date, internal_date, size, uploaded, s3_domain, s3_localpart,
				                      message_id, body_structure, recipients_json, created_modseq)
				VALUES ($1, $2, $3, $4, $5, LOWER($5), now(), now(), 100, TRUE, 'domain', 'part', $6,
				        'body', '[]', nextval('messages_modseq'))
				RETURNING id, mailbox_id
			), st AS (
				INSERT INTO message_state (message_id, mailbox_id, flags)
				SELECT id, mailbox_id, 0 FROM inserted
			)
			SELECT id FROM inserted
		`, accountID, mailboxID, uid, hash, subject, fmt.Sprintf("<%s@example.com>", hash)).Scan(&id))
		return id
	}
	insert(appenderID, 9301, legacyHash, "Legacy haystack")
	insert(ownerID, 9302, ownerHash, "Owner haystack")

	for hash, word := range map[string]string{legacyHash: "legacyneedle", ownerHash: "ownerneedle"} {
		_, err := db.GetWritePool().Exec(ctx, `
			INSERT INTO messages_fts_v2 (content_hash, account_id, text_body_tsv, sent_date)
			VALUES ($1, $2, to_tsvector('simple', $3), now())`, hash, ownerID, word)
		require.NoError(t, err)
	}
	t.Cleanup(func() {
		c := context.Background()
		db.GetWritePool().Exec(c, `DELETE FROM messages_fts_v2 WHERE content_hash = ANY($1)`, []string{legacyHash, ownerHash})
	})

	uids := func(msgs []SearchMessageResult) map[imap.UID]bool {
		out := map[imap.UID]bool{}
		for _, m := range msgs {
			out[m.UID] = true
		}
		return out
	}

	t.Run("THREAD ALL", func(t *testing.T) {
		msgs, err := db.GetMessagesForThreading(ctx, mailboxID, ownerID, &imap.SearchCriteria{}, true, true, 0)
		require.NoError(t, err)
		found := map[imap.UID]bool{}
		for _, m := range msgs {
			found[m.UID] = true
		}
		assert.True(t, found[9301], "a legacy shared-mailbox message vanished from THREAD ALL")
		assert.True(t, found[9302])
	})

	t.Run("TEXT matching a header", func(t *testing.T) {
		msgs, err := db.SearchMessagesWithCriteria(ctx, mailboxID, ownerID, &imap.SearchCriteria{Text: []string{"haystack"}}, 0, 0)
		require.NoError(t, err)
		got := uids(msgs)
		assert.True(t, got[9301], "a legacy shared-mailbox message vanished from a TEXT search that matches its subject")
		assert.True(t, got[9302])
	})

	t.Run("TEXT with a sequence set", func(t *testing.T) {
		var all imap.SeqSet
		all.AddRange(1, 0)
		msgs, err := db.SearchMessagesWithCriteria(ctx, mailboxID, ownerID,
			&imap.SearchCriteria{SeqNum: []imap.SeqSet{all}, Text: []string{"haystack"}}, 0, 0)
		require.NoError(t, err)
		got := uids(msgs)
		assert.True(t, got[9301], "a legacy shared-mailbox message vanished from a seqnum TEXT search")
		assert.True(t, got[9302])
	})

	t.Run("BODY", func(t *testing.T) {
		msgs, err := db.SearchMessagesWithCriteria(ctx, mailboxID, ownerID, &imap.SearchCriteria{Body: []string{"legacyneedle"}}, 0, 0)
		require.NoError(t, err)
		assert.True(t, uids(msgs)[9301], "the owner-keyed FTS row of a legacy message must make it searchable by body")
	})

	t.Run("sweep keeps the owner-keyed row", func(t *testing.T) {
		keys, _, err := db.GetUnusedFTSKeys(ctx, FTSKey{}, 1_000_000)
		require.NoError(t, err)
		for _, k := range keys {
			assert.False(t, k.ContentHash == legacyHash && k.AccountID == ownerID,
				"the owner-keyed FTS row of a live legacy message was listed as an orphan")
		}
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		n, err := db.DeleteMessagesFTSByKeyBatch(ctx, tx, []FTSKey{{ContentHash: legacyHash, AccountID: ownerID}})
		require.NoError(t, err)
		assert.Equal(t, int64(0), n, "the sweep deleted the owner-keyed FTS row of a live legacy message")
	})
}
