package db

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/require"
)

// A real COPY restage can lose its only vector source to source-account purge.
// Recovery may replace only empty placeholders with known-positive legacy vectors.
func TestFTSRecoverMessageContentsRepairsEmptyDestinations(t *testing.T) {
	for _, mode := range []string{"queued", "poisoned", "legacy text without known vector"} {
		t.Run(mode, func(t *testing.T) {
			skipDatabaseTestInShortMode(t)
			ctx := context.Background()
			m := migrateMessageContentsTestDB(t, 22)
			require.NoError(t, m.Up())
			database, err := NewDatabaseFromConfig(ctx, makeTestDBConfig(t), false)
			require.NoError(t, err)
			defer database.Close()
			pool := database.GetWritePool()
			f := seedMessageContentsFixture(t, database)
			var sourceAccount int64
			require.NoError(t, pool.QueryRow(ctx, `INSERT INTO accounts (deleted_at) VALUES (now()) RETURNING id`).Scan(&sourceAccount))
			_, err = pool.Exec(ctx, `INSERT INTO message_contents (content_hash, text_body, text_body_tsv) VALUES
    ('hash_indexed', NULL, to_tsvector('simple', 'zebra')),
    ('hash_queued', 'old walrus', NULL),
    ('hash_known', NULL, to_tsvector('simple', 'old words'))`)
			require.NoError(t, err)
			if mode == "legacy text without known vector" {
				_, err = pool.Exec(ctx, `UPDATE message_contents SET text_body='zebra', text_body_tsv=NULL WHERE content_hash='hash_indexed'`)
				require.NoError(t, err)
			}
			_, err = pool.Exec(ctx, `INSERT INTO messages_fts_v2 (content_hash, account_id, text_body, text_body_tsv, created_at, sent_date) VALUES
    ('hash_indexed', $1, NULL, to_tsvector('simple', 'zebra'), '2000-01-01', '2001-01-01'),
    ('hash_queued', $2, 'current walrus', NULL, '2000-01-01', '2001-01-01'),
    ('hash_known', $2, NULL, to_tsvector('simple', 'current yak'), '2000-01-01', '2001-01-01')`, sourceAccount, f.accountID)
			require.NoError(t, err)
			tx, err := pool.Begin(ctx)
			require.NoError(t, err)
			require.NoError(t, database.restageFTS(ctx, tx, f.mailboxID, []int64{1}))
			require.NoError(t, tx.Commit(ctx))
			// The production account-purge method removes the source's sole remaining vector.
			tx, err = pool.Begin(ctx)
			require.NoError(t, err)
			n, err := database.DeleteFTSRowsForAccount(ctx, tx, sourceAccount, 100)
			require.NoError(t, err)
			require.EqualValues(t, 1, n)
			require.NoError(t, tx.Commit(ctx))
			_, err = pool.Exec(ctx, `UPDATE messages_fts_v2 SET created_at='2000-01-01',sent_date='2001-01-01'
    WHERE content_hash='hash_indexed' AND account_id=$1`, f.accountID)
			require.NoError(t, err)
			if mode != "queued" {
				tx, err = pool.Begin(ctx)
				require.NoError(t, err)
				_, err = database.ProcessFTSBatch(ctx, tx, 100)
				require.NoError(t, err)
				require.NoError(t, tx.Commit(ctx))
				// Restore this queued-text control after the worker resolved the target hash.
				_, err = pool.Exec(ctx, `UPDATE messages_fts_v2 SET text_body='current walrus',text_body_tsv=NULL
     WHERE content_hash='hash_queued' AND account_id=$1`, f.accountID)
				require.NoError(t, err)
			}
			script, err := os.ReadFile(filepath.Join(moduleRoot(t), "scripts", "fts_recover_message_contents.sql"))
			require.NoError(t, err)
			_, err = pool.Exec(ctx, string(script))
			require.NoError(t, err)
			_, err = pool.Exec(ctx, string(script))
			require.NoError(t, err, "the recovery script must remain reloadable")
			var restored int
			require.NoError(t, pool.QueryRow(ctx, `SELECT inserted FROM sora_fts_recover_batch(NULL,100)`).Scan(&restored))
			if mode == "legacy text without known vector" {
				require.Zero(t, restored)
			} else {
				require.Equal(t, 1, restored)
			}
			require.NoError(t, pool.QueryRow(ctx, `SELECT inserted FROM sora_fts_recover_batch(NULL,100)`).Scan(&restored))
			require.Zero(t, restored, "a repaired row must not be rewritten on each pass")
			var text, vector string
			var metadataOK bool
			require.NoError(t, pool.QueryRow(ctx, `SELECT text_body FROM messages_fts_v2
    WHERE content_hash='hash_queued' AND account_id=$1`, f.accountID).Scan(&text))
			require.Equal(t, "current walrus", text, "do not overwrite queued destination text")
			require.NoError(t, pool.QueryRow(ctx, `SELECT text_body_tsv::text FROM messages_fts_v2
    WHERE content_hash='hash_known' AND account_id=$1`, f.accountID).Scan(&vector))
			require.Contains(t, vector, "current")
			require.NotContains(t, vector, "old", "do not replace a nonempty destination vector")
			require.NoError(t, pool.QueryRow(ctx, `SELECT bool_and(created_at='2000-01-01' AND sent_date='2001-01-01')
    FROM messages_fts_v2 WHERE account_id=$1`, f.accountID).Scan(&metadataOK))
			require.True(t, metadataOK, "repair must preserve destination metadata")
			var unresolved int
			// Execute the runbook's actual verification query, including its source filter.
			verificationStart := strings.Index(string(script), "--   SELECT count(*) FROM")
			require.GreaterOrEqual(t, verificationStart, 0)
			verificationText := string(script)[verificationStart:]
			verificationEnd := strings.Index(verificationText, ";")
			require.GreaterOrEqual(t, verificationEnd, 0)
			lines := strings.Split(verificationText[:verificationEnd+1], "\n")
			for i, line := range lines {
				lines[i] = strings.TrimPrefix(line, "--")
			}
			require.NoError(t, pool.QueryRow(ctx, strings.Join(lines, "\n")).Scan(&unresolved))
			if mode == "legacy text without known vector" {
				require.Equal(t, 1, unresolved)
			} else {
				require.Zero(t, unresolved)
			}
			results, err := database.SearchMessagesWithCriteria(ctx, f.mailboxID, f.accountID, &imap.SearchCriteria{Body: []string{"zebra"}}, 100, 3)
			require.NoError(t, err)
			if mode == "legacy text without known vector" {
				require.Empty(t, results)
			} else {
				require.Len(t, results, 1)
			}
		})
	}
}
