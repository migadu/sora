package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cancelAfterInsertDB commits the batch insert and then the operator presses Ctrl-C:
// the interrupt lands between the PostgreSQL commit and the marking of the cache rows.
type cancelAfterInsertDB struct {
	*mockResilientDatabase
	cancel context.CancelFunc
}

func (m *cancelAfterInsertDB) InsertMessagesFromImporterBatchWithRetry(ctx context.Context, opts []*db.InsertMessageOptions) ([]int64, []int64, []string, error) {
	ids, uids, hashes, err := m.mockResilientDatabase.InsertMessagesFromImporterBatchWithRetry(ctx, opts)
	m.cancel()
	return ids, uids, hashes, err
}

// The rows a mark describes are already committed in PostgreSQL, so an interrupt must
// not abandon the mark (a short local transaction), and must not be reported as the
// 30-second timeout it is not.
func TestMarkBatchInSQLiteSurvivesInterrupt(t *testing.T) {
	maildirPath := newCleanupDBMaildir(t, 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // SIGINT/SIGTERM already delivered

	importer, err := NewImporter(ctx, maildirPath, "user@example.com", 1, nil, nil, ImporterOptions{})
	require.NoError(t, err)
	t.Cleanup(func() { importer.Close() })

	const hash = "committedcontenthash00000000000000000000000000000000000000000000"
	_, err = importer.sqliteDB.Exec(
		`INSERT INTO messages (path, filename, hash, size, mailbox, s3_uploaded) VALUES (?, ?, ?, ?, ?, 0)`,
		filepath.Join(maildirPath, "cur", "msg:2,S"), "msg:2,S", hash, 128, "INBOX",
	)
	require.NoError(t, err)

	require.NoError(t, importer.markBatchInSQLite([]markedMessage{{hash: hash, mailbox: "INBOX"}}),
		"marking committed messages was abandoned because of the interrupt")

	var uploaded int
	require.NoError(t, importer.sqliteDB.QueryRow(
		`SELECT s3_uploaded FROM messages WHERE hash = ? AND mailbox = ?`, hash, "INBOX",
	).Scan(&uploaded))
	assert.Equal(t, 1, uploaded, "the committed message was left unmarked")
}

// An interrupt that arrives after a batch's PostgreSQL inserts committed: the run still
// reports the interruption, but the batch is imported, not failed, and its cache rows
// are marked so the next --incremental run does not read and upload it again.
func TestImportInterruptAfterCommitCountsTheBatchImported(t *testing.T) {
	maildirPath := newCleanupDBMaildir(t, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	importer, err := NewImporter(ctx, maildirPath, "user@example.com", 1, nil, nil, ImporterOptions{TestMode: true})
	require.NoError(t, err)
	t.Cleanup(func() { importer.Close() })
	importer.rdb = &cancelAfterInsertDB{mockResilientDatabase: newMockResilientDatabase(), cancel: cancel}

	err = importer.Run()
	require.ErrorIs(t, err, context.Canceled, "an interrupted run must report the interruption")

	assert.Equal(t, int64(0), importer.failedMessages, "messages committed to PostgreSQL were counted as failed")
	assert.Equal(t, int64(2), importer.importedMessages, "messages committed to PostgreSQL were not counted as imported")

	imported, pending := uploadedCounts(t, maildirPath)
	assert.Equal(t, 2, imported, "committed messages were left unmarked; the next --incremental run re-imports them")
	assert.Equal(t, 0, pending)
}
