package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

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

// Detached from the interrupt, the mark is still bounded, and a real timeout is
// reported as one.
func TestMarkBatchInSQLiteReportsARealTimeout(t *testing.T) {
	saved := sqliteMarkTimeout
	sqliteMarkTimeout = 50 * time.Millisecond
	t.Cleanup(func() { sqliteMarkTimeout = saved })

	importer, err := NewImporter(context.Background(), newCleanupDBMaildir(t, 0), "user@example.com", 1, nil, nil, ImporterOptions{})
	require.NoError(t, err)
	t.Cleanup(func() { importer.Close() })

	// The cache has a single connection; hold it, as a stuck writer would.
	conn, err := importer.sqliteDB.Conn(context.Background())
	require.NoError(t, err)
	defer conn.Close()

	err = importer.markBatchInSQLite([]markedMessage{{hash: "somehash", mailbox: "INBOX"}})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Contains(t, err.Error(), "timed out after 50ms")
}

// A running SQLite statement must also honor the deadline, roll back earlier
// rows of the batch, and leave no background mark that commits after return.
func TestMarkBatchInSQLiteInterruptsStatementAndRollsBack(t *testing.T) {
	saved := sqliteMarkTimeout
	sqliteMarkTimeout = 50 * time.Millisecond
	t.Cleanup(func() { sqliteMarkTimeout = saved })

	importer, err := NewImporter(context.Background(), newCleanupDBMaildir(t, 0), "user@example.com", 1, nil, nil, ImporterOptions{})
	require.NoError(t, err)
	t.Cleanup(func() { importer.Close() })
	for _, hash := range []string{"fast", "slow"} {
		_, err := importer.sqliteDB.Exec(`INSERT INTO messages (path, filename, hash, size, mailbox, s3_uploaded) VALUES (?, ?, ?, 128, 'INBOX', 0)`, hash, hash, hash)
		require.NoError(t, err)
	}
	_, err = importer.sqliteDB.Exec(`
		CREATE TRIGGER slow_mark BEFORE UPDATE ON messages WHEN NEW.hash = 'slow'
		BEGIN
			SELECT (WITH RECURSIVE seq(x) AS (
				VALUES(0) UNION ALL SELECT x + 1 FROM seq WHERE x < 1000000000
			) SELECT sum(x) FROM seq);
		END`)
	require.NoError(t, err)

	marked := []markedMessage{{hash: "fast", mailbox: "INBOX"}, {hash: "slow", mailbox: "INBOX"}}
	err = importer.markBatchInSQLite(marked)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	var uploaded int
	require.NoError(t, importer.sqliteDB.QueryRow(`SELECT sum(s3_uploaded) FROM messages`).Scan(&uploaded))
	require.Zero(t, uploaded, "the earlier row must roll back with the interrupted statement")

	_, err = importer.sqliteDB.Exec(`DROP TRIGGER slow_mark`)
	require.NoError(t, err)
	require.NoError(t, importer.markBatchInSQLite(marked), "the timed-out transaction must release its connection and locks")
	require.NoError(t, importer.sqliteDB.QueryRow(`SELECT sum(s3_uploaded) FROM messages`).Scan(&uploaded))
	require.Equal(t, 2, uploaded)
}
