package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type batchTxMsgOutcome int

const (
	batchTxInsertOK batchTxMsgOutcome = iota
	batchTxDuplicate
	batchTxUIDConflict
	batchTxInsertErr
)

type scriptedBatchRow struct {
	scan func(dest ...any) error
}

func (r scriptedBatchRow) Scan(dest ...any) error {
	return r.scan(dest...)
}

// scriptedBatchTx drives db.Database.InsertMessageFromImporter inside
// insertBatchToDBWithTransaction without requiring a live PostgreSQL server.
type scriptedBatchTx struct {
	mockTx
	outcomes  map[string]batchTxMsgOutcome
	commitErr error
	nextUID   int64
	nextRowID int64
}

func (t *scriptedBatchTx) Commit(ctx context.Context) error {
	return t.commitErr
}

func (t *scriptedBatchTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	switch {
	case strings.Contains(sql, "UPDATE mailboxes"):
		t.nextUID++
		uid := t.nextUID
		return scriptedBatchRow{scan: func(dest ...any) error {
			*dest[0].(*int64) = uid
			return nil
		}}

	case strings.Contains(sql, "SELECT uid, content_hash FROM messages"):
		msgID, _ := args[1].(string)
		contentHash, _ := args[2].(string)
		if t.outcomes[msgID] == batchTxDuplicate {
			return scriptedBatchRow{scan: func(dest ...any) error {
				*dest[0].(*int64) = 1
				*dest[1].(*string) = contentHash
				return nil
			}}
		}
		return scriptedBatchRow{scan: func(dest ...any) error {
			return pgx.ErrNoRows
		}}

	case strings.Contains(sql, "INSERT INTO messages"):
		named, _ := args[0].(pgx.NamedArgs)
		msgID, _ := named["message_id"].(string)
		switch t.outcomes[msgID] {
		case batchTxUIDConflict:
			return scriptedBatchRow{scan: func(dest ...any) error {
				return &pgconn.PgError{
					Code:           "23505",
					ConstraintName: "idx_messages_mailbox_id_uid",
				}
			}}
		case batchTxInsertErr:
			return scriptedBatchRow{scan: func(dest ...any) error {
				return errors.New("simulated batch insert failure")
			}}
		default:
			t.nextRowID++
			rowID := t.nextRowID
			return scriptedBatchRow{scan: func(dest ...any) error {
				*dest[0].(*int64) = rowID
				return nil
			}}
		}
	}
	return &mockRow{}
}

type scriptedBatchTxDB struct {
	*mockResilientDatabase
	outcomes      map[string]batchTxMsgOutcome
	commitErr     error
	mu            sync.Mutex
	deletedHashes []string
}

func (d *scriptedBatchTxDB) BeginTxWithRetry(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error) {
	return &scriptedBatchTx{
		outcomes:  d.outcomes,
		commitErr: d.commitErr,
	}, nil
}

func (d *scriptedBatchTxDB) DeleteMessageByHashAndMailboxWithRetry(ctx context.Context, accountID, mailboxID int64, hash string) (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.deletedHashes = append(d.deletedHashes, hash)
	return 1, nil
}

// TestBatchTxAbortCounts (#1004): when --batch-transaction (BatchTransactionMode)
// aborts a batch, processBatch records and counts every uploaded message in that batch
// as failed. Earlier per-message ErrUIDConflict failures and ErrDBUniqueViolation skips
// inside insertBatchToDBWithTransaction must not be applied until tx.Commit and
// markBatchInSQLite succeed, otherwise an abort double-counts them.
func TestBatchTxAbortCounts(t *testing.T) {
	t.Run("UID conflict before batch abort is counted once", func(t *testing.T) {
		maildirPath := newCleanupDBMaildir(t, 3)
		rdb := &scriptedBatchTxDB{
			mockResilientDatabase: newMockResilientDatabase(),
			outcomes: map[string]batchTxMsgOutcome{
				"cleanup-1@example.com": batchTxInsertOK,
				"cleanup-2@example.com": batchTxUIDConflict,
				"cleanup-3@example.com": batchTxInsertErr,
			},
		}
		importer := newTestModeImporter(t, maildirPath, rdb, ImporterOptions{
			BatchTransactionMode: true,
		})

		err := importer.Run()
		require.Error(t, err)
		assert.Equal(t, "import completed with 3 failed messages", err.Error())
		assert.Equal(t, int64(3), importer.totalMessages)
		assert.Equal(t, int64(3), importer.failedMessages,
			"an aborted batch must count each uploaded message once, including earlier UID conflicts")
		assert.Zero(t, importer.skippedMessages)
		assert.Zero(t, importer.importedMessages)

		failed := recordedFailedPaths(importer)
		if assert.Len(t, failed, 3, "each message of the aborted batch must appear once in failedPaths") {
			assert.Equal(t, []string{
				"1700000001.M1P1.host:2,S",
				"1700000002.M2P1.host:2,S",
				"1700000003.M3P1.host:2,S",
			}, []string{
				filepath.Base(failed[0]),
				filepath.Base(failed[1]),
				filepath.Base(failed[2]),
			})
		}

		imported, pending := uploadedCounts(t, maildirPath)
		assert.Equal(t, 0, imported)
		assert.Equal(t, 3, pending)
	})

	t.Run("duplicate skip before batch abort is not counted as both skipped and failed", func(t *testing.T) {
		maildirPath := newCleanupDBMaildir(t, 3)
		rdb := &scriptedBatchTxDB{
			mockResilientDatabase: newMockResilientDatabase(),
			outcomes: map[string]batchTxMsgOutcome{
				"cleanup-1@example.com": batchTxDuplicate,
				"cleanup-2@example.com": batchTxInsertOK,
				"cleanup-3@example.com": batchTxInsertErr,
			},
		}
		importer := newTestModeImporter(t, maildirPath, rdb, ImporterOptions{
			BatchTransactionMode: true,
		})

		err := importer.Run()
		require.Error(t, err)
		assert.Equal(t, "import completed with 3 failed messages", err.Error())
		assert.Equal(t, int64(3), importer.totalMessages)
		assert.Equal(t, int64(3), importer.failedMessages)
		assert.Zero(t, importer.skippedMessages,
			"a rolled-back batch must not leave earlier duplicates counted in skippedMessages as well as failedMessages")
		assert.Zero(t, importer.importedMessages)
		assert.Len(t, recordedFailedPaths(importer), 3)

		imported, pending := uploadedCounts(t, maildirPath)
		assert.Equal(t, 0, imported)
		assert.Equal(t, 3, pending)
	})

	t.Run("commit failure rolls back without double counting", func(t *testing.T) {
		maildirPath := newCleanupDBMaildir(t, 3)
		rdb := &scriptedBatchTxDB{
			mockResilientDatabase: newMockResilientDatabase(),
			outcomes: map[string]batchTxMsgOutcome{
				"cleanup-1@example.com": batchTxDuplicate,
				"cleanup-2@example.com": batchTxUIDConflict,
				"cleanup-3@example.com": batchTxInsertOK,
			},
			commitErr: pgx.ErrTxCommitRollback,
		}
		importer := newTestModeImporter(t, maildirPath, rdb, ImporterOptions{
			BatchTransactionMode: true,
		})

		err := importer.Run()
		require.Error(t, err)
		assert.Equal(t, "import completed with 3 failed messages", err.Error())
		assert.Equal(t, int64(3), importer.totalMessages)
		assert.Equal(t, int64(3), importer.failedMessages)
		assert.Zero(t, importer.skippedMessages)
		assert.Zero(t, importer.importedMessages)
		assert.Len(t, recordedFailedPaths(importer), 3)

		imported, pending := uploadedCounts(t, maildirPath)
		assert.Equal(t, 0, imported)
		assert.Equal(t, 3, pending)
	})

	t.Run("SQLite mark failure after commit rolls back without double counting", func(t *testing.T) {
		maildirPath := newCleanupDBMaildir(t, 3)
		rdb := &scriptedBatchTxDB{
			mockResilientDatabase: newMockResilientDatabase(),
			outcomes: map[string]batchTxMsgOutcome{
				"cleanup-1@example.com": batchTxDuplicate,
				"cleanup-2@example.com": batchTxUIDConflict,
				"cleanup-3@example.com": batchTxInsertOK,
			},
		}
		importer := newTestModeImporter(t, maildirPath, rdb, ImporterOptions{
			BatchTransactionMode: true,
		})
		_, err := importer.sqliteDB.Exec(`
			CREATE TRIGGER abort_mark BEFORE UPDATE OF s3_uploaded ON messages WHEN NEW.s3_uploaded = 1
			BEGIN
				SELECT RAISE(ABORT, 'simulated sqlite mark failure');
			END`)
		require.NoError(t, err)

		err = importer.Run()
		require.Error(t, err)
		assert.Equal(t, "import completed with 3 failed messages", err.Error())
		assert.Equal(t, int64(3), importer.totalMessages)
		assert.Equal(t, int64(3), importer.failedMessages)
		assert.Zero(t, importer.skippedMessages)
		assert.Zero(t, importer.importedMessages)
		assert.Len(t, recordedFailedPaths(importer), 3)
		assert.Len(t, rdb.deletedHashes, 1, "rollback compensation deletes only the message inserted in the batch")

		imported, pending := uploadedCounts(t, maildirPath)
		assert.Equal(t, 0, imported)
		assert.Equal(t, 3, pending)
	})

	t.Run("committed batch records UID conflicts and skips once", func(t *testing.T) {
		maildirPath := newCleanupDBMaildir(t, 3)
		rdb := &scriptedBatchTxDB{
			mockResilientDatabase: newMockResilientDatabase(),
			outcomes: map[string]batchTxMsgOutcome{
				"cleanup-1@example.com": batchTxDuplicate,
				"cleanup-2@example.com": batchTxUIDConflict,
				"cleanup-3@example.com": batchTxInsertOK,
			},
		}
		importer := newTestModeImporter(t, maildirPath, rdb, ImporterOptions{
			BatchTransactionMode: true,
		})

		err := importer.Run()
		require.Error(t, err)
		assert.Equal(t, "import completed with 1 failed messages", err.Error())
		assert.Equal(t, int64(3), importer.totalMessages)
		assert.Equal(t, int64(1), importer.importedMessages)
		assert.Equal(t, int64(1), importer.skippedMessages)
		assert.Equal(t, int64(1), importer.failedMessages)

		failed := recordedFailedPaths(importer)
		if assert.Len(t, failed, 1) {
			assert.Equal(t, "1700000002.M2P1.host:2,S", filepath.Base(failed[0]))
		}

		imported, pending := uploadedCounts(t, maildirPath)
		assert.Equal(t, 1, imported)
		assert.Equal(t, 2, pending)
	})
}
