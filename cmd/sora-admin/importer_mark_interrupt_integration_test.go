//go:build integration

package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cancelOnCommitTx commits the batch transaction and then the operator presses Ctrl-C.
type cancelOnCommitTx struct {
	pgx.Tx
	cancel context.CancelFunc
}

func (t *cancelOnCommitTx) Commit(ctx context.Context) error {
	err := t.Tx.Commit(ctx)
	t.cancel()
	return err
}

// cancelOnCommitDB hands out batch transactions whose commit is followed by the interrupt.
type cancelOnCommitDB struct {
	*resilient.ResilientDatabase
	cancel context.CancelFunc
}

func (r *cancelOnCommitDB) BeginTxWithRetry(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	tx, err := r.ResilientDatabase.BeginTxWithRetry(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &cancelOnCommitTx{Tx: tx, cancel: r.cancel}, nil
}

// --batch-tx-mode: an interrupt right after the batch transaction committed must not
// fail the mark, and so must not send the committed batch into the compensation that
// deletes it again (which, through the cancelled context, cannot run either and
// reports the messages orphaned). The batch is imported and its cache rows marked.
func TestImportInterruptAfterBatchTxCommitKeepsTheBatch(t *testing.T) {
	rdb := setupTestDatabase(t)
	defer rdb.Close()

	email := fmt.Sprintf("interrupt-batch-tx-%d@example.com", time.Now().UnixNano())
	createTestAccount(t, rdb, email, "testpassword123")

	maildirPath := newCleanupDBMaildir(t, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	importer, err := NewImporter(ctx, maildirPath, email, 1, rdb, nil, ImporterOptions{
		TestMode:             true,
		BatchTransactionMode: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { importer.Close() })
	importer.rdb = &cancelOnCommitDB{ResilientDatabase: rdb, cancel: cancel}

	err = importer.Run()
	require.ErrorIs(t, err, context.Canceled, "an interrupted run must report the interruption")

	assert.Equal(t, int64(0), importer.failedMessages, "messages committed to PostgreSQL were counted as failed")
	assert.Equal(t, int64(2), importer.importedMessages, "messages committed to PostgreSQL were not counted as imported")

	imported, pending := uploadedCounts(t, maildirPath)
	assert.Equal(t, 2, imported, "committed messages were left unmarked; the next --incremental run re-imports them")
	assert.Equal(t, 0, pending)

	var live int
	require.NoError(t, rdb.QueryRowWithRetry(context.Background(), `
		SELECT COUNT(*) FROM messages m JOIN credentials c ON c.account_id = m.account_id
		WHERE c.address = $1 AND m.expunged_at IS NULL`, email).Scan(&live))
	assert.Equal(t, 2, live, "the committed batch must stay in the mailbox")
}
