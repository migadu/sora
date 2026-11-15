package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// interruptingDB stands in for PostgreSQL in an interrupted import. The interrupt
// (SIGINT/SIGTERM cancel the import context) lands in the call named by at; from then
// on every call fails with the context's error, as the resilient database's do.
type interruptingDB struct {
	*mockResilientDatabase
	cancel context.CancelFunc
	at     string

	mu             sync.Mutex
	accountLookups int
	singleInserts  int
}

func (m *interruptingDB) GetAccountIDByAddressWithRetry(ctx context.Context, address string) (int64, error) {
	m.mu.Lock()
	m.accountLookups++
	n := m.accountLookups
	m.mu.Unlock()
	// The first lookup is Run's orphan recovery, before any batch.
	if m.at == "account lookup" && n > 1 {
		m.cancel()
	}
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("database error fetching account ID: %w", err)
	}
	return m.mockResilientDatabase.GetAccountIDByAddressWithRetry(ctx, address)
}

func (m *interruptingDB) GetOrCreateMailboxByNameWithRetry(ctx context.Context, accountID int64, name string) (*db.DBMailbox, error) {
	if m.at == "mailbox" {
		m.cancel()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return m.mockResilientDatabase.GetOrCreateMailboxByNameWithRetry(ctx, accountID, name)
}

// At "batch insert" the batch insert commits, then the interrupt lands: the next
// mailbox's batch sees it. At "single insert" the batch insert fails on its own, and
// the interrupt lands after the first message of the per-message fallback committed.
func (m *interruptingDB) InsertMessagesFromImporterBatchWithRetry(ctx context.Context, opts []*db.InsertMessageOptions) ([]int64, []int64, []string, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, err
	}
	if m.at == "single insert" {
		return nil, nil, nil, errors.New("simulated batch insert failure")
	}
	ids, uids, hashes, err := m.mockResilientDatabase.InsertMessagesFromImporterBatchWithRetry(ctx, opts)
	if m.at == "batch insert" {
		m.cancel()
	}
	return ids, uids, hashes, err
}

func (m *interruptingDB) InsertMessageFromImporterWithRetry(ctx context.Context, opts *db.InsertMessageOptions) (int64, int64, error) {
	m.mu.Lock()
	m.singleInserts++
	m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, 0, err
	}
	id, uid, err := m.mockResilientDatabase.InsertMessageFromImporterWithRetry(ctx, opts)
	if m.at == "single insert" {
		m.cancel()
	}
	return id, uid, err
}

func (m *interruptingDB) BeginTxWithRetry(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error) {
	if m.at == "begin" {
		m.cancel()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return m.mockResilientDatabase.BeginTxWithRetry(ctx, txOptions)
}

// newTwoMailboxMaildir builds a maildir with one message in INBOX and one in Sent.
func newTwoMailboxMaildir(t *testing.T) string {
	t.Helper()
	maildirPath := newCleanupDBMaildir(t, 1)
	sent := filepath.Join(maildirPath, ".Sent")
	for _, dir := range []string{"cur", "new", "tmp"} {
		require.NoError(t, os.MkdirAll(filepath.Join(sent, dir), 0755))
	}
	content := "From: user@example.com\r\nTo: other@example.org\r\nSubject: Sent message\r\nMessage-ID: <sent-1@example.com>\r\n\r\nBody\r\n"
	require.NoError(t, os.WriteFile(filepath.Join(sent, "cur", "1700000101.M101P1.host:2,S"), []byte(content), 0644))
	return maildirPath
}

// An interrupt keeps the rest of the batch from being stored; it does not make those
// messages fail. They stay pending (their cache rows unmarked) for the next run, and
// are neither counted as failed nor listed with an upload, mailbox, "account not
// found" or insert error. What committed before the interrupt is imported and marked.
func TestImportInterruptLeavesUnstoredMessagesPending(t *testing.T) {
	cases := []struct {
		name        string
		at          string // where the interrupt lands
		batchTx     bool   // --batch-transaction
		oneMailbox  bool   // both messages in INBOX, one batch insert chunk
		committed   int    // messages stored before the interrupt
		singleTries int    // per-message inserts attempted
	}{
		{name: "during the uploads", at: "upload"},
		{name: "at the insert phase's account lookup", at: "account lookup"},
		{name: "at the mailbox lookup", at: "mailbox"},
		{name: "after the first mailbox's batch insert", at: "batch insert", committed: 1},
		// The second attempt is the one that sees the interrupt.
		{name: "during the per-message fallback", at: "single insert", oneMailbox: true, committed: 1, singleTries: 2},
		{name: "at the batch transaction's begin", at: "begin", batchTx: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			maildirPath := newTwoMailboxMaildir(t)
			if tc.oneMailbox {
				maildirPath = newCleanupDBMaildir(t, 2)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			var s3 *cancelOnPutStorage
			if tc.at == "upload" {
				s3 = &cancelOnPutStorage{cancel: cancel}
			}
			importer, err := NewImporter(ctx, maildirPath, "user@example.com", 1, nil, nil, ImporterOptions{
				TestMode:             s3 == nil,
				BatchTransactionMode: tc.batchTx,
			})
			require.NoError(t, err)
			t.Cleanup(func() { importer.Close() })
			rdb := &interruptingDB{mockResilientDatabase: newMockResilientDatabase(), cancel: cancel, at: tc.at}
			importer.rdb = rdb
			if s3 != nil {
				importer.s3 = s3
			}

			err = importer.Run()
			require.ErrorIs(t, err, context.Canceled, "an interrupted run must report the interruption")
			if s3 != nil {
				require.Equal(t, 1, s3.puts, "the second upload must see the interrupt")
			}

			assert.Zero(t, importer.failedMessages, "messages the interrupt kept from being stored were counted as failed")
			assert.Empty(t, recordedFailedPaths(importer), "messages the interrupt kept from being stored were listed as failed")
			assert.Equal(t, tc.singleTries, rdb.singleInserts, "a batch insert that failed on the interrupt was retried message by message")
			assert.Equal(t, int64(tc.committed), importer.importedMessages)

			imported, pending := uploadedCounts(t, maildirPath)
			assert.Equal(t, tc.committed, imported, "messages committed before the interrupt must be marked imported")
			assert.Equal(t, 2-tc.committed, pending, "messages the interrupt kept from being stored must stay pending for the next run")
		})
	}
}
