package db

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// TestInsertMessagesBatch_QueuesPendingUpload exercises the non-importer path of
// InsertMessagesBatch: a NON-NIL uploads slice, which is what
// ResilientDatabase.InsertMessagesBatchWithRetry passes. That path queues an
// INSERT INTO pending_uploads ... ON CONFLICT (content_hash) DO NOTHING.
//
// pending_uploads has no unique index on (content_hash) alone -- the only unique
// constraint is UNIQUE (content_hash, account_id) -- so the ON CONFLICT arbiter
// cannot be inferred and PostgreSQL rejects the statement with SQLSTATE 42P10.
func TestInsertMessagesBatch_QueuesPendingUpload(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dbInstance := setupTestDatabase(t)
	defer dbInstance.Close()

	// Sanity check the schema claim: there must be no unique index over
	// pending_uploads(content_hash) alone for ON CONFLICT (content_hash) to infer.
	var soleHashUniqueIndexes int
	err := dbInstance.GetReadPool().QueryRow(ctx, `
		SELECT count(*)
		FROM pg_index i
		JOIN pg_class c ON c.oid = i.indrelid
		WHERE c.relname = 'pending_uploads'
		  AND i.indisunique
		  AND i.indnatts = 1
		  AND (
		    SELECT a.attname FROM pg_attribute a
		    WHERE a.attrelid = c.oid AND a.attnum = i.indkey[0]
		  ) = 'content_hash'
	`).Scan(&soleHashUniqueIndexes)
	require.NoError(t, err)
	t.Logf("unique indexes on pending_uploads(content_hash) alone: %d", soleHashUniqueIndexes)

	suffix := time.Now().UnixNano()
	email := fmt.Sprintf("batchupload_%d@example.com", suffix)
	accountID := createTestAccount(t, dbInstance, email, "password")
	mailboxID := createTestMailbox(t, dbInstance, accountID, fmt.Sprintf("BatchUploadBox_%d", suffix))

	tx, err := dbInstance.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	contentHash := fmt.Sprintf("hash-pending-%d", suffix)
	opts := []*InsertMessageOptions{{
		AccountID:    accountID,
		MailboxID:    mailboxID,
		MailboxName:  fmt.Sprintf("BatchUploadBox_%d", suffix),
		MessageID:    fmt.Sprintf("<batch-upload-%d@example.com>", suffix),
		ContentHash:  contentHash,
		S3Domain:     "example.com",
		S3Localpart:  "batchupload",
		Size:         1024,
		Subject:      "Batch upload test",
		InternalDate: time.Now(),
		SentDate:     time.Now(),
		// FTSRetention left at zero so the FTS statement is skipped and the
		// pending_uploads statement is the only extra queued query.
	}}

	uploads := []PendingUpload{{
		InstanceID:  "test-instance",
		ContentHash: contentHash,
		Size:        1024,
		AccountID:   accountID,
	}}

	rowIDs, uids, hashes, err := dbInstance.InsertMessagesBatch(ctx, tx, opts, uploads)

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "42P10" {
		t.Fatalf("DEFECT CONFIRMED: InsertMessagesBatch with a non-nil uploads slice failed with "+
			"SQLSTATE 42P10 (invalid_column_reference): %q. "+
			"ON CONFLICT (content_hash) on pending_uploads matches no unique index "+
			"(the constraint is UNIQUE (content_hash, account_id)); unique single-column "+
			"content_hash indexes found on pending_uploads: %d. Full error: %v",
			pgErr.Message, soleHashUniqueIndexes, err)
	}
	require.NoError(t, err, "InsertMessagesBatch must succeed when queueing a pending upload")

	require.Len(t, rowIDs, 1)
	require.Len(t, uids, 1)
	require.Len(t, hashes, 1)

	// The pending_uploads row must actually be there (visible inside the tx).
	var pendingCount int
	err = tx.QueryRow(ctx, `SELECT count(*) FROM pending_uploads WHERE content_hash = $1 AND account_id = $2`,
		contentHash, accountID).Scan(&pendingCount)
	require.NoError(t, err)
	require.Equal(t, 1, pendingCount, "expected exactly one queued pending_uploads row")
}
