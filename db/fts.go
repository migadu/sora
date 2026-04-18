package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/logger"
)

// NOTE: headerAllowlist and extractSearchableHeaders() are DEPRECATED and unused.
// headers_tsv column has been removed entirely because all searchable headers have
// dedicated indexed columns in the messages table:
//   - Subject → messages.subject (indexed, used with LIKE for partial match)
//   - From/To/Cc → messages.*_email_sort, *_name_sort (indexed, used with LIKE)
//   - Message-ID, In-Reply-To → messages.message_id, in_reply_to (indexed, exact match)
//
// The headers_tsv GIN index was 7.5 GB (vs text_body_tsv at 1.2 GB) due to indexing
// Received chains, DKIM signatures, and other noise. Removing it saves 7.5 GB and
// eliminates 12+ second FTS update queries that were blocked on GIN index updates.
//
// This code is retained temporarily for backward compatibility during migration.
// TODO: Remove after migration 000030 is deployed to all environments.

// ProcessFTSBatch processes up to 'limit' rows from messages_fts staging queue.
func (d *Database) ProcessFTSBatch(ctx context.Context, tx pgx.Tx, limit int) (int, error) {

	// Fetch up to LIMIT rows from the queue in FIFO order (oldest first)
	// Note: headers column removed in migration 000030 - only indexing text_body now
	query := `
		SELECT content_hash, text_body
		FROM messages_fts
		WHERE text_body_tsv IS NULL
		ORDER BY created_at ASC
		LIMIT $1
		FOR UPDATE SKIP LOCKED
	`
	rows, err := tx.Query(ctx, query, limit)
	if err != nil {
		return 0, fmt.Errorf("failed to poll messages_fts: %w", err)
	}
	defer rows.Close()

	type queueItem struct {
		Hash     string
		TextBody string
	}
	var items []queueItem
	for rows.Next() {
		var item queueItem
		var textBody *string
		if err := rows.Scan(&item.Hash, &textBody); err != nil {
			return 0, fmt.Errorf("failed to scan messages_fts: %w", err)
		}
		if textBody != nil {
			item.TextBody = *textBody
		}
		items = append(items, item)
	}
	rows.Close()

	if len(items) == 0 {
		return 0, nil
	}

	batch := &pgx.Batch{}
	for _, item := range items {
		// Remove pathological Base64/Hex blocks
		// PostgreSQL to_tsvector burns tremendous CPU trying to lex continuous junk bytes.
		// By removing this here in the background worker, we keep the index lean and fast
		// without burning any CPU during the IMAP APPEND hot path!
		safeBody := helpers.RemoveLongTokens(item.TextBody, 100)

		// Enqueue the update - only text_body_tsv now (headers_tsv removed)
		batch.Queue(`
			UPDATE messages_fts
			SET
				text_body_tsv = strip(to_tsvector('simple', $1)),
				text_body = NULL
			WHERE content_hash = $2
		`, safeBody, item.Hash)
	}

	br := tx.SendBatch(ctx, batch)
	defer br.Close()

	var failedHashes []string
	for i := 0; i < len(items); i++ {
		_, err := br.Exec()
		if err != nil {
			logger.Error("FTS: failed to update tsvector for content_hash", "hash", items[i].Hash, "err", err)
			failedHashes = append(failedHashes, items[i].Hash)
		}
	}
	br.Close() // Close before issuing a new command on the transaction

	// Mark failures with empty tsvector to avoid infinite loop
	if len(failedHashes) > 0 {
		_, err := tx.Exec(ctx, `
			UPDATE messages_fts
			SET
				text_body_tsv = ''::tsvector,
				text_body = NULL
			WHERE content_hash = ANY($1)
		`, failedHashes)
		if err != nil {
			logger.Error("FTS: failed to mark poison rows with empty vector", "count", len(failedHashes), "err", err)
		} else {
			logger.Warn("FTS: marked poison rows with empty vector to prevent retry loop", "count", len(failedHashes))
		}
	}

	return len(items), nil
}

// extractSearchableHeaders is DEPRECATED and unused after migration 000030.
// The headers column was dropped entirely because all searchable headers have
// dedicated columns in the messages table.
// This function is retained temporarily for backward compatibility during migration.
