package db

import (
	"bufio"
	"context"
	"fmt"
	"net/textproto"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/logger"
)

var headerBlocklist = map[string]bool{
	"Received":                true,
	"Dkim-Signature":          true,
	"Arc-Seal":                true,
	"Arc-Message-Signature":   true,
	"Authentication-Results":  true,
	"X-Google-Dkim-Signature": true,
}

// ProcessFTSBatch processes up to 'limit' rows from messages_fts staging queue.
func (d *Database) ProcessFTSBatch(ctx context.Context, tx pgx.Tx, limit int) (int, error) {

	// Fetch up to LIMIT rows from the queue in FIFO order (oldest first)
	query := `
		SELECT content_hash, headers, text_body 
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
		Headers  string
		TextBody string
	}
	var items []queueItem
	for rows.Next() {
		var item queueItem
		var headers, textBody *string
		if err := rows.Scan(&item.Hash, &headers, &textBody); err != nil {
			return 0, fmt.Errorf("failed to scan messages_fts: %w", err)
		}
		if headers != nil {
			item.Headers = *headers
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
		// Condense headers
		condensedHeaders := extractSearchableHeaders(item.Headers)

		// Remove pathological Base64/Hex blocks
		// PostgreSQL to_tsvector burns tremendous CPU trying to lex continuous junk bytes.
		// By removing this here in the background worker, we keep the index lean and fast
		// without burning any CPU during the IMAP APPEND hot path!
		safeHeaders := helpers.RemoveLongTokens(condensedHeaders, 100)
		safeBody := helpers.RemoveLongTokens(item.TextBody, 100)

		// Enqueue the update
		batch.Queue(`
			UPDATE messages_fts 
			SET 
				headers_tsv = strip(to_tsvector('simple', $1)),
				text_body_tsv = strip(to_tsvector('simple', $2)),
				headers = NULL,
				text_body = NULL
			WHERE content_hash = $3
		`, safeHeaders, safeBody, item.Hash)
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

	// Mark failures with empty tsvectors to avoid infinite loop
	if len(failedHashes) > 0 {
		_, err := tx.Exec(ctx, `
			UPDATE messages_fts 
			SET 
				text_body_tsv = ''::tsvector, 
				headers_tsv = ''::tsvector, 
				text_body = NULL, 
				headers = NULL
			WHERE content_hash = ANY($1)
		`, failedHashes)
		if err != nil {
			logger.Error("FTS: failed to mark poison rows with empty vectors", "count", len(failedHashes), "err", err)
		} else {
			logger.Warn("FTS: marked poison rows with empty vectors to prevent retry loop", "count", len(failedHashes))
		}
	}

	return len(items), nil
}

func extractSearchableHeaders(raw string) string {
	if raw == "" {
		return ""
	}

	// Parse the raw headers
	reader := bufio.NewReader(strings.NewReader(raw + "\r\n"))
	parsed, err := textproto.NewReader(reader).ReadMIMEHeader()
	if err != nil {
		return raw // Fallback to raw if parsing fails
	}

	var result strings.Builder
	for key, values := range parsed {
		// textproto.ReadHeader canonically capitalizes keys (e.g. "Dkim-Signature")
		if headerBlocklist[key] {
			continue
		}

		for _, val := range values {
			result.WriteString(val)
			result.WriteString(" ")
		}
	}
	return result.String()
}
