package db

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/logger"
)

// Only message bodies are indexed for full-text search (text_body_tsv). The
// headers/headers_tsv columns were dropped in migration 000030: all searchable
// headers have dedicated indexed columns on the messages table (subject,
// *_email_sort/*_name_sort, message_id, in_reply_to, "references"), and the
// headers_tsv GIN index was 7.5 GB of Received-chain/DKIM noise that caused
// 12+ second FTS update queries.
//
// TWO TABLES, ONE VECTOR
//
// messages_fts is keyed by content_hash alone and shared by every account holding that
// body. messages_fts_v2 (migration 000050) holds one row per (content_hash, account_id) so
// that a body search can be scoped to a single account through the composite GIN on
// (account_id, text_body_tsv), instead of scanning the whole corpus for a common term.
//
// The worker keeps both current until migration 000051 retires messages_fts, so that
// rolling back the release that introduced v2 needs no data work. That matters more than
// usual here: text_body is nulled the instant its vector is computed, so the tsvector is
// the ONLY copy of that data -- it cannot be recomputed without re-fetching and re-parsing
// every body from S3.
//
// Tokenisation happens EXACTLY ONCE per content hash however many accounts hold it: one
// anchor row is tokenised, and every other row copies the finished vector. A newsletter
// delivered to 10k accounts must not pay to_tsvector 10k times.

// ftsFanoutCap bounds how many messages_fts_v2 rows a single fan-out UPDATE may touch.
//
// All rows sharing a hash become ready the moment that hash is tokenised, and a widely
// delivered body has one row per recipient account. Fanning out to all of them in one
// statement would put an unbounded write, and an unbounded GIN maintenance burst, inside
// the worker's 30 second batch context. The fan-out loops in bounded chunks instead.
const ftsFanoutCap = 1000

// ftsQueueItem is one polled row of the staging queue.
type ftsQueueItem struct {
	Hash      string
	AccountID int64
	TextBody  string
}

// ProcessFTSBatch processes up to 'limit' rows from the messages_fts_v2 staging queue.
//
// It returns the number of rows RESOLVED -- given a vector or poisoned -- and not the number
// polled. The distinction is what stops the caller spinning: server/fts/worker.go loops while
// this reports progress, and a row that is deliberately left queued (its hash's text is still
// pending in another worker's batch) would otherwise be re-polled forever.
func (d *Database) ProcessFTSBatch(ctx context.Context, tx pgx.Tx, limit int) (int, error) {
	// FIFO over the queue index (created_at) WHERE text_body_tsv IS NULL.
	rows, err := tx.Query(ctx, `
		SELECT content_hash, account_id, text_body
		FROM messages_fts_v2
		WHERE text_body_tsv IS NULL
		ORDER BY created_at ASC
		LIMIT $1
		FOR UPDATE SKIP LOCKED
	`, limit)
	if err != nil {
		return 0, fmt.Errorf("failed to poll messages_fts_v2: %w", err)
	}

	var items []ftsQueueItem
	for rows.Next() {
		var item ftsQueueItem
		var textBody *string
		if err := rows.Scan(&item.Hash, &item.AccountID, &textBody); err != nil {
			rows.Close()
			return 0, fmt.Errorf("failed to scan messages_fts_v2: %w", err)
		}
		if textBody != nil {
			item.TextBody = *textBody
		}
		items = append(items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, fmt.Errorf("failed to read messages_fts_v2 queue: %w", err)
	}
	if len(items) == 0 {
		return 0, nil
	}

	// Collapse to one entry per hash, keeping FIFO order. The first row carrying text
	// becomes that hash's anchor: the single row we actually tokenise.
	var order []string
	anchor := make(map[string]ftsQueueItem, len(items))
	for _, item := range items {
		if _, seen := anchor[item.Hash]; !seen {
			order = append(order, item.Hash)
			anchor[item.Hash] = item
			continue
		}
		if anchor[item.Hash].TextBody == "" && item.TextBody != "" {
			anchor[item.Hash] = item
		}
	}

	// Lock order. Two workers can hold different rows of the same hash, and each touches
	// the one shared messages_fts row per hash. Walking hashes in a fixed order means two
	// batches sharing several hashes cannot take those shared rows in opposite orders.
	sort.Strings(order)

	resolved := 0
	var noText []string
	for _, hash := range order {
		item := anchor[hash]
		if item.TextBody == "" {
			// This hash's text lives on some other row (or nowhere at all). Classified
			// and handled below, in one round trip for all such hashes.
			noText = append(noText, hash)
			continue
		}
		// Each hash is tokenised inside its own savepoint. Without one, a single bad
		// payload -- to_tsvector raises 22P05 "invalid byte sequence" on some inputs, which
		// is exactly why migrations 000016/000017 exist -- aborts the whole transaction, and
		// then the poison UPDATE meant to drain that row fails too with "current
		// transaction is aborted". The queue would stall on that row forever.
		if _, err := tx.Exec(ctx, "SAVEPOINT fts_hash"); err != nil {
			return resolved, fmt.Errorf("failed to create savepoint for %s: %w", item.Hash, err)
		}
		n, err := d.tokenizeAndFanOut(ctx, tx, item)
		if err != nil {
			if _, rerr := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT fts_hash"); rerr != nil {
				return resolved, fmt.Errorf("failed to roll back savepoint for %s: %w", item.Hash, rerr)
			}
			// Only a payload PostgreSQL cannot tokenise is poison. Anything else -- a
			// deadlock, a lock or statement timeout, a dropped connection, a cancelled
			// context -- says nothing about the body, and poisoning it would be permanent
			// data loss: the text is nulled here, so the vector could never be rebuilt.
			// Fail the batch instead; it rolls back and the rows are polled again.
			if !isFTSDataError(err) {
				return resolved, fmt.Errorf("failed to index %s: %w", item.Hash, err)
			}
			logger.Error("FTS: failed to index content_hash, marking poison", "hash", item.Hash, "err", err)
			if perr := d.poisonFTSHashes(ctx, tx, []string{item.Hash}); perr != nil {
				return resolved, fmt.Errorf("failed to poison %s: %w", item.Hash, perr)
			}
			resolved++
			continue
		}
		if _, err := tx.Exec(ctx, "RELEASE SAVEPOINT fts_hash"); err != nil {
			return resolved, fmt.Errorf("failed to release savepoint for %s: %w", item.Hash, err)
		}
		resolved += n
	}

	n, err := d.resolveTextlessHashes(ctx, tx, noText)
	if err != nil {
		return resolved, err
	}
	resolved += n

	return resolved, nil
}

// tokenizeAndFanOut computes the vector for one hash exactly once and then propagates it:
// to the anchor row, to the shared messages_fts row (dual-write), and to every other v2 row
// of that hash in bounded chunks.
func (d *Database) tokenizeAndFanOut(ctx context.Context, tx pgx.Tx, item ftsQueueItem) (int, error) {
	// Remove pathological Base64/Hex blocks. PostgreSQL's to_tsvector burns tremendous CPU
	// lexing continuous junk bytes; stripping it here in the background worker keeps the
	// index lean without spending anything on the IMAP APPEND hot path.
	safeBody := helpers.RemoveLongTokens(item.TextBody, 100)

	// The one and only to_tsvector call for this hash.
	tag, err := tx.Exec(ctx, `
		UPDATE messages_fts_v2
		SET text_body_tsv = strip(to_tsvector('simple', $1)), text_body = NULL
		WHERE content_hash = $2 AND account_id = $3 AND text_body_tsv IS NULL
	`, safeBody, item.Hash, item.AccountID)
	if err != nil {
		return 0, fmt.Errorf("tokenize: %w", err)
	}
	resolved := int(tag.RowsAffected())

	// Dual-write the shared table by COPYING the vector we just computed, never by
	// tokenising again. Retired with messages_fts in migration 000051.
	//
	// SKIP LOCKED: the shared row may be held by another worker handling the same hash (or
	// by an old-binary worker during a rolling deploy), which is writing the same vector.
	// Waiting would only risk a deadlock or a lock timeout.
	if _, err := tx.Exec(ctx, `
		UPDATE messages_fts f
		SET text_body_tsv = v.text_body_tsv, text_body = NULL
		FROM messages_fts_v2 v
		WHERE f.ctid IN (SELECT ctid FROM messages_fts
		                 WHERE content_hash = $1 AND text_body_tsv IS NULL
		                 FOR UPDATE SKIP LOCKED)
		  AND v.content_hash = $1 AND v.account_id = $2 AND v.text_body_tsv IS NOT NULL
	`, item.Hash, item.AccountID); err != nil {
		return resolved, fmt.Errorf("dual-write messages_fts: %w", err)
	}

	n, err := d.fanOutVector(ctx, tx, item.Hash)
	if err != nil {
		return resolved, err
	}
	return resolved + n, nil
}

// fanOutVector copies a hash's finished vector onto its remaining per-account rows, in
// chunks of ftsFanoutCap so one very widely delivered body cannot monopolise the batch.
func (d *Database) fanOutVector(ctx context.Context, tx pgx.Tx, hash string) (int, error) {
	total := 0
	for {
		// The source vector may live in either table. Preferring v2 and falling back to
		// the shared messages_fts row matters during the transition: a hash indexed before
		// migration 000050 has its vector in the old table, and a per-account row created
		// afterwards (by a cross-account COPY, say) would otherwise sit queued forever --
		// it carries no text of its own to tokenise and no v2 sibling to copy from. The two
		// vectors are identical by construction, so which one wins is immaterial.
		//
		// Targets are taken FOR UPDATE SKIP LOCKED. A queued row that another worker has
		// polled belongs to that worker, which resolves it itself; waiting for it instead is
		// how two workers fanning out the same hash deadlocked (each waiting for the row the
		// other polled). A non-empty source vector is preferred over a poisoned '' one.
		tag, err := tx.Exec(ctx, `
			WITH src AS (
				SELECT COALESCE(
					(SELECT v.text_body_tsv FROM messages_fts_v2 v
					  WHERE v.content_hash = $1 AND v.text_body_tsv IS NOT NULL
					  ORDER BY length(v.text_body_tsv) = 0 LIMIT 1),
					(SELECT f.text_body_tsv FROM messages_fts f
					  WHERE f.content_hash = $1 AND f.text_body_tsv IS NOT NULL LIMIT 1)
				) AS tsv
			), target AS (
				SELECT ctid FROM messages_fts_v2
				WHERE content_hash = $1 AND text_body_tsv IS NULL
				LIMIT $2
				FOR UPDATE SKIP LOCKED
			)
			UPDATE messages_fts_v2 t
			SET text_body_tsv = (SELECT tsv FROM src), text_body = NULL
			WHERE t.ctid IN (SELECT ctid FROM target)
			  AND (SELECT tsv FROM src) IS NOT NULL
		`, hash, ftsFanoutCap)
		if err != nil {
			return total, fmt.Errorf("fan out %s: %w", hash, err)
		}
		n := int(tag.RowsAffected())
		total += n
		if n < ftsFanoutCap {
			return total, nil
		}
	}
}

// resolveTextlessHashes handles queued rows whose own text is gone -- the normal case for
// the second and later accounts to receive a body, since only the first delivery stages the
// text (see stageFTS in append.go).
//
// Three outcomes, and the middle one is why this cannot simply poison everything it cannot
// resolve:
//
//   - a sibling already carries a computed vector (in either table) -> copy it;
//   - no vector yet, but a sibling still carries pending text -> LEAVE QUEUED, because that
//     text is about to be tokenised by this or another worker. Poisoning here would blank
//     out a message that was always perfectly indexable;
//   - neither -> poison with an empty vector, so the queue drains instead of looping on a
//     row nothing can ever resolve.
func (d *Database) resolveTextlessHashes(ctx context.Context, tx pgx.Tx, hashes []string) (int, error) {
	if len(hashes) == 0 {
		return 0, nil
	}

	rows, err := tx.Query(ctx, `
		SELECT h.content_hash,
		       EXISTS (SELECT 1 FROM messages_fts_v2 v
		                WHERE v.content_hash = h.content_hash AND v.text_body_tsv IS NOT NULL)
		    OR EXISTS (SELECT 1 FROM messages_fts f
		                WHERE f.content_hash = h.content_hash AND f.text_body_tsv IS NOT NULL) AS has_vector,
		       EXISTS (SELECT 1 FROM messages_fts_v2 v
		                WHERE v.content_hash = h.content_hash AND v.text_body IS NOT NULL)
		    OR EXISTS (SELECT 1 FROM messages_fts f
		                WHERE f.content_hash = h.content_hash AND f.text_body IS NOT NULL) AS has_text
		FROM unnest($1::text[]) AS h(content_hash)
	`, hashes)
	if err != nil {
		return 0, fmt.Errorf("failed to classify textless fts hashes: %w", err)
	}

	var copyable, poison []string
	for rows.Next() {
		var hash string
		var hasVector, hasText bool
		if err := rows.Scan(&hash, &hasVector, &hasText); err != nil {
			rows.Close()
			return 0, fmt.Errorf("failed to scan fts classification: %w", err)
		}
		switch {
		case hasVector:
			copyable = append(copyable, hash)
		case hasText:
			// leave queued on purpose
		default:
			poison = append(poison, hash)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, fmt.Errorf("failed to read fts classification: %w", err)
	}

	resolved := 0
	for _, hash := range copyable {
		n, err := d.fanOutVector(ctx, tx, hash)
		if err != nil {
			return resolved, err
		}
		resolved += n
	}

	if len(poison) > 0 {
		if err := d.poisonFTSHashes(ctx, tx, poison); err != nil {
			return resolved, err
		}
		logger.Warn("FTS: marked poison rows with empty vector to prevent retry loop", "count", len(poison))
		resolved += len(poison)
	}

	return resolved, nil
}

// poisonFTSHashes marks a hash unsearchable-but-done in both tables, so the queue drains.
func (d *Database) poisonFTSHashes(ctx context.Context, tx pgx.Tx, hashes []string) error {
	// SKIP LOCKED for the same reason as the fan-out: a row another worker holds is that
	// worker's to resolve, and waiting for it is how batches deadlock.
	if _, err := tx.Exec(ctx, `
		UPDATE messages_fts_v2
		SET text_body_tsv = ''::tsvector, text_body = NULL
		WHERE ctid IN (SELECT ctid FROM messages_fts_v2
		               WHERE content_hash = ANY($1) AND text_body_tsv IS NULL
		               FOR UPDATE SKIP LOCKED)
	`, hashes); err != nil {
		return fmt.Errorf("failed to poison messages_fts_v2 rows: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE messages_fts
		SET text_body_tsv = ''::tsvector, text_body = NULL
		WHERE ctid IN (SELECT ctid FROM messages_fts
		               WHERE content_hash = ANY($1) AND text_body_tsv IS NULL
		               FOR UPDATE SKIP LOCKED)
	`, hashes); err != nil {
		return fmt.Errorf("failed to poison messages_fts rows: %w", err)
	}
	return nil
}

// isFTSDataError reports whether err means the body itself cannot be tokenised: a data
// exception (class 22, e.g. 22P05 invalid byte sequence) or a program limit (class 54, e.g.
// 54000 "string is too long for tsvector"). Only those justify poisoning, because only
// those would fail again on every retry.
func isFTSDataError(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return strings.HasPrefix(pgErr.Code, "22") || strings.HasPrefix(pgErr.Code, "54")
}
