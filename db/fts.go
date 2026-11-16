package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/migadu/sora/logger"
)

// Only message bodies are indexed for full-text search (text_body_tsv). The
// headers/headers_tsv columns were dropped in migration 000030: all searchable
// headers have dedicated indexed columns on the messages table (subject,
// *_email_sort/*_name_sort, message_id, in_reply_to, "references"), and the
// headers_tsv GIN index was 7.5 GB of Received-chain/DKIM noise that caused
// 12+ second FTS update queries.
//
// messages_fts_v2 (migration 000050) holds one row per (content_hash, account_id) so that a
// body search can be scoped to a single account through the composite GIN on
// (account_id, text_body_tsv), instead of scanning the whole corpus for a common term.
// text_body is nulled the instant its vector is computed, so the tsvector is the ONLY copy
// of that data: it cannot be recomputed without re-fetching and re-parsing every body from
// S3.
//
// Tokenisation happens EXACTLY ONCE per content hash however many accounts hold it: one
// anchor row is tokenised, and every other row copies the finished vector. A newsletter
// delivered to 10k accounts must not pay to_tsvector 10k times.

// ftsFanoutCap bounds how many messages_fts_v2 rows a single fan-out UPDATE may touch.
//
// All rows sharing a hash become ready the moment that hash is tokenised, and a widely
// delivered body has one row per recipient account. Fanning out to all of them in one
// statement would put an unbounded write, and an unbounded GIN maintenance burst, inside
// the worker's 30 second batch context. The fan-out loops in bounded chunks instead, and
// checks the batch's time budget between them.
const ftsFanoutCap = 1000

// ftsTokenizeChunk is how many bodies one tokenising statement takes.
//
// The worker used to send five statements per body. Over a ~20 ms path to the primary that
// was most of its time: in production each worker indexed ~29 bodies per 20 s batch while a
// single server-side loop managed ~139 a second, and the queue fell 14 hours behind. A
// statement per chunk makes the round trips per batch independent of its size. The chunk is
// also the unit of the time budget and of the savepoint, so it stays small enough to finish
// well inside one budget and to keep a transaction's subtransactions far below the 64 that
// overflow PostgreSQL's per-backend subxid cache.
const ftsTokenizeChunk = 100

// ftsTokenizeSQL is the one definition of how a body becomes a vector, applied to the SQL
// expression col. The regexp drops every run of more than 100 characters between whitespace
// or angle brackets -- base64 and hex blobs that to_tsvector burns CPU lexing into junk -- and
// drops exactly what helpers.RemoveLongTokens drops (TestFTSTokenizeMatchesRemoveLongTokens),
// so vectors are what the worker produced when it did this in Go. Doing it in SQL means a
// body's text never leaves the database: the worker used to fetch every polled body and send
// it straight back.
func ftsTokenizeSQL(col string) string {
	return "strip(to_tsvector('simple', regexp_replace(" + col + `, '[^ \t\n\r<>]{101,}', '', 'g')))`
}

// ftsSourceVectorSQL is the vector the queued rows of content hash hashCol should copy: a
// non-empty one, else a poisoned empty one (the body could not be tokenised, so no copy of it
// can be).
//
// LIMIT 1 without ORDER BY stops at the first match. Ordering by length() instead detoasted
// every vector the body already had, on every call: a newsletter indexed in 10,000 accounts
// paid 10,000 decompressions for each new copy.
func ftsSourceVectorSQL(hashCol string) string {
	return `COALESCE(
		(SELECT v.text_body_tsv FROM messages_fts_v2 v
		  WHERE v.content_hash = ` + hashCol + ` AND length(v.text_body_tsv) > 0 LIMIT 1),
		(SELECT v.text_body_tsv FROM messages_fts_v2 v
		  WHERE v.content_hash = ` + hashCol + ` AND v.text_body_tsv IS NOT NULL LIMIT 1))`
}

// fillWaitingFTSRows gives the rows of hashes that wait for a sibling's vector -- no text,
// no vector, as restageFTS writes them for a copy into another account and stageFTS for a
// body another account has indexed -- what the FTS worker would give them: the hash's vector,
// or, while the hash's text is not tokenised yet, that text.
//
// Every deletion of FTS rows (the account drain, the orphan sweep, a rekey) runs it first for
// the hashes it deletes, holding their exclusive orphan-sweep locks: the row it deletes may be
// the only one a waiting row can be filled from, and the worker, finding none, would poison
// the waiting row with an empty vector. The locks keep out deliveries and copies staging those
// hashes, so every waiting row is visible here.
//
// It does not skip a row the worker has polled: the worker fills it from a sibling that stays
// until this transaction commits, and the update then finds it filled. The sources are looked
// up only for hashes that have a waiting row, so a vector is not read for every hash deleted.
func fillWaitingFTSRows(ctx context.Context, tx pgx.Tx, hashes []string) error {
	if len(hashes) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `
		UPDATE messages_fts_v2 t
		SET text_body_tsv = s.tsv, text_body = CASE WHEN s.tsv IS NULL THEN s.text END
		FROM (SELECT w.content_hash, `+ftsSourceVectorSQL("w.content_hash")+` AS tsv,
		             (SELECT v.text_body FROM messages_fts_v2 v
		               WHERE v.content_hash = w.content_hash AND v.text_body IS NOT NULL LIMIT 1) AS text
		      FROM (SELECT DISTINCT content_hash FROM messages_fts_v2
		             WHERE content_hash = ANY($1::text[]) AND text_body_tsv IS NULL AND text_body IS NULL) w) s
		WHERE t.content_hash = s.content_hash AND t.text_body_tsv IS NULL AND t.text_body IS NULL
		  AND (s.tsv IS NOT NULL OR s.text IS NOT NULL)`, hashes); err != nil {
		return fmt.Errorf("failed to fill waiting fts rows: %w", err)
	}
	return nil
}

// ftsQueueItem is one polled row of the staging queue.
type ftsQueueItem struct {
	Hash      string
	AccountID int64
	HasText   bool
}

// ProcessFTSBatch processes up to 'limit' rows from the messages_fts_v2 staging queue.
//
// It returns the number of rows RESOLVED -- given a vector or poisoned -- and not the number
// polled. The distinction is what stops the caller spinning: server/fts/worker.go loops while
// this reports progress, and a row that is deliberately left queued (its hash's text is still
// pending in another worker's batch) would otherwise be re-polled forever.
//
// Rows are indexed oldest first, a chunk of ftsTokenizeChunk bodies per statement. Nothing
// here waits on a row another worker holds -- every cross-row write takes its targets FOR
// UPDATE SKIP LOCKED -- so no lock order is needed, and the queue order is kept: when the
// time budget runs out, what was indexed is the oldest mail. Sorting a batch by hash before
// indexing it, as this once did, left the oldest body in production queued for 14 hours while
// newer mail was indexed around it.
func (d *Database) ProcessFTSBatch(ctx context.Context, tx pgx.Tx, limit int) (int, error) {
	// FIFO over the queue index (created_at) WHERE text_body_tsv IS NULL. The text itself is
	// not fetched: it is tokenised where it lies.
	rows, err := tx.Query(ctx, `
		SELECT content_hash, account_id, text_body IS NOT NULL
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
		if err := rows.Scan(&item.Hash, &item.AccountID, &item.HasText); err != nil {
			rows.Close()
			return 0, fmt.Errorf("failed to scan messages_fts_v2: %w", err)
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

	// Collapse to one entry per hash, in queue order. The first row carrying text becomes
	// that hash's anchor: the single row that is actually tokenised.
	var order []string
	anchor := make(map[string]ftsQueueItem, len(items))
	for _, item := range items {
		cur, seen := anchor[item.Hash]
		if !seen {
			order = append(order, item.Hash)
			anchor[item.Hash] = item
			continue
		}
		if !cur.HasText && item.HasText {
			anchor[item.Hash] = item
		}
	}
	var anchors []ftsQueueItem
	var noText []string
	for _, hash := range order {
		if item := anchor[hash]; item.HasText {
			anchors = append(anchors, item)
		} else {
			// This hash's text lives on some other row (or nowhere at all). Classified
			// and handled below, in one round trip for all such hashes.
			noText = append(noText, hash)
		}
	}

	// Time budget. A full batch can outlast the caller's deadline; when it did, the whole
	// transaction rolled back and the same FIFO rows were polled again, forever. Stop
	// starting new chunks once two thirds of the remaining time is spent and commit what is
	// done: rows polled but not reached are released at commit and polled again next batch.
	outOfTime := func() bool { return false }
	if deadline, ok := ctx.Deadline(); ok {
		stopAt := time.Now().Add(time.Until(deadline) * 2 / 3)
		outOfTime = func() bool { return time.Now().After(stopAt) }
	}

	resolved := 0
	for start := 0; start < len(anchors); start += ftsTokenizeChunk {
		if outOfTime() {
			logger.Info("FTS: batch time budget spent, committing partial progress", "resolved", resolved)
			return resolved, nil
		}
		n, err := d.indexChunk(ctx, tx, anchors[start:min(start+ftsTokenizeChunk, len(anchors))], outOfTime)
		if err != nil {
			return resolved, err
		}
		resolved += n
	}

	n, err := d.resolveTextlessHashes(ctx, tx, noText, outOfTime)
	if err != nil {
		return resolved, err
	}
	resolved += n

	return resolved, nil
}

// indexChunk indexes a chunk of anchors -- one queued, text-carrying row per content hash --
// in a few set-based statements, inside one savepoint.
//
// A body PostgreSQL cannot tokenise fails the whole tokenising statement. The chunk is then
// rolled back and redone one hash at a time through indexHash, which poisons just that body.
// That path is slow, but it only runs for a chunk that holds a bad body.
func (d *Database) indexChunk(ctx context.Context, tx pgx.Tx, chunk []ftsQueueItem, outOfTime func() bool) (int, error) {
	if _, err := tx.Exec(ctx, "SAVEPOINT fts_chunk"); err != nil {
		return 0, fmt.Errorf("failed to create savepoint for fts chunk: %w", err)
	}
	n, err := d.tokenizeChunk(ctx, tx, chunk, outOfTime)
	if err == nil {
		if _, err := tx.Exec(ctx, "RELEASE SAVEPOINT fts_chunk"); err != nil {
			return 0, fmt.Errorf("failed to release savepoint for fts chunk: %w", err)
		}
		return n, nil
	}
	if _, rerr := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT fts_chunk"); rerr != nil {
		return 0, fmt.Errorf("failed to roll back savepoint for fts chunk: %w", rerr)
	}
	if !isFTSDataError(err) {
		return 0, fmt.Errorf("failed to index fts chunk: %w", err)
	}

	logger.Warn("FTS: a body in this chunk cannot be tokenised, isolating it", "chunk", len(chunk), "err", err)
	resolved := 0
	for _, item := range chunk {
		if outOfTime() {
			break
		}
		n, err := d.indexHash(ctx, tx, item.Hash, func() (int, error) {
			return d.tokenizeAndFanOut(ctx, tx, item)
		})
		if err != nil {
			return resolved, err
		}
		resolved += n
	}
	if _, err := tx.Exec(ctx, "RELEASE SAVEPOINT fts_chunk"); err != nil {
		return resolved, fmt.Errorf("failed to release savepoint for fts chunk: %w", err)
	}
	return resolved, nil
}

// tokenizeChunk is indexChunk's set-based path: tokenise every anchor whose hash has no
// vector yet, in one statement; then copy vectors onto every other queued row of those
// hashes.
//
// An anchor whose hash already carries a vector -- a body whose first copy was indexed
// earlier -- is not tokenised again; the fan-out copies the existing vector onto it. A body
// is tokenised at most once however many accounts hold it.
func (d *Database) tokenizeChunk(ctx context.Context, tx pgx.Tx, chunk []ftsQueueItem, outOfTime func() bool) (int, error) {
	hashes := make([]string, len(chunk))
	accounts := make([]int64, len(chunk))
	for i, item := range chunk {
		hashes[i] = item.Hash
		accounts[i] = item.AccountID
	}

	tag, err := tx.Exec(ctx, `
		UPDATE messages_fts_v2 t
		SET text_body_tsv = `+ftsTokenizeSQL("t.text_body")+`, text_body = NULL
		FROM unnest($1::text[], $2::bigint[]) AS a(content_hash, account_id)
		WHERE t.content_hash = a.content_hash AND t.account_id = a.account_id
		  AND t.text_body_tsv IS NULL AND t.text_body IS NOT NULL
		  AND NOT EXISTS (SELECT 1 FROM messages_fts_v2 s
		                  WHERE s.content_hash = t.content_hash AND s.text_body_tsv IS NOT NULL)
	`, hashes, accounts)
	if err != nil {
		return 0, fmt.Errorf("tokenize: %w", err)
	}
	resolved := int(tag.RowsAffected())

	n, err := d.fanOutVectors(ctx, tx, hashes, outOfTime)
	return resolved + n, err
}

// indexHash runs fn, which indexes one hash, inside its own savepoint.
//
// Without a savepoint a single bad payload -- to_tsvector raises 22P05 "invalid byte
// sequence" on some inputs, which is exactly why migrations 000016/000017 exist -- aborts the
// whole transaction, and then the poison UPDATE meant to drain that row fails too with
// "current transaction is aborted". The queue would stall on that row forever.
//
// Only a payload PostgreSQL cannot tokenise is poison. Anything else -- a deadlock, a lock or
// statement timeout, a dropped connection, a cancelled context -- says nothing about the body,
// and poisoning it would be permanent data loss: the text is nulled when a vector is written,
// so the vector could never be rebuilt. Such an error fails the batch instead; it rolls back
// and the rows are polled again.
func (d *Database) indexHash(ctx context.Context, tx pgx.Tx, hash string, fn func() (int, error)) (int, error) {
	if _, err := tx.Exec(ctx, "SAVEPOINT fts_hash"); err != nil {
		return 0, fmt.Errorf("failed to create savepoint for %s: %w", hash, err)
	}
	n, err := fn()
	if err == nil {
		if _, err := tx.Exec(ctx, "RELEASE SAVEPOINT fts_hash"); err != nil {
			return 0, fmt.Errorf("failed to release savepoint for %s: %w", hash, err)
		}
		return n, nil
	}
	if _, rerr := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT fts_hash"); rerr != nil {
		return 0, fmt.Errorf("failed to roll back savepoint for %s: %w", hash, rerr)
	}
	if !isFTSDataError(err) {
		return 0, fmt.Errorf("failed to index %s: %w", hash, err)
	}
	logger.Error("FTS: failed to index content_hash, marking poison", "hash", hash, "err", err)
	if perr := d.poisonFTSHashes(ctx, tx, []string{hash}); perr != nil {
		return 0, fmt.Errorf("failed to poison %s: %w", hash, perr)
	}
	return 1, nil
}

// tokenizeFromPendingText indexes a hash whose polled rows carry no text, from whichever
// row of that hash still holds pending text and is not locked by another worker. It reports
// found=false when every such row is held by another worker, which is then resolving the
// hash itself.
//
// Tokenising here, instead of leaving the textless rows queued until that text row's own
// turn, keeps the FIFO queue moving: textless rows that sort ahead of their text row can fill
// a whole batch, which then resolves nothing, and the worker stops for the tick with newer
// mail waiting behind them.
func (d *Database) tokenizeFromPendingText(ctx context.Context, tx pgx.Tx, hash string) (int, bool, error) {
	var accountID int64
	err := tx.QueryRow(ctx, `
		SELECT account_id FROM messages_fts_v2
		WHERE content_hash = $1 AND text_body_tsv IS NULL AND text_body IS NOT NULL
		LIMIT 1
		FOR UPDATE SKIP LOCKED
	`, hash).Scan(&accountID)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("find pending text for %s: %w", hash, err)
	}
	n, err := d.tokenizeAndFanOut(ctx, tx, ftsQueueItem{Hash: hash, AccountID: accountID, HasText: true})
	return n, true, err
}

// tokenizeAndFanOut computes the vector for one hash exactly once and then propagates it to
// every other queued row of that hash in bounded chunks. It is the one-hash-at-a-time path,
// for a chunk that holds a body PostgreSQL cannot tokenise and for textless rows whose text
// sits on another row.
func (d *Database) tokenizeAndFanOut(ctx context.Context, tx pgx.Tx, item ftsQueueItem) (int, error) {
	// The one and only to_tsvector call for this hash.
	tag, err := tx.Exec(ctx, `
		UPDATE messages_fts_v2
		SET text_body_tsv = `+ftsTokenizeSQL("text_body")+`, text_body = NULL
		WHERE content_hash = $1 AND account_id = $2 AND text_body_tsv IS NULL AND text_body IS NOT NULL
	`, item.Hash, item.AccountID)
	if err != nil {
		return 0, fmt.Errorf("tokenize: %w", err)
	}
	resolved := int(tag.RowsAffected())

	n, err := d.fanOutVectors(ctx, tx, []string{item.Hash}, nil)
	return resolved + n, err
}

// fanOutVectors copies each hash's vector (ftsSourceVectorSQL) onto that hash's queued v2
// rows, ftsFanoutCap rows per statement, until none are left or the time budget is spent.
// Rows not reached stay queued, and a later batch finishes them.
//
// Targets are taken FOR UPDATE SKIP LOCKED. A queued row that another worker has polled
// belongs to that worker, which resolves it itself; waiting for it instead is how two
// workers fanning out the same hash deadlocked (each waiting for the row the other polled).
func (d *Database) fanOutVectors(ctx context.Context, tx pgx.Tx, hashes []string, outOfTime func() bool) (int, error) {
	if len(hashes) == 0 {
		return 0, nil
	}
	total := 0
	for {
		tag, err := tx.Exec(ctx, `
			WITH target AS (
				SELECT ctid, content_hash FROM messages_fts_v2
				WHERE content_hash = ANY($1) AND text_body_tsv IS NULL
				LIMIT $2
				FOR UPDATE SKIP LOCKED
			), src AS (
				SELECT h.content_hash, `+ftsSourceVectorSQL("h.content_hash")+` AS tsv
				FROM (SELECT DISTINCT content_hash FROM target) h
			)
			UPDATE messages_fts_v2 t
			SET text_body_tsv = s.tsv, text_body = NULL
			FROM target g JOIN src s ON s.content_hash = g.content_hash
			WHERE t.ctid = g.ctid AND s.tsv IS NOT NULL
		`, hashes, ftsFanoutCap)
		if err != nil {
			return total, fmt.Errorf("fan out: %w", err)
		}
		n := int(tag.RowsAffected())
		total += n
		if n < ftsFanoutCap || (outOfTime != nil && outOfTime()) {
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
//   - a sibling already carries a computed vector -> copy it;
//   - no vector yet, but a sibling still carries pending text -> tokenise
//     that text now and fan out (tokenizeFromPendingText), or leave the rows queued if every
//     such sibling is held by another worker, which is indexing the hash itself. Poisoning
//     here would blank out a message that was always perfectly indexable;
//   - neither -> poison with an empty vector, so the queue drains instead of looping on a
//     row nothing can ever resolve.
func (d *Database) resolveTextlessHashes(ctx context.Context, tx pgx.Tx, hashes []string, outOfTime func() bool) (int, error) {
	if len(hashes) == 0 {
		return 0, nil
	}

	rows, err := tx.Query(ctx, `
		SELECT h.content_hash,
		       EXISTS (SELECT 1 FROM messages_fts_v2 v
		                WHERE v.content_hash = h.content_hash AND v.text_body_tsv IS NOT NULL) AS has_vector,
		       EXISTS (SELECT 1 FROM messages_fts_v2 v
		                WHERE v.content_hash = h.content_hash AND v.text_body IS NOT NULL) AS has_text
		FROM unnest($1::text[]) AS h(content_hash)
	`, hashes)
	if err != nil {
		return 0, fmt.Errorf("failed to classify textless fts hashes: %w", err)
	}

	var copyable, pending, poison []string
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
			pending = append(pending, hash)
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
	if len(copyable) > 0 {
		if outOfTime() {
			return resolved, nil
		}
		n, err := d.fanOutVectors(ctx, tx, copyable, outOfTime)
		if err != nil {
			return resolved, err
		}
		resolved += n
	}

	for _, hash := range pending {
		if outOfTime() {
			return resolved, nil
		}
		n, err := d.indexHash(ctx, tx, hash, func() (int, error) {
			n, _, err := d.tokenizeFromPendingText(ctx, tx, hash)
			return n, err
		})
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

// poisonFTSHashes marks a hash unsearchable-but-done, so the queue drains.
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
