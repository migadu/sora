package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Rows copied or moved before #837 (COPY and MOVE did not carry the column) and rows
// stored before migration 000036 (which added it without a backfill) hold a NULL
// "references". Every insert path since stores the empty string for a message without a
// References header, so NULL marks exactly these rows: SEARCH HEADER References misses
// them, and THREAD falls back to In-Reply-To (RFC 5256 section 3).
//
// The repair uses only the database. A row with the same content_hash holds the same
// bytes, so the same References header, and the value stored for it is the value this
// row would have had. FindNullReferences finds the values for one batch of rows and
// FillNullReferences writes them. Rows whose body no other row holds a value for stay
// NULL: only the body in S3 has their header.

// nullReferencesBatchSQL reads up to $2 rows after id $1, in id order through the primary
// key, and for each live row whose "references" is NULL, the value of the newest row with
// the same content_hash that has one, through an index on content_hash. The lookup runs
// only for those rows. An expunged row can donate: the value describes the body.
const nullReferencesBatchSQL = `
	SELECT s.id, s.missing, donor."references"
	FROM (
		SELECT id, content_hash, ("references" IS NULL AND expunged_at IS NULL) AS missing
		FROM messages
		WHERE id > $1
		ORDER BY id
		LIMIT $2
	) s
	LEFT JOIN LATERAL (
		SELECT d."references"
		FROM messages d
		WHERE s.missing AND d.content_hash = s.content_hash AND d."references" IS NOT NULL
		ORDER BY d.id DESC
		LIMIT 1
	) donor ON TRUE
	ORDER BY s.id`

// fillNullReferencesSQL writes each value to its row by primary key, only while the row
// is still live and NULL: a row expunged or filled since the scan is left as it is.
const fillNullReferencesSQL = `
	UPDATE messages m
	SET "references" = f.refs
	FROM unnest($1::bigint[], $2::text[]) AS f(id, refs)
	WHERE m.id = f.id AND m."references" IS NULL AND m.expunged_at IS NULL`

// ReferencesFill is a row with a NULL "references" and the value another row with the
// same body holds.
type ReferencesFill struct {
	ID         int64
	References string
}

// NullReferencesBatch is one batch of FindNullReferences.
type NullReferencesBatch struct {
	Scanned int              // rows read, live or not; 0 at the end of the table
	LastID  int64            // the last id read: where the next batch starts
	Missing int              // live rows among them whose "references" is NULL
	Fills   []ReferencesFill // those of them another row with the same body holds a value for, in id order
}

// FindNullReferences reads up to limit rows of messages after id afterID, in id order,
// and returns how many of them are live with a NULL "references" and, for each of those
// that another row with the same content_hash holds a value for, that value.
//
// It only reads, in one statement through the read pool, planned with its arguments
// (QueryExecModeExec), avoiding a cached generic plan; the selected custom plan
// still depends on the table statistics and arguments. It keeps no session state, so it is safe
// under PgBouncer transaction pooling.
func (d *Database) FindNullReferences(ctx context.Context, afterID int64, limit int) (NullReferencesBatch, error) {
	rows, err := d.GetReadPoolWithContext(ctx).Query(ctx, nullReferencesBatchSQL, pgx.QueryExecModeExec, afterID, limit)
	if err != nil {
		return NullReferencesBatch{}, fmt.Errorf("failed to read messages after id %d: %w", afterID, err)
	}
	defer rows.Close()

	var batch NullReferencesBatch
	for rows.Next() {
		var id int64
		var missing bool
		var references *string
		if err := rows.Scan(&id, &missing, &references); err != nil {
			return NullReferencesBatch{}, fmt.Errorf("failed to read messages after id %d: %w", afterID, err)
		}
		batch.Scanned++
		batch.LastID = id
		if !missing {
			continue
		}
		batch.Missing++
		if references != nil {
			batch.Fills = append(batch.Fills, ReferencesFill{ID: id, References: *references})
		}
	}
	if err := rows.Err(); err != nil {
		return NullReferencesBatch{}, fmt.Errorf("failed to read messages after id %d: %w", afterID, err)
	}
	return batch, nil
}

// FillNullReferences writes the values FindNullReferences found, in one statement, and
// returns how many rows it filled. A row expunged or filled since the scan is skipped.
// The write transaction bounds lock waits; its UPDATE determines lock order. No modseq changes:
// FETCH reads a message's headers from its body, so no client-visible data changes, only
// what SEARCH HEADER References and THREAD find. The column is in no index, so a fill can
// be a heap-only update.
func (d *Database) FillNullReferences(ctx context.Context, tx pgx.Tx, fills []ReferencesFill) (int64, error) {
	if len(fills) == 0 {
		return 0, nil
	}
	ids := make([]int64, len(fills))
	references := make([]string, len(fills))
	for i, f := range fills {
		ids[i], references[i] = f.ID, f.References
	}
	tag, err := tx.Exec(ctx, fillNullReferencesSQL, pgx.QueryExecModeExec, ids, references)
	if err != nil {
		return 0, fmt.Errorf("failed to fill references of %d message(s): %w", len(fills), err)
	}
	return tag.RowsAffected(), nil
}
