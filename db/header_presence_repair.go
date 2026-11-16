package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Rows stored before migration 000070 (which added header_presence without a backfill) and
// rows copied, moved, or restored from them hold a NULL header_presence. While NULL,
// online SEARCH preserves legacy predicates, so UID SEARCH HEADER From/To/Cc "" and
// FROM/TO/CC "" match messages that lack the header (#661).
//
// FindNullHeaderPresence scans one batch of messages in primary-key order and resolves any
// live NULL row whose content_hash matches another row with a non-NULL header_presence
// (same raw bytes -> identical RFC 5322 header block). Rows with no database donor are
// returned in NeedsS3 so an explicit admin repair with --from-s3 can inspect the stored
// header block in S3 and pass the resulting HeaderPresenceFill entries to
// FillNullHeaderPresence.

const nullHeaderPresenceBatchSQL = `
	SELECT s.id, s.missing, s.uploaded, s.s3_domain, s.s3_localpart, s.content_hash, donor.header_presence
	FROM (
		SELECT id, content_hash, uploaded, s3_domain, s3_localpart,
		       (header_presence IS NULL AND expunged_at IS NULL) AS missing
		FROM messages
		WHERE id > $1
		ORDER BY id
		LIMIT $2
	) s
	LEFT JOIN LATERAL (
		SELECT d.header_presence
		FROM messages d
		WHERE s.missing AND d.content_hash = s.content_hash AND d.header_presence IS NOT NULL
		ORDER BY d.id DESC
		LIMIT 1
	) donor ON TRUE
	ORDER BY s.id`

const fillNullHeaderPresenceSQL = `
	UPDATE messages m
	SET header_presence = f.mask
	FROM unnest($1::bigint[], $2::smallint[]) AS f(id, mask)
	WHERE m.id = f.id AND m.header_presence IS NULL AND m.expunged_at IS NULL`

// HeaderPresenceFill is a live row with NULL header_presence and the resolved bitmask for
// its RFC 5322 header block.
type HeaderPresenceFill struct {
	ID             int64
	HeaderPresence int16
}

// HeaderPresenceS3Candidate is a live row with NULL header_presence for which no database
// donor row had a non-NULL mask.
type HeaderPresenceS3Candidate struct {
	ID          int64
	Uploaded    bool
	S3Domain    string
	S3Localpart string
	ContentHash string
}

// NullHeaderPresenceBatch is one batch returned by FindNullHeaderPresence.
type NullHeaderPresenceBatch struct {
	Scanned int                         // rows read, live or not; 0 at end of table
	LastID  int64                       // last id read: resume cursor for the next batch
	Missing int                         // live rows among them whose header_presence is NULL
	Fills   []HeaderPresenceFill        // rows resolved from a same-content_hash DB donor
	NeedsS3 []HeaderPresenceS3Candidate // rows with no DB donor (resolvable from S3 if uploaded)
}

// FindNullHeaderPresence reads up to limit rows after afterID in primary-key order through
// the read pool (QueryExecModeExec) without holding session state.
func (d *Database) FindNullHeaderPresence(ctx context.Context, afterID int64, limit int) (NullHeaderPresenceBatch, error) {
	rows, err := d.GetReadPoolWithContext(ctx).Query(ctx, nullHeaderPresenceBatchSQL, pgx.QueryExecModeExec, afterID, limit)
	if err != nil {
		return NullHeaderPresenceBatch{}, fmt.Errorf("failed to read messages after id %d: %w", afterID, err)
	}
	defer rows.Close()

	var batch NullHeaderPresenceBatch
	for rows.Next() {
		var id int64
		var missing, uploaded bool
		var s3Domain, s3Localpart, contentHash string
		var donorMask *int16
		if err := rows.Scan(&id, &missing, &uploaded, &s3Domain, &s3Localpart, &contentHash, &donorMask); err != nil {
			return NullHeaderPresenceBatch{}, fmt.Errorf("failed to read messages after id %d: %w", afterID, err)
		}
		batch.Scanned++
		batch.LastID = id
		if !missing {
			continue
		}
		batch.Missing++
		if donorMask != nil {
			batch.Fills = append(batch.Fills, HeaderPresenceFill{ID: id, HeaderPresence: *donorMask})
		} else {
			batch.NeedsS3 = append(batch.NeedsS3, HeaderPresenceS3Candidate{
				ID:          id,
				Uploaded:    uploaded,
				S3Domain:    s3Domain,
				S3Localpart: s3Localpart,
				ContentHash: contentHash,
			})
		}
	}
	if err := rows.Err(); err != nil {
		return NullHeaderPresenceBatch{}, fmt.Errorf("failed to read messages after id %d: %w", afterID, err)
	}
	return batch, nil
}

// FillNullHeaderPresence writes resolved header_presence masks by primary key, touching
// only rows that are still live and NULL without bumping modseq.
func (d *Database) FillNullHeaderPresence(ctx context.Context, tx pgx.Tx, fills []HeaderPresenceFill) (int64, error) {
	if len(fills) == 0 {
		return 0, nil
	}
	ids := make([]int64, len(fills))
	masks := make([]int16, len(fills))
	for i, f := range fills {
		ids[i], masks[i] = f.ID, f.HeaderPresence
	}
	tag, err := tx.Exec(ctx, fillNullHeaderPresenceSQL, pgx.QueryExecModeExec, ids, masks)
	if err != nil {
		return 0, fmt.Errorf("failed to fill header_presence of %d message(s): %w", len(fills), err)
	}
	return tag.RowsAffected(), nil
}
