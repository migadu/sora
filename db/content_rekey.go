package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/helpers"
)

// Re-keying renames a stored body: its message rows and FTS rows move from one content hash
// to another, while the bytes stay the same. sora-admin uses it for bodies that older
// maildir importers stored under their SHA-256 digest, where every other path keys a body by
// its BLAKE3 digest (helpers.HashContent).

// ContentObject is one stored body: the S3 object <S3Domain>/<S3Localpart>/<ContentHash>
// that message rows point at.
type ContentObject struct {
	S3Domain    string
	S3Localpart string
	ContentHash string
}

// Key returns the object's S3 key.
func (o ContentObject) Key() string {
	return helpers.NewS3Key(o.S3Domain, o.S3Localpart, o.ContentHash)
}

// ErrRekeyUploadPending is returned by RekeyContentHash when the body has a pending upload.
// The uploader writes the old key and then marks the rows that still carry the old hash, so
// the body must not be renamed under it.
var ErrRekeyUploadPending = errors.New("the body has a pending upload")

// ListRekeyCandidates returns, in key order, up to limit distinct objects that accountID's
// uploaded message rows reference and whose key sorts after `after` (the zero value starts at
// the beginning). Expunged rows count: a restore brings them back with the hash they carry.
// A row not uploaded yet has no object to check (the importer marks its rows uploaded).
//
// A row with a delivery_hash is left out. Only an MTA delivery sets it, and that path has
// always keyed bodies by BLAKE3, so downloading the object to check it would be wasted. The
// walk follows idx_messages_s3_key_parts (account_id, s3_domain, s3_localpart, content_hash).
func (d *Database) ListRekeyCandidates(ctx context.Context, accountID int64, after ContentObject, limit int) ([]ContentObject, error) {
	rows, err := d.GetReadPoolWithContext(ctx).Query(ctx, `
		SELECT DISTINCT s3_domain, s3_localpart, content_hash
		FROM messages
		WHERE account_id = $1
		  AND (s3_domain, s3_localpart, content_hash) > ($2, $3, $4)
		  AND uploaded AND delivery_hash IS NULL
		ORDER BY s3_domain, s3_localpart, content_hash
		LIMIT $5`,
		accountID, after.S3Domain, after.S3Localpart, after.ContentHash, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list objects of account %d: %w", accountID, err)
	}
	objects, err := pgx.CollectRows(rows, pgx.RowToStructByPos[ContentObject])
	if err != nil {
		return nil, fmt.Errorf("failed to read objects of account %d: %w", accountID, err)
	}
	return objects, nil
}

// RekeyContentHash moves accountID's message rows that point at obj to newHash, under the
// same S3 domain and localpart, and returns how many rows it moved. The object
// <S3Domain>/<S3Localpart>/<newHash> must already hold the same bytes. The old object must
// remain for readers holding a pre-rekey snapshot. Deletion requires drained mail nodes
// and IsContentObjectReferenced reporting that no database rows point at it.
//
// The rows' FTS data moves with them. messages_fts_v2 is keyed by (content_hash, account_id)
// and belongs to the mailbox owner, so every row of the old hash whose account now references
// the new hash is copied to the new hash, and every row of the old hash that nothing
// references any more is deleted. Both decisions use ftsKeyReferencedSQL, the predicate of the
// orphan sweep, so a row another account (or another S3 path) still needs is kept. The text,
// vector and sent_date are copied rather than recomputed: the vector is the only copy of the
// indexed text.
//
// The sweep and the stagers coordinate through advisory locks on hashtext(hash) (see
// DeleteMessagesFTSByKeyBatch). The new hash's rows are written under the shared lock, as
// delivery does, so a sweep cannot delete a row the uncommitted messages need. The old hash's
// rows are deleted under the exclusive lock, as the sweep does, so a delivery or COPY still
// staging that hash is waited for and its rows are seen. Both are taken before any row is
// touched, so this cannot wait on a lock while holding row locks.
func (d *Database) RekeyContentHash(ctx context.Context, tx pgx.Tx, accountID int64, obj ContentObject, newHash string) (int64, error) {
	var pending bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pending_uploads WHERE content_hash = $1 AND account_id = $2)`,
		obj.ContentHash, accountID).Scan(&pending); err != nil {
		return 0, fmt.Errorf("failed to check pending uploads: %w", err)
	}
	if pending {
		return 0, ErrRekeyUploadPending
	}

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1, hashtext($2))",
		consts.SoraFTSOrphanSweepLockClassID, obj.ContentHash); err != nil {
		return 0, fmt.Errorf("failed to lock the old hash's fts rows: %w", err)
	}
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock_shared($1, hashtext($2))",
		consts.SoraFTSOrphanSweepLockClassID, newHash); err != nil {
		return 0, fmt.Errorf("failed to lock the new hash's fts rows: %w", err)
	}

	// A message stored without a Message-ID carries syntheticMessageID(hash, mailbox),
	// <hash@mailbox.synthetic.invalid>, and the importer's duplicate check matches on
	// (message_id, content_hash). The id moves with the hash, or a re-import, which derives
	// it from the new hash, would store the message a second time.
	tag, err := tx.Exec(ctx, `
		UPDATE messages SET content_hash = $5,
		       message_id = CASE WHEN starts_with(message_id, $6::text) AND message_id LIKE '%.synthetic.invalid>'
		                         THEN $7::text || substr(message_id, length($6::text) + 1)
		                         ELSE message_id END,
		       updated_at = now()
		WHERE account_id = $1 AND s3_domain = $2 AND s3_localpart = $3 AND content_hash = $4`,
		accountID, obj.S3Domain, obj.S3Localpart, obj.ContentHash, newHash,
		"<"+obj.ContentHash+"@", "<"+newHash+"@")
	if err != nil {
		return 0, fmt.Errorf("failed to re-key messages: %w", err)
	}

	// Every parameter is cast: in "INSERT ... SELECT $2" PostgreSQL would deduce $2 as text
	// in the select list and as varchar in the comparisons.
	if _, err := tx.Exec(ctx, `
		INSERT INTO messages_fts_v2 (content_hash, account_id, text_body, text_body_tsv, sent_date, created_at)
		SELECT $2::varchar(64), v.account_id, v.text_body, v.text_body_tsv, v.sent_date, v.created_at
		FROM messages_fts_v2 v
		WHERE v.content_hash = $1::varchar(64)
		  AND `+ftsKeyReferencedSQL("$2::varchar(64)", "v.account_id")+`
		ON CONFLICT (content_hash, account_id) DO NOTHING`,
		obj.ContentHash, newHash); err != nil {
		return 0, fmt.Errorf("failed to copy fts rows to the new hash: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM messages_fts_v2 v
		WHERE v.content_hash = $1::varchar(64)
		  AND NOT `+ftsKeyReferencedSQL("v.content_hash", "v.account_id"),
		obj.ContentHash); err != nil {
		return 0, fmt.Errorf("failed to delete fts rows of the old hash: %w", err)
	}

	return tag.RowsAffected(), nil
}

// IsContentObjectReferenced reports whether any message row, of any account and expunged or
// not, still points at obj, or an upload of its hash is pending. Only an object for which it
// reports false may be deleted. It reads the primary: a lagging replica could miss a row that
// was just written.
func (d *Database) IsContentObjectReferenced(ctx context.Context, obj ContentObject) (bool, error) {
	var referenced bool
	err := d.GetWritePool().QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM messages
		               WHERE content_hash = $3 AND s3_domain = $1 AND s3_localpart = $2)
		    OR EXISTS (SELECT 1 FROM pending_uploads WHERE content_hash = $3)`,
		obj.S3Domain, obj.S3Localpart, obj.ContentHash).Scan(&referenced)
	if err != nil {
		return false, fmt.Errorf("failed to check references to %s: %w", obj.Key(), err)
	}
	return referenced, nil
}
