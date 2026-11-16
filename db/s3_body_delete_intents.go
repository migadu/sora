package db

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
)

// ErrS3BodyQuarantined is a refusal to claim bytes whose earlier DELETE may still
// arrive. Waiting for a lease or heartbeat is not proof that storage finished it.
var ErrS3BodyQuarantined = fmt.Errorf("S3 body has an unresolved deletion intent: %w", consts.ErrDBNotFound)

// S3BodyRetireRow records the expunge lifecycle eligible before storage I/O.
// Tuple is only an in-memory retirement guard; reconciliation uses the logical
// lifecycle so detaching an already expunged mailbox does not erase provenance.
type S3BodyRetireRow struct {
	ID             int64     `json:"id"`
	Tuple          string    `json:"-"`
	ExpungedAt     time.Time `json:"expunged_at"`
	ExpungedModSeq *int64    `json:"expunged_modseq"`
}

type S3BodyDeleteIntent struct {
	ContentHash    string
	OperationID    string
	ObjectKeys     []string
	CreatedAt      time.Time
	LastError      *string
	RetireSnapshot []S3BodyRetireRow
}

// CheckS3BodyClaims must run after the transaction takes the account-independent
// body locks and before any storage I/O or uploaded-row admission for these hashes.
func CheckS3BodyClaims(ctx context.Context, tx pgx.Tx, hashes []string) error {
	if len(hashes) == 0 {
		return nil
	}
	var quarantined bool
	var isolation string
	if err := tx.QueryRow(ctx, `SELECT current_setting('transaction_isolation'), EXISTS(SELECT 1 FROM s3_body_delete_intents WHERE content_hash=ANY($1::text[]))`, pgx.QueryExecModeSimpleProtocol, hashes).Scan(&isolation, &quarantined); err != nil {
		return fmt.Errorf("check S3 body deletion intents: %w", err)
	}
	if isolation != "read committed" {
		return fmt.Errorf("S3 body admission requires READ COMMITTED: %w", ErrS3BodyQuarantined)
	}
	if err := checkS3BodyClaimContinuity(ctx, tx, hashes); err != nil {
		return err
	}
	if quarantined {
		return ErrS3BodyQuarantined
	}
	// Leave neither an extended-protocol portal nor the catalog lookup snapshot
	// pinned across the following storage request.
	_, err := tx.Exec(ctx, "SELECT 1")
	return err
}

// persistS3BodyDeleteIntents uses a separate committed transaction: the fence
// must survive rollback/death of the transaction that protects the reference
// snapshot. Its caller holds the body locks and must prove that holder still
// lives after this commit and before sending DELETE. A failed/unknown commit is
// never "undone" here: any committed intent must remain fail-closed.
func (d *Database) persistS3BodyDeleteIntents(ctx context.Context, keysByHash map[string][]string, snapshots map[string][]S3BodyRetireRow) (map[string]S3BodyDeleteIntent, error) {
	own := make(map[string]S3BodyDeleteIntent, len(keysByHash))
	if len(keysByHash) == 0 {
		return own, nil
	}
	tx, err := d.GetWritePool().Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		rollbackCtx, cancelRollback := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelRollback()
		_ = tx.Rollback(rollbackCtx)
	}()
	hashes := make([]string, 0, len(keysByHash))
	for hash := range keysByHash {
		hashes = append(hashes, hash)
	}
	slices.Sort(hashes)

	type entry struct {
		Hash     string            `json:"content_hash"`
		ID       string            `json:"operation_id"`
		Keys     []string          `json:"object_keys"`
		Snapshot []S3BodyRetireRow `json:"retire_snapshot"`
	}
	data := make([]entry, 0, len(hashes))
	for _, hash := range hashes {
		keys := slices.Clone(keysByHash[hash])
		slices.Sort(keys)
		keys = slices.Compact(keys)
		snapshot := snapshots[hash]
		if snapshot == nil {
			snapshot = []S3BodyRetireRow{}
		}
		data = append(data, entry{hash, uuid.NewString(), keys, snapshot})
	}
	payload, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `INSERT INTO s3_body_delete_intents(content_hash,operation_id,object_keys,retire_snapshot) SELECT content_hash,operation_id,object_keys,retire_snapshot FROM jsonb_to_recordset($1::jsonb) AS i(content_hash text,operation_id uuid,object_keys text[],retire_snapshot jsonb) ON CONFLICT(content_hash) DO NOTHING RETURNING content_hash,operation_id::text,object_keys,created_at,retire_snapshot`, payload)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var i S3BodyDeleteIntent
		if err := rows.Scan(&i.ContentHash, &i.OperationID, &i.ObjectKeys, &i.CreatedAt, &i.RetireSnapshot); err != nil {
			rows.Close()
			return nil, err
		}
		own[i.ContentHash] = i
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return own, nil
}

func clearOwnedS3BodyDeleteIntent(ctx context.Context, tx pgx.Tx, intent S3BodyDeleteIntent) error {
	tag, err := tx.Exec(ctx, `DELETE FROM s3_body_delete_intents WHERE content_hash=$1 AND operation_id=$2::uuid`, intent.ContentHash, intent.OperationID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("S3 body deletion intent ownership changed: %w", ErrS3BodyQuarantined)
	}
	return nil
}

func (d *Database) ListS3BodyDeleteIntents(ctx context.Context) ([]S3BodyDeleteIntent, error) {
	rows, err := d.GetWritePool().Query(ctx, `SELECT content_hash,operation_id::text,object_keys,created_at,last_error,retire_snapshot FROM s3_body_delete_intents ORDER BY created_at,content_hash`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var intents []S3BodyDeleteIntent
	for rows.Next() {
		var i S3BodyDeleteIntent
		if err := rows.Scan(&i.ContentHash, &i.OperationID, &i.ObjectKeys, &i.CreatedAt, &i.LastError, &i.RetireSnapshot); err != nil {
			return nil, err
		}
		intents = append(intents, i)
	}
	return intents, rows.Err()
}

// ReconcileS3BodyDeleteIntent is deliberately an operator action, not a lease
// expiry path. The caller must first prove that the old storage requests cannot
// resume. It verifies protected keys (references outside the original expunge
// lifecycle), or deletes orphan-only keys, before clearing this exact UUID.
// A failed callback or commit leaves the durable fence in place.
func (d *Database) ReconcileS3BodyDeleteIntent(ctx context.Context, hash, operationID string, storageDrained bool, fn func(context.Context, S3BodyDeleteIntent, map[string]bool) error) error {
	if !storageDrained {
		return fmt.Errorf("reconciliation requires an explicit drained-storage acknowledgement")
	}
	id, err := uuid.Parse(operationID)
	if err != nil || id == uuid.Nil {
		return fmt.Errorf("valid operation UUID is required")
	}
	lockCtx, cancel := context.WithTimeout(ctx, s3ObjectLockTimeout)
	defer cancel()
	lock, err := d.beginAdvisoryLockTx(lockCtx, pgx.ReadWrite)
	if err != nil {
		return err
	}
	defer lock.Release()
	if err := lock.Lock(lockCtx, GetS3ObjectLockID(0, hash)); err != nil {
		return err
	}
	var intent S3BodyDeleteIntent
	required := map[string]bool{}
	if err := lock.run(lockCtx, func(ctx context.Context, tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT content_hash,operation_id::text,object_keys,created_at,last_error,retire_snapshot FROM s3_body_delete_intents WHERE content_hash=$1 AND operation_id=$2::uuid FOR UPDATE`, hash, id.String()).Scan(&intent.ContentHash, &intent.OperationID, &intent.ObjectKeys, &intent.CreatedAt, &intent.LastError, &intent.RetireSnapshot)
		if err != nil {
			return fmt.Errorf("deletion intent changed or missing: %w", err)
		}
		snapshot, err := json.Marshal(intent.RetireSnapshot)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `
    SELECT DISTINCT m.s3_domain||'/'||m.s3_localpart||'/'||m.content_hash
    FROM messages m
    WHERE m.content_hash=$1 AND (m.s3_domain||'/'||m.s3_localpart||'/'||m.content_hash)=ANY($2::text[])
      AND (m.uploaded OR NOT EXISTS(SELECT 1 FROM pending_uploads p WHERE p.account_id=m.account_id AND p.content_hash=m.content_hash))
      AND NOT EXISTS(SELECT 1 FROM jsonb_to_recordset($3::jsonb) s(id bigint,expunged_at timestamptz,expunged_modseq bigint)
        WHERE m.id=s.id AND m.expunged_at=s.expunged_at AND m.expunged_modseq IS NOT DISTINCT FROM s.expunged_modseq)
  `, hash, intent.ObjectKeys, snapshot)
		if err != nil {
			return err
		}
		for rows.Next() {
			var key string
			if err := rows.Scan(&key); err != nil {
				rows.Close()
				return err
			}
			required[key] = true
		}
		rows.Close()
		return rows.Err()
	}); err != nil {
		return err
	}
	guarded, done := lock.Guard(ctx)
	defer done()
	if err := fn(guarded, intent, required); err != nil {
		lock.Release()
		d.noteS3BodyDeleteUncertainty(map[string]S3BodyDeleteIntent{hash: intent}, err)
		return err
	}
	finishCtx, stop := context.WithTimeout(ctx, s3ObjectLockTimeout)
	defer stop()
	if err := lock.run(finishCtx, func(ctx context.Context, tx pgx.Tx) error { return clearOwnedS3BodyDeleteIntent(ctx, tx, intent) }); err != nil {
		return err
	}
	return lock.commit(finishCtx)
}
