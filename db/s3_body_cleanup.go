package db

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// S3BodyCleanupResult distinguishes confirmed deletion from explicit rejection.
// Every omitted/unknown outcome retains its durable fence. Rejected must only
// include a storage response proving DELETE was refused, with no earlier uncertain
// attempt. A timeout or cancellation never supplies that proof.
type S3BodyCleanupResult struct {
	Gone     []UserScopedObjectForCleanup
	Rejected []UserScopedObjectForCleanup
}

type bodyCleanupKey struct {
	account             int64
	domain, local, hash string
}

func bodyKey(o UserScopedObjectForCleanup) bodyCleanupKey {
	return bodyCleanupKey{o.AccountID, o.S3Domain, o.S3Localpart, o.ContentHash}
}
func bodyObjectKey(o UserScopedObjectForCleanup) string {
	return o.S3Domain + "/" + o.S3Localpart + "/" + o.ContentHash
}

type retiredBodyRow = S3BodyRetireRow

// ExecuteWithS3BodyCleanup keeps the reference decision and exact-row retirement
// on one writable lock transaction. Durable intents are committed before any
// DELETE, so the remote request remains fenced if that connection subsequently
// dies. Every claimant must check these intents after taking the same body lock.
func (d *Database) ExecuteWithS3BodyCleanup(ctx context.Context, objects []UserScopedObjectForCleanup, gracePeriod time.Duration, fn func(context.Context, []UserScopedObjectForCleanup) (S3BodyCleanupResult, error)) (int64, error) {
	if len(objects) == 0 {
		return 0, nil
	}
	lockCtx, cancel := context.WithTimeout(ctx, s3ObjectLockTimeout)
	defer cancel()
	locks, err := d.beginAdvisoryLockTx(lockCtx, pgx.ReadWrite)
	if err != nil {
		return 0, err
	}
	defer locks.Release()
	ids := make([]int64, len(objects))
	for i, o := range objects {
		ids[i] = GetS3ObjectLockID(o.AccountID, o.ContentHash)
	}
	acquired, err := locks.TryLockAll(lockCtx, ids)
	if err != nil {
		return 0, err
	}
	var locked []UserScopedObjectForCleanup
	for i, ok := range acquired {
		if ok {
			locked = append(locked, objects[i])
		}
	}
	var orphans []UserScopedObjectForCleanup
	snapshot := map[bodyCleanupKey][]retiredBodyRow{}
	threshold := time.Now().Add(-gracePeriod).UTC()
	readCtx, stopRead := context.WithTimeout(ctx, s3ObjectLockTimeout)
	defer stopRead()
	if err := locks.run(readCtx, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		orphans, err = d.filterS3Orphans(ctx, tx, locked, gracePeriod)
		if err != nil {
			return err
		}

		if len(orphans) > 0 {
			accounts := make([]int64, len(orphans))
			domains := make([]string, len(orphans))
			locals := make([]string, len(orphans))
			hashes := make([]string, len(orphans))
			for i, o := range orphans {
				accounts[i] = o.AccountID
				domains[i] = o.S3Domain
				locals[i] = o.S3Localpart
				hashes[i] = o.ContentHash
			}
			rows, err := tx.Query(ctx, `SELECT m.id,m.ctid::text,m.account_id,m.s3_domain,m.s3_localpart,m.content_hash,m.expunged_at,m.expunged_modseq FROM messages m JOIN unnest($1::bigint[],$2::text[],$3::text[],$4::text[]) c(account_id,domain,localpart,hash) ON m.account_id=c.account_id AND m.s3_domain=c.domain AND m.s3_localpart=c.localpart AND m.content_hash=c.hash WHERE m.expunged_at < $5`, pgx.QueryExecModeSimpleProtocol, accounts, domains, locals, hashes, threshold)
			if err != nil {
				return err
			}
			for rows.Next() {
				var r retiredBodyRow
				var key bodyCleanupKey
				if err := rows.Scan(&r.ID, &r.Tuple, &key.account, &key.domain, &key.local, &key.hash, &r.ExpungedAt, &r.ExpungedModSeq); err != nil {
					rows.Close()
					return err
				}
				snapshot[key] = append(snapshot[key], r)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return 0, err
	}
	keys := map[string][]string{}
	for _, o := range orphans {
		if !o.KeepObject {
			keys[o.ContentHash] = append(keys[o.ContentHash], bodyObjectKey(o))
		}
	}
	snapshotsByHash := map[string][]S3BodyRetireRow{}
	for key, rows := range snapshot {
		snapshotsByHash[key.hash] = append(snapshotsByHash[key.hash], rows...)
	}
	intents, err := d.persistS3BodyDeleteIntents(readCtx, keys, snapshotsByHash)
	if err != nil {
		return 0, fmt.Errorf("persist S3 deletion fences: %w", err)
	}
	// A concurrent intent is never adopted or expired. Keep all its rows as a
	// recoverable candidate, including any equal-hash key this batch might retire.
	eligible := orphans[:0]
	for _, o := range orphans {
		if _, needsIntent := keys[o.ContentHash]; needsIntent {
			if _, owned := intents[o.ContentHash]; !owned {
				continue
			}
		}
		eligible = append(eligible, o)
	}
	orphans = eligible
	fail := func(err error) (int64, error) {
		// Release first: a failed retirement can still hold the intent row lock.
		// Its diagnostic update must not wait on our own aborted transaction.
		locks.Release()
		d.noteS3BodyDeleteUncertainty(intents, err)
		return 0, err
	}
	if err := locks.Ping(readCtx); err != nil {
		return fail(fmt.Errorf("body lock lost before storage DELETE: %w", err))
	}
	guarded, done := locks.Guard(ctx)
	defer done()
	result, err := fn(guarded, orphans)
	if err != nil {
		return fail(err)
	}
	finishCtx, stopFinish := context.WithTimeout(ctx, s3ObjectLockTimeout)
	defer stopFinish()
	if err := locks.Ping(finishCtx); err != nil {
		return fail(fmt.Errorf("body lock lost during storage DELETE: %w", err))
	}
	permitted := map[bodyCleanupKey]UserScopedObjectForCleanup{}
	for _, o := range orphans {
		permitted[bodyKey(o)] = o
	}
	gone := map[bodyCleanupKey]bool{}
	knownKeys := map[string]bool{}
	for _, o := range result.Gone {
		canonical, ok := permitted[bodyKey(o)]
		if !ok {
			return fail(fmt.Errorf("unexpected S3 retirement result"))
		}
		gone[bodyKey(o)] = true
		if !canonical.KeepObject {
			knownKeys[bodyObjectKey(o)] = true
		}
	}
	for _, o := range result.Rejected {
		if _, ok := permitted[bodyKey(o)]; !ok {
			return fail(fmt.Errorf("unexpected S3 rejection result"))
		}
		if gone[bodyKey(o)] {
			return fail(fmt.Errorf("conflicting S3 cleanup result"))
		}
		knownKeys[bodyObjectKey(o)] = true
	}
	var rowsDeleted int64
	var unresolved []string
	if err := locks.run(finishCtx, func(ctx context.Context, tx pgx.Tx) error {
		var rowIDs []int64
		var tuples []string
		for key := range gone {
			for _, r := range snapshot[key] {
				rowIDs = append(rowIDs, r.ID)
				tuples = append(tuples, r.Tuple)
			}
		}
		if len(rowIDs) > 0 {
			tag, err := tx.Exec(ctx, `DELETE FROM messages m USING unnest($1::bigint[],$2::text[]) s(id,tuple) WHERE m.id=s.id AND m.ctid=s.tuple::tid AND m.expunged_at IS NOT NULL`, rowIDs, tuples)
			if err != nil {
				return err
			}
			rowsDeleted = tag.RowsAffected()
		}
		for hash, intent := range intents {
			allKnown := true
			for _, key := range intent.ObjectKeys {
				if !knownKeys[key] {
					allKnown = false
					break
				}
			}
			if allKnown {
				if err := clearOwnedS3BodyDeleteIntent(ctx, tx, intent); err != nil {
					return err
				}
			} else {
				unresolved = append(unresolved, hash)
			}
		}
		return nil
	}); err != nil {
		return fail(fmt.Errorf("retire S3 candidates: %w", err))
	}
	if err := locks.commit(finishCtx); err != nil {
		return fail(fmt.Errorf("commit S3 retirement: %w", err))
	}
	if len(unresolved) > 0 {
		sort.Strings(unresolved)
		err := fmt.Errorf("storage deletion outcome remains quarantined for %s: %w", strings.Join(unresolved, ","), ErrS3BodyQuarantined)
		d.noteS3BodyDeleteUncertainty(intents, err)
		return rowsDeleted, err
	}
	return rowsDeleted, nil
}

func (d *Database) noteS3BodyDeleteUncertainty(intents map[string]S3BodyDeleteIntent, cause error) {
	if len(intents) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	text := cause.Error()
	if len(text) > 2048 {
		text = text[:2048]
	}
	for _, intent := range intents {
		_, _ = d.GetWritePool().Exec(ctx, `UPDATE s3_body_delete_intents SET last_error=$3 WHERE content_hash=$1 AND operation_id=$2::uuid`, intent.ContentHash, intent.OperationID, text)
	}
}
