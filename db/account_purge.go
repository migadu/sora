package db

// account_purge.go - the purge request mark on accounts, and the purge worker's claim.
//
// A purge is requested on any node and performed on a node with object storage (see
// server/cleaner/purge_worker.go). The request is accounts.purge_requested_at: set here,
// read by the worker's poll, cleared by RestoreAccount, and gone with the row when the
// purge finishes.

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/server"
)

// RequestAccountPurge marks the account behind email for purging and takes it out of
// service, in one transaction: it is soft-deleted if it is not already, the mark keeps
// the time of the first request so a repeated request does not reset the age an operator
// alerts on, and any backoff from a failed attempt is cleared so the next worker cycle
// tries again. It returns the account id and the time of the first request, or
// consts.ErrUserNotFound.
//
// The address is resolved on the transaction, so on the primary: a replica lagging behind
// an address reassignment could otherwise name an earlier account that held it.
func (db *Database) RequestAccountPurge(ctx context.Context, tx pgx.Tx, email string) (int64, time.Time, error) {
	address, err := server.NewAddress(email)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("invalid email address: %w", err)
	}

	var accountID int64
	var requestedAt time.Time
	err = tx.QueryRow(ctx, `
		UPDATE accounts a
		SET deleted_at = COALESCE(a.deleted_at, now()),
		    purge_requested_at = COALESCE(a.purge_requested_at, now()),
		    purge_attempts = 0,
		    purge_next_attempt_at = NULL
		FROM credentials c
		WHERE c.account_id = a.id AND LOWER(c.address) = $1
		RETURNING a.id, a.purge_requested_at
	`, address.FullAddress()).Scan(&accountID, &requestedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, time.Time{}, fmt.Errorf("account with email %s not found: %w", address.FullAddress(), consts.ErrUserNotFound)
	}
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("failed to request purge of account %s: %w", address.FullAddress(), err)
	}
	return accountID, requestedAt, nil
}

// ListAccountsForPurge returns up to limit accounts marked for purging that are due: out
// of service (a restored account keeps no mark, but the check costs nothing) and not
// backed off. Oldest request first, so the oldest pending purge is the one the worker
// attends to and the age an operator alerts on cannot grow behind newer requests.
//
// It reads the pool the context selects. A lagging replica may list an account whose
// purge just finished (the purge then finds no row and reports done) or miss one just
// requested (the next poll lists it); neither needs the primary.
func (db *Database) ListAccountsForPurge(ctx context.Context, limit int) ([]int64, error) {
	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, `
		SELECT id FROM accounts
		WHERE purge_requested_at IS NOT NULL
		  AND deleted_at IS NOT NULL
		  AND (purge_next_attempt_at IS NULL OR purge_next_attempt_at <= now())
		ORDER BY purge_requested_at, id
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list accounts for purge: %w", err)
	}
	defer rows.Close()
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

// RecordAccountPurgeFailure counts a failed purge attempt and sets when the next may
// run: base doubled per attempt so far, capped at max, on the database clock. It returns
// that time. An account that is no longer marked (restored, or purged by another node
// meanwhile) is left alone and the zero time is returned.
func (db *Database) RecordAccountPurgeFailure(ctx context.Context, tx pgx.Tx, accountID int64, base, max time.Duration) (time.Time, error) {
	var next *time.Time
	err := tx.QueryRow(ctx, `
		UPDATE accounts
		SET purge_attempts = purge_attempts + 1,
		    purge_next_attempt_at = now() + LEAST($3::interval, $2::interval * power(2, purge_attempts))
		WHERE id = $1 AND purge_requested_at IS NOT NULL
		RETURNING purge_next_attempt_at
	`, accountID, base, max).Scan(&next)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to record purge failure of account %d: %w", accountID, err)
	}
	if next == nil {
		return time.Time{}, nil
	}
	return *next, nil
}

// PendingAccountPurges reports how many accounts are marked for purging and out of
// service, and how long ago the oldest of them was requested (zero when there are none).
// These are what the purge gauges show; a growing age means nothing is picking purges up.
func (db *Database) PendingAccountPurges(ctx context.Context) (count int64, oldest time.Duration, err error) {
	var oldestSeconds float64
	err = db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT count(*), COALESCE(EXTRACT(EPOCH FROM now() - min(purge_requested_at)), 0)
		FROM accounts
		WHERE purge_requested_at IS NOT NULL AND deleted_at IS NOT NULL
	`).Scan(&count, &oldestSeconds)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to count pending account purges: %w", err)
	}
	return count, time.Duration(oldestSeconds * float64(time.Second)), nil
}

// AccountPurgeLockID is the advisory lock a purge worker holds while it purges the
// account, so that two nodes do not purge the same account at once. Its own keyspace,
// hashed like the S3 object locks; a collision with one of those only makes a worker
// skip the account for a cycle.
func AccountPurgeLockID(accountID int64) int64 {
	h := fnv.New64a()
	h.Write([]byte(fmt.Sprintf("account-purge:%d", accountID)))
	return int64(h.Sum64())
}

// ExecuteWithAccountPurgeLock runs fn while holding the account's purge lock, and reports
// false without running it when another node holds the lock. The lock lives in an
// AdvisoryLockTx (transaction-scoped, pooler-safe); fn's context is cancelled if the
// lock is lost meanwhile, and a loss noticed only afterwards is reported as an error.
// The purge is resumable, so a lost lock costs a repeated attempt, not correctness.
func (db *Database) ExecuteWithAccountPurgeLock(ctx context.Context, accountID int64, fn func(ctx context.Context) error) (bool, error) {
	lockCtx, cancel := context.WithTimeout(ctx, s3ObjectLockTimeout)
	defer cancel()

	lock, err := db.BeginAdvisoryLockTx(lockCtx)
	if err != nil {
		return false, fmt.Errorf("failed to lock account %d for purge: %w", accountID, err)
	}
	defer lock.Release()

	claimed, err := lock.TryLock(lockCtx, AccountPurgeLockID(accountID))
	if err != nil {
		return false, fmt.Errorf("failed to lock account %d for purge: %w", accountID, err)
	}
	if !claimed {
		return false, nil
	}

	guarded, done := lock.Guard(ctx)
	defer done()
	if err := fn(guarded); err != nil {
		return true, err
	}
	if err := lock.Err(); err != nil {
		return true, fmt.Errorf("purge lock of account %d was lost while it ran: %w", accountID, err)
	}
	return true, nil
}
