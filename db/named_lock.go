package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Named, expiring locks over the `locks` table, for work that must happen on exactly one
// node and takes too long to hold a connection open for.
//
// This is deliberately not a PostgreSQL advisory lock. An advisory lock lives on a
// session, so holding one across a minute-long ACME exchange would pin a pool connection
// for the duration; a row with an expiry needs no connection between acquire and release,
// and a node that dies mid-work is released by the expiry.
//
// The database is the point: gossip leader election has no quorum, so a network partition
// elects a leader on BOTH sides and each believes it is the only one. Postgres cannot be
// partitioned into two writable copies, so a lock taken here is a real fence.

// CertificateIssuanceLock names the lock held while ordering one domain's certificate.
// Per domain, so unrelated domains still issue in parallel.
func CertificateIssuanceLock(domain string) string {
	return "acme_issuance:" + domain
}

// NamedLock is a held claim. AcquiredAt is a fencing token, not decoration: the `locks`
// table has no owner column, so it is what lets a release identify the claim it is
// releasing and leave a later holder's claim alone.
type NamedLock struct {
	Name       string
	AcquiredAt time.Time
}

// TryAcquireNamedLock takes the named lock for ttl, returning nil if someone else holds
// it. It does not block: the caller stands down rather than queueing behind work that is
// already being done elsewhere.
//
// An expired lock is taken over. That is what makes the lock safe against a holder that
// crashed, and it is why ttl must exceed the longest plausible run of the work it
// guards - an expiry reached while the holder is still working lets a second node in.
func (d *Database) TryAcquireNamedLock(ctx context.Context, name string, ttl time.Duration) (*NamedLock, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("lock ttl must be positive, got %s", ttl)
	}

	// The WHERE clause on the DO UPDATE is the mutual exclusion: against a live row it
	// matches nothing, the statement returns no row, and the lock reads as held.
	var acquiredAt time.Time
	err := d.GetWritePool().QueryRow(ctx, `
		INSERT INTO locks (lock_name, acquired_at, expires_at)
		VALUES ($1, now(), now() + $2::interval)
		ON CONFLICT (lock_name) DO UPDATE
		SET acquired_at = now(), expires_at = now() + $2::interval
		WHERE locks.expires_at <= now()
		RETURNING acquired_at
	`, name, ttl).Scan(&acquiredAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // held by someone else
		}
		return nil, fmt.Errorf("failed to acquire lock %q: %w", name, err)
	}
	return &NamedLock{Name: name, AcquiredAt: acquiredAt}, nil
}

// ReleaseNamedLock hands a held lock back before its expiry, so the next node does not
// have to wait out the ttl.
//
// The delete is qualified by the fencing token. Without it, a node whose lock had already
// expired and been taken over would delete the NEW holder's row on its way out, and two
// nodes would run the guarded work at once - the exact failure the lock exists to prevent.
func (d *Database) ReleaseNamedLock(ctx context.Context, lock *NamedLock) error {
	if lock == nil {
		return nil
	}
	if _, err := d.GetWritePool().Exec(ctx,
		`DELETE FROM locks WHERE lock_name = $1 AND acquired_at = $2`, lock.Name, lock.AcquiredAt,
	); err != nil {
		return fmt.Errorf("failed to release lock %q: %w", lock.Name, err)
	}
	return nil
}
