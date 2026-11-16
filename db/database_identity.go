package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// ErrDatabaseIdentityUnavailable means the persisted logical database identity
// is missing or invalid. Callers must not reuse destination-specific recovery
// records without a valid identity.
var ErrDatabaseIdentityUnavailable = errors.New("database identity unavailable or invalid")

// GetDatabaseIdentity reads the logical database UUID installed by migration 68.
// It always uses the primary write pool, independently of read-replica routing
// or a caller's read snapshot. It never generates, repairs or caches an identity.
// Reconnection, backup and primary failover retain the persisted row; an
// independently operated clone must explicitly receive a new identity.
func (d *Database) GetDatabaseIdentity(ctx context.Context) (string, error) {
	if d.GetWritePool() == nil {
		return "", fmt.Errorf("%w: primary pool is not configured", ErrDatabaseIdentityUnavailable)
	}
	// The constraints allow exactly one true singleton. Reading at most two rows
	// also refuses a damaged/out-of-band schema rather than choosing an identity.
	rows, err := d.GetWritePool().Query(ctx, `SELECT singleton, identity::text FROM public.database_identity LIMIT 2`)
	if err != nil {
		return "", fmt.Errorf("read database identity: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return "", fmt.Errorf("read database identity: %w", err)
		}
		return "", fmt.Errorf("%w: singleton row is missing", ErrDatabaseIdentityUnavailable)
	}
	var singleton bool
	var raw string
	if err := rows.Scan(&singleton, &raw); err != nil {
		return "", fmt.Errorf("%w: malformed singleton row: %v", ErrDatabaseIdentityUnavailable, err)
	}
	if rows.Next() {
		return "", fmt.Errorf("%w: multiple rows", ErrDatabaseIdentityUnavailable)
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("read database identity: %w", err)
	}
	identity, err := uuid.Parse(raw)
	if !singleton || err != nil || identity == uuid.Nil || identity.String() != raw {
		return "", fmt.Errorf("%w: expected a true singleton with a canonical nonzero UUID", ErrDatabaseIdentityUnavailable)
	}
	return identity.String(), nil
}
