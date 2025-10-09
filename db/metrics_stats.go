package db

import (
	"context"
	"time"
)

// MetricsStats holds aggregate statistics for Prometheus metrics
type MetricsStats struct {
	TotalAccounts  int64
	TotalMailboxes int64
	TotalMessages  int64
	Timestamp      time.Time
}

// GetMetricsStats returns aggregate statistics for Prometheus metrics
func (d *Database) GetMetricsStats(ctx context.Context) (*MetricsStats, error) {
	stats := &MetricsStats{
		Timestamp: time.Now(),
	}

	// Use ReadPool for read-only queries
	pool := d.ReadPool
	if pool == nil {
		pool = d.WritePool
	}

	// Get total accounts (non-deleted)
	err := pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM accounts
		WHERE deleted_at IS NULL
	`).Scan(&stats.TotalAccounts)
	if err != nil {
		return nil, err
	}

	// Get total mailboxes (for non-deleted accounts)
	// Note: mailboxes table doesn't have deleted_at column
	err = pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM mailboxes m
		INNER JOIN accounts a ON m.account_id = a.id
		WHERE a.deleted_at IS NULL
	`).Scan(&stats.TotalMailboxes)
	if err != nil {
		return nil, err
	}

	// Get total messages (non-expunged, for non-deleted accounts)
	// Note: mailboxes don't have deleted_at, but messages have expunged_at
	err = pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM messages msg
		INNER JOIN mailboxes m ON msg.mailbox_id = m.id
		INNER JOIN accounts a ON m.account_id = a.id
		WHERE msg.expunged_at IS NULL
		AND a.deleted_at IS NULL
	`).Scan(&stats.TotalMessages)
	if err != nil {
		return nil, err
	}

	return stats, nil
}
