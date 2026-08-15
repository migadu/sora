package db

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// MetricsStats holds aggregate statistics for Prometheus metrics.
//
// TotalAccounts and TotalMailboxes are approximate: they are planner row
// estimates, so they lag autovacuum and include rows that are soft-deleted but
// not yet purged. Exact counts would be a table scan per collection cycle on
// every database-connected node.
type MetricsStats struct {
	TotalAccounts  int64
	TotalMailboxes int64
	TotalMessages  int64
	Timestamp      time.Time
}

const (
	// Planner row estimates, maintained by autovacuum. reltuples is -1 on a table
	// that has never been analyzed (PostgreSQL 14+), which selects the exact count
	// below.
	accountsRowEstimateQuery  = `SELECT reltuples::bigint FROM pg_class WHERE oid = to_regclass('accounts')`
	mailboxesRowEstimateQuery = `SELECT reltuples::bigint FROM pg_class WHERE oid = to_regclass('mailboxes')`

	// Exact counts, used only while an estimate is unavailable.

	// Total accounts (non-deleted).
	accountsCountQuery = `
		SELECT COUNT(*)
		FROM accounts
		WHERE deleted_at IS NULL
	`

	// Total mailboxes (live mailboxes of non-deleted accounts; exclude soft-deleted
	// mailboxes pending two-phase purge).
	mailboxesCountQuery = `
		SELECT COUNT(*)
		FROM mailboxes m
		INNER JOIN accounts a ON m.account_id = a.id
		WHERE a.deleted_at IS NULL AND m.deleted_at IS NULL
	`

	// Total messages (non-expunged, for non-deleted accounts; exclude soft-deleted
	// mailboxes whose cached stats are pending two-phase purge).
	// Use pre-aggregated mailbox_stats table instead of counting all messages.
	messagesCountQuery = `
		SELECT COALESCE(SUM(ms.message_count), 0)
		FROM mailbox_stats ms
		INNER JOIN mailboxes m ON ms.mailbox_id = m.id
		INNER JOIN accounts a ON m.account_id = a.id
		WHERE a.deleted_at IS NULL AND m.deleted_at IS NULL
	`
)

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

	var err error
	stats.TotalAccounts, err = rowCount(ctx, pool, accountsRowEstimateQuery, accountsCountQuery)
	if err != nil {
		return nil, err
	}

	stats.TotalMailboxes, err = rowCount(ctx, pool, mailboxesRowEstimateQuery, mailboxesCountQuery)
	if err != nil {
		return nil, err
	}

	err = pool.QueryRow(ctx, messagesCountQuery).Scan(&stats.TotalMessages)
	if err != nil {
		return nil, err
	}

	return stats, nil
}

// rowCount returns the estimated number of rows, falling back to the exact count
// while the estimate is unavailable (a negative estimate) so that a table awaiting
// its first analyze is not reported as empty.
func rowCount(ctx context.Context, pool *pgxpool.Pool, estimateQuery, exactQuery string) (int64, error) {
	var count int64
	if err := pool.QueryRow(ctx, estimateQuery).Scan(&count); err != nil {
		return 0, err
	}
	if count >= 0 {
		return count, nil
	}

	if err := pool.QueryRow(ctx, exactQuery).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}
