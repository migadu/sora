package db

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// RecordRedirect records that a redirect action was performed for the given account,
// charged against a redirect rate limit of the given window and limit. The row keeps the
// end of that window (expires_at), so CleanupOldRedirects keeps it while the limit that
// charged it still counts it, on whichever node the cleaner runs, and the limit
// (rate_limit), so RedirectRateLimitsOtherThan can tell a node with another one.
func (db *Database) RecordRedirect(ctx context.Context, tx pgx.Tx, accountID int64, window time.Duration, limit int) error {
	now := time.Now()
	var expiresAt *time.Time
	if window > 0 {
		t := now.Add(window)
		expiresAt = &t
	}
	var rateLimit *int
	if limit > 0 {
		rateLimit = &limit
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO redirect_log (account_id, redirect_date, created_at, expires_at, rate_limit)
		VALUES ($1, $2, $3, $4, $5)
	`, accountID, now, now, expiresAt, rateLimit)

	return err
}

// CountRedirectsSince returns the number of redirects performed by the given account within the specified duration window.
func (db *Database) CountRedirectsSince(ctx context.Context, accountID int64, window time.Duration) (int, error) {
	cutoffTime := time.Now().Add(-window)

	var count int
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT COUNT(*) FROM redirect_log 
		WHERE account_id = $1 
		AND redirect_date > $2
	`, accountID, cutoffTime).Scan(&count)

	return count, err
}

// RedirectRateWindowsOtherThan returns the redirect rate windows, shortest first and to the
// second, that redirect_log rows still inside their window were charged under
// (expires_at - redirect_date, see RecordRedirect) and that are none of windows. A node passes
// its own windows: what comes back was charged by a server whose redirect_rate_window differs,
// on which an account's limit is a different one (#1994). Rows written before migration 75
// have no window and are not looked at.
func (db *Database) RedirectRateWindowsOtherThan(ctx context.Context, windows []time.Duration) ([]time.Duration, error) {
	seconds := make([]int64, len(windows))
	for i, w := range windows {
		seconds[i] = int64(w.Round(time.Second) / time.Second)
	}
	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, `
		SELECT DISTINCT round(EXTRACT(EPOCH FROM expires_at - redirect_date))::bigint AS window_seconds
		FROM redirect_log
		WHERE expires_at > now()
		AND round(EXTRACT(EPOCH FROM expires_at - redirect_date))::bigint <> ALL($1::bigint[])
		ORDER BY window_seconds
		LIMIT 10
	`, seconds)
	if err != nil {
		return nil, err
	}
	other, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return nil, err
	}
	result := make([]time.Duration, len(other))
	for i, s := range other {
		result[i] = time.Duration(s) * time.Second
	}
	return result, nil
}

// RedirectRateLimitsOtherThan returns the redirect rate limits, smallest first, that
// redirect_log rows still inside their window were charged under (rate_limit, see
// RecordRedirect) and that are none of limits. A node passes its own limits: what comes back
// was charged by a server whose redirect_rate_limit differs, on which an account's limit is a
// different one (#2020). Rows written before migration 77 have no limit and are not looked at.
func (db *Database) RedirectRateLimitsOtherThan(ctx context.Context, limits []int) ([]int, error) {
	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, `
		SELECT DISTINCT rate_limit
		FROM redirect_log
		WHERE expires_at > now()
		AND rate_limit <> ALL($1::int[])
		ORDER BY rate_limit
		LIMIT 10
	`, limits)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int])
}

// RedirectedTargets returns the redirect targets the account's delivery of the message
// identified by deliveryHash (see InsertMessageOptions.DeliveryHash) has already handed to
// the relay, on LMTP or the Admin API. It reads the primary: the retry of a delivery can
// follow it within seconds, before a replica has the row.
func (db *Database) RedirectedTargets(ctx context.Context, accountID int64, deliveryHash string) ([]string, error) {
	rows, err := db.GetWritePool().Query(ctx, `
		SELECT redirect_to FROM redirect_deliveries
		WHERE account_id = $1 AND delivery_hash = $2
	`, accountID, deliveryHash)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// RecordRedirectDelivery records that the account's delivery of the message identified by
// deliveryHash has handed its redirect to redirectTo to the relay, so a retry of that
// delivery does not queue it again.
func (db *Database) RecordRedirectDelivery(ctx context.Context, tx pgx.Tx, accountID int64, deliveryHash, redirectTo string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO redirect_deliveries (account_id, delivery_hash, redirect_to)
		VALUES ($1, $2, $3)
		ON CONFLICT DO NOTHING
	`, accountID, deliveryHash, redirectTo)
	return err
}

// CleanupOldRedirects removes redirect log records, and the records of which deliveries
// were redirected (RecordRedirectDelivery), older than the specified duration. A redirect
// log record is also kept until the end of the window it was charged under (expires_at),
// which another node's config may have set beyond olderThan; a record without one, written
// before migration 75 or by an older binary, goes at olderThan.
func (db *Database) CleanupOldRedirects(ctx context.Context, tx pgx.Tx, olderThan time.Duration) (int64, error) {
	now := time.Now()
	cutoffTime := now.Add(-olderThan)

	result, err := tx.Exec(ctx, `
		DELETE FROM redirect_log
		WHERE redirect_date < $1
		AND (expires_at IS NULL OR expires_at < $2)
	`, cutoffTime, now)

	if err != nil {
		return 0, err
	}

	deliveries, err := tx.Exec(ctx, `
		DELETE FROM redirect_deliveries
		WHERE created_at < $1
	`, cutoffTime)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected() + deliveries.RowsAffected(), nil
}
