//go:build integration

package resilient

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/migadu/sora/pkg/retry"
)

// A query that can never succeed (here an undefined column) must come back from the
// first attempt, as the PostgreSQL error itself, not after three backed-off retries
// wrapped in ErrMaxRetriesExceeded.
func TestQueryWithRetry_NonRetryableErrorStopsAtOnce(t *testing.T) {
	cfg := testDatabaseConfig()
	rd := newTestResilientDatabase(cfg, newTestPool(t, cfg, nil))

	start := time.Now()
	rows, err := rd.QueryWithRetry(context.Background(), "SELECT no_such_column FROM pending_uploads")
	elapsed := time.Since(start)
	if err == nil {
		rows.Close()
		t.Fatal("expected an error for an undefined column")
	}
	if errors.Is(err, retry.ErrMaxRetriesExceeded) {
		t.Fatalf("non-retryable error was retried until the limit (after %v): %v", elapsed, err)
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42703" {
		t.Fatalf("expected undefined_column (42703), got %v", err)
	}
	// The first backoff alone is 500ms (less jitter); a single attempt is far below it.
	if elapsed > 250*time.Millisecond {
		t.Fatalf("non-retryable error took %v; it must not wait for a retry", elapsed)
	}
}

// The rows QueryWithRetry returns are read by the caller after it returns. pgx keeps
// watching the query's context until the rows are closed, so that context must stay
// alive until then: a result too large to be buffered when the call returns has to be
// readable to the end.
func TestQueryWithRetry_RowsReadableAfterReturn(t *testing.T) {
	cfg := testDatabaseConfig()
	rd := newTestResilientDatabase(cfg, newTestPool(t, cfg, nil))

	const want = 20000
	rows, err := rd.QueryWithRetry(context.Background(),
		"SELECT g, repeat('x', 1000) FROM generate_series(1, $1) AS g", want)
	if err != nil {
		t.Fatalf("QueryWithRetry: %v", err)
	}
	defer rows.Close()

	got := 0
	for rows.Next() {
		var n int
		var filler string
		if err := rows.Scan(&n, &filler); err != nil {
			t.Fatalf("scan row %d: %v", got+1, err)
		}
		got++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("reading rows after QueryWithRetry returned failed after %d of %d rows: %v", got, want, err)
	}
	if got != want {
		t.Fatalf("read %d rows, want %d", got, want)
	}
}
