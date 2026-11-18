package resilient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// deadConnErr is what a statement on a pooled connection the database side already
// closed returns: io.ErrUnexpectedEOF wrapped by the db layer.
var deadConnErr = fmt.Errorf("database error getting primary email for account ID 1: %w", io.ErrUnexpectedEOF)

// A read whose first connections turn out dead is answered from the next live one,
// and the circuit breaker sees one successful read, not a failure per dead connection:
// after a PostgreSQL or PgBouncer restart, counting those opened the breaker.
func TestReadRepeatsOnDeadPooledConnection(t *testing.T) {
	rd := newMessageStreamTestDatabase("1s")
	calls := 0
	res, err := rd.executeReadWithRetry(context.Background(), fastTestRetryConfig, timeoutRead, func(context.Context) (any, error) {
		calls++
		if calls <= 2 {
			return nil, deadConnErr
		}
		return "row", nil
	})
	if err != nil || res != "row" {
		t.Fatalf("read = %v, %v; want row, nil", res, err)
	}
	if calls != 3 {
		t.Errorf("read ran %d times, want 3 (two dead connections, then a live one)", calls)
	}
	if c := rd.queryBreaker.Counts(); c.TotalFailures != 0 || c.Requests != 1 {
		t.Errorf("breaker counted %d requests, %d failures; want 1 request, 0 failures", c.Requests, c.TotalFailures)
	}
}

// A write is never sent twice on this error: the connection may have gone after the
// server applied it.
func TestAutocommitWriteDoesNotRepeatOnDeadConnection(t *testing.T) {
	rd := newMessageStreamTestDatabase("1s")
	calls := 0
	_, err := rd.executeAutocommitWriteWithRetry(context.Background(), fastTestRetryConfig, timeoutWrite, func(context.Context) (any, error) {
		calls++
		return nil, deadConnErr
	})
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("write error = %v, want the dead connection's", err)
	}
	if calls != 1 {
		t.Errorf("write ran %d times, want 1", calls)
	}
}

func TestAgainOnDeadConn(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		wantCalls int
	}{
		{"first statement on a closed connection", deadConnErr, deadConnAttempts},
		{"later statement on a closed connection", fmt.Errorf("q: %w", pgconn.ErrConnClosed), deadConnAttempts},
		// The database being down: the next connection would fail the same way.
		{"failed connection attempt", &pgconn.ConnectError{Config: &pgconn.Config{}}, 1},
		{"statement error", &pgconn.PgError{Code: "23505"}, 1},
		{"context canceled", context.Canceled, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			_, err := againOnDeadConn(func() (any, error) { calls++; return nil, tc.err })
			if !errors.Is(err, tc.err) {
				t.Errorf("error = %v, want %v", err, tc.err)
			}
			if calls != tc.wantCalls {
				t.Errorf("ran %d times, want %d", calls, tc.wantCalls)
			}
		})
	}
}
