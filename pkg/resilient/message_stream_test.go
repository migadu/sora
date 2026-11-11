package resilient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/circuitbreaker"
)

func newMessageStreamTestDatabase() *ResilientDatabase {
	return &ResilientDatabase{
		config: &config.DatabaseConfig{},
		queryBreaker: circuitbreaker.NewCircuitBreaker(circuitbreaker.Settings{
			Name: "message_stream_test",
			ReadyToTrip: func(counts circuitbreaker.Counts) bool {
				return counts.Requests >= 8 && float64(counts.TotalFailures)/float64(counts.Requests) >= 0.6
			},
			IsSuccessful: isQuerySuccessful,
		}),
	}
}

func TestMessageStreamCallbackErrorsDoNotTripDatabaseBreaker(t *testing.T) {
	cause := errors.New("consumer cause")
	for _, tc := range []struct {
		name  string
		err   error
		cause error
	}{
		{"disconnected client", &net.OpError{Op: "write", Net: "tcp", Err: syscall.EPIPE}, syscall.EPIPE},
		{"consumer timeout", &net.OpError{Op: "write", Net: "tcp", Err: os.ErrDeadlineExceeded}, os.ErrDeadlineExceeded},
		{"retryable-looking consumer error", &pgconn.PgError{Code: "40001"}, nil},
		{"consumer error", errors.New("consumer failed"), nil},
		{"wrapped consumer cause", fmt.Errorf("consumer failed: %w", cause), cause},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rd := newMessageStreamTestDatabase()
			for range 10 {
				calls := 0
				err := rd.streamMessagesWithRetry(context.Background(), func([]db.Message) error {
					calls++
					return tc.err
				}, func(_ context.Context, cb db.MessageStreamCallback) error {
					return cb([]db.Message{{UID: 1}})
				})
				if calls != 1 {
					t.Fatalf("callback invoked %d times, want once", calls)
				}
				if err != tc.err || !errors.Is(err, tc.err) {
					t.Fatalf("returned %v, want original callback error %v", err, tc.err)
				}
				if tc.cause != nil && !errors.Is(err, tc.cause) {
					t.Fatalf("callback error lost wrapped cause %v: %v", tc.cause, err)
				}
			}
			if state := rd.GetQueryBreakerState(); state != circuitbreaker.StateClosed {
				t.Fatalf("consumer errors opened database breaker: %v", state)
			}
			if counts := rd.queryBreaker.Counts(); counts.TotalFailures != 0 || counts.TotalSuccesses != 10 {
				t.Fatalf("consumer outcomes counted as database failures: %+v", counts)
			}
		})
	}
}

func TestMessageStreamDatabaseFailuresStillTripBreaker(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"database failure", errors.New("database query failed")},
		{"database connection reset", &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rd := newMessageStreamTestDatabase()
			for range 8 {
				err := rd.streamMessagesWithRetry(context.Background(), func([]db.Message) error {
					t.Fatal("database failed before reaching consumer")
					return nil
				}, func(context.Context, db.MessageStreamCallback) error {
					return tc.err
				})
				if !errors.Is(err, tc.err) {
					t.Fatalf("returned %v, want database error %v", err, tc.err)
				}
			}
			if state := rd.GetQueryBreakerState(); state != circuitbreaker.StateOpen {
				t.Fatalf("database failures left breaker %v, want open", state)
			}
			err := rd.streamMessagesWithRetry(context.Background(), nil, func(context.Context, db.MessageStreamCallback) error {
				t.Fatal("open breaker ran another database query")
				return nil
			})
			if !errors.Is(err, circuitbreaker.ErrCircuitBreakerOpen) {
				t.Fatalf("open breaker returned %v", err)
			}
		})
	}
}

func TestMessageStreamDatabaseErrorsRemainRetryable(t *testing.T) {
	rd := newMessageStreamTestDatabase()
	for _, err := range []error{
		&net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded},
		&pgconn.PgError{Code: "08006"},
	} {
		if !rd.isRetryableError(err) {
			t.Errorf("database error %v should remain retryable", err)
		}
		if isQuerySuccessful(err) {
			t.Errorf("database error %v should count as a database failure", err)
		}
	}
}
