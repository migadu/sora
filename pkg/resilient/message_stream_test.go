package resilient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/migadu/go-imap"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/circuitbreaker"
	"github.com/migadu/sora/pkg/retry"
)

func newMessageStreamTestDatabase(searchTimeout string) *ResilientDatabase {
	return &ResilientDatabase{
		config: &config.DatabaseConfig{SearchTimeout: searchTimeout},
		queryBreaker: circuitbreaker.NewCircuitBreaker(circuitbreaker.Settings{
			Name: "message_stream_test",
			ReadyToTrip: func(counts circuitbreaker.Counts) bool {
				return counts.Requests >= 8 && float64(counts.TotalFailures)/float64(counts.Requests) >= 0.6
			},
			IsSuccessful: isBreakerSuccess,
		}),
	}
}

var fastTestRetryConfig = retry.BackoffConfig{
	InitialInterval: time.Millisecond,
	MaxInterval:     5 * time.Millisecond,
	Multiplier:      2.0,
	MaxRetries:      2,
	OperationName:   "test_stream_step",
}

// runChunkedTestStream drives the production chunk loop
// (db.StreamMessageChunksWithRunner) through rd.runMessageStreamStep, with fetchChunk
// standing in for the SQL, so unit tests exercise the real timeout, retry, and
// circuit-breaker boundaries without a live PostgreSQL instance. chunkIdx counts the
// chunks delivered so far, so a retried step sees the same index again.
func runChunkedTestStream(
	ctx context.Context,
	rd *ResilientDatabase,
	retryCfg retry.BackoffConfig,
	fetchChunk func(stepCtx context.Context, chunkIdx int) ([]db.Message, error),
	cb db.MessageStreamCallback,
) error {
	chunkIdx := 0
	run := func(ctx context.Context, step func(context.Context, *db.Database) error) error {
		return rd.runMessageStreamStep(ctx, retryCfg, func(stepCtx context.Context) error {
			return step(stepCtx, nil) // fetchChunk never touches the database
		})
	}
	fetch := func(stepCtx context.Context, _ *db.Database, _ imap.UID, _ uint32) ([]db.Message, int, error) {
		msgs, err := fetchChunk(stepCtx, chunkIdx)
		// A full chunk (limit == len) keeps the stream going until an empty one.
		return msgs, len(msgs), err
	}
	return db.StreamMessageChunksWithRunner(ctx, run, "test", fetch, func(chunk []db.Message) error {
		chunkIdx++
		return cb(chunk)
	})
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
			rd := newMessageStreamTestDatabase("1s")
			for range 10 {
				calls := 0
				err := runChunkedTestStream(
					context.Background(),
					rd,
					fastTestRetryConfig,
					func(_ context.Context, chunkIdx int) ([]db.Message, error) {
						if chunkIdx == 0 {
							return []db.Message{{UID: 1}}, nil
						}
						return nil, nil
					},
					func([]db.Message) error {
						calls++
						return tc.err
					},
				)
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
		{"database shutting down", &pgconn.PgError{Code: "57P01"}},
		{"database connection reset", &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rd := newMessageStreamTestDatabase("1s")
			for range 8 {
				err := runChunkedTestStream(
					context.Background(),
					rd,
					fastTestRetryConfig,
					func(context.Context, int) ([]db.Message, error) {
						return nil, tc.err
					},
					func([]db.Message) error {
						t.Fatal("database failed before reaching consumer")
						return nil
					},
				)
				if !errors.Is(err, tc.err) {
					t.Fatalf("returned %v, want database error %v", err, tc.err)
				}
			}
			if state := rd.GetQueryBreakerState(); state != circuitbreaker.StateOpen {
				t.Fatalf("database failures left breaker %v, want open", state)
			}
			err := runChunkedTestStream(
				context.Background(),
				rd,
				fastTestRetryConfig,
				func(context.Context, int) ([]db.Message, error) {
					t.Fatal("open breaker ran another database query")
					return nil, nil
				},
				nil,
			)
			if !errors.Is(err, circuitbreaker.ErrCircuitBreakerOpen) {
				t.Fatalf("open breaker returned %v", err)
			}
		})
	}
}

func TestMessageStreamDatabaseErrorsRemainRetryable(t *testing.T) {
	rd := newMessageStreamTestDatabase("1s")
	for _, err := range []error{
		&net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded},
		&pgconn.PgError{Code: "08006"},
	} {
		if !rd.isRetryableError(err) {
			t.Errorf("database error %v should remain retryable", err)
		}
		if isBreakerSuccess(err) {
			t.Errorf("database error %v should count as a database failure", err)
		}
	}
}

func TestMessageStreamPerChunkTimeoutIgnoresSlowConsumer(t *testing.T) {
	// SearchTimeout is 60ms, while the consumer sleeps 45ms on each of 3 chunks
	// (135ms total > 2x SearchTimeout). A single stream-wide opCtx would expire
	// before chunk 2; per-chunk DB timeouts must give every chunk a fresh budget.
	rd := newMessageStreamTestDatabase("60ms")

	var delivered []uint32
	err := runChunkedTestStream(
		context.Background(),
		rd,
		fastTestRetryConfig,
		func(stepCtx context.Context, chunkIdx int) ([]db.Message, error) {
			if err := stepCtx.Err(); err != nil {
				return nil, err
			}
			deadline, ok := stepCtx.Deadline()
			if !ok {
				t.Fatalf("chunk %d stepCtx missing search timeout deadline", chunkIdx)
			}
			if remaining := time.Until(deadline); remaining <= 0 {
				t.Fatalf("chunk %d started with expired deadline (%v)", chunkIdx, remaining)
			}
			if chunkIdx >= 3 {
				return nil, nil
			}
			return []db.Message{{UID: imap.UID(10 + chunkIdx)}}, nil
		},
		func(chunk []db.Message) error {
			delivered = append(delivered, uint32(chunk[0].UID))
			time.Sleep(45 * time.Millisecond)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("multi-chunk stream with slow consumer failed: %v", err)
	}
	if len(delivered) != 3 || delivered[0] != 10 || delivered[1] != 11 || delivered[2] != 12 {
		t.Fatalf("delivered UIDs = %v, want [10 11 12]", delivered)
	}
	if counts := rd.queryBreaker.Counts(); counts.TotalFailures != 0 || counts.TotalSuccesses != 4 {
		t.Fatalf("unexpected breaker counts after slow-consumer stream: %+v", counts)
	}
}

func TestMessageStreamPerChunkRetryDoesNotReplayDeliveredChunks(t *testing.T) {
	rd := newMessageStreamTestDatabase("1s")

	chunk1Attempts := 0
	var delivered []uint32
	err := runChunkedTestStream(
		context.Background(),
		rd,
		fastTestRetryConfig,
		func(_ context.Context, chunkIdx int) ([]db.Message, error) {
			switch chunkIdx {
			case 0:
				return []db.Message{{UID: 1}}, nil
			case 1:
				chunk1Attempts++
				if chunk1Attempts == 1 {
					return nil, &pgconn.PgError{Code: "08006"}
				}
				return []db.Message{{UID: 2}}, nil
			default:
				return nil, nil
			}
		},
		func(chunk []db.Message) error {
			delivered = append(delivered, uint32(chunk[0].UID))
			return nil
		},
	)
	if err != nil {
		t.Fatalf("expected chunk retry to recover, got: %v", err)
	}
	if chunk1Attempts != 2 {
		t.Fatalf("chunk 1 attempts = %d, want 2", chunk1Attempts)
	}
	if len(delivered) != 2 || delivered[0] != 1 || delivered[1] != 2 {
		t.Fatalf("delivered UIDs = %v, want [1 2] without replaying chunk 0", delivered)
	}
}

func TestMessageStreamCallerCancellationBetweenChunksDoesNotTripBreaker(t *testing.T) {
	rd := newMessageStreamTestDatabase("1s")
	ctx, cancel := context.WithCancel(context.Background())

	err := runChunkedTestStream(
		ctx,
		rd,
		fastTestRetryConfig,
		func(_ context.Context, chunkIdx int) ([]db.Message, error) {
			if chunkIdx > 0 {
				t.Fatal("cancelled caller context should stop before querying next chunk")
			}
			return []db.Message{{UID: 1}}, nil
		},
		func([]db.Message) error {
			cancel()
			return nil
		},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
	if counts := rd.queryBreaker.Counts(); counts.TotalFailures != 0 || counts.TotalSuccesses != 1 {
		t.Fatalf("caller cancellation counted as database failure: %+v", counts)
	}
}
