package delivery

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

// syncLogBuffer is a mutex-guarded sink for the process-wide slog default, which
// may be written from more than one goroutine while a test runs under -race.
type syncLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLogger routes the package logger into a buffer for the test's duration.
// No test here calls logger.Initialize, so logger.Warn and friends fall through to
// slog.Default().
func captureLogger(t *testing.T) *syncLogBuffer {
	t.Helper()
	buf := &syncLogBuffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return buf
}

// failingRelayQueue refuses every message.
type failingRelayQueue struct{ err error }

func (q *failingRelayQueue) Enqueue(_, _, _ string, _ []byte) error { return q.err }

// failingRelayHandler refuses every message.
type failingRelayHandler struct{ err error }

func (r *failingRelayHandler) SendToExternalRelay(_, _ string, _ []byte) error { return r.err }

// TestVacationHandoffFailureAfterClaimLogsWarn: once the RFC 5230 :days window has
// been claimed, a relay handoff that fails leaves the period consumed with no reply
// sent for the rest of the window. The session trace (h.log) is debug-level on both
// LMTP and the Admin API, so the loss must also reach the package logger at Warn
// with the account, the sender and the error, like a failed Sieve redirect does.
func TestVacationHandoffFailureAfterClaimLogsWarn(t *testing.T) {
	const owner = "jane@example.com"
	const senderAddr = "bob@example.net"
	sender := vacAddr(t, senderAddr)
	toAddress := vacAddr(t, owner)
	ownsJane := func(_ context.Context, _ int64, addr string) (bool, error) {
		return strings.EqualFold(addr, owner), nil
	}
	relayErr := errors.New("relay queue refused the message")

	cases := []struct {
		name    string
		handler *StandardVacationHandler
	}{
		{
			name:    "relay queue enqueue fails",
			handler: &StandardVacationHandler{Hostname: "m", RelayQueue: &failingRelayQueue{err: relayErr}, IsOwnedAddress: ownsJane},
		},
		{
			name:    "direct relay send fails",
			handler: &StandardVacationHandler{Hostname: "m", RelayHandler: &failingRelayHandler{err: relayErr}, IsOwnedAddress: ownsJane},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureLogger(t)
			oracle := &fakeVacationOracle{}
			reply := evaluateVacation(t, oracle, senderAddr)
			orig := makeMessage(map[string]string{"From": senderAddr, "To": owner})

			err := tc.handler.HandleVacationResponse(context.Background(), 42, reply, sender, toAddress, orig)
			if !errors.Is(err, relayErr) {
				t.Fatalf("HandleVacationResponse error = %v, want %v", err, relayErr)
			}
			// The claim stood: the window is consumed although nothing went out.
			if len(oracle.recorded) != 1 {
				t.Fatalf("expected the response period to stay consumed, recorded %v", oracle.recorded)
			}

			out := logs.String()
			want := []string{"Sieve vacation reply could not be", "account_id=42", senderAddr, relayErr.Error()}
			var found bool
			for _, line := range strings.Split(out, "\n") {
				if !strings.Contains(line, "level=WARN") {
					continue
				}
				matches := true
				for _, w := range want {
					if !strings.Contains(line, w) {
						matches = false
						break
					}
				}
				if matches {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("no WARN line naming account 42, sender %s and the relay error after a claimed vacation reply was lost; log output:\n%s", senderAddr, out)
			}
		})
	}
}
