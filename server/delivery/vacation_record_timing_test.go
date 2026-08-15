package delivery

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/server/sieveengine"
)

// fakeVacationOracle stands in for the database-backed oracle: it allows the first
// response per sender and records the ones that are committed, tracking the order of
// the record relative to the relay handoff.
type fakeVacationOracle struct {
	recorded  []string
	recordErr error
}

func (o *fakeVacationOracle) IsVacationResponseAllowed(_ context.Context, _ int64, originalSender string, _ string, _ time.Duration) (bool, error) {
	for _, s := range o.recorded {
		if s == originalSender {
			return false, nil
		}
	}
	return true, nil
}

func (o *fakeVacationOracle) RecordVacationResponseSent(_ context.Context, _ int64, originalSender string, _ string) error {
	if o.recordErr != nil {
		return o.recordErr
	}
	o.recorded = append(o.recorded, originalSender)
	return nil
}

func (o *fakeVacationOracle) CountRedirectsSince(_ context.Context, _ int64, _ time.Duration) (int, error) {
	return 0, nil
}

func (o *fakeVacationOracle) RecordRedirect(_ context.Context, _ int64) error { return nil }

// orderedRelayQueue notes how many suppression records existed at handoff time.
type orderedRelayQueue struct {
	oracle           *fakeVacationOracle
	calls            int
	recordsAtHandoff int
	err              error
}

func (q *orderedRelayQueue) Enqueue(_, _, _ string, _ []byte) error {
	q.calls++
	q.recordsAtHandoff = len(q.oracle.recorded)
	return q.err
}

const vacationScript = `require "vacation";
vacation :days 7 :subject "Away" "I am away";
`

// evaluateVacation runs a vacation script the way a delivery does and returns the
// resulting sieve action.
func evaluateVacation(t *testing.T, oracle *fakeVacationOracle, sender string) sieveengine.Result {
	t.Helper()
	executor, err := sieveengine.NewSieveExecutorWithOracleAndExtensions(vacationScript, 42, oracle, oracle, 10, time.Hour, 0, []string{"vacation"})
	if err != nil {
		t.Fatalf("create executor: %v", err)
	}
	result, err := executor.Evaluate(context.Background(), sieveengine.Context{
		EnvelopeFrom: sender,
		EnvelopeTo:   "jane@example.com",
		Header:       map[string][]string{"From": {sender}, "To": {"jane@example.com"}},
		Body:         "hello",
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if result.Action != sieveengine.ActionVacation {
		t.Fatalf("action = %s, want %s", result.Action, sieveengine.ActionVacation)
	}
	return result
}

// TestVacationSuppressionRecordedOnlyOnSend covers the RFC 5230 §4.5 per-sender period:
// the window may only be consumed by a reply that is actually handed off for delivery,
// and it must be consumed before the handoff so a redelivery cannot produce a second
// reply.
func TestVacationSuppressionRecordedOnlyOnSend(t *testing.T) {
	const owner = "jane@example.com"
	sender := vacAddr(t, "bob@external.com")
	toAddress := vacAddr(t, owner)
	ownsJane := func(_ context.Context, _ int64, addr string) (bool, error) {
		return strings.EqualFold(addr, owner), nil
	}

	t.Run("handler suppresses the reply -> window not consumed", func(t *testing.T) {
		oracle := &fakeVacationOracle{}
		result := evaluateVacation(t, oracle, "bob@external.com")

		rq := &orderedRelayQueue{oracle: oracle}
		h := &StandardVacationHandler{Hostname: "m", RelayQueue: rq, IsOwnedAddress: ownsJane}
		// The account is not in To/Cc, so HandleVacationResponse must not reply.
		orig := makeMessage(map[string]string{"From": "bob@external.com", "To": "list@example.com"})

		if err := h.HandleVacationResponse(context.Background(), 42, result, sender, toAddress, orig); err != nil {
			t.Fatalf("HandleVacationResponse: %v", err)
		}
		if rq.calls != 0 {
			t.Fatalf("expected suppression (0 enqueues), got %d", rq.calls)
		}
		if len(oracle.recorded) != 0 {
			t.Errorf("suppression window consumed by a reply that was never sent: recorded %v", oracle.recorded)
		}
	})

	t.Run("relay not configured -> window not consumed", func(t *testing.T) {
		oracle := &fakeVacationOracle{}
		result := evaluateVacation(t, oracle, "bob@external.com")

		h := &StandardVacationHandler{Hostname: "m", IsOwnedAddress: ownsJane}
		orig := makeMessage(map[string]string{"From": "bob@external.com", "To": owner})

		if err := h.HandleVacationResponse(context.Background(), 42, result, sender, toAddress, orig); err != nil {
			t.Fatalf("HandleVacationResponse: %v", err)
		}
		if len(oracle.recorded) != 0 {
			t.Errorf("suppression window consumed without a relay to send through: recorded %v", oracle.recorded)
		}
	})

	t.Run("reply sent -> window consumed once, before the handoff", func(t *testing.T) {
		oracle := &fakeVacationOracle{}
		result := evaluateVacation(t, oracle, "bob@external.com")

		rq := &orderedRelayQueue{oracle: oracle}
		h := &StandardVacationHandler{Hostname: "m", RelayQueue: rq, IsOwnedAddress: ownsJane}
		orig := makeMessage(map[string]string{"From": "bob@external.com", "To": owner})

		if err := h.HandleVacationResponse(context.Background(), 42, result, sender, toAddress, orig); err != nil {
			t.Fatalf("HandleVacationResponse: %v", err)
		}
		if rq.calls != 1 {
			t.Fatalf("expected 1 enqueue, got %d", rq.calls)
		}
		if len(oracle.recorded) != 1 {
			t.Fatalf("expected the window to be consumed once, recorded %v", oracle.recorded)
		}
		if rq.recordsAtHandoff != 1 {
			t.Errorf("window must be consumed before the handoff; records at enqueue = %d", rq.recordsAtHandoff)
		}

		// A second message from the same sender is now inside the window.
		executor, err := sieveengine.NewSieveExecutorWithOracleAndExtensions(vacationScript, 42, oracle, oracle, 10, time.Hour, 0, []string{"vacation"})
		if err != nil {
			t.Fatalf("create executor: %v", err)
		}
		next, err := executor.Evaluate(context.Background(), sieveengine.Context{
			EnvelopeFrom: "bob@external.com",
			EnvelopeTo:   owner,
			Header:       map[string][]string{"From": {"bob@external.com"}, "To": {owner}},
			Body:         "hello again",
		})
		if err != nil {
			t.Fatalf("evaluate (second): %v", err)
		}
		if next.Action != sieveengine.ActionKeep {
			t.Errorf("second message action = %s, want %s (inside the per-sender window)", next.Action, sieveengine.ActionKeep)
		}
	})

	t.Run("recording fails -> no reply is handed off", func(t *testing.T) {
		oracle := &fakeVacationOracle{recordErr: errors.New("db down")}
		result := evaluateVacation(t, oracle, "bob@external.com")

		rq := &orderedRelayQueue{oracle: oracle}
		h := &StandardVacationHandler{Hostname: "m", RelayQueue: rq, IsOwnedAddress: ownsJane}
		orig := makeMessage(map[string]string{"From": "bob@external.com", "To": owner})

		if err := h.HandleVacationResponse(context.Background(), 42, result, sender, toAddress, orig); err == nil {
			t.Fatalf("expected an error when the suppression record cannot be written")
		}
		if rq.calls != 0 {
			t.Errorf("expected no handoff when the window cannot be recorded, got %d", rq.calls)
		}
	})
}
