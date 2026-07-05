package lmtp

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestApplyCommandTimeout covers the ctx-wrapping helper: nil timeouts and
// unknown commands are no-ops, configured commands get a deadline.
func TestApplyCommandTimeout(t *testing.T) {
	base := context.Background()

	ctx, cancel := applyCommandTimeout(base, "DATA", nil)
	cancel()
	if ctx != base {
		t.Error("nil timeouts: expected original context")
	}

	timeouts := defaultCommandTimeouts()
	ctx, cancel = applyCommandTimeout(base, "MAIL", timeouts)
	cancel()
	if ctx != base {
		t.Error("unknown command: expected original context")
	}

	timeouts.Data = 0
	ctx, cancel = applyCommandTimeout(base, "DATA", timeouts)
	cancel()
	if ctx != base {
		t.Error("zero timeout (disabled): expected original context")
	}

	timeouts.Data = 5 * time.Second
	ctx, cancel = applyCommandTimeout(base, "DATA", timeouts)
	defer cancel()
	if _, ok := ctx.Deadline(); !ok {
		t.Error("configured command: expected a deadline on the context")
	}
}

// TestCommandTimeoutDeadlineFires verifies the wrapped context actually
// expires: a delivery pipeline blocked on a wedged backend would be released
// within the configured bound.
func TestCommandTimeoutDeadlineFires(t *testing.T) {
	timeouts := defaultCommandTimeouts()
	timeouts.Rcpt = 10 * time.Millisecond

	ctx, cancel := applyCommandTimeout(context.Background(), "RCPT", timeouts)
	defer cancel()

	select {
	case <-ctx.Done():
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Errorf("ctx.Err() = %v, want DeadlineExceeded", ctx.Err())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("per-command deadline never fired")
	}
}

// TestCommandTimedOutClassification verifies the timeout-vs-shutdown
// classifier used by the RCPT/DATA error paths: only an expired execution
// deadline reads as a cap timeout (451, MTA requeues); a plain cancellation
// (client disconnect, server shutdown) and a live context do not (421 path).
func TestCommandTimedOutClassification(t *testing.T) {
	expired, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-expired.Done()
	if !commandTimedOut(expired) {
		t.Error("expired deadline: expected commandTimedOut = true")
	}

	cancelled, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if commandTimedOut(cancelled) {
		t.Error("plain cancellation: expected commandTimedOut = false")
	}

	if commandTimedOut(context.Background()) {
		t.Error("live context: expected commandTimedOut = false")
	}
}

// TestCommandTimeoutsOverrides verifies defaults survive partial overrides and
// explicit zeros disable individual caps.
func TestCommandTimeoutsOverrides(t *testing.T) {
	timeouts := defaultCommandTimeouts()
	timeouts.ApplyOverrides(map[string]time.Duration{
		"data":    2 * time.Minute,
		"rcpt":    0, // explicit disable
		"unknown": time.Second,
	})

	if timeouts.Data != 2*time.Minute {
		t.Errorf("Data = %v, want 2m (override)", timeouts.Data)
	}
	if timeouts.Rcpt != 0 {
		t.Errorf("Rcpt = %v, want 0 (disabled by override)", timeouts.Rcpt)
	}
}
