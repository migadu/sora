package imap

import (
	"context"
	"testing"
	"time"
)

// TestCommandTimeout_EnforcedOnSearch verifies that the meteredSession applies
// a hard timeout to SEARCH commands, cancelling the context before the handler
// finishes if it exceeds the configured limit.
func TestCommandTimeout_EnforcedOnSearch(t *testing.T) {
	timeout := 50 * time.Millisecond

	timeouts := CommandTimeouts{
		Search: timeout,
	}

	// Simulate a SEARCH handler that blocks for longer than the timeout.
	// We only need the context to verify it gets cancelled.
	var handlerCtx context.Context
	handlerDone := make(chan struct{})

	parentCtx := context.Background()
	cmdCtx, cancel := applyCommandTimeout(parentCtx, "SEARCH", &timeouts)
	defer cancel()

	handlerCtx = cmdCtx

	go func() {
		defer close(handlerDone)
		// Simulate a slow handler: wait for the context to be cancelled.
		<-handlerCtx.Done()
	}()

	select {
	case <-handlerDone:
		// Handler's context was cancelled — good.
	case <-time.After(1 * time.Second):
		t.Fatal("command timeout was not enforced; handler was not cancelled within 1s")
	}

	elapsed := time.Since(time.Time{}) // just checking the context error
	_ = elapsed

	if handlerCtx.Err() != context.DeadlineExceeded {
		t.Fatalf("expected context.DeadlineExceeded, got %v", handlerCtx.Err())
	}
}

// TestCommandTimeout_NotAppliedToUnconfiguredCommand verifies that commands
// without a configured timeout get no additional deadline.
func TestCommandTimeout_NotAppliedToUnconfiguredCommand(t *testing.T) {
	timeouts := CommandTimeouts{
		Search: 50 * time.Millisecond,
		// SELECT is not configured (zero value).
	}

	parentCtx := context.Background()
	cmdCtx, cancel := applyCommandTimeout(parentCtx, "SELECT", &timeouts)
	defer cancel()

	// The context should have no deadline since SELECT has no timeout.
	if _, ok := cmdCtx.Deadline(); ok {
		t.Fatal("expected no deadline for unconfigured command, but got one")
	}
}

// TestCommandTimeout_NilTimeoutsNoOp verifies that a nil CommandTimeouts
// produces no deadline (safe for sessions where timeouts are disabled).
func TestCommandTimeout_NilTimeoutsNoOp(t *testing.T) {
	parentCtx := context.Background()
	cmdCtx, cancel := applyCommandTimeout(parentCtx, "SEARCH", nil)
	defer cancel()

	if _, ok := cmdCtx.Deadline(); ok {
		t.Fatal("expected no deadline when CommandTimeouts is nil")
	}
}

// TestCommandTimeout_ExistingDeadlineShorterThanCommand verifies that if the
// parent context already has a tighter deadline (e.g. from the client
// connection), the command timeout does NOT extend it.
func TestCommandTimeout_ExistingDeadlineShorterThanCommand(t *testing.T) {
	timeouts := CommandTimeouts{
		Search: 10 * time.Second,
	}

	parentCtx, parentCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer parentCancel()

	cmdCtx, cancel := applyCommandTimeout(parentCtx, "SEARCH", &timeouts)
	defer cancel()

	deadline, ok := cmdCtx.Deadline()
	if !ok {
		t.Fatal("expected a deadline")
	}

	// The effective deadline should be ≈50ms from now (the parent's tighter
	// deadline), not 10s.
	remaining := time.Until(deadline)
	if remaining > 1*time.Second {
		t.Fatalf("expected deadline to be the parent's tighter deadline (~50ms remaining), got %v remaining", remaining)
	}
}
