package pop3

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/migadu/sora/config"
)

// TestApplyCommandTimeout covers the ctx-wrapping helper: nil timeouts and
// unknown commands are no-ops, configured commands get a deadline.
func TestApplyCommandTimeout(t *testing.T) {
	base := context.Background()

	ctx, cancel := applyCommandTimeout(base, "RETR", nil)
	cancel()
	if ctx != base {
		t.Error("nil timeouts: expected original context")
	}

	timeouts := defaultCommandTimeouts()
	ctx, cancel = applyCommandTimeout(base, "NOOP", timeouts)
	cancel()
	if ctx != base {
		t.Error("unknown command: expected original context")
	}

	timeouts.Retr = 0
	ctx, cancel = applyCommandTimeout(base, "RETR", timeouts)
	cancel()
	if ctx != base {
		t.Error("zero timeout (disabled): expected original context")
	}

	timeouts.Retr = 5 * time.Second
	ctx, cancel = applyCommandTimeout(base, "RETR", timeouts)
	defer cancel()
	if _, ok := ctx.Deadline(); !ok {
		t.Error("configured command: expected a deadline on the context")
	}
}

// TestCommandTimeoutDeadlineFires verifies the wrapped context actually
// expires: a blocked command waiting on ctx.Done() would be released within
// the configured bound.
func TestCommandTimeoutDeadlineFires(t *testing.T) {
	timeouts := defaultCommandTimeouts()
	timeouts.Quit = 10 * time.Millisecond

	ctx, cancel := applyCommandTimeout(context.Background(), "QUIT", timeouts)
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

// TestCommandTimeoutsOverridesWiring verifies New() starts from defaults and
// applies operator overrides from the options.
func TestCommandTimeoutsOverridesWiring(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := New(ctx, "test", "localhost", "127.0.0.1:0", nil, nil, nil, nil, POP3ServerOptions{
		MaxConnections: 10,
		CommandTimeoutOverrides: map[string]time.Duration{
			"retr": 7 * time.Second,
			"quit": 0, // explicit disable
		},
		Config: &config.Config{},
	})
	if err != nil {
		t.Fatalf("Failed to create POP3 server: %v", err)
	}

	if srv.commandTimeouts.Retr != 7*time.Second {
		t.Errorf("Retr = %v, want 7s (override)", srv.commandTimeouts.Retr)
	}
	if srv.commandTimeouts.Quit != 0 {
		t.Errorf("Quit = %v, want 0 (disabled by override)", srv.commandTimeouts.Quit)
	}
	if srv.commandTimeouts.Stat != DefaultCommandTimeouts().Stat {
		t.Errorf("Stat = %v, want %v (default preserved)", srv.commandTimeouts.Stat, DefaultCommandTimeouts().Stat)
	}
}
