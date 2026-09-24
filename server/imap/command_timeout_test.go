package imap

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

// TestCommandTimeout_EnforcedOnRename pins the RENAME cap. RENAME had no per-command
// deadline at all, so a rename that blocked (or, before the mailbox_path fix, rewrote
// every message row in the mailbox) ran until the session itself went away.
func TestCommandTimeout_EnforcedOnRename(t *testing.T) {
	timeouts := CommandTimeouts{Rename: 50 * time.Millisecond}

	cmdCtx, cancel := applyCommandTimeout(context.Background(), "RENAME", &timeouts)
	defer cancel()

	if _, ok := cmdCtx.Deadline(); !ok {
		t.Fatal("expected RENAME to get a deadline")
	}

	select {
	case <-cmdCtx.Done():
	case <-time.After(1 * time.Second):
		t.Fatal("RENAME timeout was not enforced within 1s")
	}

	if cmdCtx.Err() != context.DeadlineExceeded {
		t.Fatalf("expected context.DeadlineExceeded, got %v", cmdCtx.Err())
	}
}

// TestDefaultCommandTimeouts_CoversRename guards the default: a zero value means "no
// cap at all", which is what RENAME used to have.
func TestDefaultCommandTimeouts_CoversRename(t *testing.T) {
	if got := DefaultCommandTimeouts().Rename; got <= 0 {
		t.Fatalf("RENAME must have a default timeout, got %v", got)
	}
}

// FETCH is the one expensive command left uncapped on purpose: its duration is dominated
// by how fast the client drains a large body, so a default cap would be a cap on slow
// connections. The knob still has to work for operators who want one — it was parsed into
// config and stored on the session, but never applied to any context.
func TestCommandTimeout_FetchUncappedByDefaultButConfigurable(t *testing.T) {
	if got := DefaultCommandTimeouts().Fetch; got != 0 {
		t.Fatalf("FETCH must default to uncapped, got %v", got)
	}

	none, cancelNone := applyCommandTimeout(context.Background(), "FETCH", &CommandTimeouts{})
	defer cancelNone()
	if _, ok := none.Deadline(); ok {
		t.Fatal("FETCH must get no deadline when none is configured")
	}

	configured := CommandTimeouts{Fetch: 50 * time.Millisecond}
	cmdCtx, cancel := applyCommandTimeout(context.Background(), "FETCH", &configured)
	defer cancel()
	if _, ok := cmdCtx.Deadline(); !ok {
		t.Fatal("a configured FETCH timeout must reach the command context")
	}

	select {
	case <-cmdCtx.Done():
	case <-time.After(1 * time.Second):
		t.Fatal("configured FETCH timeout was not enforced within 1s")
	}
	if cmdCtx.Err() != context.DeadlineExceeded {
		t.Fatalf("expected context.DeadlineExceeded, got %v", cmdCtx.Err())
	}
}

// Every command applyCommandTimeout knows about must actually have a call site.
//
// FETCH did not: the switch case existed, the config field was parsed and stored, and
// nothing ever called applyCommandTimeout for it — because FETCH is not wrapped by
// meteredSession (it self-instruments), so adding the timeout there was a no-op that
// looked done. RENAME had the opposite hole: a call site was never added at all.
// A settings knob that silently does nothing is worse than no knob.
func TestCommandTimeoutsAreWiredAtCallSites(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	callSite := regexp.MustCompile(`applyCommandTimeout\([^,]+,\s*"([A-Z]+)"`)
	switchCase := regexp.MustCompile(`case\s+"([A-Z]+)":\s*\n\s*timeout = timeouts\.`)

	wired := map[string]bool{}
	var known []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if e.Name() == "command_timeout.go" {
			for _, m := range switchCase.FindAllStringSubmatch(string(src), -1) {
				known = append(known, m[1])
			}
			continue
		}
		if strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		for _, m := range callSite.FindAllStringSubmatch(string(src), -1) {
			wired[m[1]] = true
		}
	}

	if len(known) == 0 {
		t.Fatal("found no commands in applyCommandTimeout's switch; the guard is not looking at the right file")
	}
	for _, cmd := range known {
		if !wired[cmd] {
			t.Errorf("%s has a timeout in applyCommandTimeout but no call site applies it — the setting does nothing", cmd)
		}
	}
}
