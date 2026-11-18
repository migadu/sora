package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestAcquireReadLock_CommandContextCancelled verifies that when a command
// context is cancelled while waiting for a contended lock, the lock attempt
// aborts promptly rather than waiting for the full MutexTimeout (5s).
//
// Before the fix, AcquireReadLockWithTimeout used only the session context
// stored in the helper struct, so cancelling a per-command context had no
// effect on the lock wait.
func TestAcquireReadLock_CommandContextCancelled(t *testing.T) {
	var mu sync.RWMutex
	sessionCtx := context.Background() // long-lived session context — stays open

	helper := NewMutexTimeoutHelper(&mu, sessionCtx, "test", func(format string, args ...any) {
		t.Logf(format, args...)
	})

	// Hold a write lock so the read lock attempt blocks.
	mu.Lock()
	defer mu.Unlock()

	// Simulate a command context that gets cancelled almost immediately.
	cmdCtx, cmdCancel := context.WithCancel(sessionCtx)

	go func() {
		time.Sleep(50 * time.Millisecond)
		cmdCancel()
	}()

	start := time.Now()
	acquired, release := helper.AcquireReadLockWithTimeout(cmdCtx)
	elapsed := time.Since(start)
	defer release()

	if acquired {
		t.Fatal("expected lock acquisition to fail when command context is cancelled")
	}

	// The key assertion: with the fix, the attempt should abort in ~50ms
	// (when cmdCtx is cancelled). Without the fix, it waits for the full
	// MutexTimeout (5s) because only the session context (Background) is used.
	if elapsed > 500*time.Millisecond {
		t.Fatalf("lock wait took %v; expected prompt abort on command context cancellation (< 500ms)", elapsed)
	}
}

// TestAcquireWriteLock_CommandContextCancelled is the write-lock counterpart.
func TestAcquireWriteLock_CommandContextCancelled(t *testing.T) {
	var mu sync.RWMutex
	sessionCtx := context.Background()

	helper := NewMutexTimeoutHelper(&mu, sessionCtx, "test", func(format string, args ...any) {
		t.Logf(format, args...)
	})

	// Hold a read lock so the write lock attempt blocks.
	mu.RLock()
	defer mu.RUnlock()

	cmdCtx, cmdCancel := context.WithCancel(sessionCtx)

	go func() {
		time.Sleep(50 * time.Millisecond)
		cmdCancel()
	}()

	start := time.Now()
	acquired, release := helper.AcquireWriteLockWithTimeout(cmdCtx)
	elapsed := time.Since(start)
	defer release()

	if acquired {
		t.Fatal("expected lock acquisition to fail when command context is cancelled")
	}

	if elapsed > 500*time.Millisecond {
		t.Fatalf("lock wait took %v; expected prompt abort on command context cancellation (< 500ms)", elapsed)
	}
}

// TestAcquireReadLock_UncontestedStillWorks ensures the happy path is unchanged:
// when the lock is free, AcquireReadLockWithTimeout succeeds immediately.
func TestAcquireReadLock_UncontestedStillWorks(t *testing.T) {
	var mu sync.RWMutex
	sessionCtx := context.Background()

	helper := NewMutexTimeoutHelper(&mu, sessionCtx, "test", func(format string, args ...any) {
		t.Logf(format, args...)
	})

	cmdCtx := context.Background()

	acquired, release := helper.AcquireReadLockWithTimeout(cmdCtx)
	if !acquired {
		t.Fatal("expected lock acquisition to succeed on uncontested mutex")
	}
	release()
}

// TestAcquireWriteLock_UncontestedStillWorks ensures the happy path is unchanged
// for write locks.
func TestAcquireWriteLock_UncontestedStillWorks(t *testing.T) {
	var mu sync.RWMutex
	sessionCtx := context.Background()

	helper := NewMutexTimeoutHelper(&mu, sessionCtx, "test", func(format string, args ...any) {
		t.Logf(format, args...)
	})

	cmdCtx := context.Background()

	acquired, release := helper.AcquireWriteLockWithTimeout(cmdCtx)
	if !acquired {
		t.Fatal("expected lock acquisition to succeed on uncontested mutex")
	}
	release()
}

// TestAcquireReadLock_SessionContextCancelledStillAborts ensures backwards
// compatibility: if the session context (stored in h.ctx) is cancelled, the
// lock attempt still aborts promptly even when the command context is alive.
func TestAcquireReadLock_SessionContextCancelledStillAborts(t *testing.T) {
	var mu sync.RWMutex
	sessionCtx, sessionCancel := context.WithCancel(context.Background())

	helper := NewMutexTimeoutHelper(&mu, sessionCtx, "test", func(format string, args ...any) {
		t.Logf(format, args...)
	})

	// Hold a write lock so the read lock attempt blocks.
	mu.Lock()
	defer mu.Unlock()

	// Command context stays alive, but the session context gets cancelled.
	cmdCtx := context.Background()

	go func() {
		time.Sleep(50 * time.Millisecond)
		sessionCancel()
	}()

	start := time.Now()
	acquired, release := helper.AcquireReadLockWithTimeout(cmdCtx)
	elapsed := time.Since(start)
	defer release()

	if acquired {
		t.Fatal("expected lock acquisition to fail when session context is cancelled")
	}

	if elapsed > 500*time.Millisecond {
		t.Fatalf("lock wait took %v; expected prompt abort on session context cancellation (< 500ms)", elapsed)
	}
}

// TestAcquireWriteLockForClose_SessionContextCancelledStillWaits: a teardown runs
// after shutdown cancelled the session context and must still wait for the command
// holding the lock, not give up at once (#1947).
func TestAcquireWriteLockForClose_SessionContextCancelledStillWaits(t *testing.T) {
	var mu sync.RWMutex
	sessionCtx, sessionCancel := context.WithCancel(context.Background())
	sessionCancel()

	helper := NewMutexTimeoutHelper(&mu, sessionCtx, "test", func(format string, args ...any) {
		t.Logf(format, args...)
	})

	mu.Lock()
	go func() {
		time.Sleep(50 * time.Millisecond)
		mu.Unlock()
	}()

	acquired, release := helper.AcquireWriteLockForClose()
	if !acquired {
		t.Fatal("expected the close to wait for the lock although the session context is cancelled")
	}
	release()
}

// TestAcquireLock_CancelledContextTakesFreeLock: a teardown path that passes an already
// cancelled context must still get a free lock, and a free lock is not a timeout. Both the
// lock goroutine and the cancelled context used to be ready at the select, so the helper
// often reported "not acquired" and counted a lock timeout for a lock nobody held (#2004).
func TestAcquireLock_CancelledContextTakesFreeLock(t *testing.T) {
	const iterations = 1000
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	for _, mode := range []string{"write", "read"} {
		t.Run(mode, func(t *testing.T) {
			var mu sync.RWMutex
			name := "test-2004-free-" + mode
			helper := NewMutexTimeoutHelper(&mu, cancelled, name, t.Logf)
			acquire := helper.AcquireWriteLockWithTimeout
			if mode == "read" {
				acquire = helper.AcquireReadLockWithTimeout
			}
			timeouts := metrics.SessionLockTimeouts.WithLabelValues(name, mode)
			before := testutil.ToFloat64(timeouts)

			missed := 0
			for range iterations {
				acquired, release := acquire(cancelled)
				if !acquired {
					missed++
				}
				release()
			}
			if missed > 0 {
				t.Errorf("%d of %d attempts on a free lock with a cancelled context reported not acquired", missed, iterations)
			}
			if got := testutil.ToFloat64(timeouts) - before; got != 0 {
				t.Errorf("lock timeouts metric rose by %v for a free lock, want 0", got)
			}
			// No goroutine may still hold the lock after the last release.
			waitForFreeLock(t, &mu)
		})
	}
}

// TestAcquireLock_CancelledContextHeldLockGivesUp: a cancelled context still gives up on a
// lock that is held, promptly, counts one timeout, and the attempt left waiting in the
// background releases the lock once it gets it, so the mutex is free again afterwards.
func TestAcquireLock_CancelledContextHeldLockGivesUp(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	for _, mode := range []string{"write", "read"} {
		t.Run(mode, func(t *testing.T) {
			var mu sync.RWMutex
			name := "test-2004-held-" + mode
			helper := NewMutexTimeoutHelper(&mu, cancelled, name, t.Logf)
			acquire := helper.AcquireWriteLockWithTimeout
			if mode == "read" {
				acquire = helper.AcquireReadLockWithTimeout
			}
			timeouts := metrics.SessionLockTimeouts.WithLabelValues(name, mode)
			before := testutil.ToFloat64(timeouts)

			mu.Lock()
			start := time.Now()
			acquired, release := acquire(cancelled)
			elapsed := time.Since(start)
			release()
			if acquired {
				t.Fatal("acquired a lock that another goroutine holds")
			}
			if elapsed > 500*time.Millisecond {
				t.Errorf("gave up after %v, want a prompt return on a cancelled context", elapsed)
			}
			if got := testutil.ToFloat64(timeouts) - before; got != 1 {
				t.Errorf("lock timeouts metric rose by %v, want 1", got)
			}
			mu.Unlock()
			// The abandoned attempt takes the lock when it is released and must drop it.
			waitForFreeLock(t, &mu)
		})
	}
}

// waitForFreeLock fails the test unless mu becomes free for writing within a second.
func waitForFreeLock(t *testing.T, mu *sync.RWMutex) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !mu.TryLock() {
		if time.Now().After(deadline) {
			t.Fatal("the mutex is still held: an abandoned lock attempt did not release it")
		}
		time.Sleep(time.Millisecond)
	}
	mu.Unlock()
}
