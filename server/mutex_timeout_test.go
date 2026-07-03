package server

import (
	"context"
	"sync"
	"testing"
	"time"
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
