package server

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/migadu/sora/pkg/metrics"
)

// MutexTimeout defines how long to wait for mutex acquisition before timing out
const MutexTimeout = 5 * time.Second

// MutexTimeoutHelper provides methods for acquiring mutex locks with timeouts
type MutexTimeoutHelper struct {
	mutex *sync.RWMutex
	ctx   context.Context
	log   func(format string, args ...any)
	name  string // protocol label of the session lock metrics
}

// NewMutexTimeoutHelper creates a new helper for mutex timeout operations. name is
// the protocol ("imap", "pop3", ...); it labels the session lock metrics, lowercased
// like the protocol label of the command, error and authentication metrics.
func NewMutexTimeoutHelper(mutex *sync.RWMutex, ctx context.Context, name string, log func(format string, args ...any)) *MutexTimeoutHelper {
	return &MutexTimeoutHelper{
		mutex: mutex,
		ctx:   ctx,
		log:   log,
		name:  strings.ToLower(name),
	}
}

// AcquireReadLockWithTimeout attempts to acquire a read lock with a timeout.
// It returns true if the lock was successfully acquired, false otherwise.
// The caller MUST call the returned release function to unlock the mutex.
//
// The cmdCtx parameter is the context for the current command/operation.
// A free lock is always taken, even when a context is already cancelled. Otherwise
// the wait is cancelled by whichever fires first: the command context, the session
// context (h.ctx), or the MutexTimeout.
func (h *MutexTimeoutHelper) AcquireReadLockWithTimeout(cmdCtx context.Context) (bool, func()) {
	start := time.Now()
	// A free lock is taken at once, whatever the contexts say: teardown passes a cancelled
	// one, and a free lock is never a timeout (#2004).
	if h.mutex.TryRLock() {
		metrics.SessionLockDuration.WithLabelValues(h.name, "read", "success").Observe(time.Since(start).Seconds())
		return true, h.mutex.RUnlock
	}
	// Merge session and command contexts: cancel on whichever fires first.
	merged, mergedCancel := context.WithCancel(cmdCtx)
	go func() {
		select {
		case <-h.ctx.Done():
			mergedCancel()
		case <-merged.Done():
		}
	}()
	ctx, cancel := context.WithTimeout(merged, MutexTimeout)
	defer cancel()
	defer mergedCancel()

	lockChan := make(chan struct{}, 1)
	go func() {
		h.mutex.RLock()
		lockChan <- struct{}{}
	}()

	select {
	case <-lockChan:
		metrics.SessionLockDuration.WithLabelValues(h.name, "read", "success").Observe(time.Since(start).Seconds())
		return true, h.mutex.RUnlock
	case <-ctx.Done():
		// Both cases are ready when the lock came free as the wait ended, and select picks
		// either; a lock the attempt got is not a timeout.
		select {
		case <-lockChan:
			metrics.SessionLockDuration.WithLabelValues(h.name, "read", "success").Observe(time.Since(start).Seconds())
			return true, h.mutex.RUnlock
		default:
		}
		metrics.SessionLockTimeouts.WithLabelValues(h.name, "read").Inc()
		metrics.SessionLockDuration.WithLabelValues(h.name, "read", "timeout").Observe(time.Since(start).Seconds())
		go func() {
			// Wait for the lock attempt to complete to avoid leaking goroutines
			<-lockChan
			// If we got the lock after timing out, release it immediately
			h.mutex.RUnlock()
		}()
		return false, func() {} // Return a no-op function
	}
}

// AcquireWriteLockWithTimeout attempts to acquire a write lock with a timeout.
// It returns true if the lock was successfully acquired, false otherwise.
// The caller MUST call the returned release function to unlock the mutex.
//
// The cmdCtx parameter is the context for the current command/operation.
// A free lock is always taken, even when a context is already cancelled. Otherwise
// the wait is cancelled by whichever fires first: the command context, the session
// context (h.ctx), or the MutexTimeout.
func (h *MutexTimeoutHelper) AcquireWriteLockWithTimeout(cmdCtx context.Context) (bool, func()) {
	// Merge session and command contexts: cancel on whichever fires first.
	merged, mergedCancel := context.WithCancel(cmdCtx)
	go func() {
		select {
		case <-h.ctx.Done():
			mergedCancel()
		case <-merged.Done():
		}
	}()
	defer mergedCancel()
	return h.acquireWriteLock(merged)
}

// AcquireWriteLockForClose acquires the write lock for a session's teardown. It waits
// up to MutexTimeout and, unlike AcquireWriteLockWithTimeout, is not cancelled by the
// session context: a server shutdown cancels that context before the sessions are
// closed, and the close must still wait for a command that holds the lock rather than
// clear the state that command is using.
func (h *MutexTimeoutHelper) AcquireWriteLockForClose() (bool, func()) {
	return h.acquireWriteLock(context.Background())
}

// acquireWriteLock takes a free write lock at once, else waits for it until parent is
// done or MutexTimeout passes.
func (h *MutexTimeoutHelper) acquireWriteLock(parent context.Context) (bool, func()) {
	start := time.Now()
	// A free lock is taken at once, whatever the contexts say: teardown passes a cancelled
	// one, and a free lock is never a timeout (#2004).
	if h.mutex.TryLock() {
		metrics.SessionLockDuration.WithLabelValues(h.name, "write", "success").Observe(time.Since(start).Seconds())
		return true, h.mutex.Unlock
	}
	ctx, cancel := context.WithTimeout(parent, MutexTimeout)
	defer cancel()

	lockChan := make(chan struct{}, 1)
	go func() {
		h.mutex.Lock()
		lockChan <- struct{}{}
	}()

	select {
	case <-lockChan:
		metrics.SessionLockDuration.WithLabelValues(h.name, "write", "success").Observe(time.Since(start).Seconds())
		return true, h.mutex.Unlock
	case <-ctx.Done():
		// Both cases are ready when the lock came free as the wait ended, and select picks
		// either; a lock the attempt got is not a timeout.
		select {
		case <-lockChan:
			metrics.SessionLockDuration.WithLabelValues(h.name, "write", "success").Observe(time.Since(start).Seconds())
			return true, h.mutex.Unlock
		default:
		}
		metrics.SessionLockTimeouts.WithLabelValues(h.name, "write").Inc()
		metrics.SessionLockDuration.WithLabelValues(h.name, "write", "timeout").Observe(time.Since(start).Seconds())
		go func() {
			// Wait for the lock attempt to complete to avoid leaking goroutines
			<-lockChan
			// If we got the lock after timing out, release it immediately
			h.mutex.Unlock()
		}()
		return false, func() {} // Return a no-op function
	}
}
