package server

import (
	"context"
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
	name  string // Protocol name for logging
}

// NewMutexTimeoutHelper creates a new helper for mutex timeout operations
func NewMutexTimeoutHelper(mutex *sync.RWMutex, ctx context.Context, name string, log func(format string, args ...any)) *MutexTimeoutHelper {
	return &MutexTimeoutHelper{
		mutex: mutex,
		ctx:   ctx,
		log:   log,
		name:  name,
	}
}

// AcquireReadLockWithTimeout attempts to acquire a read lock with a timeout.
// It returns true if the lock was successfully acquired, false otherwise.
// The caller MUST call the returned release function to unlock the mutex.
//
// The cmdCtx parameter is the context for the current command/operation.
// The lock attempt is cancelled by whichever fires first: the command context,
// the session context (h.ctx), or the MutexTimeout.
func (h *MutexTimeoutHelper) AcquireReadLockWithTimeout(cmdCtx context.Context) (bool, func()) {
	start := time.Now()
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
		metrics.MailboxLockDuration.WithLabelValues(h.name, "read", "success").Observe(time.Since(start).Seconds())
		return true, h.mutex.RUnlock
	case <-ctx.Done():
		metrics.MailboxLockTimeouts.WithLabelValues(h.name, "read").Inc()
		metrics.MailboxLockDuration.WithLabelValues(h.name, "read", "timeout").Observe(time.Since(start).Seconds())
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
// The lock attempt is cancelled by whichever fires first: the command context,
// the session context (h.ctx), or the MutexTimeout.
func (h *MutexTimeoutHelper) AcquireWriteLockWithTimeout(cmdCtx context.Context) (bool, func()) {
	start := time.Now()
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
		h.mutex.Lock()
		lockChan <- struct{}{}
	}()

	select {
	case <-lockChan:
		metrics.MailboxLockDuration.WithLabelValues(h.name, "write", "success").Observe(time.Since(start).Seconds())
		return true, h.mutex.Unlock
	case <-ctx.Done():
		metrics.MailboxLockTimeouts.WithLabelValues(h.name, "write").Inc()
		metrics.MailboxLockDuration.WithLabelValues(h.name, "write", "timeout").Observe(time.Since(start).Seconds())
		go func() {
			// Wait for the lock attempt to complete to avoid leaking goroutines
			<-lockChan
			// If we got the lock after timing out, release it immediately
			h.mutex.Unlock()
		}()
		return false, func() {} // Return a no-op function
	}
}
