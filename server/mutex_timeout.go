package server

import (
	"context"
	"sync"
	"time"
)

// MutexTimeout defines how long to wait for mutex acquisition before timing out
const MutexTimeout = 5 * time.Second

// MutexTimeoutHelper provides methods for acquiring mutex locks with timeouts
type MutexTimeoutHelper struct {
	mutex *sync.RWMutex
	ctx   context.Context
	log   func(format string, args ...interface{})
	name  string // Protocol name for logging
}

// NewMutexTimeoutHelper creates a new helper for mutex timeout operations
func NewMutexTimeoutHelper(mutex *sync.RWMutex, ctx context.Context, name string, log func(format string, args ...interface{})) *MutexTimeoutHelper {
	return &MutexTimeoutHelper{
		mutex: mutex,
		ctx:   ctx,
		log:   log,
		name:  name,
	}
}

// AcquireReadLockWithTimeout attempts to acquire a read lock with a timeout.
// It returns true if the lock was successfully acquired, false otherwise.
// The caller must call the returned cancel function when done with the lock,
// after calling RUnlock() themselves.
func (h *MutexTimeoutHelper) AcquireReadLockWithTimeout() (bool, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(h.ctx, MutexTimeout)
	lockChan := make(chan struct{})

	go func() {
		h.mutex.RLock()
		close(lockChan)
	}()

	select {
	case <-lockChan:
		// Lock acquired successfully
		return true, cancel
	case <-ctx.Done():
		// Lock acquisition timed out or context was canceled
		go func() {
			// Wait for the lock attempt to complete to avoid leaking goroutines
			select {
			case <-lockChan:
				// If we got the lock after timing out, release it
				h.mutex.RUnlock()
			case <-time.After(time.Second):
				// If we can't get the lock after waiting another second,
				// something is seriously wrong, but we can't do much about it
				h.log("[%s][MUTEX] Critical warning: Failed to clean up read lock after timeout", h.name)
			}
		}()
		return false, cancel
	}
}

// AcquireWriteLockWithTimeout attempts to acquire a write lock with a timeout.
// It returns true if the lock was successfully acquired, false otherwise.
// The caller must call the returned cancel function when done with the lock,
// after calling Unlock() themselves.
func (h *MutexTimeoutHelper) AcquireWriteLockWithTimeout() (bool, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(h.ctx, MutexTimeout)
	lockChan := make(chan struct{})

	go func() {
		h.mutex.Lock()
		close(lockChan)
	}()

	select {
	case <-lockChan:
		// Lock acquired successfully
		return true, cancel
	case <-ctx.Done():
		// Lock acquisition timed out or context was canceled
		go func() {
			// Wait for the lock attempt to complete to avoid leaking goroutines
			select {
			case <-lockChan:
				// If we got the lock after timing out, release it
				h.mutex.Unlock()
			case <-time.After(time.Second):
				// If we can't get the lock after waiting another second,
				// something is seriously wrong, but we can't do much about it
				h.log("[%s][MUTEX] WARNING: failed to clean up write lock after timeout", h.name)
			}
		}()
		return false, cancel
	}
}
