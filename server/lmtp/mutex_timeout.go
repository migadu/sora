package lmtp

import (
	"context"
	"time"
)

// MutexTimeout defines how long to wait for mutex acquisition before timing out
const MutexTimeout = 30 * time.Second

// acquireReadLockWithTimeout attempts to acquire a read lock with a timeout.
// It returns true if the lock was successfully acquired, false otherwise.
// The caller must call the returned cancel function when done with the lock,
// after calling RUnlock() themselves.
func (s *LMTPSession) acquireReadLockWithTimeout() (bool, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(s.ctx, MutexTimeout)
	lockChan := make(chan struct{})

	go func() {
		s.mutex.RLock()
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
				s.mutex.RUnlock()
			case <-time.After(time.Second):
				// If we can't get the lock after waiting another second,
				// something is seriously wrong, but we can't do much about it
				s.Log("[LMTP][MUTEX] Critical warning: Failed to clean up read lock after timeout")
			}
		}()
		return false, cancel
	}
}

// acquireWriteLockWithTimeout attempts to acquire a write lock with a timeout.
// It returns true if the lock was successfully acquired, false otherwise.
// The caller must call the returned cancel function when done with the lock,
// after calling Unlock() themselves.
func (s *LMTPSession) acquireWriteLockWithTimeout() (bool, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(s.ctx, MutexTimeout)
	lockChan := make(chan struct{})

	go func() {
		s.mutex.Lock()
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
				s.mutex.Unlock()
			case <-time.After(time.Second):
				// If we can't get the lock after waiting another second,
				// something is seriously wrong, but we can't do much about it
				s.Log("[LMTP][MUTEX] Critical warning: Failed to clean up write lock after timeout")
			}
		}()
		return false, cancel
	}
}
