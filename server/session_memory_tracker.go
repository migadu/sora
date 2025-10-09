package server

import (
	"fmt"
	"sync/atomic"
)

// SessionMemoryTracker tracks memory usage for a single session
// to prevent memory exhaustion attacks and provide visibility into resource usage
type SessionMemoryTracker struct {
	allocatedBytes atomic.Int64 // Current allocated bytes
	peakBytes      atomic.Int64 // Peak allocated bytes during session lifetime
	maxAllowed     int64        // Maximum allowed bytes (0 = unlimited)
}

// NewSessionMemoryTracker creates a new session memory tracker
func NewSessionMemoryTracker(maxAllowed int64) *SessionMemoryTracker {
	return &SessionMemoryTracker{
		maxAllowed: maxAllowed,
	}
}

// Allocate records memory allocation and updates peak if necessary
// Returns an error if allocation would exceed the maximum allowed limit
func (t *SessionMemoryTracker) Allocate(bytes int64) error {
	if bytes < 0 {
		return fmt.Errorf("cannot allocate negative bytes: %d", bytes)
	}

	current := t.allocatedBytes.Add(bytes)

	// Check if we exceeded the limit
	if t.maxAllowed > 0 && current > t.maxAllowed {
		// Roll back the allocation
		t.allocatedBytes.Add(-bytes)
		return fmt.Errorf("memory limit exceeded: would use %d bytes (limit: %d bytes)",
			current, t.maxAllowed)
	}

	// Update peak if needed (lock-free algorithm)
	for {
		peak := t.peakBytes.Load()
		if current <= peak {
			break
		}
		// Try to update peak; if someone else updated it, loop and check again
		if t.peakBytes.CompareAndSwap(peak, current) {
			break
		}
	}

	return nil
}

// Free records memory deallocation
func (t *SessionMemoryTracker) Free(bytes int64) {
	if bytes < 0 {
		return // Ignore negative frees
	}

	t.allocatedBytes.Add(-bytes)

	// Ensure we don't go negative (defensive programming)
	for {
		current := t.allocatedBytes.Load()
		if current >= 0 {
			break
		}
		// If negative, reset to 0
		if t.allocatedBytes.CompareAndSwap(current, 0) {
			break
		}
	}
}

// Current returns the currently allocated bytes
func (t *SessionMemoryTracker) Current() int64 {
	return t.allocatedBytes.Load()
}

// Peak returns the peak allocated bytes during the session
func (t *SessionMemoryTracker) Peak() int64 {
	return t.peakBytes.Load()
}

// MaxAllowed returns the maximum allowed bytes
func (t *SessionMemoryTracker) MaxAllowed() int64 {
	return t.maxAllowed
}

// Reset resets the tracker (useful for testing or session reuse)
func (t *SessionMemoryTracker) Reset() {
	t.allocatedBytes.Store(0)
	t.peakBytes.Store(0)
}

// Stats returns a snapshot of current tracking statistics
func (t *SessionMemoryTracker) Stats() SessionMemoryStats {
	return SessionMemoryStats{
		Current:    t.Current(),
		Peak:       t.Peak(),
		MaxAllowed: t.maxAllowed,
	}
}

// SessionMemoryStats holds memory statistics for a session
type SessionMemoryStats struct {
	Current    int64 // Currently allocated bytes
	Peak       int64 // Peak allocated bytes
	MaxAllowed int64 // Maximum allowed bytes (0 = unlimited)
}

// FormatBytes formats bytes in a human-readable format
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
