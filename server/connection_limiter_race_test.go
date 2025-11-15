package server

import (
	"net"
	"sync"
	"testing"
	"time"
)

// TestConnectionLimiterDoubleDecrementRace tests that the cleanup function
// can safely be called multiple times without double-decrementing the counter.
// This simulates the scenario where both session.close() and panic recovery
// might try to call releaseConn().
func TestConnectionLimiterDoubleDecrementRace(t *testing.T) {
	limiter := NewConnectionLimiter("TEST", 100, 10)

	// Create a fake remote address
	addr := &net.TCPAddr{
		IP:   net.ParseIP("192.0.2.1"),
		Port: 12345,
	}

	// Accept a connection
	cleanup, err := limiter.AcceptWithRealIP(addr, "")
	if err != nil {
		t.Fatalf("AcceptWithRealIP failed: %v", err)
	}

	// Verify counter incremented
	if limiter.currentTotal.Load() != 1 {
		t.Errorf("Expected total=1, got %d", limiter.currentTotal.Load())
	}

	// Simulate race: multiple goroutines try to call cleanup concurrently
	// This can happen if:
	// 1. session.close() calls cleanup (normal path)
	// 2. panic recovery calls cleanup (error path)
	// 3. Both check "if releaseConn != nil" before either sets it to nil
	var wg sync.WaitGroup
	const goroutines = 10

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cleanup() // All goroutines call cleanup
		}()
	}

	// Wait for all calls to complete
	wg.Wait()

	// Counter should be 0 (decremented exactly once), not negative
	total := limiter.currentTotal.Load()
	if total != 0 {
		t.Errorf("Double-decrement detected! Expected total=0, got %d", total)
	}

	// Also verify per-IP counter
	stats := limiter.GetStats()
	if len(stats.IPConnections) != 0 {
		t.Errorf("IP should be cleaned up, but found: %+v", stats.IPConnections)
	}
}

// TestConnectionLimiterConcurrentAcceptRelease tests that concurrent
// accept and release operations maintain correct counts.
func TestConnectionLimiterConcurrentAcceptRelease(t *testing.T) {
	limiter := NewConnectionLimiter("TEST", 1000, 100)

	const connections = 100
	var wg sync.WaitGroup

	// Accept many connections concurrently
	cleanups := make([]func(), connections)
	for i := 0; i < connections; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			addr := &net.TCPAddr{
				IP:   net.ParseIP("192.0.2.1"),
				Port: 10000 + idx,
			}
			cleanup, err := limiter.AcceptWithRealIP(addr, "")
			if err != nil {
				t.Errorf("AcceptWithRealIP failed: %v", err)
				return
			}
			cleanups[idx] = cleanup
		}(i)
	}
	wg.Wait()

	// Verify all connections were counted
	if limiter.currentTotal.Load() != int64(connections) {
		t.Errorf("Expected total=%d, got %d", connections, limiter.currentTotal.Load())
	}

	// Release all connections concurrently
	for i := 0; i < connections; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if cleanups[idx] != nil {
				cleanups[idx]()
			}
		}(i)
	}
	wg.Wait()

	// All connections should be released
	if limiter.currentTotal.Load() != 0 {
		t.Errorf("Expected total=0 after release, got %d", limiter.currentTotal.Load())
	}
}

// TestConnectionLimiterPanicRecovery tests that cleanup happens correctly
// even if session.close() is never called (simulating early panic).
func TestConnectionLimiterPanicRecovery(t *testing.T) {
	limiter := NewConnectionLimiter("TEST", 100, 10)

	addr := &net.TCPAddr{
		IP:   net.ParseIP("192.0.2.1"),
		Port: 12345,
	}

	// Accept a connection
	cleanup, err := limiter.AcceptWithRealIP(addr, "")
	if err != nil {
		t.Fatalf("AcceptWithRealIP failed: %v", err)
	}

	// Verify counter incremented
	if limiter.currentTotal.Load() != 1 {
		t.Errorf("Expected total=1, got %d", limiter.currentTotal.Load())
	}

	// Simulate panic recovery calling cleanup
	func() {
		defer func() {
			if r := recover(); r != nil {
				// Panic recovery calls cleanup
				if cleanup != nil {
					cleanup()
				}
			}
		}()
		panic("simulated panic")
	}()

	// Counter should be decremented to 0
	if limiter.currentTotal.Load() != 0 {
		t.Errorf("Expected total=0 after panic recovery cleanup, got %d", limiter.currentTotal.Load())
	}

	// Calling cleanup again should be safe (no double-decrement)
	cleanup()
	if limiter.currentTotal.Load() != 0 {
		t.Errorf("Double-decrement after second cleanup! Expected total=0, got %d", limiter.currentTotal.Load())
	}
}

// TestConnectionLimiterRapidAcceptRelease tests rapid accept/release cycles
// to expose any race conditions in counter management.
func TestConnectionLimiterRapidAcceptRelease(t *testing.T) {
	limiter := NewConnectionLimiter("TEST", 1000, 100)

	const iterations = 1000
	const goroutines = 10

	var wg sync.WaitGroup

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(gID int) {
			defer wg.Done()

			for i := 0; i < iterations; i++ {
				addr := &net.TCPAddr{
					IP:   net.ParseIP("192.0.2.1"),
					Port: 10000 + gID*iterations + i,
				}

				cleanup, err := limiter.AcceptWithRealIP(addr, "")
				if err != nil {
					t.Errorf("AcceptWithRealIP failed: %v", err)
					return
				}

				// Immediately release
				cleanup()

				// Small random delay to create timing variations
				if i%100 == 0 {
					time.Sleep(time.Microsecond)
				}
			}
		}(g)
	}

	wg.Wait()

	// All connections should be released
	final := limiter.currentTotal.Load()
	if final != 0 {
		t.Errorf("Expected total=0 after all accept/release cycles, got %d (possible race condition)", final)
	}
}
