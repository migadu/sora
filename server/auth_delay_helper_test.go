package server

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// MockAuthDelayHelper for testing
type MockAuthDelayHelper struct {
	delay time.Duration
}

func (m *MockAuthDelayHelper) GetAuthenticationDelay(remoteAddr net.Addr) time.Duration {
	return m.delay
}

func TestDelayManager_BasicAcquireRelease(t *testing.T) {
	dm := NewDelayManager(3) // Max 3 concurrent delays per IP

	// Should acquire 3 slots successfully
	if !dm.tryAcquire("1.2.3.4") {
		t.Fatal("Should acquire first slot")
	}
	if !dm.tryAcquire("1.2.3.4") {
		t.Fatal("Should acquire second slot")
	}
	if !dm.tryAcquire("1.2.3.4") {
		t.Fatal("Should acquire third slot")
	}

	// Fourth slot should fail (queue full)
	if dm.tryAcquire("1.2.3.4") {
		t.Fatal("Should NOT acquire fourth slot (queue full)")
	}

	// Release one slot
	dm.release("1.2.3.4")

	// Should now acquire one more slot
	if !dm.tryAcquire("1.2.3.4") {
		t.Fatal("Should acquire slot after release")
	}

	// Clean up
	dm.release("1.2.3.4")
	dm.release("1.2.3.4")
	dm.release("1.2.3.4")
}

func TestDelayManager_PerIPIsolation(t *testing.T) {
	dm := NewDelayManager(2) // Max 2 concurrent delays per IP

	// IP1 acquires 2 slots (full)
	if !dm.tryAcquire("1.2.3.4") {
		t.Fatal("IP1 should acquire first slot")
	}
	if !dm.tryAcquire("1.2.3.4") {
		t.Fatal("IP1 should acquire second slot")
	}
	if dm.tryAcquire("1.2.3.4") {
		t.Fatal("IP1 should NOT acquire third slot (full)")
	}

	// IP2 should still acquire slots (independent queue)
	if !dm.tryAcquire("5.6.7.8") {
		t.Fatal("IP2 should acquire first slot")
	}
	if !dm.tryAcquire("5.6.7.8") {
		t.Fatal("IP2 should acquire second slot")
	}
	if dm.tryAcquire("5.6.7.8") {
		t.Fatal("IP2 should NOT acquire third slot (full)")
	}

	// Clean up
	dm.release("1.2.3.4")
	dm.release("1.2.3.4")
	dm.release("5.6.7.8")
	dm.release("5.6.7.8")
}

func TestDelayManager_CleanupEmptySemaphores(t *testing.T) {
	dm := NewDelayManager(2)

	// Acquire and release
	dm.tryAcquire("1.2.3.4")
	dm.release("1.2.3.4")

	// Semaphore should be removed from map after release (cleanup)
	dm.mu.Lock()
	_, exists := dm.ipCounts["1.2.3.4"]
	dm.mu.Unlock()

	if exists {
		t.Fatal("Semaphore should be removed after release (cleanup)")
	}
}

func TestApplyAuthenticationDelay_NoLimiter(t *testing.T) {
	ctx := context.Background()
	addr := &StringAddr{Addr: "1.2.3.4:1234"}

	// No limiter provided
	err := ApplyAuthenticationDelay(ctx, nil, addr, "imap")
	if err != nil {
		t.Fatalf("Should not return error with nil limiter: %v", err)
	}
}

func TestApplyAuthenticationDelay_NoDelay(t *testing.T) {
	ctx := context.Background()
	addr := &StringAddr{Addr: "1.2.3.4:1234"}
	limiter := &MockAuthDelayHelper{delay: 0}

	// Zero delay - should return immediately
	err := ApplyAuthenticationDelay(ctx, limiter, addr, "imap")
	if err != nil {
		t.Fatalf("Should not return error with zero delay: %v", err)
	}
}

func TestApplyAuthenticationDelay_DelayCompletes(t *testing.T) {
	ctx := context.Background()
	addr := &StringAddr{Addr: "1.2.3.4:1234"}
	limiter := &MockAuthDelayHelper{delay: 50 * time.Millisecond}

	start := time.Now()
	err := ApplyAuthenticationDelay(ctx, limiter, addr, "imap")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Should not return error: %v", err)
	}
	if elapsed < 50*time.Millisecond {
		t.Fatalf("Should wait at least 50ms, got %v", elapsed)
	}
}

func TestApplyAuthenticationDelay_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	addr := &StringAddr{Addr: "1.2.3.4:1234"}
	limiter := &MockAuthDelayHelper{delay: 5 * time.Second}

	// Cancel context after 10ms
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := ApplyAuthenticationDelay(ctx, limiter, addr, "imap")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Should return error when context cancelled")
	}
	if err != context.Canceled {
		t.Fatalf("Should return context.Canceled, got %v", err)
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("Should cancel quickly, got %v", elapsed)
	}
}

func TestApplyAuthenticationDelay_QueueFull(t *testing.T) {
	// Use a fresh delay manager for this test
	dm := NewDelayManager(2) // Max 2 concurrent delays per IP

	ctx := context.Background()
	addr := &StringAddr{Addr: "10.20.30.40:1234"}
	limiter := &MockAuthDelayHelper{delay: 1 * time.Second}

	var wg sync.WaitGroup
	var successCount, rejectCount atomic.Int32
	startBarrier := make(chan struct{})

	// Start 10 concurrent delays for same IP
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startBarrier // Wait for all goroutines to be ready
			err := applyAuthenticationDelayWithManager(ctx, limiter, addr, "imap", dm)
			if err == ErrDelayQueueFull {
				rejectCount.Add(1)
			} else if err == nil {
				successCount.Add(1)
			}
		}()
	}

	// Release all goroutines at once
	close(startBarrier)

	// Wait for all to complete
	wg.Wait()

	// Should have exactly 2 successes and 8 rejections
	if successCount.Load() != 2 {
		t.Fatalf("Expected 2 successes, got %d", successCount.Load())
	}
	if rejectCount.Load() != 8 {
		t.Fatalf("Expected 8 rejections, got %d", rejectCount.Load())
	}
}

func TestApplyAuthenticationDelay_MultipleIPs(t *testing.T) {
	// Use a fresh delay manager for this test
	dm := NewDelayManager(2) // Max 2 concurrent delays per IP

	ctx := context.Background()
	limiter := &MockAuthDelayHelper{delay: 500 * time.Millisecond}

	var wg sync.WaitGroup
	var totalRejections atomic.Int32
	startBarrier := make(chan struct{})

	// Start 5 concurrent delays for each of 3 different IPs (15 total)
	for ipIdx := 1; ipIdx <= 3; ipIdx++ {
		for i := 0; i < 5; i++ {
			wg.Add(1)
			addr := &StringAddr{Addr: net.JoinHostPort("20.30.40."+string(rune('0'+ipIdx)), "1234")}
			go func() {
				defer wg.Done()
				<-startBarrier // Wait for all goroutines to be ready
				err := applyAuthenticationDelayWithManager(ctx, limiter, addr, "imap", dm)
				if err == ErrDelayQueueFull {
					totalRejections.Add(1)
				}
			}()
		}
	}

	// Release all goroutines at once
	close(startBarrier)

	// Wait for all to complete
	wg.Wait()

	// Each IP should have 2 successes and 3 rejections (15 total = 6 successes + 9 rejections)
	if totalRejections.Load() != 9 {
		t.Fatalf("Expected 9 total rejections (3 per IP), got %d", totalRejections.Load())
	}
}

func TestDelayManager_ConcurrentCleanup(t *testing.T) {
	dm := NewDelayManager(3)

	var wg sync.WaitGroup
	// Test concurrent acquire/release with cleanup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip := "1.2.3.4"
			if dm.tryAcquire(ip) {
				time.Sleep(1 * time.Millisecond)
				dm.release(ip)
			}
		}()
	}

	wg.Wait()

	// All semaphores should be cleaned up
	dm.mu.Lock()
	mapSize := len(dm.ipCounts)
	dm.mu.Unlock()

	if mapSize > 0 {
		t.Fatalf("Expected empty map after cleanup, got %d entries", mapSize)
	}
}
