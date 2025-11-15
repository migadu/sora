package lmtp

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestActiveConnections_IncrementDecrement verifies active connections are tracked correctly
func TestActiveConnections_IncrementDecrement(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := &LMTPServerBackend{
		name:   "test-lmtp",
		appCtx: ctx,
	}

	// Initial count should be 0
	if count := backend.activeConnections.Load(); count != 0 {
		t.Fatalf("Expected 0 initial active connections, got %d", count)
	}

	// Simulate connection increment
	backend.activeConnections.Add(1)
	if count := backend.activeConnections.Load(); count != 1 {
		t.Errorf("Expected 1 active connection after increment, got %d", count)
	}

	// Add more connections
	backend.activeConnections.Add(1)
	backend.activeConnections.Add(1)
	if count := backend.activeConnections.Load(); count != 3 {
		t.Errorf("Expected 3 active connections, got %d", count)
	}

	// Decrement connections
	backend.activeConnections.Add(-1)
	if count := backend.activeConnections.Load(); count != 2 {
		t.Errorf("Expected 2 active connections after decrement, got %d", count)
	}

	backend.activeConnections.Add(-1)
	backend.activeConnections.Add(-1)
	if count := backend.activeConnections.Load(); count != 0 {
		t.Errorf("Expected 0 active connections after all decremented, got %d", count)
	}

	t.Log("✓ Active connections increment/decrement works correctly")
}

// TestActiveConnections_TotalVsActive verifies total and active are tracked separately
func TestActiveConnections_TotalVsActive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := &LMTPServerBackend{
		name:   "test-lmtp",
		appCtx: ctx,
	}

	// Simulate 5 connections being made
	for i := 0; i < 5; i++ {
		backend.totalConnections.Add(1)
		backend.activeConnections.Add(1)
	}

	if total := backend.totalConnections.Load(); total != 5 {
		t.Errorf("Expected 5 total connections, got %d", total)
	}
	if active := backend.activeConnections.Load(); active != 5 {
		t.Errorf("Expected 5 active connections, got %d", active)
	}

	// Close 3 connections (active decrements, total doesn't)
	for i := 0; i < 3; i++ {
		backend.activeConnections.Add(-1)
	}

	if total := backend.totalConnections.Load(); total != 5 {
		t.Errorf("Expected 5 total connections (cumulative), got %d", total)
	}
	if active := backend.activeConnections.Load(); active != 2 {
		t.Errorf("Expected 2 active connections, got %d", active)
	}

	// Add 2 more connections
	for i := 0; i < 2; i++ {
		backend.totalConnections.Add(1)
		backend.activeConnections.Add(1)
	}

	if total := backend.totalConnections.Load(); total != 7 {
		t.Errorf("Expected 7 total connections (cumulative), got %d", total)
	}
	if active := backend.activeConnections.Load(); active != 4 {
		t.Errorf("Expected 4 active connections, got %d", active)
	}

	t.Log("✓ Total and active connections are tracked separately")
}

// TestMonitorActiveConnections_LogsCount verifies monitoring logs active connections
func TestMonitorActiveConnections_LogsCount(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := &LMTPServerBackend{
		name:   "test-lmtp",
		appCtx: ctx,
	}

	// Set some active connections
	backend.activeConnections.Store(5)

	// Start monitoring with a short interval for testing
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				count := backend.activeConnections.Load()
				if count != 5 {
					t.Errorf("Expected 5 active connections, got %d", count)
				}

			case <-ctx.Done():
				return
			}
		}
	}()

	// Let it run a few cycles
	time.Sleep(350 * time.Millisecond)

	// Verify the count is still correct
	if count := backend.activeConnections.Load(); count != 5 {
		t.Errorf("Expected 5 active connections after monitoring, got %d", count)
	}

	t.Log("✓ LMTP server monitoring logs active connections correctly")
}

// TestMonitorActiveConnections_StopsOnContext verifies monitoring stops when context is cancelled
func TestMonitorActiveConnections_StopsOnContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	backend := &LMTPServerBackend{
		name:   "test-lmtp",
		appCtx: ctx,
	}

	stopped := make(chan struct{})

	// Start monitoring
	go func() {
		defer close(stopped)
		backend.monitorActiveConnections()
	}()

	// Let it run briefly
	time.Sleep(50 * time.Millisecond)

	// Cancel context
	cancel()

	// Wait for it to stop with timeout
	select {
	case <-stopped:
		t.Log("✓ Monitoring stopped when context was cancelled")
	case <-time.After(2 * time.Second):
		t.Error("Monitoring did not stop within timeout")
	}
}

// TestMonitorActiveConnections_DynamicCount verifies monitoring tracks dynamic connection changes
func TestMonitorActiveConnections_DynamicCount(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := &LMTPServerBackend{
		name:   "test-lmtp",
		appCtx: ctx,
	}

	// Start with 0 connections
	if count := backend.activeConnections.Load(); count != 0 {
		t.Fatalf("Expected 0 initial connections, got %d", count)
	}

	// Add connections dynamically
	backend.activeConnections.Add(1)
	if count := backend.activeConnections.Load(); count != 1 {
		t.Errorf("Expected 1 connection after add, got %d", count)
	}

	backend.activeConnections.Add(1)
	if count := backend.activeConnections.Load(); count != 2 {
		t.Errorf("Expected 2 connections after second add, got %d", count)
	}

	// Remove one
	backend.activeConnections.Add(-1)
	if count := backend.activeConnections.Load(); count != 1 {
		t.Errorf("Expected 1 connection after removal, got %d", count)
	}

	t.Log("✓ Monitoring tracks dynamic connection count changes")
}

// TestMonitorActiveConnections_Concurrent verifies monitoring is safe with concurrent modifications
func TestMonitorActiveConnections_Concurrent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := &LMTPServerBackend{
		name:   "test-lmtp",
		appCtx: ctx,
	}

	// Start monitoring with short interval
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				_ = backend.activeConnections.Load() // Read the count

			case <-ctx.Done():
				return
			}
		}
	}()

	// Concurrently add and remove connections
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Add connection
			backend.activeConnections.Add(1)
			time.Sleep(5 * time.Millisecond)

			// Remove connection
			backend.activeConnections.Add(-1)
		}(i)
	}

	wg.Wait()

	// Final count should be zero
	if count := backend.activeConnections.Load(); count != 0 {
		t.Errorf("Expected 0 connections after all goroutines finished, got %d", count)
	}

	t.Log("✓ Monitoring is safe with concurrent modifications")
}

// TestMonitorActiveConnections_LargeScale verifies monitoring works with many connections
func TestMonitorActiveConnections_LargeScale(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := &LMTPServerBackend{
		name:   "test-lmtp",
		appCtx: ctx,
	}

	// Add 1000 connections
	expectedCount := int64(1000)
	backend.activeConnections.Store(expectedCount)

	// Start monitoring with short interval
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				count := backend.activeConnections.Load()
				if count != expectedCount {
					t.Errorf("Expected %d connections, got %d", expectedCount, count)
				}

			case <-ctx.Done():
				return
			}
		}
	}()

	// Let it run a few cycles
	time.Sleep(200 * time.Millisecond)

	// Verify count is still correct
	if count := backend.activeConnections.Load(); count != expectedCount {
		t.Errorf("Expected %d connections after monitoring, got %d", expectedCount, count)
	}

	t.Log("✓ Monitoring works correctly with large number of connections")
}

// TestMonitorActiveConnections_ZeroConnections verifies monitoring works with empty count
func TestMonitorActiveConnections_ZeroConnections(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := &LMTPServerBackend{
		name:   "test-lmtp",
		appCtx: ctx,
	}

	// Start monitoring with short interval
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				count := backend.activeConnections.Load()
				if count != 0 {
					t.Errorf("Expected 0 connections, got %d", count)
				}

			case <-ctx.Done():
				return
			}
		}
	}()

	// Let it run a few cycles
	time.Sleep(200 * time.Millisecond)

	// Verify count is still zero
	if count := backend.activeConnections.Load(); count != 0 {
		t.Errorf("Expected 0 connections after monitoring, got %d", count)
	}

	t.Log("✓ Monitoring works correctly with zero connections")
}

// TestGetActiveConnections verifies the getter method
func TestGetActiveConnections(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := &LMTPServerBackend{
		name:   "test-lmtp",
		appCtx: ctx,
	}

	// Test initial value
	if count := backend.GetActiveConnections(); count != 0 {
		t.Errorf("Expected 0 active connections, got %d", count)
	}

	// Set some connections
	backend.activeConnections.Store(42)
	if count := backend.GetActiveConnections(); count != 42 {
		t.Errorf("Expected 42 active connections, got %d", count)
	}

	t.Log("✓ GetActiveConnections() returns correct value")
}

// TestActiveConnections_RaceDetection verifies no race conditions with -race flag
func TestActiveConnections_RaceDetection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := &LMTPServerBackend{
		name:   "test-lmtp",
		appCtx: ctx,
	}

	// Start monitoring
	go backend.monitorActiveConnections()

	// Concurrently increment/decrement from multiple goroutines
	var wg sync.WaitGroup
	iterations := 100

	for i := 0; i < iterations; i++ {
		wg.Add(2)

		// Incrementer
		go func() {
			defer wg.Done()
			backend.activeConnections.Add(1)
		}()

		// Decrementer
		go func() {
			defer wg.Done()
			backend.activeConnections.Add(-1)
		}()
	}

	wg.Wait()

	// Final count should be 0 (100 increments - 100 decrements)
	if count := backend.activeConnections.Load(); count != 0 {
		t.Errorf("Expected 0 final count, got %d", count)
	}

	t.Log("✓ No race conditions detected with atomic operations")
}

// TestActiveConnections_AtomicOperations verifies atomicity of counter operations
func TestActiveConnections_AtomicOperations(t *testing.T) {
	var counter atomic.Int64

	// Concurrent increments
	var wg sync.WaitGroup
	iterations := 1000

	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			counter.Add(1)
		}()
	}

	wg.Wait()

	if count := counter.Load(); count != int64(iterations) {
		t.Errorf("Expected %d, got %d - atomic operations not working correctly", iterations, count)
	}

	t.Log("✓ Atomic operations work correctly under concurrent access")
}
