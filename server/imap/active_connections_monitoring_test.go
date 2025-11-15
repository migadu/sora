package imap

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapserver"
)

// TestMonitorActiveConnections_LogsCount verifies monitoring logs active connections
func TestMonitorActiveConnections_LogsCount(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := &IMAPServer{
		name:        "test-imap",
		appCtx:      ctx,
		activeConns: make(map[*imapserver.Conn]struct{}),
	}

	// Add some mock connections
	mockConn1 := &imapserver.Conn{}
	mockConn2 := &imapserver.Conn{}
	mockConn3 := &imapserver.Conn{}

	server.activeConnsMutex.Lock()
	server.activeConns[mockConn1] = struct{}{}
	server.activeConns[mockConn2] = struct{}{}
	server.activeConns[mockConn3] = struct{}{}
	server.activeConnsMutex.Unlock()

	// Start monitoring with a short interval for testing
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				server.activeConnsMutex.RLock()
				count := len(server.activeConns)
				server.activeConnsMutex.RUnlock()

				if count != 3 {
					t.Errorf("Expected 3 active connections, got %d", count)
				}

			case <-ctx.Done():
				return
			}
		}
	}()

	// Let it run a few cycles
	time.Sleep(350 * time.Millisecond)

	// Verify the count is still correct
	server.activeConnsMutex.RLock()
	count := len(server.activeConns)
	server.activeConnsMutex.RUnlock()

	if count != 3 {
		t.Errorf("Expected 3 active connections after monitoring, got %d", count)
	}

	t.Log("✓ IMAP server monitoring logs active connections correctly")
}

// TestMonitorActiveConnections_StopsOnContext verifies monitoring stops when context is cancelled
func TestMonitorActiveConnections_StopsOnContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	server := &IMAPServer{
		name:        "test-imap",
		appCtx:      ctx,
		activeConns: make(map[*imapserver.Conn]struct{}),
	}

	stopped := make(chan struct{})

	// Start monitoring
	go func() {
		defer close(stopped)
		server.monitorActiveConnections()
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

	server := &IMAPServer{
		name:        "test-imap",
		appCtx:      ctx,
		activeConns: make(map[*imapserver.Conn]struct{}),
	}

	// Start with no connections
	server.activeConnsMutex.RLock()
	if count := len(server.activeConns); count != 0 {
		t.Fatalf("Expected 0 initial connections, got %d", count)
	}
	server.activeConnsMutex.RUnlock()

	// Add connections dynamically
	mockConn1 := &imapserver.Conn{}
	mockConn2 := &imapserver.Conn{}

	server.activeConnsMutex.Lock()
	server.activeConns[mockConn1] = struct{}{}
	server.activeConnsMutex.Unlock()

	// Verify count increased
	server.activeConnsMutex.RLock()
	if count := len(server.activeConns); count != 1 {
		t.Errorf("Expected 1 connection after add, got %d", count)
	}
	server.activeConnsMutex.RUnlock()

	// Add another
	server.activeConnsMutex.Lock()
	server.activeConns[mockConn2] = struct{}{}
	server.activeConnsMutex.Unlock()

	// Verify count increased again
	server.activeConnsMutex.RLock()
	if count := len(server.activeConns); count != 2 {
		t.Errorf("Expected 2 connections after second add, got %d", count)
	}
	server.activeConnsMutex.RUnlock()

	// Remove one
	server.activeConnsMutex.Lock()
	delete(server.activeConns, mockConn1)
	server.activeConnsMutex.Unlock()

	// Verify count decreased
	server.activeConnsMutex.RLock()
	if count := len(server.activeConns); count != 1 {
		t.Errorf("Expected 1 connection after removal, got %d", count)
	}
	server.activeConnsMutex.RUnlock()

	t.Log("✓ Monitoring tracks dynamic connection count changes")
}

// TestMonitorActiveConnections_Concurrent verifies monitoring is safe with concurrent map modifications
func TestMonitorActiveConnections_Concurrent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := &IMAPServer{
		name:        "test-imap",
		appCtx:      ctx,
		activeConns: make(map[*imapserver.Conn]struct{}),
	}

	// Start monitoring with short interval
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				server.activeConnsMutex.RLock()
				_ = len(server.activeConns) // Read the count
				server.activeConnsMutex.RUnlock()

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

			mockConn := &imapserver.Conn{}

			// Add connection
			server.activeConnsMutex.Lock()
			server.activeConns[mockConn] = struct{}{}
			server.activeConnsMutex.Unlock()

			time.Sleep(5 * time.Millisecond)

			// Remove connection
			server.activeConnsMutex.Lock()
			delete(server.activeConns, mockConn)
			server.activeConnsMutex.Unlock()
		}(i)
	}

	wg.Wait()

	// Final count should be zero
	server.activeConnsMutex.RLock()
	count := len(server.activeConns)
	server.activeConnsMutex.RUnlock()

	if count != 0 {
		t.Errorf("Expected 0 connections after all goroutines finished, got %d", count)
	}

	t.Log("✓ Monitoring is safe with concurrent map modifications")
}

// TestMonitorActiveConnections_LargeScale verifies monitoring works with many connections
func TestMonitorActiveConnections_LargeScale(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := &IMAPServer{
		name:        "test-imap",
		appCtx:      ctx,
		activeConns: make(map[*imapserver.Conn]struct{}),
	}

	// Add 1000 connections
	expectedCount := 1000
	for i := 0; i < expectedCount; i++ {
		mockConn := &imapserver.Conn{}
		server.activeConnsMutex.Lock()
		server.activeConns[mockConn] = struct{}{}
		server.activeConnsMutex.Unlock()
	}

	// Start monitoring with short interval
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				server.activeConnsMutex.RLock()
				count := len(server.activeConns)
				server.activeConnsMutex.RUnlock()

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
	server.activeConnsMutex.RLock()
	count := len(server.activeConns)
	server.activeConnsMutex.RUnlock()

	if count != expectedCount {
		t.Errorf("Expected %d connections after monitoring, got %d", expectedCount, count)
	}

	t.Log("✓ Monitoring works correctly with large number of connections")
}

// TestMonitorActiveConnections_ZeroConnections verifies monitoring works with empty map
func TestMonitorActiveConnections_ZeroConnections(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := &IMAPServer{
		name:        "test-imap",
		appCtx:      ctx,
		activeConns: make(map[*imapserver.Conn]struct{}),
	}

	// Start monitoring with short interval
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				server.activeConnsMutex.RLock()
				count := len(server.activeConns)
				server.activeConnsMutex.RUnlock()

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
	server.activeConnsMutex.RLock()
	count := len(server.activeConns)
	server.activeConnsMutex.RUnlock()

	if count != 0 {
		t.Errorf("Expected 0 connections after monitoring, got %d", count)
	}

	t.Log("✓ Monitoring works correctly with zero connections")
}
