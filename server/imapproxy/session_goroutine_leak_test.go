package imapproxy

import (
	"context"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestStartProxy_NoGoroutineLeaks verifies all goroutines exit when startProxy completes
func TestStartProxy_NoGoroutineLeaks(t *testing.T) {
	// Get initial goroutine count
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	initialGoroutines := runtime.NumGoroutine()

	// Create mock connections
	clientConn, backendConn := net.Pipe()
	defer clientConn.Close()
	defer backendConn.Close()

	// Create session context that will be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create mock server
	server := &Server{
		name: "test-imap-proxy",
		ctx:  ctx,
	}

	// Create session
	session := &Session{
		server:      server,
		clientConn:  clientConn,
		backendConn: backendConn,
		ctx:         ctx,
		cancel:      cancel,
		username:    "test@example.com",
		startTime:   time.Now(),
	}

	// Run startProxy in a goroutine
	done := make(chan struct{})
	go func() {
		defer close(done)
		session.startProxy()
	}()

	// Let it run briefly
	time.Sleep(50 * time.Millisecond)

	// Cancel context to trigger shutdown
	cancel()

	// Close connections to unblock copy operations
	clientConn.Close()
	backendConn.Close()

	// Wait for startProxy to complete
	select {
	case <-done:
		t.Log("✓ startProxy completed")
	case <-time.After(2 * time.Second):
		t.Fatal("startProxy did not complete within timeout")
	}

	// Give goroutines time to clean up
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	// Check for goroutine leaks
	finalGoroutines := runtime.NumGoroutine()
	leaked := finalGoroutines - initialGoroutines

	if leaked > 2 { // Allow small variance (test goroutine + parent)
		t.Errorf("Goroutine leak detected: initial=%d, final=%d, leaked=%d",
			initialGoroutines, finalGoroutines, leaked)

		// Print stack traces for debugging
		buf := make([]byte, 1<<20)
		stackSize := runtime.Stack(buf, true)
		t.Logf("Goroutine stack traces:\n%s", buf[:stackSize])
	} else {
		t.Log("✓ No goroutine leaks detected")
	}
}

// TestStartProxy_ContextCancellationGoroutineExits verifies the context cancellation goroutine exits
func TestStartProxy_ContextCancellationGoroutineExits(t *testing.T) {
	// Create mock connections
	clientConn, backendConn := net.Pipe()

	// Create session context
	ctx, cancel := context.WithCancel(context.Background())

	// Track if context cancellation goroutine ran
	var cancellationGoroutineRan sync.WaitGroup
	cancellationGoroutineRan.Add(1)

	// Simulate the context cancellation goroutine
	go func() {
		<-ctx.Done()
		clientConn.Close()
		backendConn.Close()
		cancellationGoroutineRan.Done()
	}()

	// Cancel context
	cancel()

	// Wait for goroutine to complete
	done := make(chan struct{})
	go func() {
		cancellationGoroutineRan.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.Log("✓ Context cancellation goroutine exited")
	case <-time.After(1 * time.Second):
		t.Error("Context cancellation goroutine did not exit within timeout")
	}
}

// TestStartProxy_CopyGoroutinesUnblockOnContextCancel verifies copy goroutines unblock when context is cancelled
func TestStartProxy_CopyGoroutinesUnblockOnContextCancel(t *testing.T) {
	// Create pipe connections
	clientConn, backendConn := net.Pipe()
	defer clientConn.Close()
	defer backendConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := &Server{
		name: "test-imap-proxy",
		ctx:  ctx,
	}

	session := &Session{
		server:      server,
		clientConn:  clientConn,
		backendConn: backendConn,
		ctx:         ctx,
		cancel:      cancel,
		username:    "test@example.com",
		startTime:   time.Now(),
	}

	// Start proxy
	proxyDone := make(chan struct{})
	go func() {
		defer close(proxyDone)
		session.startProxy()
	}()

	// Let copy goroutines start and block on Read
	time.Sleep(100 * time.Millisecond)

	// Cancel context - this should trigger connection closure and unblock reads
	cancel()

	// Wait for startProxy to complete
	select {
	case <-proxyDone:
		t.Log("✓ Copy goroutines unblocked when context was cancelled")
	case <-time.After(2 * time.Second):
		t.Error("Copy goroutines did not unblock within timeout")
	}
}

// TestStartProxy_ActivityUpdaterExits verifies activity updater goroutine exits
func TestStartProxy_ActivityUpdaterExits(t *testing.T) {
	clientConn, backendConn := net.Pipe()
	defer clientConn.Close()
	defer backendConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := &Server{
		name: "test-imap-proxy",
		ctx:  ctx,
	}

	session := &Session{
		server:      server,
		clientConn:  clientConn,
		backendConn: backendConn,
		ctx:         ctx,
		cancel:      cancel,
		username:    "test@example.com",
		startTime:   time.Now(),
	}

	// Track goroutine count before starting proxy
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	beforeCount := runtime.NumGoroutine()

	// Start proxy
	proxyDone := make(chan struct{})
	go func() {
		defer close(proxyDone)
		session.startProxy()
	}()

	// Let it run briefly
	time.Sleep(100 * time.Millisecond)

	// Cancel context
	cancel()

	// Wait for completion
	select {
	case <-proxyDone:
		t.Log("✓ startProxy completed")
	case <-time.After(2 * time.Second):
		t.Fatal("startProxy did not complete within timeout")
	}

	// Give goroutines time to clean up
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	afterCount := runtime.NumGoroutine()
	if afterCount > beforeCount+1 { // +1 for the test goroutine itself
		t.Errorf("Activity updater may not have exited: before=%d, after=%d",
			beforeCount, afterCount)
	} else {
		t.Log("✓ Activity updater goroutine exited")
	}
}

// TestStartProxy_ConcurrentShutdown tests shutdown under concurrent connection activity
func TestStartProxy_ConcurrentShutdown(t *testing.T) {
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	initialGoroutines := runtime.NumGoroutine()

	// Run multiple proxy sessions concurrently
	iterations := 10
	var wg sync.WaitGroup

	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			clientConn, backendConn := net.Pipe()
			ctx, cancel := context.WithCancel(context.Background())

			server := &Server{
				name: "test-imap-proxy",
				ctx:  ctx,
			}

			session := &Session{
				server:      server,
				clientConn:  clientConn,
				backendConn: backendConn,
				ctx:         ctx,
				cancel:      cancel,
				username:    "test@example.com",
				startTime:   time.Now(),
			}

			// Start proxy
			proxyDone := make(chan struct{})
			go func() {
				defer close(proxyDone)
				session.startProxy()
			}()

			// Write some data to keep copies busy
			go func() {
				clientConn.Write([]byte("test data"))
			}()
			go func() {
				io.Copy(io.Discard, backendConn)
			}()

			// Let it run briefly
			time.Sleep(20 * time.Millisecond)

			// Shutdown
			cancel()
			clientConn.Close()
			backendConn.Close()

			// Wait for completion
			select {
			case <-proxyDone:
				// Success
			case <-time.After(1 * time.Second):
				t.Errorf("Session %d: startProxy did not complete within timeout", id)
			}
		}(i)
	}

	wg.Wait()

	// Check for leaks
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	finalGoroutines := runtime.NumGoroutine()
	leaked := finalGoroutines - initialGoroutines

	if leaked > 2 {
		t.Errorf("Goroutine leak in concurrent shutdown: initial=%d, final=%d, leaked=%d",
			initialGoroutines, finalGoroutines, leaked)
	} else {
		t.Log("✓ No goroutine leaks in concurrent shutdown")
	}
}

// TestStartProxy_ReadBlockedDuringShutdown verifies goroutines exit even when Read is blocked
func TestStartProxy_ReadBlockedDuringShutdown(t *testing.T) {
	clientConn, backendConn := net.Pipe()

	ctx, cancel := context.WithCancel(context.Background())

	server := &Server{
		name: "test-imap-proxy",
		ctx:  ctx,
	}

	session := &Session{
		server:      server,
		clientConn:  clientConn,
		backendConn: backendConn,
		ctx:         ctx,
		cancel:      cancel,
		username:    "test@example.com",
		startTime:   time.Now(),
	}

	// Start proxy - goroutines will block on Read since no data is being sent
	proxyDone := make(chan struct{})
	go func() {
		defer close(proxyDone)
		session.startProxy()
	}()

	// Let goroutines start and block on Read
	time.Sleep(100 * time.Millisecond)

	// Cancel context - this MUST unblock the reads by closing connections
	cancel()

	// Wait for startProxy to complete
	select {
	case <-proxyDone:
		t.Log("✓ Blocked reads were unblocked by context cancellation")
	case <-time.After(2 * time.Second):
		t.Error("Blocked reads were NOT unblocked - goroutine leak!")

		// Print stack traces for debugging
		buf := make([]byte, 1<<20)
		stackSize := runtime.Stack(buf, true)
		t.Logf("Goroutine stack traces:\n%s", buf[:stackSize])
	}
}
