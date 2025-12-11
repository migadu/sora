//go:build integration
// +build integration

package lmtpproxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// TestHungBackendConnection simulates a backend that closes TCP connection
// without properly sending data, causing Read() to block indefinitely.
// This reproduces the production issue where 4,093 connections were stuck.
func TestHungBackendConnection(t *testing.T) {
	// Start a backend server that accepts connections but never responds
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	backendAddr := listener.Addr().String()
	t.Logf("Backend listening on %s", backendAddr)

	// Track if goroutine completed
	var goroutineCompleted bool
	var mu sync.Mutex

	// Backend that accepts connection but never sends data or FIN
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		// Keep connection open but don't send anything
		// Simulate a hung backend that neither sends data nor closes properly
		t.Logf("Backend accepted connection from %s", conn.RemoteAddr())

		// Sleep indefinitely to simulate hung connection
		time.Sleep(10 * time.Minute)
		conn.Close()
	}()

	// Simulate the proxy session behavior
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Connect to backend
	clientConn, err := net.Dial("tcp", backendAddr)
	if err != nil {
		t.Fatalf("Failed to connect to backend: %v", err)
	}
	defer clientConn.Close()

	t.Logf("Connected to backend from %s", clientConn.LocalAddr())

	// Create buffered reader (simulating what LMTP proxy does)
	backendReader := bufio.NewReader(clientConn)

	// Simulate copyBufferedReaderToConn WITHOUT connection close on context cancel
	// This reproduces the bug: Read() blocks even after ctx.Done()
	go func() {
		defer func() {
			mu.Lock()
			goroutineCompleted = true
			mu.Unlock()
			t.Logf("Goroutine completed")
		}()

		buf := make([]byte, 32*1024)

		// The bug: ctx.Done() check happens BEFORE Read(), but once Read() blocks,
		// we never get back to check ctx.Done() again.
		// This is exactly what happens in copyBufferedReaderToConn()
		select {
		case <-ctx.Done():
			t.Logf("Context already cancelled before Read()")
			return
		default:
		}

		// This Read() will block indefinitely because:
		// 1. Backend never sends data
		// 2. Backend never sends FIN
		// 3. No context cancellation handler to close the connection
		// 4. No read deadline set
		// 5. No TCP keepalive enabled (or keepalive timeout is hours)
		t.Logf("Calling Read() - this will block forever...")
		nr, err := backendReader.Read(buf)
		t.Logf("Read() returned: nr=%d, err=%v", nr, err)

		if err != nil {
			t.Logf("Read error: %v", err)
			return
		}

		// We never get here because Read() never returns
		t.Logf("Read completed with %d bytes", nr)
	}()

	// Wait for context timeout (2 seconds)
	<-ctx.Done()
	t.Logf("Context timeout reached")

	// Give goroutine a moment to detect cancellation
	time.Sleep(100 * time.Millisecond)

	// Check if goroutine completed
	mu.Lock()
	completed := goroutineCompleted
	mu.Unlock()

	if !completed {
		t.Errorf("REPRODUCTION CONFIRMED: Goroutine is still hung in Read() even after context cancellation")
		t.Errorf("This is the root cause of the 4,093 stuck connections in production")
	} else {
		t.Logf("Goroutine completed successfully")
	}

	// Now test WITH proper context-aware reading
	t.Logf("\n=== Testing with connection close on context cancellation ===")

	// Reconnect
	clientConn2, err := net.Dial("tcp", backendAddr)
	if err != nil {
		t.Fatalf("Failed to reconnect: %v", err)
	}
	defer clientConn2.Close()

	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()

	var goroutine2Completed bool
	var mu2 sync.Mutex

	// Start context cancellation handler (like LMTP proxy has)
	go func() {
		<-ctx2.Done()
		t.Logf("Context cancelled - closing connection to unblock Read()")
		clientConn2.Close()
	}()

	backendReader2 := bufio.NewReader(clientConn2)

	go func() {
		defer func() {
			mu2.Lock()
			goroutine2Completed = true
			mu2.Unlock()
			t.Logf("Goroutine 2 completed")
		}()

		buf := make([]byte, 32*1024)
		for {
			select {
			case <-ctx2.Done():
				t.Logf("Context cancelled, goroutine 2 exiting")
				return
			default:
			}

			t.Logf("Goroutine 2 calling Read()...")
			nr, err := backendReader2.Read(buf)
			t.Logf("Goroutine 2 Read() returned: nr=%d, err=%v", nr, err)

			if err != nil {
				t.Logf("Goroutine 2 Read error (expected after connection close): %v", err)
				return
			}
		}
	}()

	// Wait for context timeout
	<-ctx2.Done()
	t.Logf("Context 2 timeout reached")

	// Give goroutine time to detect closed connection
	time.Sleep(200 * time.Millisecond)

	mu2.Lock()
	completed2 := goroutine2Completed
	mu2.Unlock()

	if !completed2 {
		t.Errorf("FIX FAILED: Goroutine 2 still hung even with connection close")
	} else {
		t.Logf("SUCCESS: Goroutine 2 completed after connection close")
		t.Logf("This confirms that absolute session timeout fix will work")
	}
}

// TestReadDeadlineDetectsStaleConnection tests that read deadline
// can detect a stale backend connection during data transfer
func TestReadDeadlineDetectsStaleConnection(t *testing.T) {
	// Start a backend server that accepts connections but never sends data after greeting
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	backendAddr := listener.Addr().String()
	t.Logf("Backend listening on %s", backendAddr)

	// Backend that accepts connection and sends greeting, but then never sends data
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Send LMTP greeting
		conn.Write([]byte("220 backend.example.com LMTP Service Ready\r\n"))

		// Now go silent - simulate backend that hangs during data transfer
		t.Logf("Backend sent greeting, now going silent")
		time.Sleep(10 * time.Minute) // Stay silent to simulate hung backend
	}()

	// Connect to backend
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	backendConn, err := net.Dial("tcp", backendAddr)
	if err != nil {
		t.Fatalf("Failed to connect to backend: %v", err)
	}
	defer backendConn.Close()

	t.Logf("Connected to backend")

	// Read greeting
	backendReader := bufio.NewReader(backendConn)
	greeting, err := backendReader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	t.Logf("Received greeting: %s", greeting)

	// Simulate copyBufferedReaderToConn WITH read deadline (the fix)
	copyWithReadDeadline := func() (int64, error) {
		const readDeadline = 2 * time.Second // Short timeout for test
		var totalBytes int64
		buf := make([]byte, 32*1024)

		for {
			select {
			case <-ctx.Done():
				return totalBytes, ctx.Err()
			default:
			}

			// THE FIX: Set read deadline on backend connection
			if err := backendConn.SetReadDeadline(time.Now().Add(readDeadline)); err != nil {
				t.Logf("Failed to set read deadline: %v", err)
			}

			t.Logf("Calling Read() with %v deadline...", readDeadline)
			nr, err := backendReader.Read(buf)

			if nr > 0 {
				totalBytes += int64(nr)
				t.Logf("Read %d bytes", nr)
			}

			if err != nil {
				// Check if this is a timeout error (stale connection detected!)
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					t.Logf("SUCCESS: Read timeout detected stale backend connection after %v", readDeadline)
					return totalBytes, err
				}
				if err != io.EOF {
					return totalBytes, err
				}
				return totalBytes, nil
			}
		}
	}

	// Test the fix
	startTime := time.Now()
	_, err = copyWithReadDeadline()
	elapsed := time.Since(startTime)

	if err == nil {
		t.Errorf("Expected timeout error, got nil")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Errorf("Expected net.Error timeout, got: %v", err)
	} else {
		t.Logf("SUCCESS: Stale connection detected in %v (expected ~2s)", elapsed)
		if elapsed > 3*time.Second {
			t.Errorf("Detection took too long: %v (expected ~2s)", elapsed)
		}
	}
}

// TestTCPKeepaliveDetectsDeadConnection tests that TCP keepalive
// can detect a truly dead connection (network partition scenario)
func TestTCPKeepaliveDetectsDeadConnection(t *testing.T) {
	t.Skip("This test requires actual network partition simulation - run manually if needed")

	// This would require:
	// 1. Setting up a connection
	// 2. Enabling TCP keepalive with very short period (e.g., 1 second)
	// 3. Using iptables/pf to drop packets (simulate network partition)
	// 4. Verifying Read() eventually returns error after keepalive probes fail
	//
	// TCP keepalive parameters on FreeBSD:
	// - net.inet.tcp.keepidle: time before first keepalive probe (default 7200s)
	// - net.inet.tcp.keepintvl: interval between probes (default 75s)
	// - net.inet.tcp.keepcnt: number of probes before declaring dead (default 8)
	//
	// So even with SetKeepAlivePeriod(2 * time.Minute), it takes:
	// - 2 minutes idle before first probe
	// - Then 8 probes * 75 seconds = 10 minutes
	// - Total: ~12 minutes to detect dead connection
	//
	// For production, we should consider shorter keepalive settings or
	// rely on absolute session timeout as the primary safeguard.
}
