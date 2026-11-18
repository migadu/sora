//go:build integration
// +build integration

package lmtpproxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// TestBackendClosesConnectionCleanly tests that when backend closes connection properly
// (sends FIN), the Read() returns EOF and goroutine exits cleanly
func TestBackendClosesConnectionCleanly(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	backendAddr := listener.Addr().String()
	t.Logf("Backend listening on %s", backendAddr)

	// Backend that accepts connection, sends greeting, then closes immediately
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		t.Logf("Backend accepted connection, sending greeting then closing")
		conn.Write([]byte("220 backend.example.com LMTP Service Ready\r\n"))
		time.Sleep(100 * time.Millisecond)
		conn.Close() // Clean close - sends FIN
		t.Logf("Backend closed connection")
	}()

	// Connect to backend
	backendConn, err := net.Dial("tcp", backendAddr)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer backendConn.Close()

	backendReader := bufio.NewReader(backendConn)

	// Read greeting
	greeting, err := backendReader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	t.Logf("Received greeting: %s", greeting)

	// Now try to read more - should get EOF immediately
	t.Logf("Attempting to read after backend closed...")
	buf := make([]byte, 1024)

	// Set a short read deadline to ensure test doesn't hang if something is wrong
	backendConn.SetReadDeadline(time.Now().Add(2 * time.Second))

	nr, err := backendReader.Read(buf)

	if err != io.EOF && err == nil {
		t.Errorf("Expected EOF or error, got nr=%d, err=%v", nr, err)
	} else if err == io.EOF {
		t.Logf("SUCCESS: Got EOF as expected when backend closed cleanly")
	} else {
		t.Logf("Got error (acceptable): %v", err)
	}
}

// TestBackendClosesConnectionAbruptly tests backend sending RST (abrupt close)
func TestBackendClosesConnectionAbruptly(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	backendAddr := listener.Addr().String()
	t.Logf("Backend listening on %s", backendAddr)

	// Backend that accepts connection, sends greeting, then abruptly closes (RST)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		t.Logf("Backend accepted connection, sending greeting")
		conn.Write([]byte("220 backend.example.com LMTP Service Ready\r\n"))

		// Force abrupt close by setting SO_LINGER to 0 (sends RST instead of FIN)
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetLinger(0) // 0 means send RST on close
		}

		time.Sleep(100 * time.Millisecond)
		conn.Close() // This will send RST due to SetLinger(0)
		t.Logf("Backend sent RST")
	}()

	// Connect to backend
	backendConn, err := net.Dial("tcp", backendAddr)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer backendConn.Close()

	backendReader := bufio.NewReader(backendConn)

	// Read greeting
	greeting, err := backendReader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	t.Logf("Received greeting: %s", greeting)

	// Wait a moment for RST to arrive
	time.Sleep(200 * time.Millisecond)

	// Now try to read more - should get connection reset error
	t.Logf("Attempting to read after backend sent RST...")
	buf := make([]byte, 1024)

	// Set read deadline to ensure test doesn't hang
	backendConn.SetReadDeadline(time.Now().Add(2 * time.Second))

	nr, err := backendReader.Read(buf)

	if err == nil {
		t.Errorf("Expected error after RST, got nr=%d", nr)
	} else {
		t.Logf("SUCCESS: Got error as expected after RST: %v", err)
		// Should be "connection reset by peer" or similar
	}
}

// TestBackendSlowButResponding tests backend that responds slowly but is still alive
// The read deadline should be generous enough to allow slow responses
func TestBackendSlowButResponding(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	backendAddr := listener.Addr().String()
	t.Logf("Backend listening on %s", backendAddr)

	// Backend that responds but very slowly (simulates slow disk, heavy load, etc.)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		t.Logf("Backend accepted connection, sending greeting")
		conn.Write([]byte("220 backend.example.com LMTP Service Ready\r\n"))

		// Simulate slow response - send data in chunks with delays
		// Should be UNDER the 5-minute read deadline to succeed
		delays := []time.Duration{
			1 * time.Second,
			2 * time.Second,
			1 * time.Second,
		}

		for i, delay := range delays {
			time.Sleep(delay)
			chunk := []byte("DATA CHUNK ")
			chunk = append(chunk, byte('0'+i))
			chunk = append(chunk, '\r', '\n')
			n, err := conn.Write(chunk)
			t.Logf("Backend sent chunk %d (%d bytes) after %v delay", i, n, delay)
			if err != nil {
				t.Logf("Backend write error: %v", err)
				return
			}
		}

		t.Logf("Backend finished sending slow data")
	}()

	// Connect to backend
	backendConn, err := net.Dial("tcp", backendAddr)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer backendConn.Close()

	backendReader := bufio.NewReader(backendConn)

	// Read greeting
	greeting, err := backendReader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	t.Logf("Received greeting: %s", greeting)

	// Read chunks with read deadline (simulate the fix)
	const readDeadline = 5 * time.Second // Generous enough for slow responses
	chunksRead := 0
	totalBytes := 0

	for i := 0; i < 3; i++ {
		// Set read deadline before each read (like the fix does)
		if err := backendConn.SetReadDeadline(time.Now().Add(readDeadline)); err != nil {
			t.Fatalf("Failed to set read deadline: %v", err)
		}

		line, err := backendReader.ReadString('\n')
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				t.Errorf("TIMEOUT: Slow backend timed out - read deadline too short! Got timeout after reading %d chunks", chunksRead)
				return
			}
			t.Fatalf("Read error: %v", err)
		}

		chunksRead++
		totalBytes += len(line)
		t.Logf("Read chunk %d: %s (total: %d bytes)", chunksRead, line, totalBytes)
	}

	if chunksRead == 3 {
		t.Logf("SUCCESS: Read all chunks from slow backend without timeout")
		t.Logf("Read deadline (%v) is generous enough for slow responses", readDeadline)
	} else {
		t.Errorf("Only read %d/3 chunks", chunksRead)
	}
}

// TestBackendStopsResponding: a backend that sends its greeting and then goes silent
// (it reads LHLO but never answers) must fail connectToBackend within about the
// connect timeout, which readBackendLine applies to every handshake reply. A backend
// silent from the start is TestConnectToBackendSilentBackendTimesOut.
func TestBackendStopsResponding(t *testing.T) {
	const connectTimeout = 500 * time.Millisecond
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	gotLHLO := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.WriteString(conn, "220 backend.example.com LMTP Service Ready\r\n")
		r := bufio.NewReader(conn)
		if line, err := r.ReadString('\n'); err == nil && strings.HasPrefix(strings.ToUpper(line), "LHLO") {
			gotLHLO <- struct{}{}
		}
		io.Copy(io.Discard, r) // silent until the proxy closes
	}()

	srv := &Server{
		name:        "test",
		hostname:    "test-host",
		connManager: newLMTPTestConnManager(t, ln.Addr().String(), connectTimeout),
	}
	clientA, clientB := net.Pipe()
	t.Cleanup(func() { clientA.Close(); clientB.Close() })
	sess := &Session{
		server:          srv,
		clientConn:      clientA,
		originalAddress: "user@example.com",
		ctx:             context.Background(),
	}

	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- sess.connectToBackend() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("connectToBackend succeeded against a backend that never answers LHLO")
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("connectToBackend took %v; must fail within about the connect timeout %v", elapsed, connectTimeout)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("connectToBackend hung on a backend that went silent after its greeting")
	}
	select {
	case <-gotLHLO:
	default:
		t.Error("precondition: the backend never received LHLO, so the silence was not after the greeting")
	}
}
