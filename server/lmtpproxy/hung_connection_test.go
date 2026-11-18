//go:build integration
// +build integration

package lmtpproxy

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
)

// TestHungBackendConnection drives a real proxy session into a backend that
// accepts TCP and then never sends a byte (no greeting, no FIN), with the
// backend connect timeout (the per-read deadline of readBackendLine) far longer
// than the absolute session timeout. The absolute session timeout must end the
// session: its watchdog closes the BACKEND connection too, which is what
// unblocks the goroutine parked in the backend read. Before that, closing only
// the client connection left such sessions hung (4,093 stuck connections in
// production). The connect-timeout deadline on the same read is covered by
// TestConnectToBackendSilentBackendTimesOut.
func TestHungBackendConnection(t *testing.T) {
	const (
		absoluteTimeout = 2 * time.Second
		connectTimeout  = 30 * time.Second // the read deadline must not be what ends the session
		bound           = 10 * time.Second
	)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	accepted := make(chan struct{})
	backendClosed := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		close(accepted)
		// Never write. Reading only observes the proxy closing its side.
		io.Copy(io.Discard, conn)
		close(backendClosed)
	}()

	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"address": r.URL.Query().Get("email")})
	}))
	t.Cleanup(lookup.Close)
	srv, err := New(context.Background(), nil, "test-host", ServerOptions{
		Name: "hung-backend", RemoteAddrs: []string{ln.Addr().String()}, RemotePort: 24,
		ConnectTimeout:         connectTimeout,
		AbsoluteSessionTimeout: absoluteTimeout,
		RemoteLookup:           &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "?email=$email", Timeout: "1s"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Stop() })

	front, serverEnd := net.Pipe()
	sess := newSession(srv, serverEnd, nil)
	done := make(chan struct{})
	start := time.Now()
	go func() { defer close(done); sess.handleConnection() }()
	t.Cleanup(func() {
		front.Close()
		<-done
	})
	// Drain the client side so the session never blocks writing a reply.
	go io.Copy(io.Discard, front)

	write := func(cmd string) {
		t.Helper()
		front.SetWriteDeadline(time.Now().Add(bound))
		if _, err := io.WriteString(front, cmd+"\r\n"); err != nil {
			t.Fatalf("%s: %v", strings.Fields(cmd)[0], err)
		}
	}
	write("LHLO client.example.org")
	write("MAIL FROM:<sender@example.com>")
	write("RCPT TO:<user@example.com>") // the proxy dials the backend and waits for its greeting

	select {
	case <-accepted:
	case <-time.After(bound):
		t.Fatal("the proxy never connected to the backend")
	}
	select {
	case <-done:
		t.Fatalf("precondition: the session ended %v after it started, before blocking on the hung backend", time.Since(start))
	default:
	}

	select {
	case <-done:
	case <-time.After(bound):
		t.Fatalf("session still blocked on the hung backend %v after start (absolute timeout %v, connect timeout %v)",
			time.Since(start), absoluteTimeout, connectTimeout)
	}
	select {
	case <-backendClosed:
	case <-time.After(bound):
		t.Fatal("the session ended but left the backend connection open")
	}
	if elapsed := time.Since(start); elapsed < absoluteTimeout {
		t.Errorf("session ended after %v, before the absolute timeout %v: something other than the timeout ended it", elapsed, absoluteTimeout)
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
