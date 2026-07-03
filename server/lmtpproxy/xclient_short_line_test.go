package lmtpproxy

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// TestXCLIENTShortFinalLHLOLineNoPanic verifies that a short final LHLO line
// (e.g. a bare "250") after an XCLIENT session reset does not crash the
// session. Regression test for the LMTP proxy review (2026-07-03): the loop
// checked `len(lhloResponse) >= 3 && lhloResponse[3] != '-'`, indexing byte 3
// on a 3-byte line — an index-out-of-range panic triggered by the backend's
// response.
func TestXCLIENTShortFinalLHLOLineNoPanic(t *testing.T) {
	clientConn, clientPeer := net.Pipe()
	defer clientConn.Close()
	defer clientPeer.Close()

	backendConn, backendPeer := net.Pipe()
	defer backendConn.Close()
	defer backendPeer.Close()

	srv := &Server{
		name:        "test",
		hostname:    "proxy.example.com",
		connManager: newLMTPTestConnManager(t, "127.0.0.1:9", 2*time.Second),
	}

	sess := &Session{
		server:        srv,
		clientConn:    clientConn,
		backendConn:   backendConn,
		backendReader: bufio.NewReader(backendConn),
		backendWriter: bufio.NewWriter(backendConn),
		ctx:           context.Background(),
	}

	// Scripted backend: accept XCLIENT with a session reset (220), then answer
	// the re-sent LHLO with a bare "250" — a valid final line with no text.
	go func() {
		r := bufio.NewReader(backendPeer)
		line, err := r.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "XCLIENT ") {
			return
		}
		backendPeer.Write([]byte("220 reset\r\n"))
		line, err = r.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "LHLO ") {
			return
		}
		backendPeer.Write([]byte("250\r\n"))
	}()

	done := make(chan error, 1)
	go func() {
		done <- sess.sendForwardingParametersToBackend(sess.backendWriter, sess.backendReader)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("sendForwardingParametersToBackend failed on short final LHLO line: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sendForwardingParametersToBackend did not return (hung or panicked goroutine)")
	}
}
