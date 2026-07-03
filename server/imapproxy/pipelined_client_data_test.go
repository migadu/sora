package imapproxy

import (
	"bufio"
	"net"
	"testing"
	"time"
)

// TestDrainClientReaderToBackend verifies that commands the client pipelined
// behind LOGIN/AUTHENTICATE — which land in the pre-auth bufio.Reader's
// buffer — are forwarded to the backend at the auth-to-relay switchover.
// Regression test for the pipelined-data loss (proxy review H3, 2026-07-03):
// the relay used to read only the raw connection and silently dropped these
// bytes, hanging the client.
func TestDrainClientReaderToBackend(t *testing.T) {
	clientA, clientB := net.Pipe()
	backendA, backendB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()
	defer backendA.Close()
	defer backendB.Close()

	sess := &Session{
		server:       &Server{name: "test"},
		clientConn:   clientA,
		clientReader: bufio.NewReader(clientA),
		backendConn:  backendA,
	}

	pipelined := "a2 SELECT INBOX\r\n"
	go func() { _, _ = clientB.Write([]byte(pipelined)) }()

	// Force the pipelined bytes into the bufio.Reader's buffer (as reading the
	// LOGIN line would have done).
	if _, err := sess.clientReader.Peek(len(pipelined)); err != nil {
		t.Fatalf("failed to buffer pipelined data: %v", err)
	}

	got := make(chan string, 1)
	go func() {
		buf := make([]byte, len(pipelined))
		_ = backendB.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _ := backendB.Read(buf)
		got <- string(buf[:n])
	}()

	n, err := sess.drainClientReaderToBackend()
	if err != nil {
		t.Fatalf("drainClientReaderToBackend: %v", err)
	}
	if n != int64(len(pipelined)) {
		t.Errorf("drained %d bytes, want %d", n, len(pipelined))
	}
	if forwarded := <-got; forwarded != pipelined {
		t.Errorf("backend received %q, want %q", forwarded, pipelined)
	}
	if buffered := sess.clientReader.Buffered(); buffered != 0 {
		t.Errorf("clientReader still has %d buffered bytes after drain", buffered)
	}
}
