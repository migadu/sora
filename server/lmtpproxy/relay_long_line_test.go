package lmtpproxy

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// TestProxyClientToBackendStreamsLongLines verifies that the client-to-backend
// relay forwards a line larger than the bufio buffer intact. Regression test
// for the LMTP proxy review (2026-07-03): the loop used ReadString('\n'),
// which buffered an entire line in memory before forwarding — a message with
// one huge line (no CRLF) grew proxy memory without bound. The fix streams
// buffer-sized chunks via ReadSlice.
func TestProxyClientToBackendStreamsLongLines(t *testing.T) {
	clientConn, clientPeer := net.Pipe()
	defer clientConn.Close()
	defer clientPeer.Close()

	backendConn, backendPeer := net.Pipe()
	defer backendConn.Close()
	defer backendPeer.Close()

	sess := &Session{
		server:        &Server{name: "test", authIdleTimeout: 5 * time.Second},
		clientConn:    clientConn,
		clientReader:  bufio.NewReader(clientConn),
		backendConn:   backendConn,
		backendWriter: bufio.NewWriter(backendConn),
		ctx:           context.Background(),
	}

	// 200 KiB single line (default bufio buffer is 4 KiB), then a normal line.
	payload := bytes.Repeat([]byte("a"), 200*1024)
	payload = append(payload, '\r', '\n')
	payload = append(payload, []byte(".\r\n")...)

	// Backend side: accumulate everything the proxy forwards.
	var received bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(&received, backendPeer)
	}()

	// Client side: write the payload, then close to end the relay.
	go func() {
		clientPeer.Write(payload)
		clientPeer.Close()
	}()

	done := make(chan struct{})
	go func() {
		sess.proxyClientToBackend()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("proxyClientToBackend did not return")
	}

	// Unblock the backend reader and collect what was received.
	backendConn.Close()
	wg.Wait()

	if !bytes.Equal(received.Bytes(), payload) {
		t.Fatalf("relayed data mismatch: sent %d bytes, received %d bytes", len(payload), received.Len())
	}
}
