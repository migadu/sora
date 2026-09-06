package lmtpproxy

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

// newRelayTestSession wires a Session to two in-memory connections: the "client" side
// and the "backend" side, each with the peer end handed back to the test.
func newRelayTestSession(t *testing.T, acceptedRcpts int) (sess *Session, clientPeer, backendPeer net.Conn) {
	t.Helper()
	clientConn, clientPeer := net.Pipe()
	backendConn, backendPeer := net.Pipe()
	t.Cleanup(func() { clientConn.Close(); clientPeer.Close(); backendConn.Close(); backendPeer.Close() })
	sess = &Session{
		server:        &Server{name: "test", authIdleTimeout: 5 * time.Second},
		clientConn:    clientConn,
		clientReader:  bufio.NewReader(clientConn),
		clientWriter:  bufio.NewWriter(clientConn),
		backendConn:   backendConn,
		backendReader: bufio.NewReader(backendConn),
		backendWriter: bufio.NewWriter(backendConn),
		ctx:           context.Background(),
		acceptedRcpts: acceptedRcpts,
	}
	return sess, clientPeer, backendPeer
}

// readExactly reads len(want) bytes from c (net.Pipe delivers writes synchronously).
func readExactly(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	got := 0
	for got < n {
		m, err := c.Read(buf[got:])
		if err != nil {
			t.Fatalf("read after %d of %d bytes: %v", got, n, err)
		}
		got += m
	}
	return buf
}

// TestRelayMessageDataStreamsLongLines verifies that the relay forwards a line larger
// than the bufio buffer intact. Regression test for the LMTP proxy review
// (2026-07-03): the loop used ReadString('\n'), which buffered an entire line in memory
// before forwarding — a message with one huge line (no CRLF) grew proxy memory without
// bound. The fix streams buffer-sized chunks via ReadSlice; the inline relay keeps that.
func TestRelayMessageDataStreamsLongLines(t *testing.T) {
	sess, clientPeer, backendPeer := newRelayTestSession(t, 1)

	// 200 KiB single line (default bufio buffer is 4 KiB), then the end-of-data marker.
	payload := bytes.Repeat([]byte("a"), 200*1024)
	payload = append(payload, '\r', '\n')
	payload = append(payload, []byte(".\r\n")...)

	// Backend side: receive the whole body, then answer the one accepted recipient.
	received := make(chan []byte, 1)
	go func() {
		received <- readExactly(t, backendPeer, len(payload))
		backendPeer.Write([]byte("250 2.0.0 Ok\r\n"))
	}()
	// Client side: send the body, then expect the relayed reply.
	go func() { clientPeer.Write(payload) }()

	// net.Pipe writes block until the peer reads, so the client side must consume the
	// relayed reply concurrently with the relay.
	reply := make(chan string, 1)
	go func() { reply <- string(readExactly(t, clientPeer, len("250 2.0.0 Ok\r\n"))) }()

	done := make(chan bool, 1)
	go func() { done <- sess.relayMessageData() }()

	select {
	case ok := <-done:
		if !ok {
			t.Fatal("relayMessageData reported the session must end")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("relayMessageData did not return")
	}
	if got := <-received; !bytes.Equal(got, payload) {
		t.Fatalf("relayed data mismatch: sent %d bytes, received %d bytes", len(payload), len(got))
	}
	if r := <-reply; r != "250 2.0.0 Ok\r\n" {
		t.Fatalf("client got %q, want the backend's end-of-data reply", r)
	}
}

// TestRelayMessageDataStopsAtEndOfData pins the property behind connection reuse: the
// relay stops exactly at the end-of-data marker, relays one reply per accepted
// recipient, and leaves whatever the client pipelined afterwards (the next MAIL FROM)
// in the command reader instead of forwarding it raw to the backend.
func TestRelayMessageDataStopsAtEndOfData(t *testing.T) {
	sess, clientPeer, backendPeer := newRelayTestSession(t, 2)

	body := []byte("Subject: one\r\n\r\nline\r\n..\r\n.not the end either\r\nbare-lf\n.\r\n.\r\n")
	next := []byte("MAIL FROM:<next@example.com>\r\n")

	received := make(chan []byte, 1)
	go func() {
		received <- readExactly(t, backendPeer, len(body))
		backendPeer.Write([]byte("250-2.0.0 first\r\n250 2.0.0 first\r\n250 2.0.0 second\r\n"))
	}()
	go func() { clientPeer.Write(append(append([]byte{}, body...), next...)) }()

	// Both replies (the first one multi-line) must reach the client; read them
	// concurrently (net.Pipe writes block until read).
	want := "250-2.0.0 first\r\n250 2.0.0 first\r\n250 2.0.0 second\r\n"
	reply := make(chan string, 1)
	go func() { reply <- string(readExactly(t, clientPeer, len(want))) }()

	done := make(chan bool, 1)
	go func() { done <- sess.relayMessageData() }()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("relayMessageData reported the session must end")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("relayMessageData did not return")
	}
	if got := <-received; !bytes.Equal(got, body) {
		t.Fatalf("backend received %q, want exactly the body up to the end-of-data marker", got)
	}
	if r := <-reply; r != want {
		t.Fatalf("client got %q, want %q", r, want)
	}
	// The pipelined MAIL FROM is still waiting for the command loop.
	line, err := sess.clientReader.ReadString('\n')
	if err != nil || line != string(next) {
		t.Fatalf("next command not left in the client reader: %q (%v)", line, err)
	}
}
