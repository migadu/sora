package lmtpproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/server"
)

// newImplicitTLSServer returns a proxy whose listener does implicit TLS.
func newImplicitTLSServer(t *testing.T) *Server {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cert, err := tls.LoadX509KeyPair("../../testdata/sora.crt", "../../testdata/sora.key")
	if err != nil {
		t.Fatal(err)
	}
	return &Server{
		name:           "test",
		hostname:       "test-host",
		ctx:            ctx,
		cancel:         cancel,
		activeSessions: make(map[*Session]struct{}),
		tls:            true,
		tlsConfig:      &tls.Config{Certificates: []tls.Certificate{cert}},
	}
}

// acceptImplicitTLS returns a session for a connection the implicit-TLS
// listener accepted, registered as the accept loop registers it before the
// session runs, and the client end of that connection.
func acceptImplicitTLS(t *testing.T, srv *Server) (*Session, net.Conn) {
	t.Helper()
	serverEnd, client := net.Pipe()
	conn := server.NewSoraTLSConn(serverEnd, srv.tlsConfig, server.SoraConnConfig{Protocol: "lmtp_proxy"})
	sess := newSession(srv, conn, nil)
	srv.registerSession(sess)
	return sess, client
}

// runSession runs sess until the test ends, closing client first.
func runSession(t *testing.T, sess *Session, client net.Conn) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.handleConnection()
	}()
	t.Cleanup(func() {
		client.Close()
		<-done
	})
}

// startHandshakingSession runs a session of an implicit-TLS proxy whose client
// has sent the first byte of a TLS record and nothing more: the session's
// deferred handshake is under way, waiting for the rest of the ClientHello
// until its deadline.
func startHandshakingSession(t *testing.T, srv *Server) net.Conn {
	t.Helper()
	sess, client := acceptImplicitTLS(t, srv)
	runSession(t, sess, client)
	// A net.Pipe write returns once the other end has read it: here, once the
	// handshake has peeked at the byte.
	_ = client.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Write([]byte{0x16}); err != nil {
		t.Fatalf("starting the TLS handshake: %v", err)
	}
	return client
}

// assertClosedSilently checks that conn was closed with nothing written to it.
func assertClosedSilently(t *testing.T, name string, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, err := io.ReadAll(conn)
	if len(got) != 0 {
		t.Errorf("%s: read %q, want nothing", name, got)
	}
	if err != nil {
		t.Errorf("%s: %v, want the connection closed", name, err)
	}
}

// The shutdown notice must not wait for a session's pending TLS handshake: its
// write did, one session after another, for up to the 10 s handshake deadline
// each, before the shutdown closed anything (#754). A session still in its
// handshake is closed without a notice, which also ends the handshake.
func TestShutdownDoesNotWaitForPendingTLSHandshakes(t *testing.T) {
	srv := newImplicitTLSServer(t)
	var clients []net.Conn
	for range 3 {
		clients = append(clients, startHandshakingSession(t, srv))
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.sendGracefulShutdownMessage()
	}()
	t.Cleanup(func() {
		for _, c := range clients {
			c.Close()
		}
		<-done
	})
	// The notice step lingers 1 s for clients to read it; nothing else may add to that.
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the shutdown notice is still waiting for the pending TLS handshakes after 3s")
	}

	for i, c := range clients {
		assertClosedSilently(t, fmt.Sprintf("handshaking client %d", i+1), c)
	}
}

// lockedBuffer is a bytes.Buffer safe to log into from several goroutines.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// The accept loop registers a session before the session starts its deferred
// handshake. A notice written in between is refused by the TLS listener's
// guard, which logs it at ERROR as a listener wiring bug (#754): the shutdown
// closes such a session without a notice instead.
func TestShutdownNoticeSkipsSessionBeforeItsTLSHandshake(t *testing.T) {
	logs := &lockedBuffer{}
	prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelError})))
	t.Cleanup(func() { logger.Swap(prev) })

	srv := newImplicitTLSServer(t)
	_, client := acceptImplicitTLS(t, srv)
	defer client.Close()

	srv.sendGracefulShutdownMessage()

	if strings.Contains(logs.String(), "before deferred TLS handshake") {
		t.Errorf("the shutdown notice was written before the session's TLS handshake:\n%s", logs.String())
	}
	assertClosedSilently(t, "client", client)
}

// A session past its implicit-TLS handshake and greeting still gets the
// shutdown notice, after the greeting and through TLS.
func TestShutdownNoticeReachesImplicitTLSClient(t *testing.T) {
	srv := newImplicitTLSServer(t)
	sess, client := acceptImplicitTLS(t, srv)
	runSession(t, sess, client)

	tlsConn := tls.Client(client, &tls.Config{InsecureSkipVerify: true})
	_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	r := bufio.NewReader(tlsConn)
	if line := readReply(t, r); !strings.HasPrefix(line, "220 ") {
		t.Fatalf("greeting = %q", line)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.sendGracefulShutdownMessage()
	}()
	t.Cleanup(func() { <-done })
	if line := readReply(t, r); !strings.HasPrefix(line, "421 ") {
		t.Fatalf("shutdown notice through TLS = %q, want a 421", line)
	}
	if rest, err := io.ReadAll(r); len(rest) != 0 || err != nil {
		t.Errorf("after the notice: read %q, %v; want the connection closed", rest, err)
	}
}
