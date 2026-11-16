package imapproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
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
// implicit-TLS handshake. A BYE written in between is refused by the TLS
// listener's guard, which logs it at ERROR as a listener wiring bug (#754):
// the shutdown closes such a session without a BYE instead.
func TestShutdownByeSkipsSessionBeforeItsTLSHandshake(t *testing.T) {
	logs := &lockedBuffer{}
	prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelError})))
	t.Cleanup(func() { logger.Swap(prev) })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cert, err := tls.LoadX509KeyPair("../../testdata/sora.crt", "../../testdata/sora.key")
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{name: "test", hostname: "test-host", ctx: ctx, cancel: cancel, activeSessions: make(map[*Session]struct{})}
	serverEnd, client := net.Pipe()
	defer client.Close()
	conn := server.NewSoraTLSConn(serverEnd, &tls.Config{Certificates: []tls.Certificate{cert}}, server.SoraConnConfig{Protocol: "imap_proxy"})
	srv.addSession(newSession(srv, conn))

	srv.sendGracefulShutdownBye()

	if strings.Contains(logs.String(), "before deferred TLS handshake") {
		t.Errorf("the shutdown BYE was written before the session's TLS handshake:\n%s", logs.String())
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if got, err := io.ReadAll(client); len(got) != 0 || err != nil {
		t.Errorf("client: read %q, %v; want the connection closed with nothing written", got, err)
	}
}

// A session that has sent its greeting still gets the shutdown BYE.
func TestShutdownByeReachesGreetedClient(t *testing.T) {
	sess, _, r, greeting := startSTARTTLSSession(t)
	if !strings.HasPrefix(greeting, "* OK ") {
		t.Fatalf("greeting = %q", greeting)
	}
	sess.server.addSession(sess) // as the accept loop does
	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.server.sendGracefulShutdownBye()
	}()
	t.Cleanup(func() { <-done })
	if line := readLine(t, r); line != "* BYE Server shutting down, please reconnect" {
		t.Fatalf("shutdown notice = %q, want the BYE", line)
	}
}

func waitForGracefulShutdownFlag(t *testing.T, sess *Session) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		sess.mu.Lock()
		shuttingDown := sess.gracefulShutdown
		sess.mu.Unlock()
		if shuttingDown {
			// Let sendGracefulShutdownBye's spawned sendBye goroutine run and observe
			// the pre-greeting / in-STARTTLS state before the handshake completes.
			time.Sleep(20 * time.Millisecond)
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out waiting for gracefulShutdown flag")
}

// An implicit-TLS session registered in activeSessions before its deferred TLS
// handshake finishes can complete PerformDeferredTLSHandshake during
// sendGracefulShutdownBye's 1-second sleep, after sendBye skipped it (!greeted).
// Once gracefulShutdown is set, sendGreeting must not write * OK and leave the
// greeted client to be hard-closed without * BYE.
func TestShutdownByeRefusesGreetingAfterShutdownStarts(t *testing.T) {
	logs := &lockedBuffer{}
	prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelError})))
	t.Cleanup(func() { logger.Swap(prev) })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cert, err := tls.LoadX509KeyPair("../../testdata/sora.crt", "../../testdata/sora.key")
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		name:           "test",
		hostname:       "test-host",
		ctx:            ctx,
		cancel:         cancel,
		activeSessions: make(map[*Session]struct{}),
	}
	srv.settings.Store(&reloadableSettings{maxAuthErrors: 5, authIdleTimeout: 5 * time.Second})

	serverEnd, clientRaw := net.Pipe()
	conn := server.NewSoraTLSConn(serverEnd, &tls.Config{Certificates: []tls.Certificate{cert}}, server.SoraConnConfig{Protocol: "imap_proxy"})
	sess := newSession(srv, conn)
	srv.addSession(sess)

	sessDone := make(chan struct{})
	go func() {
		defer close(sessDone)
		sess.handleConnection()
	}()
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		srv.sendGracefulShutdownBye()
	}()
	t.Cleanup(func() {
		clientRaw.Close()
		<-sessDone
		<-shutdownDone
	})

	waitForGracefulShutdownFlag(t, sess)

	_ = clientRaw.SetDeadline(time.Now().Add(3 * time.Second))
	tlsClient := tls.Client(clientRaw, &tls.Config{InsecureSkipVerify: true})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	got, err := io.ReadAll(tlsClient)
	if len(got) != 0 || err != nil {
		t.Errorf("client read %q (err=%v); want connection closed without * OK greeting once shutdown has started", got, err)
	}
	if strings.Contains(logs.String(), "Failed to send greeting") || strings.Contains(logs.String(), "before deferred TLS handshake") {
		t.Errorf("unexpected error log during shutdown:\n%s", logs.String())
	}
}

// A greeted session that began STARTTLS before sendGracefulShutdownBye ran has
// sendBye skip it while startTLSInProgress is true. When the TLS handshake
// finishes inside sendGracefulShutdownBye's 1-second grace window, the upgraded
// TLS connection must receive * BYE before closing.
func TestShutdownByeSentAfterSTARTTLSHandshakeCompletesDuringShutdown(t *testing.T) {
	sess, conn, r, greeting := startSTARTTLSSession(t)
	if !strings.HasPrefix(greeting, "* OK ") {
		t.Fatalf("greeting = %q", greeting)
	}
	sess.server.addSession(sess)

	if _, err := io.WriteString(conn, "s STARTTLS\r\n"); err != nil {
		t.Fatalf("write STARTTLS: %v", err)
	}
	if line := readLine(t, r); line != "s OK Begin TLS negotiation now" {
		t.Fatalf("STARTTLS = %q", line)
	}

	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		sess.server.sendGracefulShutdownBye()
	}()
	t.Cleanup(func() { <-shutdownDone })

	waitForGracefulShutdownFlag(t, sess)

	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	tlsClient := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("TLS handshake after STARTTLS: %v", err)
	}
	tr := bufio.NewReader(tlsClient)
	line, err := tr.ReadString('\n')
	if err != nil {
		t.Fatalf("reading shutdown BYE over upgraded TLS conn: got %q, err=%v", line, err)
	}
	if got := strings.TrimRight(line, "\r\n"); got != "* BYE Server shutting down, please reconnect" {
		t.Fatalf("shutdown notice over TLS = %q, want %q", got, "* BYE Server shutting down, please reconnect")
	}
	if rest, err := io.ReadAll(tr); len(rest) != 0 || err != nil {
		t.Errorf("trailing data after shutdown BYE = %q, err=%v; want clean EOF", rest, err)
	}
}
