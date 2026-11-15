package imapproxy

import (
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
