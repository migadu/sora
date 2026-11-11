package imap

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/migadu/sora/pkg/metrics"
	serverPkg "github.com/migadu/sora/server"
)

// syncLogBuffer collects go-imap's log output, written from connection goroutines.
type syncLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// newTTLTestServer serves a database-free IMAPServer whose limiter trusts loopback,
// so an ID from the test client carries proxy forwarding parameters.
func newTTLTestServer(t *testing.T, name string) (*IMAPServer, string, *syncLogBuffer) {
	t.Helper()
	appCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := &IMAPServer{
		name:        name,
		hostname:    name,
		appCtx:      appCtx,
		caps:        imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapID: {}},
		activeConns: make(map[*imapserver.Conn]struct{}),
		limiter:     serverPkg.NewConnectionLimiterWithTrustedNets("IMAP", 0, 0, []string{"127.0.0.0/8"}),
	}
	srv.settings.Store(&reloadableSettings{})
	var golog syncLogBuffer
	is := imapserver.New(&imapserver.Options{
		NewSession:   srv.newSession,
		Logger:       log.New(&golog, "", 0),
		InsecureAuth: true,
		Caps:         srv.caps,
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go is.Serve(ln)
	t.Cleanup(func() { is.Close() })
	return srv, ln.Addr().String(), &golog
}

// sendExpiredTTL connects, sends an ID whose x-proxy-ttl a hop takes to 0, and returns
// everything the server sent after it, up to the connection closing (or 3s).
func sendExpiredTTL(t *testing.T, addr string) string {
	t.Helper()
	return sendLoopingTTL(t, addr, "1")
}

// sendLoopingTTL is sendExpiredTTL for any x-proxy-ttl value that must end the connection.
func sendLoopingTTL(t *testing.T, addr, ttl string) string {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	c.Write([]byte(`a ID ("name" "proxy" "x-proxy-ttl" "` + ttl + `" "x-originating-ip" "198.51.100.7")` + "\r\n"))
	// A client that ignores the refusal and carries on.
	c.Write([]byte("b NOOP\r\n"))
	// EOF or a reset both mean the server closed it; only the deadline means it did not.
	rest, err := io.ReadAll(r)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("connection still open 3s after the expired TTL; server sent:\n%s", rest)
	}
	return string(rest)
}

// waitFor polls cond for up to 2s: the session's Close runs on go-imap's connection
// goroutine after the client sees the socket close.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// An ID from a trusted proxy whose TTL has run out is a proxy loop: the connection is
// dropped, and the session is closed (and counted out) exactly once.
func TestIDExpiredProxyTTLDropsConnection(t *testing.T) {
	srv, addr, golog := newTTLTestServer(t, "ttl-drop")

	rest := sendExpiredTTL(t, addr)
	if strings.Contains(rest, "a OK") || strings.Contains(rest, "b OK") {
		t.Errorf("connection served commands after the expired TTL:\n%s", rest)
	}

	waitFor(t, "the session to close", func() bool { return srv.totalConnections.Load() <= 0 })
	time.Sleep(100 * time.Millisecond) // room for a second Close to show up
	if got := srv.totalConnections.Load(); got != 0 {
		t.Errorf("totalConnections = %d after the connection ended, want 0", got)
	}
	gauge := metrics.ConnectionsCurrent.WithLabelValues("imap", srv.name, srv.hostname)
	if got := testutil.ToFloat64(gauge); got != 0 {
		t.Errorf("connections gauge = %v after the connection ended, want 0", got)
	}
	done := make(chan struct{})
	go func() { srv.sessionsWg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("sessionsWg.Wait did not return after the only session ended")
	}
	if strings.Contains(golog.String(), "panic") {
		t.Errorf("go-imap recovered a panic:\n%s", golog.String())
	}
}

// With another session open, the drain must still wait for it: the looping
// connection's session counts out once, not twice.
func TestIDExpiredProxyTTLKeepsDrainCountWithOtherSessions(t *testing.T) {
	srv, addr, _ := newTTLTestServer(t, "ttl-drain")
	srv.sessionsWg.Add(1) // another open session

	sendExpiredTTL(t, addr)
	waitFor(t, "the session to close", func() bool { return srv.totalConnections.Load() <= 0 })

	done := make(chan struct{})
	go func() { srv.sessionsWg.Wait(); close(done) }()
	select {
	case <-done:
		t.Fatal("sessionsWg.Wait returned while another counted session is still open")
	case <-time.After(300 * time.Millisecond):
	}
	srv.sessionsWg.Done() // the other session ends
	<-done
}

// Close is safe to call twice: the second call changes no counter.
func TestIMAPSessionCloseIsIdempotent(t *testing.T) {
	srv := &IMAPServer{name: "close-twice", hostname: "close-twice", appCtx: context.Background()}
	ctx, cancel := context.WithCancel(context.Background())
	s := &IMAPSession{server: srv, ctx: ctx, cancel: cancel, startTime: time.Now()}
	s.Protocol = "IMAP"

	srv.totalConnections.Add(1)
	srv.sessionsWg.Add(2) // this session and another one still open

	s.Close()
	s.Close()

	if got := srv.totalConnections.Load(); got != 0 {
		t.Errorf("totalConnections = %d after two Close calls, want 0", got)
	}
	done := make(chan struct{})
	go func() { srv.sessionsWg.Wait(); close(done) }()
	select {
	case <-done:
		t.Fatal("sessionsWg.Wait returned while another counted session is still open")
	case <-time.After(200 * time.Millisecond):
	}
	srv.sessionsWg.Done() // the other session ends
	<-done
}

// A TTL that arrives already spent is the same loop as one this hop spends: the
// connection is dropped rather than answered and left open.
func TestIDNonPositiveProxyTTLDropsConnection(t *testing.T) {
	for _, ttl := range []string{"0", "-1"} {
		t.Run(ttl, func(t *testing.T) {
			srv, addr, _ := newTTLTestServer(t, "ttl-nonpositive-"+ttl)

			rest := sendLoopingTTL(t, addr, ttl)
			if strings.Contains(rest, "a OK") || strings.Contains(rest, "b OK") {
				t.Errorf("connection served commands after x-proxy-ttl %s:\n%s", ttl, rest)
			}
			waitFor(t, "the session to close", func() bool { return srv.totalConnections.Load() <= 0 })
		})
	}
}

// sendIDAndLogout sends an ID with the given forwarding fields, then LOGOUT, and returns
// everything the server answered.
func sendIDAndLogout(t *testing.T, addr, fields string) string {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	c.Write([]byte(`a ID ("name" "proxy" ` + fields + `)` + "\r\n"))
	c.Write([]byte("b LOGOUT\r\n"))
	rest, err := io.ReadAll(r)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("no LOGOUT within 3s; server sent:\n%s", rest)
	}
	return string(rest)
}

// A TTL that is not a number is an invalid forwarding parameter, not a loop: the ID is
// answered and the connection kept, but none of the forwarded identity is applied. A
// valid TTL is applied and echoed with one hop spent; an ID that carries no TTL at all
// is not forwarding and is left alone.
func TestIDMalformedProxyTTLIgnoresForwarding(t *testing.T) {
	const origin = `"x-originating-ip" "198.51.100.7"`
	for _, tc := range []struct {
		name, fields string
		applied      bool
	}{
		{"non-numeric", `"x-proxy-ttl" "abc" ` + origin, false},
		{"empty", `"x-proxy-ttl" "" ` + origin, false},
		{"trailing garbage", `"x-proxy-ttl" "5x" ` + origin, false},
		{"absent", origin, false},
		{"valid", `"x-proxy-ttl" "5" ` + origin, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, addr, _ := newTTLTestServer(t, "ttl-malformed")

			rest := sendIDAndLogout(t, addr, tc.fields)
			if !strings.Contains(rest, "a OK") || !strings.Contains(rest, "b OK") {
				t.Fatalf("ID and LOGOUT were not both answered:\n%s", rest)
			}
			if got := strings.Contains(rest, "198.51.100.7"); got != tc.applied {
				t.Errorf("forwarded identity applied = %v, want %v:\n%s", got, tc.applied, rest)
			}
			if tc.applied && !strings.Contains(rest, `"x-proxy-ttl" "4"`) {
				t.Errorf("valid TTL 5 was not echoed as 4:\n%s", rest)
			}
		})
	}
}
