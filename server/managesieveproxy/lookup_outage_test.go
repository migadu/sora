package managesieveproxy

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
)

// failureCountingLimiter is an auth limiter that allows everything and counts the
// failed attempts recorded against the client.
type failureCountingLimiter struct{ failures atomic.Int32 }

func (l *failureCountingLimiter) CanAttemptAuth(context.Context, net.Addr, string) error { return nil }
func (l *failureCountingLimiter) CanAttemptAuthWithProxy(context.Context, net.Conn, *server.ProxyProtocolInfo, string) error {
	return nil
}
func (l *failureCountingLimiter) RecordAuthAttempt(_ context.Context, _ net.Addr, _ string, success bool) {
	if !success {
		l.failures.Add(1)
	}
}
func (l *failureCountingLimiter) RecordAuthAttemptWithProxy(_ context.Context, _ net.Conn, _ *server.ProxyProtocolInfo, _ string, success bool) {
	if !success {
		l.failures.Add(1)
	}
}
func (l *failureCountingLimiter) IsIPBlocked(net.Addr) bool { return false }
func (l *failureCountingLimiter) IsIPBlockedWithProxy(net.Conn, *server.ProxyProtocolInfo) bool {
	return false
}
func (l *failureCountingLimiter) GetStats(context.Context, time.Duration) map[string]any { return nil }
func (l *failureCountingLimiter) Stop()                                                  {}

func outageLookup(t *testing.T) *config.RemoteLookupConfig {
	t.Helper()
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(lookup.Close)
	return &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "/lookup?email=$email", Timeout: "2s"}
}

func freeTestAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func dialTest(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	var conn net.Conn
	var err error
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if conn, err = net.Dial("tcp", addr); err == nil || time.Now().After(deadline) {
			break
		}
	}
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	return conn, bufio.NewReader(conn)
}

func readLineWithPrefix(t *testing.T, r *bufio.Reader, prefixes ...string) string {
	t.Helper()
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read (waiting for %q): %v", prefixes, err)
		}
		for _, p := range prefixes {
			if strings.HasPrefix(line, p) {
				return strings.TrimSpace(line)
			}
		}
	}
}

// TestManageSieveProxyLookupOutageIsATemporaryFailure: when the remote lookup service
// is down AUTHENTICATE is answered NO (TRYLATER) (RFC 5804 section 1.3, "a command
// failed due to a temporary server failure"), not as a wrong password, and the attempt
// is not charged to the auth rate limiter.
func TestManageSieveProxyLookupOutageIsATemporaryFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := freeTestAddr(t)
	srv, err := New(ctx, &resilient.ResilientDatabase{}, "localhost", ServerOptions{
		Name: "outage", Addr: addr, RemoteAddrs: []string{"127.0.0.1:1"}, ConnectTimeout: time.Second,
		InsecureAuth: true, RemoteLookup: outageLookup(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	limiter := &failureCountingLimiter{}
	srv.authLimiter = limiter
	go func() { _ = srv.Start() }()
	defer srv.Stop()

	conn, r := dialTest(t, addr)
	readLineWithPrefix(t, r, "OK")
	// "\x00anna@example.com\x00secret"
	const plain = "AGFubmFAZXhhbXBsZS5jb20Ac2VjcmV0"
	for i := 1; i <= 2; i++ {
		conn.Write([]byte(`AUTHENTICATE "PLAIN" "` + plain + "\"\r\n"))
		if reply := readLineWithPrefix(t, r, "OK", "NO", "BYE"); !strings.HasPrefix(reply, "NO (TRYLATER)") {
			t.Errorf("AUTHENTICATE %d during a lookup outage: %q, want NO (TRYLATER) ...", i, reply)
		}
	}
	if n := limiter.failures.Load(); n != 0 {
		t.Errorf("%d failed login(s) recorded in the auth rate limiter for a lookup outage, want 0", n)
	}
}
