package imapproxy

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
type failureCountingLimiter struct {
	fakeAuthLimiter
	failures atomic.Int32
}

func (l *failureCountingLimiter) RecordAuthAttemptWithProxy(_ context.Context, _ net.Conn, _ *server.ProxyProtocolInfo, _ string, success bool) {
	if !success {
		l.failures.Add(1)
	}
}

func (l *failureCountingLimiter) RecordAuthAttempt(_ context.Context, _ net.Addr, _ string, success bool) {
	if !success {
		l.failures.Add(1)
	}
}

// TestIMAPProxyLookupOutageIsATemporaryFailure: when the remote lookup service is down
// the login is answered NO [UNAVAILABLE] (RFC 5530 section 3, "a subsystem is down"),
// not as a wrong password, and the attempt is not charged to the auth rate limiter:
// clients retrying their saved password during an outage must not get blocked.
func TestIMAPProxyLookupOutageIsATemporaryFailure(t *testing.T) {
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer lookup.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	srv, err := New(ctx, &resilient.ResilientDatabase{}, "localhost", ServerOptions{
		Name: "outage", Addr: addr, RemoteAddrs: []string{"127.0.0.1:1"}, ConnectTimeout: time.Second,
		InsecureAuth: true,
		RemoteLookup: &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "/lookup?email=$email", Timeout: "2s"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	limiter := &failureCountingLimiter{}
	srv.authLimiter = limiter
	go func() { _ = srv.Start() }()
	defer srv.Stop()

	var conn net.Conn
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if conn, err = net.Dial("tcp", addr); err == nil || time.Now().After(deadline) {
			break
		}
	}
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatalf("greeting: %v", err)
	}

	for i := 1; i <= 2; i++ {
		if _, err := conn.Write([]byte("a1 LOGIN anna@example.com secret\r\n")); err != nil {
			t.Fatal(err)
		}
		var reply string
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				t.Fatalf("LOGIN %d reply: %v", i, err)
			}
			if strings.HasPrefix(line, "a1 ") {
				reply = strings.TrimSpace(line)
				break
			}
		}
		if !strings.HasPrefix(reply, "a1 NO [UNAVAILABLE]") {
			t.Errorf("LOGIN %d during a lookup outage: %q, want a1 NO [UNAVAILABLE] ...", i, reply)
		}
	}
	if n := limiter.failures.Load(); n != 0 {
		t.Errorf("%d failed login(s) recorded in the auth rate limiter for a lookup outage, want 0", n)
	}
}
