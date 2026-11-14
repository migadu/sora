package imapproxy

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestIMAPProxyUnparseableUsernameIsAFailedLogin: on a proxy that authenticates
// against the database (no remote lookup), a login whose username does not parse
// as an address is a failed login like any other: recorded as a failure by the auth
// rate limiter and counted in
// sora_authentication_attempts_total{protocol="imap_proxy",result="failure"}.
func TestIMAPProxyUnparseableUsernameIsAFailedLogin(t *testing.T) {
	const name = "unparseable-username"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	srv, err := New(ctx, &resilient.ResilientDatabase{}, "localhost", ServerOptions{
		Name: name, Addr: addr, RemoteAddrs: []string{"127.0.0.1:1"}, ConnectTimeout: time.Second,
		InsecureAuth: true,
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

	failures := func() float64 {
		return testutil.ToFloat64(metrics.AuthenticationAttempts.WithLabelValues("imap_proxy", name, "localhost", "failure"))
	}
	// "\x00not-an-address\x00secret"
	const plain = "AG5vdC1hbi1hZGRyZXNzAHNlY3JldA=="
	for _, command := range []string{
		"a1 LOGIN not-an-address secret\r\n",
		"a1 AUTHENTICATE PLAIN " + plain + "\r\n",
	} {
		verb := strings.Fields(command)[1]
		recorded, before := limiter.failures.Load(), failures()
		if _, err := conn.Write([]byte(command)); err != nil {
			t.Fatal(err)
		}
		var reply string
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				t.Fatalf("%s reply: %v", verb, err)
			}
			if strings.HasPrefix(line, "a1 ") {
				reply = strings.TrimSpace(line)
				break
			}
		}
		if reply != "a1 NO Authentication failed" {
			t.Errorf("%s with an unparseable username: %q, want a1 NO Authentication failed", verb, reply)
		}
		if n := limiter.failures.Load() - recorded; n != 1 {
			t.Errorf("%s: %d failed attempts recorded in the auth rate limiter, want 1", verb, n)
		}
		if grew := failures() - before; grew != 1 {
			t.Errorf("%s: sora_authentication_attempts_total{protocol=\"imap_proxy\",result=\"failure\"} grew by %v, want 1", verb, grew)
		}
	}
}
