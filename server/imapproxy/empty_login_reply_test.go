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
)

// TestIMAPProxyEmptyLoginCredentialGetsTheBadCredentialsReply: a LOGIN whose user
// name or password is an empty string is a well-formed LOGIN with credentials no
// account can have. It gets the reply every other failed login gets, and is counted
// as one (#2067), so the reply does not single it out. A user name that does not
// parse is the control: it already got that reply. (#2068)
func TestIMAPProxyEmptyLoginCredentialGetsTheBadCredentialsReply(t *testing.T) {
	var lookups atomic.Int32
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lookups.Add(1)
		http.Error(w, "not found", http.StatusNotFound)
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
		Name: "empty-login", Addr: addr, RemoteAddrs: []string{"127.0.0.1:1"}, ConnectTimeout: time.Second,
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

	cases := []struct{ name, command string }{
		{"unparseable user name (control)", "a LOGIN not-an-address secret"},
		{"empty password", `a LOGIN user@example.com ""`},
		{"empty user name", `a LOGIN "" secret`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
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

			asked, recorded := lookups.Load(), limiter.failures.Load()
			conn.Write([]byte(tc.command + "\r\n"))
			var reply string
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					t.Fatalf("reading the LOGIN reply: %v", err)
				}
				if strings.HasPrefix(line, "a ") {
					reply = strings.TrimSpace(line)
					break
				}
			}
			if reply != "a NO Authentication failed" {
				t.Errorf("reply %q, want the bad-credentials reply %q", reply, "a NO Authentication failed")
			}
			if n := lookups.Load() - asked; n != 0 {
				t.Errorf("the lookup service was asked %d times", n)
			}
			if n := limiter.failures.Load() - recorded; n != 1 {
				t.Errorf("%d failed attempts recorded in the auth rate limiter, want 1", n)
			}
		})
	}
}
