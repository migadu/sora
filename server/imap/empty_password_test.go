package imap

import (
	"bufio"
	"context"
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestEmptyPasswordIsAFailedLogin: an empty password is a credential no account can
// have. It is refused without a lookup, but like any other failed login: past the
// rate-limit check, recorded by the auth rate limiter and in
// sora_authentication_attempts_total{protocol="imap",result="failure"}, with the
// bad-credentials reply. That is the rule docs/AUTHENTICATION.md section 3 gives for
// malformed credentials (#1987), so a client sending them is slowed and blocked
// like one guessing passwords. (#2067)
func TestEmptyPasswordIsAFailedLogin(t *testing.T) {
	const name = "empty-password"
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	limiter := &unparseableLoginLimiter{}
	srv, err := New(ctx, name, "localhost", addr, &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, &cache.Cache{}, IMAPServerOptions{
		InsecureAuth:        true,
		AppendLimit:         DefaultAppendLimit,
		MaxConnections:      10,
		Config:              &config.Config{},
		AuthLimiterOverride: limiter,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	serveReloadTestServer(t, srv, addr)

	cases := []struct{ name, command string }{
		{"LOGIN", `a LOGIN user@example.com ""`},
		{"AUTHENTICATE_PLAIN", "a AUTHENTICATE PLAIN " + base64.StdEncoding.EncodeToString([]byte("\x00user@example.com\x00"))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			r := bufio.NewReader(c)
			readTagged(t, r, "* OK")

			counter := metrics.AuthenticationAttempts.WithLabelValues("imap", name, "localhost", "failure")
			checks, failures, counted := limiter.checks.Load(), limiter.failures.Load(), testutil.ToFloat64(counter)
			c.Write([]byte(tc.command + "\r\n"))
			if reply, want := strings.TrimSpace(readTagged(t, r, "a ")), "a NO [AUTHENTICATIONFAILED] "+authFailedError().Text; reply != want {
				t.Errorf("reply %q, want the bad-credentials reply %q", reply, want)
			}
			if n := limiter.checks.Load() - checks; n != 1 {
				t.Errorf("the auth rate limiter was consulted %d times, want 1", n)
			}
			if n := limiter.failures.Load() - failures; n != 1 {
				t.Errorf("%d failed attempts recorded in the auth rate limiter, want 1", n)
			}
			if grew := testutil.ToFloat64(counter) - counted; grew != 1 {
				t.Errorf("sora_authentication_attempts_total{protocol=\"imap\",result=\"failure\"} grew by %v, want 1", grew)
			}
		})
	}
}
