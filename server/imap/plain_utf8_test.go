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

// TestAuthenticatePlainWithInvalidUTF8IsAFailedLogin: RFC 4616 section 2 defines
// every field of a PLAIN message as UTF-8 ("authzid = 1*SAFE", SAFE being "any
// UTF-8 encoded Unicode character except NUL"). A message whose authorization
// identity, authentication identity or password is not valid UTF-8 names no
// account, so it is refused with the bad-credentials reply before anything is
// looked up, as a failed login: one rate-limit check, one recorded failure, one
// counted failure. This server has no database: a login that reaches the lookup
// gets no such reply. (#1988)
func TestAuthenticatePlainWithInvalidUTF8IsAFailedLogin(t *testing.T) {
	const name = "plain-invalid-utf8"
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

	cases := []struct{ name, authzid, authcid, password string }{
		{"authorization identity", "jos\xe9@example.com", "user@example.com", "secret"},
		{"authentication identity", "", "jos\xe9@example.com", "secret"},
		{"password", "", "user@example.com", "caf\xe9"},
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
			msg := base64.StdEncoding.EncodeToString([]byte(tc.authzid + "\x00" + tc.authcid + "\x00" + tc.password))
			c.Write([]byte("a AUTHENTICATE PLAIN " + msg + "\r\n"))
			if reply, want := strings.TrimSpace(readTagged(t, r, "a ")), "a NO [AUTHENTICATIONFAILED] "+authFailedError().Text; reply != want {
				t.Fatalf("reply %q, want %q", reply, want)
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
