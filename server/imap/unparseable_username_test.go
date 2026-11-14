package imap

import (
	"bufio"
	"context"
	"encoding/base64"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	serverPkg "github.com/migadu/sora/server"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// unparseableLoginLimiter is an auth limiter that allows every attempt and counts
// the checks made and the failed attempts recorded.
type unparseableLoginLimiter struct {
	checks   atomic.Int32
	failures atomic.Int32
}

func (l *unparseableLoginLimiter) CanAttemptAuth(context.Context, net.Addr, string) error {
	l.checks.Add(1)
	return nil
}
func (l *unparseableLoginLimiter) CanAttemptAuthWithProxy(context.Context, net.Conn, *serverPkg.ProxyProtocolInfo, string) error {
	l.checks.Add(1)
	return nil
}
func (l *unparseableLoginLimiter) RecordAuthAttempt(_ context.Context, _ net.Addr, _ string, success bool) {
	if !success {
		l.failures.Add(1)
	}
}
func (l *unparseableLoginLimiter) RecordAuthAttemptWithProxy(_ context.Context, _ net.Conn, _ *serverPkg.ProxyProtocolInfo, _ string, success bool) {
	if !success {
		l.failures.Add(1)
	}
}
func (l *unparseableLoginLimiter) IsIPBlocked(net.Addr) bool { return false }
func (l *unparseableLoginLimiter) IsIPBlockedWithProxy(net.Conn, *serverPkg.ProxyProtocolInfo) bool {
	return false
}
func (l *unparseableLoginLimiter) GetStats(context.Context, time.Duration) map[string]any { return nil }
func (l *unparseableLoginLimiter) Stop()                                                  {}

// TestUnparseableUsernameIsAFailedLogin: a login whose username does not parse as an
// address is a failed login like any other. It passes the progressive delay and the
// rate-limit check, is recorded as a failure by the auth rate limiter, and is counted
// in sora_authentication_attempts_total{protocol="imap",result="failure"}, as the
// ManageSieve backend counts it. The master-SASL-shaped self-login (authorization
// identity = authentication identity = the master SASL username, wrong password)
// falls through to that path (sasl.go), so without the count a master-password guess
// in that form was invisible to failed-login monitoring while every other form was
// counted.
func TestUnparseableUsernameIsAFailedLogin(t *testing.T) {
	const name = "unparseable-username"
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
		MasterSASLUsername:  []byte("proxyuser"),
		MasterSASLPassword:  []byte("master-sasl-secret"),
		AuthLimiterOverride: limiter,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	serveReloadTestServer(t, srv, addr)
	failures := func() float64 {
		return testutil.ToFloat64(metrics.AuthenticationAttempts.WithLabelValues("imap", name, "localhost", "failure"))
	}

	authenticate := func(identity, username, password string) func(c net.Conn, r *bufio.Reader) string {
		return func(c net.Conn, r *bufio.Reader) string {
			c.Write([]byte("a AUTHENTICATE PLAIN\r\n"))
			readTagged(t, r, "+")
			c.Write([]byte(base64.StdEncoding.EncodeToString([]byte(identity+"\x00"+username+"\x00"+password)) + "\r\n"))
			return readTagged(t, r, "a ")
		}
	}
	logins := []struct {
		name  string
		login func(c net.Conn, r *bufio.Reader) string
	}{
		{"LOGIN", func(c net.Conn, r *bufio.Reader) string {
			c.Write([]byte("a LOGIN not-an-address secret\r\n"))
			return readTagged(t, r, "a ")
		}},
		{"AUTHENTICATE", authenticate("", "not-an-address", "secret")},
		{"AUTHENTICATE/master_SASL_self_login", authenticate("proxyuser", "proxyuser", "wrong")},
	}
	for _, tc := range logins {
		t.Run(tc.name, func(t *testing.T) {
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			r := bufio.NewReader(c)
			readTagged(t, r, "* OK")

			checks, recorded, before := limiter.checks.Load(), limiter.failures.Load(), failures()
			if reply := tc.login(c, r); !strings.HasPrefix(reply, "a NO [AUTHENTICATIONFAILED]") {
				t.Errorf("login with an unparseable username: %q, want a NO [AUTHENTICATIONFAILED] ...", strings.TrimSpace(reply))
			}
			if n := limiter.checks.Load() - checks; n != 1 {
				t.Errorf("the auth rate limiter was consulted %d times, want 1", n)
			}
			if n := limiter.failures.Load() - recorded; n != 1 {
				t.Errorf("%d failed attempts recorded in the auth rate limiter, want 1", n)
			}
			if grew := failures() - before; grew != 1 {
				t.Errorf("sora_authentication_attempts_total{protocol=\"imap\",result=\"failure\"} grew by %v, want 1", grew)
			}
		})
	}
}
