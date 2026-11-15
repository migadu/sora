package pop3

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/go-pop3/pop3server"
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
// in sora_authentication_attempts_total{protocol="pop3",result="failure"}, as the
// ManageSieve backend counts it. The master-SASL-shaped self-login (authorization
// identity = authentication identity = the master SASL username, wrong password)
// falls through to that path, so without the count a master-password guess in that
// form was invisible to failed-login monitoring while every other form was counted.
func TestUnparseableUsernameIsAFailedLogin(t *testing.T) {
	const name = "unparseable-username"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	limiter := &unparseableLoginLimiter{}
	srv, err := New(ctx, name, "localhost", "127.0.0.1:0", &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, &cache.Cache{}, POP3ServerOptions{
		InsecureAuth:        true,
		Config:              &config.Config{},
		MasterSASLUsername:  "proxyuser",
		MasterSASLPassword:  "master-sasl-secret",
		AuthLimiterOverride: limiter,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(srv.Close)
	failures := func() float64 {
		return testutil.ToFloat64(metrics.AuthenticationAttempts.WithLabelValues("pop3", name, "localhost", "failure"))
	}

	logins := []struct {
		name  string
		login func(s *POP3Session) error
	}{
		{"USER_PASS", func(s *POP3Session) error {
			return s.Login(ctx, "not-an-address", "secret")
		}},
		{"AUTH_PLAIN", func(s *POP3Session) error {
			return s.AuthenticatePlain(ctx, "", "not-an-address", "secret")
		}},
		{"AUTH_PLAIN/master_SASL_self_login", func(s *POP3Session) error {
			return s.AuthenticatePlain(ctx, "proxyuser", "proxyuser", "wrong")
		}},
	}
	for _, tc := range logins {
		t.Run(tc.name, func(t *testing.T) {
			c1, c2 := net.Pipe()
			defer c1.Close()
			defer c2.Close()
			sctx, scancel := context.WithCancel(ctx)
			defer scancel()
			s := &POP3Session{server: srv, conn: c1, deleted: make(map[int]bool), ctx: sctx, cancel: scancel}
			s.Protocol = "POP3"
			s.ServerName = srv.name
			s.HostName = srv.hostname
			s.RemoteIP = "127.0.0.1"
			s.mutexHelper = serverPkg.NewMutexTimeoutHelper(&s.mutex, sctx, "POP3", s.InfoLog)

			checks, recorded, before := limiter.checks.Load(), limiter.failures.Load(), failures()
			err := tc.login(s)
			if reply, ok := err.(*pop3server.Error); !ok || reply.Code != "AUTH" {
				t.Errorf("login with an unparseable username: %v, want -ERR [AUTH] ...", err)
			}
			if n := limiter.checks.Load() - checks; n != 1 {
				t.Errorf("the auth rate limiter was consulted %d times, want 1", n)
			}
			if n := limiter.failures.Load() - recorded; n != 1 {
				t.Errorf("%d failed attempts recorded in the auth rate limiter, want 1", n)
			}
			if grew := failures() - before; grew != 1 {
				t.Errorf("sora_authentication_attempts_total{protocol=\"pop3\",result=\"failure\"} grew by %v, want 1", grew)
			}
		})
	}
}
