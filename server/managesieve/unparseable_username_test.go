package managesieve

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
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
func (l *unparseableLoginLimiter) CanAttemptAuthWithProxy(context.Context, net.Conn, *server.ProxyProtocolInfo, string) error {
	l.checks.Add(1)
	return nil
}
func (l *unparseableLoginLimiter) RecordAuthAttempt(_ context.Context, _ net.Addr, _ string, success bool) {
	if !success {
		l.failures.Add(1)
	}
}
func (l *unparseableLoginLimiter) RecordAuthAttemptWithProxy(_ context.Context, _ net.Conn, _ *server.ProxyProtocolInfo, _ string, success bool) {
	if !success {
		l.failures.Add(1)
	}
}
func (l *unparseableLoginLimiter) IsIPBlocked(net.Addr) bool { return false }
func (l *unparseableLoginLimiter) IsIPBlockedWithProxy(net.Conn, *server.ProxyProtocolInfo) bool {
	return false
}
func (l *unparseableLoginLimiter) GetStats(context.Context, time.Duration) map[string]any { return nil }
func (l *unparseableLoginLimiter) Stop()                                                  {}

// TestUnparseableUsernameIsAFailedLogin: a login whose username does not parse as an
// address is a failed login like any other. It passes the progressive delay and the
// rate-limit check, is recorded as a failure by the auth rate limiter, and is counted
// in sora_authentication_attempts_total{result="failure"}, on LOGIN as on AUTHENTICATE.
// The master-SASL-shaped self-login (authorization identity = authentication identity
// = the master SASL username, wrong password) falls through to that path.
func TestUnparseableUsernameIsAFailedLogin(t *testing.T) {
	const name = "unparseable-username"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	limiter := &unparseableLoginLimiter{}
	srv, err := New(ctx, name, "localhost", "127.0.0.1:0", &resilient.ResilientDatabase{}, ManageSieveServerOptions{
		MasterSASLUsername:  "proxyuser",
		MasterSASLPassword:  "master-sasl-secret",
		AuthLimiterOverride: limiter,
		Config:              &config.Config{},
	})
	if err != nil {
		t.Fatal(err)
	}
	failures := func() float64 {
		return testutil.ToFloat64(metrics.AuthenticationAttempts.WithLabelValues("managesieve", name, "localhost", "failure"))
	}

	logins := []struct {
		name  string
		login func(s *ManageSieveSession) error
	}{
		{"LOGIN", func(s *ManageSieveSession) error {
			return s.Login(ctx, "not-an-address", "secret")
		}},
		{"AUTHENTICATE", func(s *ManageSieveSession) error {
			return s.AuthenticatePlain(ctx, "", "not-an-address", "secret")
		}},
		{"AUTHENTICATE/master_SASL_self_login", func(s *ManageSieveSession) error {
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
			s := &ManageSieveSession{server: srv, conn: c1, ctx: sctx, cancel: scancel, startTime: time.Now()}
			s.Protocol = "ManageSieve"
			s.RemoteIP = "127.0.0.1"
			s.Id = "sess"
			s.Stats = srv
			s.mutexHelper = server.NewMutexTimeoutHelper(&s.mutex, sctx, "MANAGESIEVE", func(string, ...any) {})

			checks, recorded, before := limiter.checks.Load(), limiter.failures.Load(), failures()
			if err := tc.login(s); err == nil {
				t.Fatal("a login with an unparseable username succeeded")
			}
			if n := limiter.checks.Load() - checks; n != 1 {
				t.Errorf("the auth rate limiter was consulted %d times, want 1", n)
			}
			if n := limiter.failures.Load() - recorded; n != 1 {
				t.Errorf("%d failed attempts recorded in the auth rate limiter, want 1", n)
			}
			if grew := failures() - before; grew != 1 {
				t.Errorf("sora_authentication_attempts_total{result=\"failure\"} grew by %v, want 1", grew)
			}
		})
	}
}

// refusingLoginLimiter refuses every attempt, as a limiter does once a key is blocked,
// and counts the failed attempts recorded.
type refusingLoginLimiter struct{ unparseableLoginLimiter }

func (l *refusingLoginLimiter) CanAttemptAuthWithProxy(context.Context, net.Conn, *server.ProxyProtocolInfo, string) error {
	l.checks.Add(1)
	return server.ErrRateLimitExceeded
}

// TestUnparseableUsernameIsGatedBeforeItIsRecorded: the record for an unparseable
// username sits BEHIND the rate-limit gate. Recording a failure at a site the gate does
// not protect is worse than not recording it: the attempt feeds the source IP's Tier-2
// counter, which is enforced at TCP accept, at full connection rate, while the block it
// earns is never applied to the attempts creating it. On a shared egress that blocks
// every other user behind the same address. A refused attempt therefore records
// nothing and is answered like a bad credential, as the parser's own refusal is.
func TestUnparseableUsernameIsGatedBeforeItIsRecorded(t *testing.T) {
	const name = "unparseable-username-gated"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	limiter := &refusingLoginLimiter{}
	srv, err := New(ctx, name, "localhost", "127.0.0.1:0", &resilient.ResilientDatabase{}, ManageSieveServerOptions{
		AuthLimiterOverride: limiter,
		Config:              &config.Config{},
	})
	if err != nil {
		t.Fatal(err)
	}

	logins := []struct {
		name  string
		login func(s *ManageSieveSession) error
	}{
		{"LOGIN", func(s *ManageSieveSession) error {
			return s.Login(ctx, "not-an-address", "secret")
		}},
		{"AUTHENTICATE", func(s *ManageSieveSession) error {
			return s.AuthenticatePlain(ctx, "", "not-an-address", "secret")
		}},
	}
	for _, tc := range logins {
		t.Run(tc.name, func(t *testing.T) {
			c1, c2 := net.Pipe()
			defer c1.Close()
			defer c2.Close()
			sctx, scancel := context.WithCancel(ctx)
			defer scancel()
			s := &ManageSieveSession{server: srv, conn: c1, ctx: sctx, cancel: scancel, startTime: time.Now()}
			s.Protocol = "ManageSieve"
			s.RemoteIP = "127.0.0.1"
			s.Id = "sess"
			s.Stats = srv
			s.mutexHelper = server.NewMutexTimeoutHelper(&s.mutex, sctx, "MANAGESIEVE", func(string, ...any) {})

			checks, recorded := limiter.checks.Load(), limiter.failures.Load()
			if err := tc.login(s); err != errAuthFailed {
				t.Errorf("a refused login with an unparseable username: %#v, want the bad-credential reply %#v", err, errAuthFailed)
			}
			if n := limiter.checks.Load() - checks; n != 1 {
				t.Errorf("the auth rate limiter was consulted %d times, want 1", n)
			}
			if n := limiter.failures.Load() - recorded; n != 0 {
				t.Errorf("%d failed attempts recorded for a login the gate refused, want 0: the username reached the parser", n)
			}
		})
	}
}
