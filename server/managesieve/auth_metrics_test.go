package managesieve

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/crypto/bcrypt"
)

// TestAuthenticationAttemptsMetrics verifies that ManageSieve AuthenticatePlain
// does not count non-credential refusals in sora_authentication_attempts_total:
//   - an AuthenticatePlain whose credentials succeed for authnID while authzID
//     names another user ("Proxy authentication requires master credentials")
//     must not increment result="failure";
//   - an AuthenticatePlain refused by the rate-limit gate or aborted in delay
//     must not increment result="failure", matching Login.
func TestAuthenticationAttemptsMetrics(t *testing.T) {
	hashed, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword: %v", err)
	}

	newServer := func(t *testing.T, name string, limiter server.AuthLimiter) *ManageSieveServer {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)

		srv, err := New(ctx, name, "localhost", "127.0.0.1:0", &resilient.ResilientDatabase{}, ManageSieveServerOptions{
			Config:              &config.Config{},
			LookupCache:         &config.LookupCacheConfig{Enabled: true},
			AuthLimiterOverride: limiter,
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(srv.Close)
		srv.lookupCache.SetSuccess("alice@example.com", 42, string(hashed), "correct-password")
		return srv
	}

	newSession := func(t *testing.T, srv *ManageSieveServer) *ManageSieveSession {
		t.Helper()
		c1, c2 := net.Pipe()
		t.Cleanup(func() {
			_ = c1.Close()
			_ = c2.Close()
		})
		sctx, scancel := context.WithCancel(context.Background())
		t.Cleanup(scancel)
		s := &ManageSieveSession{
			server:    srv,
			conn:      c1,
			ctx:       sctx,
			cancel:    scancel,
			startTime: time.Now(),
		}
		s.Protocol = "ManageSieve"
		s.RemoteIP = "127.0.0.1"
		s.Id = "sess"
		s.Stats = srv
		s.mutexHelper = server.NewMutexTimeoutHelper(&s.mutex, sctx, "MANAGESIEVE", func(string, ...any) {})
		return s
	}

	metricDeltas := func(name string, fn func()) (successDelta, failureDelta float64) {
		succ := metrics.AuthenticationAttempts.WithLabelValues("managesieve", name, "localhost", "success")
		fail := metrics.AuthenticationAttempts.WithLabelValues("managesieve", name, "localhost", "failure")
		s0, f0 := testutil.ToFloat64(succ), testutil.ToFloat64(fail)
		fn()
		return testutil.ToFloat64(succ) - s0, testutil.ToFloat64(fail) - f0
	}

	t.Run("AuthenticatePlain_proxy_authz_refusal_with_valid_credentials", func(t *testing.T) {
		const name = "test-ms-metrics-authz-refusal"
		srv := newServer(t, name, nil)
		sess := newSession(t, srv)

		sDelta, fDelta := metricDeltas(name, func() {
			err := sess.AuthenticatePlain(context.Background(), "bob@example.com", "alice@example.com", "correct-password")
			if err == nil {
				t.Fatal("AuthenticatePlain succeeded, want authorization refusal")
			}
		})
		if sDelta != 0 || fDelta != 0 {
			t.Errorf("authorization-refused AuthenticatePlain deltas = (success=%v, failure=%v), want (0, 0)", sDelta, fDelta)
		}
	})

	t.Run("AuthenticatePlain_rate_limited_matches_Login", func(t *testing.T) {
		const name = "test-ms-metrics-ratelimited"
		limiter := &blockingAuthLimiter{}
		srv := newServer(t, name, limiter)
		sess := newSession(t, srv)

		loginSucc, loginFail := metricDeltas(name, func() {
			if err := sess.Login(context.Background(), "alice@example.com", "wrong"); !errors.Is(err, errAuthFailed) {
				t.Fatalf("Login err = %v, want errAuthFailed", err)
			}
		})
		saslSucc, saslFail := metricDeltas(name, func() {
			if err := sess.AuthenticatePlain(context.Background(), "", "alice@example.com", "wrong"); !errors.Is(err, errAuthFailed) {
				t.Fatalf("AuthenticatePlain err = %v, want errAuthFailed", err)
			}
		})
		if saslSucc != loginSucc || saslFail != loginFail {
			t.Errorf("rate-limited AuthenticatePlain deltas = (success=%v, failure=%v), want Login's (%v, %v)",
				saslSucc, saslFail, loginSucc, loginFail)
		}
	})

	t.Run("AuthenticatePlain_delay_canceled_matches_Login", func(t *testing.T) {
		const name = "test-ms-metrics-delay-canceled"
		limiter := &slowDelayLimiter{}
		srv := newServer(t, name, limiter)
		sess := newSession(t, srv)

		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		loginSucc, loginFail := metricDeltas(name, func() {
			if err := sess.Login(canceledCtx, "alice@example.com", "wrong"); !errors.Is(err, errAuthFailedClose) {
				t.Fatalf("Login err = %v, want errAuthFailedClose", err)
			}
		})
		saslSucc, saslFail := metricDeltas(name, func() {
			if err := sess.AuthenticatePlain(canceledCtx, "", "alice@example.com", "wrong"); !errors.Is(err, errAuthFailedClose) {
				t.Fatalf("AuthenticatePlain err = %v, want errAuthFailedClose", err)
			}
		})
		if saslSucc != loginSucc || saslFail != loginFail {
			t.Errorf("delay-canceled AuthenticatePlain deltas = (success=%v, failure=%v), want Login's (%v, %v)",
				saslSucc, saslFail, loginSucc, loginFail)
		}
	})
}

type blockingAuthLimiter struct{}

func (b *blockingAuthLimiter) CanAttemptAuth(context.Context, net.Addr, string) error {
	return &server.RateLimitError{Reason: "ip_blocked", BlockedUntil: time.Now().Add(time.Minute)}
}

func (b *blockingAuthLimiter) CanAttemptAuthWithProxy(context.Context, net.Conn, *server.ProxyProtocolInfo, string) error {
	return &server.RateLimitError{Reason: "ip_blocked", BlockedUntil: time.Now().Add(time.Minute)}
}

func (b *blockingAuthLimiter) RecordAuthAttempt(context.Context, net.Addr, string, bool) {}

func (b *blockingAuthLimiter) RecordAuthAttemptWithProxy(context.Context, net.Conn, *server.ProxyProtocolInfo, string, bool) {
}

func (b *blockingAuthLimiter) GetAuthenticationDelay(net.Addr) time.Duration { return 0 }
func (b *blockingAuthLimiter) IsIPBlocked(net.Addr) bool                     { return true }
func (b *blockingAuthLimiter) IsIPBlockedWithProxy(net.Conn, *server.ProxyProtocolInfo) bool {
	return true
}
func (b *blockingAuthLimiter) GetStats(context.Context, time.Duration) map[string]any { return nil }
func (b *blockingAuthLimiter) Stop()                                                  {}

type slowDelayLimiter struct{ blockingAuthLimiter }

func (s *slowDelayLimiter) GetAuthenticationDelay(net.Addr) time.Duration { return time.Second }
