package pop3

import (
	"context"
	"fmt"
	"net"
	"testing"

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

// TestMalformedCredentialsAreFailedLogins: credentials that no account can have
// (a user name that does not parse, a user name or password that is not valid
// UTF-8, an empty password) follow one rule on the POP3 backend, whatever makes
// them malformed and however they are sent: refused with the bad-credentials reply
// without a lookup, but as a failed login, past the rate-limit check and recorded
// by the auth rate limiter and in
// sora_authentication_attempts_total{protocol="pop3",result="failure"}. A client
// sending garbage is then slowed and blocked like one guessing passwords. This
// server has no database: a login that reaches the lookup panics. (#1987)
func TestMalformedCredentialsAreFailedLogins(t *testing.T) {
	const name = "malformed-credentials"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	limiter := &unparseableLoginLimiter{}
	srv, err := New(ctx, name, "localhost", "127.0.0.1:0", &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, &cache.Cache{}, POP3ServerOptions{
		InsecureAuth:        true,
		Config:              &config.Config{},
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
		{"USER_PASS/unparseable user name", func(s *POP3Session) error {
			return s.Login(ctx, "not-an-address", "secret")
		}},
		{"USER_PASS/user name not UTF-8", func(s *POP3Session) error {
			return s.Login(ctx, "jos\xe9@example.com", "secret")
		}},
		{"USER_PASS/password not UTF-8", func(s *POP3Session) error {
			return s.Login(ctx, "user@example.com", "caf\xe9")
		}},
		{"USER_PASS/empty password", func(s *POP3Session) error {
			return s.Login(ctx, "user@example.com", `""`) // unquoted to ""
		}},
		{"AUTH_PLAIN/password not UTF-8", func(s *POP3Session) error {
			return s.AuthenticatePlain(ctx, "", "user@example.com", "secret\x80")
		}},
		{"AUTH_PLAIN/empty password", func(s *POP3Session) error {
			return s.AuthenticatePlain(ctx, "", "user@example.com", "")
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
			err := func() (err error) {
				defer func() {
					if r := recover(); r != nil {
						err = fmt.Errorf("the credentials were looked up (no database here): %v", r)
					}
				}()
				return tc.login(s)
			}()
			if reply, ok := err.(*pop3server.Error); !ok || reply.Code != "AUTH" || reply.Message != "Authentication failed" {
				t.Fatalf("login: %v, want -ERR [AUTH] Authentication failed", err)
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
