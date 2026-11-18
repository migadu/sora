package managesieve

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestAuthenticatePlainWithInvalidUTF8IsAFailedLogin: RFC 4616 section 2 defines
// every field of a PLAIN message as UTF-8 ("authzid = 1*SAFE", SAFE being "any
// UTF-8 encoded Unicode character except NUL"). A message whose authorization
// identity, authentication identity or password is not valid UTF-8 names no
// account, so it is refused with the bad-credentials reply before anything is
// looked up, as a failed login: one rate-limit check, one recorded failure, one
// counted failure. This server has no database: a login that reaches the lookup
// panics. (#1988)
func TestAuthenticatePlainWithInvalidUTF8IsAFailedLogin(t *testing.T) {
	const name = "plain-invalid-utf8"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	limiter := &unparseableLoginLimiter{}
	srv, err := New(ctx, name, "localhost", "127.0.0.1:0", &resilient.ResilientDatabase{}, ManageSieveServerOptions{
		AuthLimiterOverride: limiter,
		Config:              &config.Config{},
	})
	if err != nil {
		t.Fatal(err)
	}
	failures := func() float64 {
		return testutil.ToFloat64(metrics.AuthenticationAttempts.WithLabelValues("managesieve", name, "localhost", "failure"))
	}

	cases := []struct{ name, authzid, authcid, password string }{
		{"authorization identity", "jos\xe9@example.com", "user@example.com", "secret"},
		{"authentication identity", "", "jos\xe9@example.com", "secret"},
		{"password", "", "user@example.com", "caf\xe9"},
	}
	for _, tc := range cases {
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
			err := func() (err error) {
				defer func() {
					if r := recover(); r != nil {
						err = fmt.Errorf("the credentials were looked up (no database here): %v", r)
					}
				}()
				return s.AuthenticatePlain(sctx, tc.authzid, tc.authcid, tc.password)
			}()
			if err != errAuthFailed {
				t.Fatalf("AUTHENTICATE PLAIN: %v, want %v", err, errAuthFailed)
			}
			if n := limiter.checks.Load() - checks; n != 1 {
				t.Errorf("the auth rate limiter was consulted %d times, want 1", n)
			}
			if n := limiter.failures.Load() - recorded; n != 1 {
				t.Errorf("%d failed attempts recorded in the auth rate limiter, want 1", n)
			}
			if grew := failures() - before; grew != 1 {
				t.Errorf("sora_authentication_attempts_total{protocol=\"managesieve\",result=\"failure\"} grew by %v, want 1", grew)
			}
		})
	}
}
