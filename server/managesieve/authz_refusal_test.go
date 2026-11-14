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

// TestAuthorizationRefusalNeedsCredentials: an AUTHENTICATE PLAIN that asks to act as
// another user with a wrong password is answered and counted like any other bad
// credential, whether or not its authentication identity is the master SASL username.
// RFC 4616 section 2 verifies the authentication identity and password first and the
// authorization identity second, so only a client whose credentials checked out may be
// told it cannot act as somebody else. Refusing every other authentication identity
// before the password, unrecorded, while the master SASL username got the
// bad-credential reply and a recorded failure, confirmed a guessed master SASL username
// to anyone who could reach the port.
func TestAuthorizationRefusalNeedsCredentials(t *testing.T) {
	const name = "authz-refusal-needs-credentials"
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

	type outcome struct {
		reply            string
		checks, failures int32
		counted          float64
	}
	attempt := func(authnID string) outcome {
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

		counter := metrics.AuthenticationAttempts.WithLabelValues("managesieve", name, "localhost", "failure")
		checks, failures, counted := limiter.checks.Load(), limiter.failures.Load(), testutil.ToFloat64(counter)
		err := s.AuthenticatePlain(ctx, "victim@example.com", authnID, "wrong")
		return outcome{
			reply:    fmt.Sprintf("%#v", err),
			checks:   limiter.checks.Load() - checks,
			failures: limiter.failures.Load() - failures,
			counted:  testutil.ToFloat64(counter) - counted,
		}
	}

	master := attempt("proxyuser")
	other := attempt("notmaster")
	if master != other {
		t.Errorf("wrong password answered differently by authentication identity:\n  master SASL username: %+v\n  other username:       %+v", master, other)
	}
	if want := (outcome{reply: fmt.Sprintf("%#v", errAuthFailed), checks: 1, failures: 1, counted: 1}); other != want {
		t.Errorf("other username, wrong password: %+v, want %+v (the bad-credential reply, one rate-limit check, one recorded and one counted failure)", other, want)
	}
}
