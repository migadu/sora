package managesieve

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestAuthenticateEmptyPasswordIsAFailedLogin: AUTHENTICATE PLAIN with an empty
// password is a credential no account can have. Over the wire, it is refused with
// the bad-credentials reply without a lookup, but like any other failed login: one
// rate-limit check, one recorded failure, one counted failure (docs/AUTHENTICATION.md
// section 3). This server has no database: a login that reaches the lookup gets no
// such reply. (#2067)
func TestAuthenticateEmptyPasswordIsAFailedLogin(t *testing.T) {
	const name = "authenticate-empty-password"
	limiter := &unparseableLoginLimiter{}
	srv := newServerForConfig(t, config.ServerConfig{Name: name}, ManageSieveServerOptions{
		InsecureAuth:        true,
		AuthLimiterOverride: limiter,
	})
	conn, r, _ := dialManageSieve(t, srv)

	counter := metrics.AuthenticationAttempts.WithLabelValues("managesieve", name, "localhost", "failure")
	checks, failures, counted := limiter.checks.Load(), limiter.failures.Load(), testutil.ToFloat64(counter)
	conn.Write([]byte(`AUTHENTICATE "PLAIN" "` + base64.StdEncoding.EncodeToString([]byte("\x00user@example.com\x00")) + "\"\r\n"))
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the AUTHENTICATE reply: %v", err)
	}
	if reply := strings.TrimRight(line, "\r\n"); reply != `NO "Authentication failed"` {
		t.Errorf("reply %q, want NO \"Authentication failed\"", reply)
	}
	if n := limiter.checks.Load() - checks; n != 1 {
		t.Errorf("the auth rate limiter was consulted %d times, want 1", n)
	}
	if n := limiter.failures.Load() - failures; n != 1 {
		t.Errorf("%d failed attempts recorded in the auth rate limiter, want 1", n)
	}
	if grew := testutil.ToFloat64(counter) - counted; grew != 1 {
		t.Errorf("sora_authentication_attempts_total{protocol=\"managesieve\",result=\"failure\"} grew by %v, want 1", grew)
	}
}
