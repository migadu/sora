package pop3proxy

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestPOP3ProxyMalformedCredentialsAreFailedLogins: credentials that no account can
// have (a user name that does not parse, a user name or password that is not valid
// UTF-8, an empty password) follow one rule on the POP3 proxy, as on the backend:
// refused with the bad-credentials reply without a lookup, but as a failed login,
// recorded by the auth rate limiter and in
// sora_authentication_attempts_total{protocol="pop3_proxy",result="failure"}. This
// proxy has no database: a login that reaches the lookup fails another way. (#1987)
func TestPOP3ProxyMalformedCredentialsAreFailedLogins(t *testing.T) {
	const name = "malformed-credentials"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := freeTestAddr(t)
	srv, err := New(ctx, "localhost", addr, &resilient.ResilientDatabase{}, POP3ProxyServerOptions{
		Name: name, RemoteAddrs: []string{"127.0.0.1:1"}, ConnectTimeout: time.Second,
		InsecureAuth: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	limiter := &failureCountingLimiter{}
	srv.authLimiter = limiter
	go func() { _ = srv.Start() }()
	defer srv.Stop()

	plain := func(authcid, password string) []string {
		return []string{"AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte("\x00"+authcid+"\x00"+password))}
	}
	cases := []struct {
		name     string
		commands []string // the last one is the login
	}{
		{"USER_PASS/unparseable user name", []string{"USER not-an-address", "PASS secret"}},
		{"USER_PASS/user name not UTF-8", []string{"USER jos\xe9@example.com", "PASS secret"}},
		{"USER_PASS/password not UTF-8", []string{"USER user@example.com", "PASS caf\xe9"}},
		{"USER_PASS/empty password", []string{"USER user@example.com", `PASS ""`}}, // unquoted to ""
		{"AUTH_PLAIN/password not UTF-8", plain("user@example.com", "secret\x80")},
		{"AUTH_PLAIN/empty password", plain("user@example.com", "")},
	}
	failures := func() float64 {
		return testutil.ToFloat64(metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", name, "localhost", "failure"))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, r := dialTest(t, addr)
			defer conn.Close()
			readLineWithPrefix(t, r, "+OK")

			recorded, before := limiter.failures.Load(), failures()
			for _, cmd := range tc.commands[:len(tc.commands)-1] {
				conn.Write([]byte(cmd + "\r\n"))
				readLineWithPrefix(t, r, "+OK")
			}
			conn.Write([]byte(tc.commands[len(tc.commands)-1] + "\r\n"))
			if reply := readLineWithPrefix(t, r, "+OK", "-ERR"); reply != "-ERR [AUTH] Authentication failed" {
				t.Fatalf("login reply %q, want -ERR [AUTH] Authentication failed", reply)
			}
			if n := limiter.failures.Load() - recorded; n != 1 {
				t.Errorf("%d failed attempts recorded in the auth rate limiter, want 1", n)
			}
			if grew := failures() - before; grew != 1 {
				t.Errorf("sora_authentication_attempts_total{protocol=\"pop3_proxy\",result=\"failure\"} grew by %v, want 1", grew)
			}
		})
	}
}
