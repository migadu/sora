package imapproxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestIMAPProxyEmptyPasswordIsAFailedLogin: an empty password, by LOGIN or by
// AUTHENTICATE PLAIN, is a credential no account can have. The proxy refuses it
// without asking the lookup service, but like any other failed login: recorded by
// the auth rate limiter and in
// sora_authentication_attempts_total{protocol="imap_proxy",result="failure"}, the
// rule of docs/AUTHENTICATION.md section 3 (#1987). (#2067)
func TestIMAPProxyEmptyPasswordIsAFailedLogin(t *testing.T) {
	const name = "empty-password"
	var lookups atomic.Int32
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lookups.Add(1)
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer lookup.Close()

	srv, err := New(context.Background(), &resilient.ResilientDatabase{}, "localhost", ServerOptions{
		Name: name, Addr: "127.0.0.1:0", RemoteAddrs: []string{"127.0.0.1:1"}, ConnectTimeout: time.Second,
		InsecureAuth: true,
		RemoteLookup: &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "/lookup?email=$email", Timeout: "2s"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Stop()
	limiter := &verdictlessLimiter{}
	srv.authLimiter = limiter
	failures := func() float64 {
		return testutil.ToFloat64(metrics.AuthenticationAttempts.WithLabelValues("imap_proxy", name, "localhost", "failure"))
	}

	cases := []struct {
		name  string
		login func(s *Session) error
	}{
		{"LOGIN", func(s *Session) error { return s.authenticateUser("user@example.com", "") }},
		{"AUTHENTICATE_PLAIN", func(s *Session) error { return s.authenticateUserWithAuthzID("", "user@example.com", "") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, remote := net.Pipe()
			defer client.Close()
			defer remote.Close()
			asked, recorded, before := lookups.Load(), limiter.failures.Load(), failures()
			if err := tc.login(newSession(srv, remote)); !errors.Is(err, consts.ErrAuthenticationFailed) {
				t.Errorf("login: %v, want %v", err, consts.ErrAuthenticationFailed)
			}
			if n := lookups.Load() - asked; n != 0 {
				t.Errorf("the lookup service was asked %d times", n)
			}
			if n := limiter.failures.Load() - recorded; n != 1 {
				t.Errorf("%d failed attempts recorded in the auth rate limiter, want 1", n)
			}
			if grew := failures() - before; grew != 1 {
				t.Errorf("sora_authentication_attempts_total{protocol=\"imap_proxy\",result=\"failure\"} grew by %v, want 1", grew)
			}
		})
	}
}
