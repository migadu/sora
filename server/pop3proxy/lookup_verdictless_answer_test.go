package pop3proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
)

// verdictlessLimiter allows every attempt and counts the failed ones recorded.
type verdictlessLimiter struct{ failures atomic.Int32 }

func (l *verdictlessLimiter) CanAttemptAuth(context.Context, net.Addr, string) error { return nil }
func (l *verdictlessLimiter) CanAttemptAuthWithProxy(context.Context, net.Conn, *server.ProxyProtocolInfo, string) error {
	return nil
}
func (l *verdictlessLimiter) RecordAuthAttempt(_ context.Context, _ net.Addr, _ string, success bool) {
	if !success {
		l.failures.Add(1)
	}
}
func (l *verdictlessLimiter) RecordAuthAttemptWithProxy(_ context.Context, _ net.Conn, _ *server.ProxyProtocolInfo, _ string, success bool) {
	if !success {
		l.failures.Add(1)
	}
}
func (l *verdictlessLimiter) IsIPBlocked(net.Addr) bool { return false }
func (l *verdictlessLimiter) IsIPBlockedWithProxy(net.Conn, *server.ProxyProtocolInfo) bool {
	return false
}
func (l *verdictlessLimiter) GetStats(context.Context, time.Duration) map[string]any { return nil }
func (l *verdictlessLimiter) Stop()                                                  {}

// verdictlessOutcome is what two logins with the same password leave behind.
type verdictlessOutcome struct {
	errs     [2]string
	failures int32 // failed attempts charged to the auth rate limiter
	lookups  int32 // requests that reached the lookup service
	cached   bool  // a lookup-cache entry was written for the user
}

func loginTwiceAgainstLookup(t *testing.T, answer http.HandlerFunc) verdictlessOutcome {
	t.Helper()
	var lookups atomic.Int32
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lookups.Add(1)
		answer(w, r)
	}))
	defer lookup.Close()

	srv, err := New(context.Background(), "localhost", "127.0.0.1:0", &resilient.ResilientDatabase{}, POP3ProxyServerOptions{
		Name: "verdictless", RemoteAddrs: []string{"127.0.0.1:1"}, ConnectTimeout: time.Second,
		InsecureAuth: true,
		RemoteLookup: &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "/lookup?email=$email", Timeout: "2s"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Stop()
	limiter := &verdictlessLimiter{}
	srv.authLimiter = limiter

	var out verdictlessOutcome
	for i := range out.errs {
		client, remote := net.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		sess := &POP3ProxySession{server: srv, clientConn: remote, listenerConn: remote, ctx: ctx, cancel: cancel}
		out.errs[i] = fmt.Sprint(sess.authenticate("anna@example.com", "secret"))
		cancel()
		client.Close()
		remote.Close()
	}
	out.failures = limiter.failures.Load()
	out.lookups = lookups.Load()
	_, out.cached = srv.lookupCache.Get(srv.name, "anna@example.com")
	return out
}

// TestPOP3ProxyVerdictlessLookupAnswersAreAnOutage: a lookup answer that says nothing
// about the password (429, 408, another 4xx, a 200 that is not the documented JSON or
// whose password_hash sora cannot verify) is handled exactly like a lookup outage (503):
// the same reply and rate-limiter charge, nothing cached, so the next login asks the
// lookup service again. Before the fix a 4xx was a wrong password whose negative cache
// entry refused the same (correct) password for negative_ttl, and a malformed 200 had
// its own wrong-password branch. An unverifiable password_hash was a wrong password
// until #499.
func TestPOP3ProxyVerdictlessLookupAnswersAreAnOutage(t *testing.T) {
	outage := loginTwiceAgainstLookup(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	})
	for _, c := range []struct {
		name   string
		answer http.HandlerFunc
	}{
		{"429", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "slow down", http.StatusTooManyRequests) }},
		{"408", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "timeout", http.StatusRequestTimeout) }},
		{"400", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "bad request", http.StatusBadRequest) }},
		{"200 not JSON", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>maintenance</html>")) }},
		{"200 without password_hash", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"address": "anna@example.com"}`))
		}},
		{"200 with a password_hash sora cannot verify", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"address": "anna@example.com", "password_hash": "{SHA512-CRYPT}$6$saltsaltsaltsalt$Uz0B733KLAcpeAFT5hlALRwUMzwqxSoBO9VG7Ph8v7auZDaXL8PutBQPqOVLMvwy0rORlpwlXHm83Z4uAhgLB0"}`))
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := loginTwiceAgainstLookup(t, c.answer); got != outage {
				t.Errorf("lookup answered %s: %+v\nlookup outage (503):   %+v", c.name, got, outage)
			}
		})
	}
}
