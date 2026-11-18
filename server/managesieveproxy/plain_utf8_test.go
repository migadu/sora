package managesieveproxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/crypto/bcrypt"
)

// TestManageSieveProxyAuthenticatePlainWithInvalidUTF8IsAFailedLogin: RFC 4616
// section 2 defines every field of a PLAIN message as UTF-8. A message whose
// authorization identity, authentication identity or password is not valid UTF-8
// names no account, so the proxy refuses it with the bad-credentials reply without
// asking the lookup service, as a failed login recorded by the auth rate limiter
// and in sora_authentication_attempts_total{protocol="managesieve_proxy",
// result="failure"}. The lookup service here accepts every user with the password
// "secret". (#1988)
func TestManageSieveProxyAuthenticatePlainWithInvalidUTF8IsAFailedLogin(t *testing.T) {
	const name = "plain-invalid-utf8"
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	var lookups atomic.Int32
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lookups.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"address": r.URL.Query().Get("email"), "password_hash": string(hash)})
	}))
	defer lookup.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := freeTestAddr(t)
	srv, err := New(ctx, &resilient.ResilientDatabase{}, "localhost", ServerOptions{
		Name: name, Addr: addr, RemoteAddrs: []string{"127.0.0.1:1"}, ConnectTimeout: time.Second,
		InsecureAuth: true,
		RemoteLookup: &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "/lookup?email=$email", Timeout: "2s"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	limiter := &failureCountingLimiter{}
	srv.authLimiter = limiter
	go func() { _ = srv.Start() }()
	defer srv.Stop()
	failures := func() float64 {
		return testutil.ToFloat64(metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", name, "localhost", "failure"))
	}

	cases := []struct{ name, authzid, authcid, password string }{
		{"authorization identity", "jos\xe9@example.com", "user1@example.com", "secret"},
		{"authentication identity", "", "jos\xe9@example.com", "secret"},
		{"password", "", "user2@example.com", "caf\xe9"},
	} // one user per case: a cached login would answer the next case without a lookup
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, r := dialTest(t, addr)
			readLineWithPrefix(t, r, "OK")
			asked, recorded, before := lookups.Load(), limiter.failures.Load(), failures()
			msg := base64.StdEncoding.EncodeToString([]byte(tc.authzid + "\x00" + tc.authcid + "\x00" + tc.password))
			conn.Write([]byte(`AUTHENTICATE "PLAIN" "` + msg + "\"\r\n"))
			if reply := readLineWithPrefix(t, r, "OK", "NO", "BYE"); reply != `NO "Authentication failed"` {
				t.Errorf("AUTHENTICATE PLAIN: %q, want NO \"Authentication failed\"", reply)
			}
			if n := lookups.Load() - asked; n != 0 {
				t.Errorf("the lookup service was asked %d times", n)
			}
			if n := limiter.failures.Load() - recorded; n != 1 {
				t.Errorf("%d failed attempts recorded in the auth rate limiter, want 1", n)
			}
			if grew := failures() - before; grew != 1 {
				t.Errorf("sora_authentication_attempts_total{protocol=\"managesieve_proxy\",result=\"failure\"} grew by %v, want 1", grew)
			}
		})
	}
}
