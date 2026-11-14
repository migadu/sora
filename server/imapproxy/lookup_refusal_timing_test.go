package imapproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
)

// lookupRefusal is what two logins with the same wrong password leave behind.
type lookupRefusal struct {
	errs     [2]string
	verified bool  // the first refusal took at least half a password verification
	failures int32 // failed attempts charged to the auth rate limiter
	lookups  int32 // requests that reached the lookup service
	cached   bool  // a lookup-cache entry was written for the user
}

func refuseTwiceAgainstLookup(t *testing.T, verification time.Duration, answer http.HandlerFunc) lookupRefusal {
	t.Helper()
	var lookups atomic.Int32
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lookups.Add(1)
		answer(w, r)
	}))
	defer lookup.Close()

	// lookup_local_users is off: the lookup service is authoritative.
	srv, err := New(context.Background(), &resilient.ResilientDatabase{}, "localhost", ServerOptions{
		Name: "refusal", Addr: "127.0.0.1:0", RemoteAddrs: []string{"127.0.0.1:1"}, ConnectTimeout: time.Second,
		InsecureAuth: true,
		RemoteLookup: &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "/lookup?email=$email", Timeout: "2s"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Stop()
	limiter := &verdictlessLimiter{}
	srv.authLimiter = limiter

	var out lookupRefusal
	for i := range out.errs {
		client, remote := net.Pipe()
		start := time.Now()
		out.errs[i] = fmt.Sprint(newSession(srv, remote).authenticateUser("anna@example.com", "wrong-password"))
		if i == 0 {
			out.verified = time.Since(start) >= verification/2
		}
		client.Close()
		remote.Close()
	}
	out.failures = limiter.failures.Load()
	out.lookups = lookups.Load()
	_, out.cached = srv.lookupCache.Get(srv.name, "anna@example.com")
	return out
}

// TestIMAPProxyLookupRefusalsLookAlike: the lookup service never sees the password, so
// for an address it knows the proxy verifies the password against the returned hash
// before refusing a wrong one. Every other refusal must cost the same verification and
// be cached the same way, or the response time to a login (and to its repeat) shows
// whether the lookup service knows the address. Before the fix a 404 or 3xx (with
// lookup_local_users off) and a 401 or 403 were refused without a verification, and a
// 404 or 3xx was not cached, so a repeat of the same password asked the service again.
func TestIMAPProxyLookupRefusalsLookAlike(t *testing.T) {
	// Cost 10 keeps one verification in the tens of milliseconds, far above a lookup
	// round trip on loopback. The dummy hash follows BcryptCost.
	origCost := db.BcryptCost
	db.BcryptCost = 10
	t.Cleanup(func() { db.BcryptCost = origCost })

	hash, err := db.GenerateBcryptHash("right-password")
	if err != nil {
		t.Fatalf("GenerateBcryptHash: %v", err)
	}
	// One password verification. Load only ever adds time, so the fastest of a few runs
	// is the floor.
	db.DummyVerifyPassword("warm-up") // generates the dummy hash at this cost
	verification := time.Duration(1 << 62)
	for range 3 {
		start := time.Now()
		db.DummyVerifyPassword("wrong-password")
		verification = min(verification, time.Since(start))
	}

	known := refuseTwiceAgainstLookup(t, verification, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"address": "anna@example.com", "password_hash": hash})
	})
	if !known.verified || known.lookups != 1 || !known.cached {
		t.Fatalf("known address, wrong password: %+v; want a verification, one lookup and a cached refusal", known)
	}
	for _, c := range []struct {
		name   string
		answer http.HandlerFunc
	}{
		{"404", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }},
		{"302", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/elsewhere", http.StatusFound) }},
		{"401", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "refused", http.StatusUnauthorized) }},
		{"403", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "refused", http.StatusForbidden) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := refuseTwiceAgainstLookup(t, verification, c.answer); got != known {
				t.Errorf("lookup answered %s: %+v\nknown address, wrong password: %+v", c.name, got, known)
			}
		})
	}
}
