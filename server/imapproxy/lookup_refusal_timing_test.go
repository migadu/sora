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
	"github.com/migadu/sora/testutils"
	"golang.org/x/crypto/bcrypt"
)

// lookupRefusal is what two logins with the same wrong password leave behind.
type lookupRefusal struct {
	errs          [2]string
	verifications [2]int // password verifications each login ran
	failures      int32  // failed attempts charged to the auth rate limiter
	lookups       int32  // requests that reached the lookup service
	cached        bool   // a lookup-cache entry was written for the user
	successKeys   string // the rate-limit keys successes were recorded under
}

func refuseTwiceAgainstLookup(t *testing.T, answer http.HandlerFunc) lookupRefusal {
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
		before := testutils.PasswordVerifications()
		out.errs[i] = fmt.Sprint(newSession(srv, remote).authenticateUser("anna@example.com", "wrong-password"))
		out.verifications[i] = testutils.PasswordVerifications() - before
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
//
// The verifications are counted, not timed (#782): a wall-clock floor calibrated
// under CPU contention fails a correct login that runs after the contention eases.
// The dummy hash follows BcryptCost, so a refusal verifying it does the same bcrypt
// work as one verifying the returned hash (TestDummyBcryptHash_Valid), and the cheapest
// cost keeps the test fast.
func TestIMAPProxyLookupRefusalsLookAlike(t *testing.T) {
	origCost := db.BcryptCost
	db.BcryptCost = bcrypt.MinCost
	t.Cleanup(func() { db.BcryptCost = origCost })

	hash, err := db.GenerateBcryptHash("right-password")
	if err != nil {
		t.Fatalf("GenerateBcryptHash: %v", err)
	}

	known := refuseTwiceAgainstLookup(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"address": "anna@example.com", "password_hash": hash})
	})
	if known.verifications[0] != 1 || known.lookups != 1 || !known.cached {
		t.Fatalf("known address, wrong password: %+v; want one verification, one lookup and a cached refusal", known)
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
			if got := refuseTwiceAgainstLookup(t, c.answer); got != known {
				t.Errorf("lookup answered %s: %+v\nknown address, wrong password: %+v", c.name, got, known)
			}
		})
	}
}
