package userapiproxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
	"github.com/migadu/sora/testutils"
	"golang.org/x/crypto/bcrypt"
)

const (
	rateLimitKnown         = "known@example.com"
	rateLimitRightPassword = "right-password"
)

// knownAddressLookup is a routing lookup that knows one address, in pool sora0, and
// answers every other one 404.
type knownAddressLookup struct{}

func (knownAddressLookup) LookupUserRoute(ctx context.Context, email, password string) (*proxy.UserRoutingInfo, proxy.AuthResult, error) {
	return knownAddressLookup{}.LookupUserRouteWithOptions(ctx, email, password, true)
}
func (knownAddressLookup) LookupUserRouteWithOptions(_ context.Context, email, _ string, _ bool) (*proxy.UserRoutingInfo, proxy.AuthResult, error) {
	if email == rateLimitKnown {
		return &proxy.UserRoutingInfo{PoolName: "sora0", AccountID: 42}, proxy.AuthSuccess, nil
	}
	return nil, proxy.AuthUserNotFound, nil
}
func (knownAddressLookup) LookupUserRouteWithClientIP(ctx context.Context, email, password, _ string, routeOnly bool) (*proxy.UserRoutingInfo, proxy.AuthResult, error) {
	return knownAddressLookup{}.LookupUserRouteWithOptions(ctx, email, password, routeOnly)
}
func (knownAddressLookup) Close() error { return nil }

// rateLimitedProxy is a User API proxy (New) with the login rate limit limit, over pool
// sora0 of one backend that answers a login 200 for rateLimitRightPassword and 401
// "Invalid credentials" for any other, as a User API backend without a limiter of its
// own does. hits counts the logins that reach it. The routing lookup is
// knownAddressLookup, without lookup_local_users: a login for any other address is
// refused by the proxy itself.
func rateLimitedProxy(t *testing.T, limit config.AuthRateLimiterConfig) (handler http.Handler, hits *atomic.Int32) {
	t.Helper()
	return rateLimitedProxyWith(t, limit, nil)
}

// rateLimitedProxyWith is rateLimitedProxy whose backend calls verify, if not nil, before
// it answers a login: the time the backend takes to verify the password.
func rateLimitedProxyWith(t *testing.T, limit config.AuthRateLimiterConfig, verify func()) (handler http.Handler, hits *atomic.Int32) {
	t.Helper()
	origCost := db.BcryptCost
	db.BcryptCost = bcrypt.MinCost
	t.Cleanup(func() { db.BcryptCost = origCost })

	hits = new(atomic.Int32)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		var req struct{ Email, Password string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		if verify != nil {
			verify()
		}
		w.Header().Set("Content-Type", "application/json")
		if req.Password == rateLimitRightPassword {
			_, _ = w.Write([]byte(`{"token":"t","expires_at":0,"email":"` + req.Email + `","account_id":42}`))
			return
		}
		server.SetBearerChallenge(w.Header(), server.UserAPIRealm, "")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Invalid credentials"}` + "\n"))
	}))
	t.Cleanup(backend.Close)

	s, err := New(t.Context(), &resilient.ResilientDatabase{}, ServerOptions{
		Name:           "rate-limited-proxy",
		Addr:           "127.0.0.1:0",
		JWTSecret:      corsTestSecret,
		AllowedOrigins: []string{corsTestOrigin},
		Pools:          []proxy.PoolSpec{{Name: "sora0", Backends: []string{strings.TrimPrefix(backend.URL, "http://")}}},
		AuthRateLimit:  limit,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(s.cancel)
	m := proxy.NewMaintenance()
	m.Set(nil)
	s.connManager.SetMaintenance(m)
	s.routingLookup = knownAddressLookup{}
	return s.setupHandler(), hits
}

// rateLimit is an enabled login rate limit with the defaults, except that nothing is
// blocked or delayed unless a test says so.
func rateLimit() config.AuthRateLimiterConfig {
	c := config.DefaultAuthRateLimiterConfig()
	c.Enabled = true
	c.MaxAttemptsPerIPUsername = 1000
	c.MaxAttemptsPerIP = 1000
	c.DelayStartThreshold = 1000
	c.CleanupInterval = time.Hour
	return c
}

// loginResult is what a login through the proxy cost and got.
type loginResult struct {
	code          int
	header        http.Header
	reached       bool // the login reached the backend
	verifications int  // password verifications on the proxy
	elapsed       time.Duration
}

func sendLogin(t *testing.T, h http.Handler, hits *atomic.Int32, ip, email, password string) loginResult {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/user/auth/login", strings.NewReader(`{"email":"`+email+`","password":"`+password+`"}`))
	r.RemoteAddr = ip + ":40000"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", corsTestOrigin)
	w := httptest.NewRecorder()
	hitsBefore, verificationsBefore, start := hits.Load(), testutils.PasswordVerifications(), time.Now()
	h.ServeHTTP(w, r)
	res := loginResult{
		code:          w.Code,
		header:        w.Result().Header,
		reached:       hits.Load() > hitsBefore,
		verifications: testutils.PasswordVerifications() - verificationsBefore,
		elapsed:       time.Since(start),
	}
	if w.Code != http.StatusOK {
		if msg := errorBody(t, w); msg != "Invalid credentials" {
			t.Errorf("login %s from %s: status %d %q, want \"Invalid credentials\"", email, ip, w.Code, msg)
		}
	}
	return res
}

// checkFailed fails unless res is a wrong-password answer for an address the lookup
// knows (known: the backend answered it) or does not know (the proxy answered it after
// one verification).
func checkFailed(t *testing.T, res loginResult, known bool, what string) {
	t.Helper()
	if res.code != http.StatusUnauthorized {
		t.Errorf("%s: status %d, want 401", what, res.code)
	}
	if known && (!res.reached || res.verifications != 0) {
		t.Errorf("%s: reached the backend %v, %d verifications on the proxy; want the backend's answer", what, res.reached, res.verifications)
	}
	if !known && (res.reached || res.verifications != 1) {
		t.Errorf("%s: reached the backend %v, %d verifications on the proxy; want the proxy's answer after one verification", what, res.reached, res.verifications)
	}
}

// checkBlocked fails unless res is the answer to a blocked login: a wrong password's
// 401 with a backend's headers, answered by the proxy at once, with no verification and
// without asking a backend.
func checkBlocked(t *testing.T, res loginResult, what string) {
	t.Helper()
	wantHeader := wrongPasswordHeader()
	if res.code != http.StatusUnauthorized {
		t.Errorf("%s: status %d, want 401", what, res.code)
	}
	if res.reached || res.verifications != 0 {
		t.Errorf("%s: reached the backend %v, %d verifications on the proxy; want neither", what, res.reached, res.verifications)
	}
	if !reflect.DeepEqual(res.header, wantHeader) {
		t.Errorf("%s: headers %v, want a backend's %v", what, res.header, wantHeader)
	}
}

// Every login through the proxy is rate limited by the proxy, per client IP and address
// (Tier 1), whoever answers it: a backend of the user's pool for an address the lookup
// knows, the proxy itself for one it does not know (named pools, lookup_local_users
// off). Logins the proxy refused itself were never counted, so after a few attempts the
// answers for a known address became fast refusals while those for an unknown one kept
// costing a password verification each (#895): the response time showed which addresses
// the lookup knows.
func TestUserAPIProxy_LoginRateLimitPerIPAndAddress(t *testing.T) {
	limit := rateLimit()
	limit.MaxAttemptsPerIPUsername = 3
	for _, c := range []struct {
		name    string
		email   string
		spelled string // the same address as the rate limit keys it
		known   bool
	}{
		{"address the lookup knows", rateLimitKnown, "Known+tag@Example.COM", true},
		{"address the lookup does not know", "unknown@example.com", "Unknown+tag@Example.COM", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, hits := rateLimitedProxy(t, limit)
			for i := 1; i <= limit.MaxAttemptsPerIPUsername; i++ {
				checkFailed(t, sendLogin(t, h, hits, "192.0.2.1", c.email, "wrong-password"), c.known, "failure before the block")
			}
			checkBlocked(t, sendLogin(t, h, hits, "192.0.2.1", c.email, rateLimitRightPassword), "the right password, blocked")
			checkBlocked(t, sendLogin(t, h, hits, "192.0.2.1", c.spelled, "wrong-password"), "the address spelled otherwise, blocked")
			checkFailed(t, sendLogin(t, h, hits, "192.0.2.2", c.email, "wrong-password"), c.known, "the same address from another IP")
		})
	}
}

// One client IP has one failure count (Tier 2), over the addresses the lookup knows and
// those it does not: counted apart, an IP that tried many unknown addresses was blocked
// for those and not for known ones, and the fast refusals showed which were unknown.
func TestUserAPIProxy_LoginRateLimitPerIP(t *testing.T) {
	limit := rateLimit()
	limit.MaxAttemptsPerIP = 4
	h, hits := rateLimitedProxy(t, limit)

	checkFailed(t, sendLogin(t, h, hits, "192.0.2.1", rateLimitKnown, "wrong-password"), true, "failure 1")
	checkFailed(t, sendLogin(t, h, hits, "192.0.2.1", "unknown1@example.com", "wrong-password"), false, "failure 2")
	checkFailed(t, sendLogin(t, h, hits, "192.0.2.1", rateLimitKnown, "wrong-password"), true, "failure 3")
	checkFailed(t, sendLogin(t, h, hits, "192.0.2.1", "unknown2@example.com", "wrong-password"), false, "failure 4")

	checkBlocked(t, sendLogin(t, h, hits, "192.0.2.1", rateLimitKnown, "wrong-password"), "known address from the blocked IP")
	checkBlocked(t, sendLogin(t, h, hits, "192.0.2.1", "unknown3@example.com", "wrong-password"), "unknown address from the blocked IP")
	checkFailed(t, sendLogin(t, h, hits, "192.0.2.2", rateLimitKnown, "wrong-password"), true, "known address from another IP")
	checkFailed(t, sendLogin(t, h, hits, "192.0.2.2", "unknown3@example.com", "wrong-password"), false, "unknown address from another IP")
}

// The progressive delay follows the IP's failures over every address, and holds back a
// login for an address the lookup knows as long as one for an address it does not know.
func TestUserAPIProxy_LoginRateLimitDelay(t *testing.T) {
	const delay = 300 * time.Millisecond
	limit := rateLimit()
	limit.DelayStartThreshold = 1
	limit.InitialDelay = delay
	limit.MaxDelay = delay
	h, hits := rateLimitedProxy(t, limit)

	checkFailed(t, sendLogin(t, h, hits, "192.0.2.1", "unknown@example.com", "wrong-password"), false, "first failure")
	for _, c := range []struct {
		email string
		known bool
	}{{rateLimitKnown, true}, {"unknown@example.com", false}} {
		res := sendLogin(t, h, hits, "192.0.2.1", c.email, "wrong-password")
		checkFailed(t, res, c.known, c.email)
		if res.elapsed < delay {
			t.Errorf("%s after a failure from its IP: answered in %v, want a delay of at least %v", c.email, res.elapsed, delay)
		}
	}
}

// The backend's answer to a login it verified counts like the proxy's own: a 200 is a
// success, which clears the IP's and the address's failures, as on a backend.
func TestUserAPIProxy_LoginRateLimitCountsTheBackendsVerdict(t *testing.T) {
	limit := rateLimit()
	limit.MaxAttemptsPerIPUsername = 2
	h, hits := rateLimitedProxy(t, limit)

	checkFailed(t, sendLogin(t, h, hits, "192.0.2.1", rateLimitKnown, "wrong-password"), true, "failure 1")
	if res := sendLogin(t, h, hits, "192.0.2.1", rateLimitKnown, rateLimitRightPassword); res.code != http.StatusOK || !res.reached {
		t.Fatalf("the right password: status %d, reached the backend %v; want the backend's 200", res.code, res.reached)
	}
	checkFailed(t, sendLogin(t, h, hits, "192.0.2.1", rateLimitKnown, "wrong-password"), true, "failure 1 after the success")
	checkFailed(t, sendLogin(t, h, hits, "192.0.2.1", rateLimitKnown, "wrong-password"), true, "failure 2 after the success")
	checkBlocked(t, sendLogin(t, h, hits, "192.0.2.1", rateLimitKnown, "wrong-password"), "after two failures")
}

// A login a backend answers is counted whether or not its client waits for the answer,
// as the proxy's own refusals are, which it counts however soon the client leaves. A
// client that left while the backend verified the password went uncounted, so it could
// tell from the rate limit alone which addresses the lookup knows: max_attempts_per_ip_username
// abandoned logins blocked an address the lookup does not know, never one it knows.
func TestUserAPIProxy_LoginRateLimitCountsALoginItsClientLeft(t *testing.T) {
	limit := rateLimit()
	limit.MaxAttemptsPerIPUsername = 2
	verifying, answer := make(chan struct{}, 1), make(chan struct{})
	h, hits := rateLimitedProxyWith(t, limit, func() {
		verifying <- struct{}{}
		<-answer
	})

	for i := 1; i <= limit.MaxAttemptsPerIPUsername; i++ {
		ctx, leave := context.WithCancel(context.Background())
		r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/user/auth/login", strings.NewReader(`{"email":"`+rateLimitKnown+`","password":"wrong-password"}`))
		r.RemoteAddr = "192.0.2.1:40000"
		done := make(chan struct{})
		go func() {
			defer close(done)
			h.ServeHTTP(httptest.NewRecorder(), r)
		}()
		<-verifying
		leave()                           // the client goes away while the backend verifies the password
		time.Sleep(50 * time.Millisecond) // time for the proxy to see it gone
		answer <- struct{}{}              // the backend's 401
		<-done
	}
	close(answer)
	checkBlocked(t, sendLogin(t, h, hits, "192.0.2.1", rateLimitKnown, "wrong-password"), "after logins whose client left before the backend answered")
}
