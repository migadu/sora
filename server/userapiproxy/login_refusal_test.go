package userapiproxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
	"github.com/migadu/sora/testutils"
	"golang.org/x/crypto/bcrypt"
)

// With named pools and lookup_local_users off, a login for an address the remote lookup
// does not know (404/3xx) or refuses (401/403) reaches no backend: a backend of another
// pool may hold another account under that address. A login with a wrong password for an
// address the lookup knows is answered by a backend of the user's pool: 401
// {"error": "Invalid credentials"} after one password verification. The proxy must refuse
// the other two the same way, in status, body, headers and verifications spent, or the
// answer shows what the lookup knows of the address (and a client takes a 503 for an
// outage and retries). The second login is answered from the lookup cache where the
// answer is cached (a 404), and must look the same.
//
// What stays a temporary failure: a lookup that cannot be asked, and a refresh, whose
// caller already holds a token and so learns nothing from the status.
//
// The verifications are counted, not timed (#782). The dummy hash follows BcryptCost, so
// the cheapest cost keeps the test fast without changing what is counted.
func TestUserAPIProxy_LoginTheLookupRefusesLooksLikeAWrongPassword(t *testing.T) {
	origCost := db.BcryptCost
	db.BcryptCost = bcrypt.MinCost
	t.Cleanup(func() { db.BcryptCost = origCost })

	const login = `{"email":"nobody@example.com","password":"wrong-password"}`
	refresh := `{"token":"` + corsTestToken(t, time.Hour) + `"}`

	// What a backend's wrong-password answer carries (userapi corsMiddleware, then
	// writeError through writeJSON), with the same allowed_origins as the proxy's.
	wantHeader := http.Header{}
	server.SetCORSHeaders(wantHeader, corsTestOrigin, []string{corsTestOrigin})
	wantHeader.Set("Content-Type", "application/json")

	for _, c := range []struct {
		name          string
		lookup        *scriptedLookup
		path, body    string
		code          int
		msg           string
		verifications int // per request
	}{
		{"login, lookup answers 404 or 3xx", &scriptedLookup{result: proxy.AuthUserNotFound}, "/user/auth/login", login, http.StatusUnauthorized, "Invalid credentials", 1},
		{"login, lookup answers 401 or 403", &scriptedLookup{result: proxy.AuthFailed}, "/user/auth/login", login, http.StatusUnauthorized, "Invalid credentials", 1},
		{"login, lookup service down", &scriptedLookup{result: proxy.AuthTemporarilyUnavailable, err: errors.New("connection refused")}, "/user/auth/login", login, http.StatusServiceUnavailable, "Service unavailable", 0},
		{"refresh, lookup answers 404 or 3xx", &scriptedLookup{result: proxy.AuthUserNotFound}, "/user/auth/refresh", refresh, http.StatusServiceUnavailable, "Service unavailable", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, _ := newPoolsMaintenanceServer(t) // lookup_local_users off
			s.settings.Store(&reloadableSettings{jwtSecret: corsTestSecret, allowedOrigins: []string{corsTestOrigin}})
			s.lookupCache = lookupcache.New("test", "test", 5*time.Minute, time.Minute, 100, time.Hour, 0)
			t.Cleanup(func() { _ = s.lookupCache.Stop(context.Background()) })
			s.routingLookup = c.lookup
			handler := s.setupHandler()

			for i := 1; i <= 2; i++ {
				r := httptest.NewRequest(http.MethodPost, c.path, strings.NewReader(c.body))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", corsTestOrigin)
				w := httptest.NewRecorder()
				before := testutils.PasswordVerifications()
				handler.ServeHTTP(w, r)
				verifications := testutils.PasswordVerifications() - before

				if w.Code != c.code {
					t.Fatalf("request %d: status %d (%q), want %d", i, w.Code, w.Body.String(), c.code)
				}
				if msg := errorBody(t, w); msg != c.msg {
					t.Errorf("request %d: error %q, want %q", i, msg, c.msg)
				}
				if verifications != c.verifications {
					t.Errorf("request %d: %d password verifications, want %d", i, verifications, c.verifications)
				}
				if c.code == http.StatusUnauthorized {
					if got := w.Result().Header; !reflect.DeepEqual(got, wantHeader) {
						t.Errorf("request %d: headers %v, want a backend's %v", i, got, wantHeader)
					}
				}
			}
		})
	}
}

// A login whose body a backend refuses before it looks anyone up (no password, an empty
// one, one that is not a string) names nobody the proxy routes by: a backend answers it
// 400 from the request alone, whatever the lookup would say of the address. Routed by the
// address instead, it was answered 400 for an address the lookup knows and 503 for one it
// does not know, which shows what the lookup knows without a password.
func TestUserAPIProxy_LoginRefusedFromItsBodyIsNotLookedUp(t *testing.T) {
	reference, addr, hits := countingBackend(t)

	bodies := []struct{ name, body string }{
		{"no password", `{"email":"user@example.com"}`},
		{"empty password", `{"email":"user@example.com","password":""}`},
		{"null password", `{"email":"user@example.com","password":null}`},
		{"password not a string", `{"email":"user@example.com","password":5}`},
	}
	for _, answer := range []struct {
		name   string
		info   *proxy.UserRoutingInfo
		result proxy.AuthResult
	}{
		{"lookup knows the address", &proxy.UserRoutingInfo{PoolName: "sora0", AccountID: 42}, proxy.AuthSuccess},
		{"lookup answers 404 or 3xx", nil, proxy.AuthUserNotFound},
		{"lookup answers 401 or 403", nil, proxy.AuthFailed},
	} {
		proxied, lookup := newNamelessAuthProxy(t, ServerOptions{Pools: []proxy.PoolSpec{{Name: "sora0", Backends: []string{addr}}}})
		lookup.info, lookup.result = answer.info, answer.result
		for _, b := range bodies {
			t.Run(answer.name+"/"+b.name, func(t *testing.T) {
				send := func(h http.Handler) *httptest.ResponseRecorder {
					r := httptest.NewRequest(http.MethodPost, "/user/auth/login", strings.NewReader(b.body))
					r.Header.Set("Content-Type", "application/json")
					w := httptest.NewRecorder()
					h.ServeHTTP(w, r)
					return w
				}
				direct := send(reference)
				before := hits.Load()
				viaProxy := send(proxied)

				if direct.Code != http.StatusBadRequest {
					t.Fatalf("backend answered %d (%q), want 400", direct.Code, direct.Body.String())
				}
				if viaProxy.Code != direct.Code || viaProxy.Body.String() != direct.Body.String() {
					t.Errorf("proxy answered %d %q, want the backend's %d %q", viaProxy.Code, viaProxy.Body.String(), direct.Code, direct.Body.String())
				}
				if n := hits.Load() - before; n != 1 {
					t.Errorf("the login reached a backend %d times, want once", n)
				}
			})
		}
		if asked := lookup.asked(); len(asked) != 0 {
			t.Errorf("%s: the routing lookup was asked for %v", answer.name, asked)
		}
	}
}
