package userapiproxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/proxy"
	"github.com/migadu/sora/testutils"
	"golang.org/x/crypto/bcrypt"
)

// A flat remote_addrs list refuses the users the remote lookup refuses, as named pools
// do (#911). A 401/403 is "the way to refuse an account" (config.toml.example), with no
// fallback, and a 404/3xx without lookup_local_users is a refusal too. Routed into the
// list, the backend logged such a user in with the right password, and served the
// requests of a token issued before the refusal. A login is answered as a wrong password
// (401 {"error": "Invalid credentials"}, the backend's headers, one password
// verification), a request carrying a token or a refresh 503, and none reaches a
// backend. The second request of each pair is answered from the lookup cache where the
// answer is cached (a 404).
//
// What still reaches the list: a user the lookup does not know with lookup_local_users
// (the backend checks its own database), and any user while the lookup cannot be asked
// (a flat list is one pool, routed as before pools).
func TestUserAPIProxy_FlatListRefusesWhatTheLookupRefuses(t *testing.T) {
	origCost := db.BcryptCost
	db.BcryptCost = bcrypt.MinCost
	t.Cleanup(func() { db.BcryptCost = origCost })

	var hits atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"issued-by-the-backend"}`))
	}))
	t.Cleanup(backend.Close)

	const login = `{"email":"user@example.com","password":"right-password"}`
	token := corsTestToken(t, time.Hour) // user@example.com, account 42
	refresh := `{"token":"` + token + `"}`

	wantHeader := wrongPasswordHeader()

	refused := func() *scriptedLookup { return &scriptedLookup{result: proxy.AuthFailed} }
	unknown := func() *scriptedLookup { return &scriptedLookup{result: proxy.AuthUserNotFound} }
	down := func() *scriptedLookup {
		return &scriptedLookup{result: proxy.AuthTemporarilyUnavailable, err: errors.New("connection refused")}
	}
	for _, c := range []struct {
		name             string
		lookup           *scriptedLookup
		lookupLocalUsers bool
		method, path     string
		body             string
		code             int    // the proxy's own answer; 0 = forwarded to the backend
		msg              string // its error
		verifications    int    // per request
	}{
		{"login, lookup answers 401 or 403", refused(), false, http.MethodPost, "/user/auth/login", login, http.StatusUnauthorized, "Invalid credentials", 1},
		{"login, lookup answers 401 or 403, lookup_local_users on", refused(), true, http.MethodPost, "/user/auth/login", login, http.StatusUnauthorized, "Invalid credentials", 1},
		{"login, lookup answers 404 or 3xx", unknown(), false, http.MethodPost, "/user/auth/login", login, http.StatusUnauthorized, "Invalid credentials", 1},
		{"token request, lookup answers 401 or 403", refused(), false, http.MethodGet, "/user/mailboxes", "", http.StatusServiceUnavailable, "Service unavailable", 0},
		{"token request, lookup answers 404 or 3xx", unknown(), false, http.MethodGet, "/user/mailboxes", "", http.StatusServiceUnavailable, "Service unavailable", 0},
		{"refresh, lookup answers 401 or 403", refused(), false, http.MethodPost, "/user/auth/refresh", refresh, http.StatusServiceUnavailable, "Service unavailable", 0},
		{"refresh, lookup answers 404 or 3xx", unknown(), false, http.MethodPost, "/user/auth/refresh", refresh, http.StatusServiceUnavailable, "Service unavailable", 0},

		{"login, lookup answers 404 or 3xx, lookup_local_users on", unknown(), true, http.MethodPost, "/user/auth/login", login, 0, "", 0},
		{"token request, lookup answers 404 or 3xx, lookup_local_users on", unknown(), true, http.MethodGet, "/user/mailboxes", "", 0, "", 0},
		{"login, lookup service down", down(), false, http.MethodPost, "/user/auth/login", login, 0, "", 0},
		{"token request, lookup service down", down(), false, http.MethodGet, "/user/mailboxes", "", 0, "", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, err := New(t.Context(), &resilient.ResilientDatabase{}, ServerOptions{
				Name:           "flat-list-proxy",
				Addr:           "127.0.0.1:0",
				RemoteAddrs:    []string{strings.TrimPrefix(backend.URL, "http://")},
				JWTSecret:      corsTestSecret,
				AllowedOrigins: []string{corsTestOrigin},
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			t.Cleanup(s.cancel)
			m := proxy.NewMaintenance()
			m.Set(nil)
			s.connManager.SetMaintenance(m)
			s.lookupCache = lookupcache.New("test", "test", 5*time.Minute, time.Minute, 100, time.Hour, 0)
			t.Cleanup(func() { _ = s.lookupCache.Stop(context.Background()) })
			s.routingLookup = c.lookup
			s.lookupLocalUsers = c.lookupLocalUsers
			handler := s.setupHandler()

			for i := 1; i <= 2; i++ {
				r := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
				if c.body != "" {
					r.Header.Set("Content-Type", "application/json")
				} else {
					r.Header.Set("Authorization", "Bearer "+token)
				}
				r.Header.Set("Origin", corsTestOrigin)
				w := httptest.NewRecorder()
				beforeHits := hits.Load()
				before := testutils.PasswordVerifications()
				handler.ServeHTTP(w, r)
				verifications := testutils.PasswordVerifications() - before
				reached := hits.Load() - beforeHits

				if c.code == 0 {
					if reached != 1 || w.Code != http.StatusOK {
						t.Fatalf("request %d: reached the backend %d times, answered %d (%q); want it forwarded to the flat list", i, reached, w.Code, w.Body.String())
					}
					continue
				}
				if reached != 0 {
					t.Errorf("request %d: reached the backend %d times, want never", i, reached)
				}
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
			// Only a 404/3xx is cached: the second request for that user is answered from
			// the negative cache entry, the others ask the lookup again.
			wantAsked := 2
			if c.lookup.result == proxy.AuthUserNotFound {
				wantAsked = 1
			}
			if asked := len(c.lookup.asked()); asked != wantAsked {
				t.Errorf("the lookup was asked %d times for the two requests, want %d", asked, wantAsked)
			}
		})
	}
}
