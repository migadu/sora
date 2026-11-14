package proxy

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/db"
)

// TestHTTPRemoteLookupDoesNotFollowRedirects: the lookup client must not follow a 3xx
// answer. The https-or-loopback rule is checked only for the configured URL, so a
// followed redirect could take the request (and its bearer token) anywhere and the
// answer there would decide the login and the backend. Every 3xx must reach the
// client's own 3xx branch, which reports the user as not found.
func TestHTTPRemoteLookupDoesNotFollowRedirects(t *testing.T) {
	hash, err := db.GenerateBcryptHash("secret")
	if err != nil {
		t.Fatalf("GenerateBcryptHash: %v", err)
	}

	var targetHits, targetAuthHeaders atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		if r.Header.Get("Authorization") != "" {
			targetAuthHeaders.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"address":       "user@example.com",
			"password_hash": hash,
			"server":        "198.51.100.7:143",
		})
	}))
	defer target.Close()

	for _, status := range []int{
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			targetHits.Store(0)
			targetAuthHeaders.Store(0)

			lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.URL+"/lookup?email=user%40example.com", status)
			}))
			defer lookup.Close()

			client := NewHTTPRemoteLookupClient(
				lookup.URL+"/lookup?email=$email",
				5*time.Second,
				"test-token",
				143,
				false, false, false, false, false, false, false,
				nil, nil,
			)

			info, result, err := client.LookupUserRoute(context.Background(), "user@example.com", "secret")
			if err != nil {
				t.Fatalf("LookupUserRoute: unexpected error: %v", err)
			}
			if result != AuthUserNotFound {
				t.Errorf("result = %v (routing %+v), want AuthUserNotFound (the 3xx answer itself)", result, info)
			}
			if n := targetHits.Load(); n != 0 {
				t.Errorf("redirect target was requested %d time(s), want 0 (redirects must not be followed)", n)
			}
			if n := targetAuthHeaders.Load(); n != 0 {
				t.Errorf("redirect target received the bearer token %d time(s)", n)
			}
		})
	}
}

// TestHTTPRemoteLookupNotFoundAnswersKeepConnection: a not-found answer (404, or a 3xx
// now that redirects are not followed) must leave the keep-alive connection reusable.
// An HTTP/1.1 body closed unread makes the transport drop the connection, so on a split
// deployment (lookup_local_users) every lookup of a local user would pay a new TCP and
// TLS handshake. Go's redirect follower used to drain the 3xx body for us.
func TestHTTPRemoteLookupNotFoundAnswersKeepConnection(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"302", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		}},
		{"404", func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var conns atomic.Int32
			lookup := httptest.NewUnstartedServer(tc.handler)
			lookup.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					conns.Add(1)
				}
			}
			lookup.Start()
			defer lookup.Close()

			client := NewHTTPRemoteLookupClient(
				lookup.URL+"/lookup?email=$email",
				5*time.Second,
				"test-token",
				143,
				false, false, false, false, false, false, false,
				nil, nil,
			)

			const lookups = 5
			for i := 0; i < lookups; i++ {
				_, result, err := client.LookupUserRoute(context.Background(), "user@example.com", "secret")
				if err != nil {
					t.Fatalf("LookupUserRoute: unexpected error: %v", err)
				}
				if result != AuthUserNotFound {
					t.Fatalf("result = %v, want AuthUserNotFound", result)
				}
			}
			if n := conns.Load(); n != 1 {
				t.Errorf("%d lookups opened %d connections, want 1 (the answer body must be drained so the connection is reused)", lookups, n)
			}
		})
	}
}
