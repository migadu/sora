package pop3proxy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/server"
)

// TestPOP3CachedLoginRoutesUnderBaseAddress: a login answered from the lookup cache must
// leave the session with the same username as the uncached login it replays. That
// username is the routing key (affinity, consistent hash), the authorization identity
// sent to the backend with master SASL credentials and the connection tracker's key.
// The main-database path names the user by the base address (without +detail or
// @SUFFIX) and caches no ActualEmail, so a cache hit without one must fall back to the
// base address, not to the name exactly as submitted (#681).
func TestPOP3CachedLoginRoutesUnderBaseAddress(t *testing.T) {
	cases := []struct {
		name        string
		submitted   string
		actualEmail string
		want        string
	}{
		{name: "plain address", submitted: "user@example.com", want: "user@example.com"},
		{name: "+detail", submitted: "user+tag@example.com", want: "user@example.com"},
		{name: "master suffix", submitted: "user@example.com@admin", want: "user@example.com"},
		{name: "+detail and master suffix", submitted: "user+tag@example.com@admin", want: "user@example.com"},
		{name: "case folded", submitted: "User+Tag@Example.COM", want: "user@example.com"},
		// A remote-lookup entry carries the address the lookup resolved; it still wins.
		{name: "resolved address", submitted: "user@example.com@TOKEN", actualEmail: "resolved@example.org", want: "resolved@example.org"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			cache := newPOP3TestLookupCache(t)
			srv := &POP3ProxyServer{
				name:                       "test",
				hostname:                   "test-host",
				appCtx:                     ctx,
				cancel:                     cancel,
				connManager:                newPOP3TestConnManager(t, "127.0.0.1:1", 500*time.Millisecond), // nothing listens here
				lookupCache:                cache,
				authLimiter:                (*server.AuthRateLimiter)(nil), // rate limiting disabled
				positiveRevalidationWindow: 30 * time.Second,
				activeSessions:             make(map[*POP3ProxySession]struct{}),
				masterUsername:             "admin",
				masterPassword:             "master-secret",
			}

			// The entry a previous login with this name and password left behind.
			cache.Set("test", tc.submitted, &lookupcache.CacheEntry{
				AccountID:      42,
				PasswordDigest: lookupcache.NewPasswordDigest("secret"),
				ActualEmail:    tc.actualEmail,
				Result:         lookupcache.AuthSuccess,
			})

			client, remote := net.Pipe()
			defer client.Close()
			defer remote.Close()
			sess := &POP3ProxySession{server: srv, clientConn: client, listenerConn: client, ctx: ctx, cancel: cancel}

			// A cache hit goes on to connect to the backend, routed by the session
			// username; nothing listens there, so the login ends in a backend error.
			err := sess.authenticate(tc.submitted, "secret")
			if err == nil || errors.Is(err, consts.ErrAuthenticationFailed) {
				t.Fatalf("cached login: err = %v, want the unreachable backend's error (the cache hit was not taken)", err)
			}
			if sess.username != tc.want {
				t.Errorf("cached login %q: session username (routing key) = %q, want %q", tc.submitted, sess.username, tc.want)
			}
			if sess.submittedUsername != tc.submitted {
				t.Errorf("submittedUsername (lookup-cache key) = %q, want %q", sess.submittedUsername, tc.submitted)
			}
		})
	}
}
