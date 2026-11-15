package managesieveproxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestLookupCacheResultsNamedAsOnTheOtherProxies: sora_lookup_cache_results_total is
// one family for every proxy, so an outcome carries the same result label on each. The
// ManageSieve proxy called a cached login "hit_positive" (the IMAP and POP3 proxies:
// "hit") and a wrong password on a fresh entry "hit_positive_fresh" (elsewhere
// "hit_positive_wrong_pw"), which left it out of any hit ratio taken by result.
func TestLookupCacheResultsNamedAsOnTheOtherProxies(t *testing.T) {
	origCost := db.BcryptCost
	db.BcryptCost = 4 // the dummy verification of a refused login; its cost is not tested here
	t.Cleanup(func() { db.BcryptCost = origCost })

	for _, tc := range []struct {
		name, password, want string
		wantErr              bool
	}{
		{"cached login", "secret", "hit", false},
		{"wrong password on a fresh entry", "wrong-password", "hit_positive_wrong_pw", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			connManager, err := proxy.NewConnectionManager([]string{"127.0.0.1:1"}, 4190, false, false, false, 500*time.Millisecond)
			if err != nil {
				t.Fatalf("failed to create connection manager: %v", err)
			}
			srv := &Server{
				name:                       "test",
				hostname:                   "test-host",
				ctx:                        ctx,
				cancel:                     cancel,
				connManager:                connManager,
				lookupCache:                newMSTestLookupCache(t),
				authLimiter:                (*server.AuthRateLimiter)(nil), // rate limiting disabled
				positiveRevalidationWindow: time.Minute,
				activeSessions:             make(map[*Session]struct{}),
			}
			srv.lookupCache.Set(srv.name, "user@example.com", &lookupcache.CacheEntry{
				AccountID:      42,
				PasswordDigest: lookupcache.NewPasswordDigest("secret"),
				Result:         lookupcache.AuthSuccess,
			})

			client, remote := net.Pipe()
			defer client.Close()
			defer remote.Close()
			sess := &Session{server: srv, clientConn: client, listenerConn: client, ctx: ctx, cancel: cancel}

			counter := metrics.LookupCacheResults.WithLabelValues("managesieve_proxy", tc.want)
			before := testutil.ToFloat64(counter)
			if err := sess.authenticateUser("user@example.com", tc.password, time.Now()); (err != nil) != tc.wantErr {
				t.Fatalf("authenticateUser error = %v, want error %v", err, tc.wantErr)
			}
			if d := testutil.ToFloat64(counter) - before; d != 1 {
				t.Errorf(`sora_lookup_cache_results_total{protocol="managesieve_proxy",result=%q} grew by %v, want 1`, tc.want, d)
			}
		})
	}
}
