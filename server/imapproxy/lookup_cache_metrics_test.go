package imapproxy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/prometheus/client_golang/prometheus"
)

// counterValue returns the value of the counter series of family whose labels
// include all of labels, 0 when there is none.
func counterValue(t *testing.T, family string, labels map[string]string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != family {
			continue
		}
	series:
		for _, m := range mf.GetMetric() {
			for name, value := range labels {
				found := false
				for _, lp := range m.GetLabel() {
					if lp.GetName() == name && lp.GetValue() == value {
						found = true
					}
				}
				if !found {
					continue series
				}
			}
			return m.GetCounter().GetValue()
		}
	}
	return 0
}

// TestCachedLoginIsNotABodyCacheHit: sora_cache_operations_total is the message body
// cache's counter. A login answered from the proxy's lookup cache is counted under
// sora_lookup_cache_results_total{protocol="imap_proxy"}, not as a body cache hit.
func TestCachedLoginIsNotABodyCacheHit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cache := newTestLookupCache(t)
	srv := &Server{
		name:                       "test",
		hostname:                   "test-host",
		ctx:                        ctx,
		cancel:                     cancel,
		activeSessions:             make(map[*Session]struct{}),
		connManager:                newTestConnManager(t, "127.0.0.1:1"),
		lookupCache:                cache,
		authLimiter:                &fakeAuthLimiter{},
		positiveRevalidationWindow: 30 * time.Second,
	}
	cache.Set("test", "user@example.com", &lookupcache.CacheEntry{
		AccountID:      42,
		PasswordDigest: lookupcache.NewPasswordDigest("secret"),
		Result:         lookupcache.AuthSuccess,
	})

	bodyHit := map[string]string{"operation": "get", "result": "hit"}
	proxyHit := map[string]string{"protocol": "imap_proxy", "result": "hit"}
	bodyHits0 := counterValue(t, "sora_cache_operations_total", bodyHit)
	proxyHits0 := counterValue(t, "sora_lookup_cache_results_total", proxyHit)

	client, remote := net.Pipe()
	defer client.Close()
	defer remote.Close()
	if err := newSession(srv, client).authenticateUser("user@example.com", "secret"); err != nil {
		t.Fatalf("cached login: %v", err)
	}

	if d := counterValue(t, "sora_cache_operations_total", bodyHit) - bodyHits0; d != 0 {
		t.Errorf(`sora_cache_operations_total{operation="get",result="hit"} grew by %v on a cached login, want 0`, d)
	}
	if d := counterValue(t, "sora_lookup_cache_results_total", proxyHit) - proxyHits0; d != 1 {
		t.Errorf(`sora_lookup_cache_results_total{protocol="imap_proxy",result="hit"} grew by %v, want 1`, d)
	}
}

// TestLoginWithoutLookupCacheCountsNoMiss: a proxy whose lookup cache is disabled reads
// no cache, so a login is no miss in sora_lookup_cache_results_total (the POP3 and
// ManageSieve proxies count none either); with the cache enabled the same login is one.
func TestLoginWithoutLookupCacheCountsNoMiss(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cache      *lookupcache.LookupCache
		wantMisses float64
	}{
		{"cache disabled", nil, 0},
		{"cache enabled", newTestLookupCache(t), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			srv := &Server{
				name:                       "test",
				hostname:                   "test-host",
				ctx:                        ctx,
				cancel:                     cancel,
				activeSessions:             make(map[*Session]struct{}),
				connManager:                newTestConnManager(t, "127.0.0.1:1"),
				lookupCache:                tc.cache,
				authLimiter:                &fakeAuthLimiter{},
				positiveRevalidationWindow: 30 * time.Second,
				masterUsername:             []byte("MASTER"),
				masterPassword:             []byte("master-secret"),
			}

			miss := map[string]string{"protocol": "imap_proxy", "result": "miss"}
			misses0 := counterValue(t, "sora_lookup_cache_results_total", miss)

			client, remote := net.Pipe()
			defer client.Close()
			defer remote.Close()
			// A wrong master password is refused right after the cache, without a lookup.
			err := newSession(srv, client).authenticateUser("user@example.com@MASTER", "wrong")
			if !errors.Is(err, consts.ErrAuthenticationFailed) {
				t.Fatalf("login with a wrong master password: %v, want %v", err, consts.ErrAuthenticationFailed)
			}

			if d := counterValue(t, "sora_lookup_cache_results_total", miss) - misses0; d != tc.wantMisses {
				t.Errorf(`sora_lookup_cache_results_total{protocol="imap_proxy",result="miss"} grew by %v, want %v`, d, tc.wantMisses)
			}
		})
	}
}
