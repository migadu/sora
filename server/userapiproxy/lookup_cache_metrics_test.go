package userapiproxy

import (
	"context"
	"testing"
	"time"

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

// TestRouteUser_LookupCacheReadCountedOnce: the lookup cache counts its own hits and
// misses. routeUser counted each read a second time in the same counters, so every
// User API proxy request showed up as two lookups. The proxy's view of the read goes
// to sora_lookup_cache_results_total{protocol="userapi_proxy"} instead.
func TestRouteUser_LookupCacheReadCountedOnce(t *testing.T) {
	s, _ := newPoolsMaintenanceServer(t)
	s.lookupCache = lookupcache.New(5*time.Minute, time.Minute, 100, time.Hour, 0)
	t.Cleanup(func() { _ = s.lookupCache.Stop(context.Background()) })
	s.routingLookup = poolAnswer("sora1")

	read := func() (hits, misses, proxyHits, proxyMisses float64) {
		return counterValue(t, "sora_lookup_cache_hits_total", nil),
			counterValue(t, "sora_lookup_cache_misses_total", nil),
			counterValue(t, "sora_lookup_cache_results_total", map[string]string{"protocol": "userapi_proxy", "result": "hit"}),
			counterValue(t, "sora_lookup_cache_results_total", map[string]string{"protocol": "userapi_proxy", "result": "miss"})
	}
	hits0, misses0, proxyHits0, proxyMisses0 := read()

	// A miss (the lookup answers and the answer is cached), then a hit.
	for i := 0; i < 2; i++ {
		if _, err := s.routeUser(context.Background(), "user@example.com", 42, false); err != nil {
			t.Fatalf("routeUser #%d: %v", i+1, err)
		}
	}

	hits, misses, proxyHits, proxyMisses := read()
	if d := hits - hits0; d != 1 {
		t.Errorf("sora_lookup_cache_hits_total grew by %v, want 1", d)
	}
	if d := misses - misses0; d != 1 {
		t.Errorf("sora_lookup_cache_misses_total grew by %v, want 1", d)
	}
	if d := proxyHits - proxyHits0; d != 1 {
		t.Errorf(`sora_lookup_cache_results_total{protocol="userapi_proxy",result="hit"} grew by %v, want 1`, d)
	}
	if d := proxyMisses - proxyMisses0; d != 1 {
		t.Errorf(`sora_lookup_cache_results_total{protocol="userapi_proxy",result="miss"} grew by %v, want 1`, d)
	}
}
