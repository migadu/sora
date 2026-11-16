package lookupcache

import (
	"context"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestGaugesArePerCache: a node runs one lookup cache per server (IMAP, POP3 and
// ManageSieve backends, every proxy, the User API). The entries and hit-rate gauges
// must show each cache's own value, not whichever cache wrote last.
func TestGaugesArePerCache(t *testing.T) {
	a := New("imap_proxy", "gauge-test-a", time.Hour, time.Hour, 100, time.Hour, time.Minute)
	defer a.Stop(context.Background())
	b := New("pop3_proxy", "gauge-test-b", time.Hour, time.Hour, 100, time.Hour, time.Minute)
	defer b.Stop(context.Background())

	// a: 3 entries, 1 hit in 2 lookups (50%).
	a.Set("srv-a", "one@example.com", &CacheEntry{AccountID: 1})
	a.Set("srv-a", "two@example.com", &CacheEntry{AccountID: 2})
	a.Set("srv-a", "three@example.com", &CacheEntry{AccountID: 3})
	a.Get("srv-a", "one@example.com")
	a.Get("srv-a", "nobody@example.com")
	a.cleanup()

	// b, written last: 1 entry, 3 hits in 4 lookups (75%).
	b.Set("srv-b", "one@example.com", &CacheEntry{AccountID: 1})
	for i := 0; i < 3; i++ {
		b.Get("srv-b", "one@example.com")
	}
	b.Get("srv-b", "nobody@example.com")
	b.cleanup()

	for _, c := range []struct {
		protocol, server     string
		wantEntries, wantHit float64
	}{
		{"imap_proxy", "gauge-test-a", 3, 50},
		{"pop3_proxy", "gauge-test-b", 1, 75},
	} {
		if got := testutil.ToFloat64(metrics.LookupCacheEntriesTotal.WithLabelValues(c.protocol, c.server)); got != c.wantEntries {
			t.Errorf("sora_lookup_cache_entries_total{protocol=%q,server_name=%q} = %v, want %v", c.protocol, c.server, got, c.wantEntries)
		}
		if got := testutil.ToFloat64(metrics.LookupCacheHitRate.WithLabelValues(c.protocol, c.server)); got != c.wantHit {
			t.Errorf("sora_lookup_cache_hit_rate{protocol=%q,server_name=%q} = %v, want %v", c.protocol, c.server, got, c.wantHit)
		}
	}
}
