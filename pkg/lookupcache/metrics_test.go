package lookupcache

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// gaugeValues returns the value of every series of a gauge family.
func gaugeValues(t *testing.T, family string) []float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var values []float64
	for _, mf := range mfs {
		if mf.GetName() != family {
			continue
		}
		for _, m := range mf.GetMetric() {
			values = append(values, m.GetGauge().GetValue())
		}
	}
	return values
}

func hasValue(values []float64, want float64) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

// TestGaugesArePerCache: a node runs one lookup cache per server (IMAP, POP3 and
// ManageSieve backends, every proxy, the User API). The entries and hit-rate gauges
// must show each cache's own value, not whichever cache wrote last.
func TestGaugesArePerCache(t *testing.T) {
	a := New(time.Hour, time.Hour, 100, time.Hour, time.Minute)
	defer a.Stop(context.Background())
	b := New(time.Hour, time.Hour, 100, time.Hour, time.Minute)
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

	entries := gaugeValues(t, "sora_lookup_cache_entries_total")
	if !hasValue(entries, 3) || !hasValue(entries, 1) {
		t.Errorf("sora_lookup_cache_entries_total series = %v, want one cache at 3 and one at 1", entries)
	}
	hitRate := gaugeValues(t, "sora_lookup_cache_hit_rate")
	if !hasValue(hitRate, 50) || !hasValue(hitRate, 75) {
		t.Errorf("sora_lookup_cache_hit_rate series = %v, want one cache at 50 and one at 75", hitRate)
	}
}
