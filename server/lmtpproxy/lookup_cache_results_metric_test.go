package lmtpproxy

import (
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestLMTPLookupCacheResultsCountMisses: sora_lookup_cache_results_total is how a proxy
// used what its lookup cache returned. The LMTP proxy counted its hits but never a miss,
// so its hit ratio read 100% however many recipients were looked up afresh. A proxy whose
// lookup cache is disabled reads no cache and counts nothing.
func TestLMTPLookupCacheResultsCountMisses(t *testing.T) {
	results := func(result string) float64 {
		return testutil.ToFloat64(metrics.LookupCacheResults.WithLabelValues("lmtp_proxy", result))
	}

	for _, tc := range []struct {
		name                 string
		lookupCache          *config.LookupCacheConfig
		wantMisses, wantHits float64
		cacheEnabled         bool
	}{
		{"cache enabled", nil, 1, 1, true},
		{"cache disabled", &config.LookupCacheConfig{Enabled: false}, 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := newNotFoundProxy(t, ServerOptions{RemoteAddrs: []string{"127.0.0.1:1"}, LookupCache: tc.lookupCache}, "reject")
			if got := srv.lookupCache != nil; got != tc.cacheEnabled {
				t.Fatalf("lookup cache enabled = %v, want %v", got, tc.cacheEnabled)
			}
			misses0, hits0 := results("miss"), results("hit_negative")

			recipientError(t, srv, "nobody@example.com") // looked up, and cached when enabled
			recipientError(t, srv, "nobody@example.com") // from the cache when enabled

			if d := results("miss") - misses0; d != tc.wantMisses {
				t.Errorf(`sora_lookup_cache_results_total{protocol="lmtp_proxy",result="miss"} grew by %v, want %v`, d, tc.wantMisses)
			}
			if d := results("hit_negative") - hits0; d != tc.wantHits {
				t.Errorf(`sora_lookup_cache_results_total{protocol="lmtp_proxy",result="hit_negative"} grew by %v, want %v`, d, tc.wantHits)
			}
		})
	}
}
