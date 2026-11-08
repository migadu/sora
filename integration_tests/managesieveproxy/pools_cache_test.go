//go:build integration

package managesieveproxy_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/proxy"
)

// TestManageSieveProxyCachedPoolOutlivesLookupAnswer: within the lookup cache's positive TTL
// an authentication is routed by the pool the cached answer named, without asking the lookup
// again, even after the answer has changed; once the TTL has passed the new answer applies.
func TestManageSieveProxyCachedPoolOutlivesLookupAnswer(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	backend, _ := common.SetupManageSieveServerWithMaster(t)
	defer backend.Close()
	rdb := backend.ResilientDB

	user := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("sieve-cache-%d@example.com", time.Now().UnixNano()), "pw")
	lookup, lookupURL := newPoolLookup(t)
	lookup.add(t, user, "live")

	const ttl = 2 * time.Second
	proxyAddr := common.GetRandomAddress(t)
	p := setupManageSieveProxyWithPools(t, rdb, proxyAddr, []proxy.PoolSpec{
		{Name: "live", Backends: []string{backend.Address}},
		{Name: "dead", Backends: []string{"127.0.0.1:1"}},
	}, lookupURL, &config.LookupCacheConfig{Enabled: true, PositiveTTL: ttl.String(), NegativeTTL: "1s", CleanupInterval: "1s", MaxSize: 100})
	defer p.Close()

	if resp := sieveAuth(t, proxyAddr, user); !strings.HasPrefix(resp, "OK") {
		t.Fatalf("first auth: %s", resp)
	}
	if n := lookup.calls.Load(); n != 1 {
		t.Fatalf("first auth asked the lookup %d times, want 1", n)
	}
	if resp := sieveAuth(t, proxyAddr, user); !strings.HasPrefix(resp, "OK") {
		t.Fatalf("second auth within the TTL: %s", resp)
	}
	lookup.add(t, user, "dead")
	if resp := sieveAuth(t, proxyAddr, user); !strings.HasPrefix(resp, "OK") {
		t.Fatalf("auth within the TTL after the answer changed: %s (the cached pool must still route)", resp)
	}
	if n := lookup.calls.Load(); n != 1 {
		t.Fatalf("auths within the TTL asked the lookup again (%d calls)", n)
	}
	time.Sleep(ttl + 500*time.Millisecond)
	if resp := sieveAuth(t, proxyAddr, user); !strings.HasPrefix(resp, "NO") {
		t.Fatalf("auth after the TTL with the dead-pool answer: %s, want NO", resp)
	}
	if n := lookup.calls.Load(); n != 2 {
		t.Fatalf("auth after the TTL asked the lookup %d times in total, want 2", n)
	}
}
