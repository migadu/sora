//go:build integration

package pop3proxy_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/proxy"
)

// TestPOP3ProxyCachedPoolOutlivesLookupAnswer: within the lookup cache's positive TTL a login
// is routed by the pool the cached answer named, without asking the lookup again, even after
// the answer has changed; once the TTL has passed the new answer applies.
func TestPOP3ProxyCachedPoolOutlivesLookupAnswer(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	backend, _ := common.SetupPOP3ServerWithPROXY(t)
	defer backend.Close()
	rdb := backend.ResilientDB

	user := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("pop3-cache-%d@example.com", time.Now().UnixNano()), "pw")
	lookup, lookupURL := newPoolLookup(t)
	lookup.add(t, user, "live")

	const ttl = 2 * time.Second
	proxyAddr := common.GetRandomAddress(t)
	p := setupPOP3ProxyWithPools(t, rdb, proxyAddr, []proxy.PoolSpec{
		{Name: "live", Backends: []string{backend.Address}, Settings: proxy.BackendSettings{UseProxyProtocol: true}},
		{Name: "dead", Backends: []string{"127.0.0.1:1"}, Settings: proxy.BackendSettings{UseProxyProtocol: true}},
	}, lookupURL, &config.LookupCacheConfig{Enabled: true, PositiveTTL: ttl.String(), NegativeTTL: "1s", CleanupInterval: "1s", MaxSize: 100})
	defer p.Close()

	if resp := pop3Login(t, proxyAddr, user); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("first login: %s", resp)
	}
	if n := lookup.calls.Load(); n != 1 {
		t.Fatalf("first login asked the lookup %d times, want 1", n)
	}
	if resp := pop3Login(t, proxyAddr, user); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("second login within the TTL: %s", resp)
	}
	lookup.add(t, user, "dead")
	if resp := pop3Login(t, proxyAddr, user); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("login within the TTL after the answer changed: %s (the cached pool must still route)", resp)
	}
	if n := lookup.calls.Load(); n != 1 {
		t.Fatalf("logins within the TTL asked the lookup again (%d calls)", n)
	}
	time.Sleep(ttl + 500*time.Millisecond)
	if resp := pop3Login(t, proxyAddr, user); strings.HasPrefix(resp, "+OK") || !strings.Contains(resp, "SYS/TEMP") {
		t.Fatalf("login after the TTL with the dead-pool answer: %s, want -ERR [SYS/TEMP]", resp)
	}
	if n := lookup.calls.Load(); n != 2 {
		t.Fatalf("login after the TTL asked the lookup %d times in total, want 2", n)
	}
}
