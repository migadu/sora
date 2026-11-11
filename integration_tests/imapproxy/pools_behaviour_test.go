//go:build integration

package imapproxy_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imapproxy"
	"github.com/migadu/sora/server/proxy"
)

// setupIMAPProxy starts an IMAP proxy with the given pools (or, with none, whatever tweak
// sets as RemoteAddrs) and a remote lookup at lookupURL; it returns the proxy address.
func setupIMAPProxy(t *testing.T, rdb *resilient.ResilientDatabase, pools []proxy.PoolSpec, lookupURL string, tweak func(*imapproxy.ServerOptions)) string {
	t.Helper()
	addr := common.GetRandomAddress(t)
	opts := imapproxy.ServerOptions{
		Name:               "test-proxy-pools",
		Addr:               addr,
		Pools:              pools,
		RemotePort:         143,
		MasterSASLUsername: "proxyuser",
		MasterSASLPassword: "proxypass",
		ConnectTimeout:     5 * time.Second,
		AuthIdleTimeout:    30 * time.Second,
		AuthRateLimit:      server.AuthRateLimiterConfig{Enabled: false},
		TrustedProxies:     []string{"127.0.0.0/8", "::1/128"},
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled:                true,
			URL:                    lookupURL,
			Timeout:                "5s",
			RemoteUseProxyProtocol: true,
		},
	}
	if tweak != nil {
		tweak(&opts)
	}
	p, err := imapproxy.New(context.Background(), rdb, "test-proxy-pools", opts)
	if err != nil {
		t.Fatalf("imapproxy.New: %v", err)
	}
	go func() {
		if err := p.Start(); err != nil {
			t.Logf("proxy: %v", err)
		}
	}()
	t.Cleanup(func() { p.Stop() })
	time.Sleep(200 * time.Millisecond)
	return addr
}

func answer(t *testing.T, account common.TestAccount, pool string) map[string]any {
	t.Helper()
	a := map[string]any{"address": account.Email, "password_hash": hashOf(t, account.Password)}
	if pool != "" {
		a["pool"] = pool
	}
	return a
}

func expectUnavailable(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: login succeeded, want NO [UNAVAILABLE]", what)
	}
	var ie *imap.Error
	if !errors.As(err, &ie) || ie.Code != imap.ResponseCodeUnavailable {
		t.Fatalf("%s: login error = %v, want NO [UNAVAILABLE]", what, err)
	}
}

// TestIMAPProxyPoolSettingsArePerPool: each pool's backend-leg settings apply to that pool's
// backends and to no other. Two identical backends that both REQUIRE the PROXY protocol sit
// in two pools of one proxy; only the pool whose block switches the header on can be logged
// into, and swapping the two blocks swaps which user gets in.
func TestIMAPProxyPoolSettingsArePerPool(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	backendA, _ := common.SetupIMAPServerWithPROXY(t)
	defer backendA.Close()
	backendB, _ := common.SetupIMAPServerWithPROXY(t)
	defer backendB.Close()
	rdb := backendA.ResilientDB

	stamp := time.Now().UnixNano()
	userA := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("settings-a-%d@example.com", stamp), "pw-a")
	userB := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("settings-b-%d@example.com", stamp), "pw-b")
	lookup, lookupURL := newPoolLookup(t)
	lookup.set(userA.Email, answer(t, userA, "pool-a"))
	lookup.set(userB.Email, answer(t, userB, "pool-b"))

	pools := func(headerForA, headerForB bool) []proxy.PoolSpec {
		return []proxy.PoolSpec{
			{Name: "pool-a", Backends: []string{backendA.Address}, Settings: proxy.BackendSettings{UseProxyProtocol: headerForA}},
			{Name: "pool-b", Backends: []string{backendB.Address}, Settings: proxy.BackendSettings{UseProxyProtocol: headerForB}},
		}
	}

	proxyA := setupIMAPProxy(t, rdb, pools(true, false), lookupURL, nil)
	if err := imapLogin(t, proxyA, userA); err != nil {
		t.Fatalf("pool-a with the header on: %v", err)
	}
	expectUnavailable(t, "pool-b with the header off", imapLogin(t, proxyA, userB))

	proxyB := setupIMAPProxy(t, rdb, pools(false, true), lookupURL, nil)
	expectUnavailable(t, "pool-a with the header off", imapLogin(t, proxyB, userA))
	if err := imapLogin(t, proxyB, userB); err != nil {
		t.Fatalf("pool-b with the header on: %v", err)
	}
}

// TestIMAPProxyCachedPoolOutlivesLookupAnswer: within the lookup cache's positive TTL a
// login is routed by the pool the cached answer named, without asking the lookup again,
// even after the lookup's answer has changed; once the TTL has passed the new answer applies.
func TestIMAPProxyCachedPoolOutlivesLookupAnswer(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	backend, _ := common.SetupIMAPServerWithPROXY(t)
	defer backend.Close()
	rdb := backend.ResilientDB

	user := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("cache-%d@example.com", time.Now().UnixNano()), "pw")
	lookup, lookupURL := newPoolLookup(t)
	lookup.set(user.Email, answer(t, user, "live"))

	pools := []proxy.PoolSpec{
		{Name: "live", Backends: []string{backend.Address}, Settings: proxy.BackendSettings{UseProxyProtocol: true}},
		{Name: "dead", Backends: []string{"127.0.0.1:1"}, Settings: proxy.BackendSettings{UseProxyProtocol: true}},
	}
	const ttl = 2 * time.Second
	proxyAddr := setupIMAPProxy(t, rdb, pools, lookupURL, func(o *imapproxy.ServerOptions) {
		o.LookupCache = &config.LookupCacheConfig{Enabled: true, PositiveTTL: ttl.String(), NegativeTTL: "1s", CleanupInterval: "1s", MaxSize: 100}
	})

	if err := imapLogin(t, proxyAddr, user); err != nil {
		t.Fatalf("first login: %v", err)
	}
	if n := lookup.calls.Load(); n != 1 {
		t.Fatalf("first login asked the lookup %d times, want 1", n)
	}
	if err := imapLogin(t, proxyAddr, user); err != nil {
		t.Fatalf("second login within the TTL: %v", err)
	}
	if n := lookup.calls.Load(); n != 1 {
		t.Fatalf("a login within the TTL asked the lookup again (%d calls)", n)
	}

	// The answer now names a dead pool. Until the cached answer expires the user still
	// lands in the live pool it was cached with.
	lookup.set(user.Email, answer(t, user, "dead"))
	if err := imapLogin(t, proxyAddr, user); err != nil {
		t.Fatalf("login within the TTL after the answer changed: %v (the cached pool must still route)", err)
	}
	if n := lookup.calls.Load(); n != 1 {
		t.Fatalf("a login within the TTL asked the lookup again (%d calls)", n)
	}

	time.Sleep(ttl + 500*time.Millisecond)
	expectUnavailable(t, "login after the TTL with the dead-pool answer", imapLogin(t, proxyAddr, user))
	if n := lookup.calls.Load(); n != 2 {
		t.Fatalf("login after the TTL asked the lookup %d times in total, want 2", n)
	}
}

// TestIMAPProxyDefaultPoolTakesAnswersWithoutPool: an answer that names no pool (auth-only,
// the pre-pools format) is routed into the pool marked default, and only there.
func TestIMAPProxyDefaultPoolTakesAnswersWithoutPool(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	backend, _ := common.SetupIMAPServerWithPROXY(t)
	defer backend.Close()
	rdb := backend.ResilientDB

	user := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("authonly-%d@example.com", time.Now().UnixNano()), "pw")
	lookup, lookupURL := newPoolLookup(t)
	lookup.set(user.Email, answer(t, user, ""))

	live := proxy.PoolSpec{Name: "live", Backends: []string{backend.Address}, Settings: proxy.BackendSettings{UseProxyProtocol: true}}
	dead := proxy.PoolSpec{Name: "dead", Backends: []string{"127.0.0.1:1"}, Settings: proxy.BackendSettings{UseProxyProtocol: true}}

	liveDefault, deadDefault := live, dead
	liveDefault.Default, deadDefault.Default = true, true

	if err := imapLogin(t, setupIMAPProxy(t, rdb, []proxy.PoolSpec{liveDefault, dead}, lookupURL, nil), user); err != nil {
		t.Fatalf("auth-only answer with the live pool as default: %v", err)
	}
	expectUnavailable(t, "auth-only answer with the dead pool as default", imapLogin(t, setupIMAPProxy(t, rdb, []proxy.PoolSpec{live, deadDefault}, lookupURL, nil), user))
}

// TestIMAPProxyLocalUsersLandInDefaultPool: with lookup_local_users, a user the lookup does
// not know authenticates against the local database and is routed into the default pool,
// and only there.
func TestIMAPProxyLocalUsersLandInDefaultPool(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	backend, _ := common.SetupIMAPServerWithPROXY(t)
	defer backend.Close()
	rdb := backend.ResilientDB

	user := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("local-%d@example.com", time.Now().UnixNano()), "pw")
	_, lookupURL := newPoolLookup(t) // knows nobody: every lookup is a 404

	live := proxy.PoolSpec{Name: "live", Backends: []string{backend.Address}, Settings: proxy.BackendSettings{UseProxyProtocol: true}}
	dead := proxy.PoolSpec{Name: "dead", Backends: []string{"127.0.0.1:1"}, Settings: proxy.BackendSettings{UseProxyProtocol: true}}
	liveDefault, deadDefault := live, dead
	liveDefault.Default, deadDefault.Default = true, true
	localUsers := func(o *imapproxy.ServerOptions) { o.RemoteLookup.LookupLocalUsers = true }

	if err := imapLogin(t, setupIMAPProxy(t, rdb, []proxy.PoolSpec{liveDefault, dead}, lookupURL, localUsers), user); err != nil {
		t.Fatalf("local user with the live pool as default: %v", err)
	}
	expectUnavailable(t, "local user with the dead pool as default", imapLogin(t, setupIMAPProxy(t, rdb, []proxy.PoolSpec{live, deadDefault}, lookupURL, localUsers), user))
}

// TestIMAPProxyWithoutPoolsIgnoresPoolAnswer: a proxy still configured with remote_addrs
// (no [[pool]] blocks) keeps serving a user whose lookup answer already names a pool, from
// remote_addrs, so the lookup API can switch to pool answers before every proxy is
// reconfigured. An explicit server in the answer still pins.
func TestIMAPProxyWithoutPoolsIgnoresPoolAnswer(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	backend, _ := common.SetupIMAPServerWithPROXY(t)
	defer backend.Close()
	rdb := backend.ResilientDB

	stamp := time.Now().UnixNano()
	pooled := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("legacy-pooled-%d@example.com", stamp), "pw")
	pinned := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("legacy-pinned-%d@example.com", stamp), "pw")
	lookup, lookupURL := newPoolLookup(t)
	lookup.set(pooled.Email, answer(t, pooled, "sora-b"))
	pin := answer(t, pinned, "sora-b")
	pin["server"] = backend.Address
	lookup.set(pinned.Email, pin)

	legacy := setupIMAPProxy(t, rdb, nil, lookupURL, func(o *imapproxy.ServerOptions) {
		o.RemoteAddrs = []string{backend.Address}
		o.RemoteUseProxyProtocol = true
	})
	if err := imapLogin(t, legacy, pooled); err != nil {
		t.Fatalf("pool answer on a remote_addrs proxy: %v", err)
	}
	if err := imapLogin(t, legacy, pinned); err != nil {
		t.Fatalf("explicit server next to a pool name on a remote_addrs proxy: %v", err)
	}
}
