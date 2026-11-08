//go:build integration

package imapproxy_test

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imapproxy"
)

// TestIMAPProxyCachedPinNeverFallsBack: a login served from the lookup cache treats the
// backend the lookup pinned exactly as the uncached login does. When that backend has gone
// away the login fails without the proxy connecting to any other backend: a pin is not a
// preference to fall back from.
func TestIMAPProxyCachedPinNeverFallsBack(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	pinned, _ := common.SetupIMAPServerWithPROXY(t)
	rdb := pinned.ResilientDB
	user := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("cached-pin-%d@example.com", time.Now().UnixNano()), "pw")

	// The proxy's own list: never for a user the lookup pins elsewhere.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var otherHits atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			otherHits.Add(1)
			c.Close()
		}
	}()

	lookup, lookupURL := newPoolLookup(t)
	a := answer(t, user, "")
	a["server"] = pinned.Address
	lookup.set(user.Email, a)

	proxyAddr := common.GetRandomAddress(t)
	p, err := imapproxy.New(context.Background(), rdb, "test-proxy-cached-pin", imapproxy.ServerOptions{
		Name:               "test-proxy-cached-pin",
		Addr:               proxyAddr,
		RemoteAddrs:        []string{ln.Addr().String()},
		RemotePort:         143,
		MasterSASLUsername: "proxyuser",
		MasterSASLPassword: "proxypass",
		ConnectTimeout:     3 * time.Second,
		AuthIdleTimeout:    30 * time.Second,
		AuthRateLimit:      server.AuthRateLimiterConfig{Enabled: false},
		TrustedProxies:     []string{"127.0.0.0/8", "::1/128"},
		LookupCache:        &config.LookupCacheConfig{Enabled: true, PositiveTTL: "5m", NegativeTTL: "1m", CleanupInterval: "1m", MaxSize: 100},
		RemoteLookup:       &config.RemoteLookupConfig{Enabled: true, URL: lookupURL, Timeout: "5s", RemoteUseProxyProtocol: true},
	})
	if err != nil {
		t.Fatalf("imapproxy.New: %v", err)
	}
	go func() { _ = p.Start() }()
	t.Cleanup(func() { p.Stop() })
	time.Sleep(200 * time.Millisecond)

	if err := imapLogin(t, proxyAddr, user); err != nil {
		t.Fatalf("uncached login to the pinned backend: %v", err)
	}
	if err := imapLogin(t, proxyAddr, user); err != nil {
		t.Fatalf("cached login to the pinned backend: %v", err)
	}
	if n := lookup.calls.Load(); n != 1 {
		t.Fatalf("lookup asked %d times, want once (the second login is a cache hit)", n)
	}

	pinned.Close() // the pinned backend goes away; the cache still names it
	time.Sleep(100 * time.Millisecond)
	expectUnavailable(t, "cached login to a pinned backend that is gone", imapLogin(t, proxyAddr, user))
	time.Sleep(100 * time.Millisecond)
	if n := otherHits.Load(); n != 0 {
		t.Fatalf("the proxy connected %d time(s) to a backend the lookup did not name", n)
	}
}
