//go:build integration

package pop3proxy_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/pop3proxy"
)

// setupPOP3ProxyWithRateLimiting creates a POP3 proxy with authentication rate
// limiting enabled, fronting the given backends.
func setupPOP3ProxyWithRateLimiting(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, rateLimitConfig server.AuthRateLimiterConfig) *common.TestServer {
	t.Helper()

	opts := pop3proxy.POP3ProxyServerOptions{
		Name:               "test-proxy-rate-limit",
		RemoteAddrs:        backendAddrs,
		RemotePort:         110,
		MasterSASLUsername: "proxyuser",
		MasterSASLPassword: "proxypass",
		ConnectTimeout:     10 * time.Second,
		AuthIdleTimeout:    30 * time.Minute,
		AuthRateLimit:      rateLimitConfig,
		// No TrustedProxies: the proxy passes that list to the auth rate limiter as
		// its exemption list, and the loopback test client would then be exempt from
		// all IP-based blocking.
	}

	proxy, err := pop3proxy.New(context.Background(), "test-proxy-rate-limit", proxyAddr, rdb, opts)
	if err != nil {
		t.Fatalf("Failed to create POP3 proxy: %v", err)
	}

	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("POP3 proxy error: %v", err)
		}
	}()
	time.Sleep(200 * time.Millisecond)

	wrapper := &POP3ProxyWrapper{proxy: proxy, addr: proxyAddr, rdb: rdb}
	t.Cleanup(func() { _ = wrapper.Stop() })

	return &common.TestServer{
		Address:     proxyAddr,
		Server:      wrapper,
		ResilientDB: rdb,
	}
}

// TestPOP3Proxy_RateLimiting_Tier1_KeyIsCanonical proves the POP3 proxy canonicalises
// the Tier-1 (IP+username) key at BOTH the check and the record sites: it checked the
// raw submitted username while recording a mix of raw username, base address and
// resolved email, so varying the case or the +detail sidestepped Tier 1 entirely.
func TestPOP3Proxy_RateLimiting_Tier1_KeyIsCanonical(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backendServer, account := common.SetupPOP3ServerWithMaster(t)
	defer backendServer.Close()

	proxyAddr := common.GetRandomAddress(t)
	// Tier 1 only; Tier 2 and progressive delays disabled so the assertion is on
	// blocking alone and never on timing.
	proxy := setupPOP3ProxyWithRateLimiting(t, backendServer.ResilientDB, proxyAddr, []string{backendServer.Address}, server.AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 3,
		IPUsernameBlockDuration:  2 * time.Minute,
		IPUsernameWindowDuration: 5 * time.Minute,
		MaxAttemptsPerIP:         0,   // Tier 2 disabled
		DelayStartThreshold:      100, // delays disabled
		CleanupInterval:          1 * time.Minute,
	})
	defer proxy.Close()

	withTag := func(tag string) string {
		return strings.Replace(account.Email, "@", "+"+tag+"@", 1)
	}

	login := func(username, password string) string {
		client, err := NewPOP3Client(proxyAddr)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		defer client.Close()

		if err := client.SendCommand("USER " + username); err != nil {
			t.Fatalf("USER: %v", err)
		}
		if _, err := client.ReadResponse(); err != nil {
			t.Fatalf("USER read: %v", err)
		}
		if err := client.SendCommand("PASS " + password); err != nil {
			t.Fatalf("PASS: %v", err)
		}
		resp, err := client.ReadResponse()
		if err != nil {
			// A rate-limited proxy may drop the connection instead of replying.
			return fmt.Sprintf("-ERR (connection closed: %v)", err)
		}
		return resp
	}

	// Three failures, each under a DIFFERENT raw string for the same account.
	variants := []string{
		strings.ToUpper(account.Email), // case variation
		withTag("t1"),                  // +detail variation
		withTag("t2"),                  // another +detail variation
	}
	for i, variant := range variants {
		if resp := login(variant, fmt.Sprintf("wrong-password-%d", i)); strings.HasPrefix(resp, "+OK") {
			t.Fatalf("attempt %d (%q): login should have failed, got %q", i+1, variant, resp)
		}
	}

	// A fourth, again-unseen raw form of the same account — with the CORRECT
	// password. It must be refused: the failures above belong to the same
	// canonical key.
	if resp := login(withTag("t3"), account.Password); strings.HasPrefix(resp, "+OK") {
		t.Fatalf("login allowed after 3 failures for the same account: proxy Tier 1 is bypassable by varying case or +detail, got %q", resp)
	} else {
		t.Logf("✓ proxy Tier 1 blocked the canonical key regardless of the submitted form: %s", resp)
	}
}
