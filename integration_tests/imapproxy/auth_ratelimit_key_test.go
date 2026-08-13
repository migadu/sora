//go:build integration

package imapproxy_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imapproxy"
)

// setupIMAPProxyWithRateLimiting creates an IMAP proxy with authentication rate
// limiting enabled, fronting the given backends.
func setupIMAPProxyWithRateLimiting(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, rateLimitConfig server.AuthRateLimiterConfig) *common.TestServer {
	t.Helper()

	opts := imapproxy.ServerOptions{
		Name:               "test-proxy-rate-limit",
		Addr:               proxyAddr,
		RemoteAddrs:        backendAddrs,
		RemotePort:         143,
		MasterSASLUsername: backendMasterSASLUsername,
		MasterSASLPassword: backendMasterSASLPassword,
		ConnectTimeout:     10 * time.Second,
		AuthIdleTimeout:    30 * time.Minute,
		AuthRateLimit:      rateLimitConfig,
		// No TrustedProxies: the proxy passes that list to the auth rate limiter as
		// its exemption list, and the loopback test client would then be exempt from
		// all IP-based blocking.
	}

	proxy, err := imapproxy.New(context.Background(), rdb, "test-proxy-rate-limit", opts)
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("IMAP proxy error: %w", err)
		}
	}()
	time.Sleep(200 * time.Millisecond)

	t.Cleanup(func() { proxy.Stop() })

	return &common.TestServer{
		Address:     proxyAddr,
		Server:      proxy,
		ResilientDB: rdb,
	}
}

// TestIMAPProxy_RateLimiting_Tier1_KeyIsCanonical proves the proxy canonicalises the
// Tier-1 (IP+username) key at BOTH the check and the record sites.
//
// The proxy checked the raw submitted username but recorded under a mix of raw
// username, parsedAddr.BaseAddress() and the remote-lookup resolved email. Varying
// the case or the +detail therefore produced a fresh check key on every attempt and
// Tier 1 never engaged, while the recorded blocks piled up on the canonical address.
func TestIMAPProxy_RateLimiting_Tier1_KeyIsCanonical(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backendServer, account := common.SetupIMAPServerWithMaster(t)
	defer backendServer.Close()

	proxyAddr := common.GetRandomAddress(t)
	// Tier 1 only; Tier 2 and progressive delays disabled so the assertion is on
	// blocking alone and never on timing.
	proxy := setupIMAPProxyWithRateLimiting(t, backendServer.ResilientDB, proxyAddr, []string{backendServer.Address}, server.AuthRateLimiterConfig{
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

	login := func(address, password string) error {
		c, err := imapclient.DialInsecure(proxyAddr, nil)
		if err != nil {
			t.Fatalf("dial failed: %v", err)
		}
		defer c.Close()
		return c.Login(address, password).Wait()
	}

	// Three failures, each under a DIFFERENT raw string for the same account.
	variants := []string{
		strings.ToUpper(account.Email), // case variation
		withTag("t1"),                  // +detail variation
		withTag("t2"),                  // another +detail variation
	}
	for i, variant := range variants {
		if err := login(variant, fmt.Sprintf("wrong-password-%d", i)); err == nil {
			t.Fatalf("attempt %d (%q): login should have failed", i+1, variant)
		}
	}

	// A fourth, again-unseen raw form of the same account — with the CORRECT
	// password. It must be refused: the failures above belong to the same
	// canonical key.
	if err := login(withTag("t3"), account.Password); err == nil {
		t.Fatal("login allowed after 3 failures for the same account: proxy Tier 1 is bypassable by varying case or +detail")
	} else {
		t.Logf("✓ proxy Tier 1 blocked the canonical key regardless of the submitted form: %v", err)
	}
}
