//go:build integration

package managesieveproxy_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/managesieveproxy"
)

// setupManageSieveProxyWithRateLimiting creates a ManageSieve proxy with
// authentication rate limiting enabled, fronting the given backends.
func setupManageSieveProxyWithRateLimiting(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, rateLimitConfig server.AuthRateLimiterConfig) *common.TestServer {
	t.Helper()

	opts := managesieveproxy.ServerOptions{
		Name:               "test-managesieve-proxy-rate-limit",
		Addr:               proxyAddr,
		RemoteAddrs:        backendAddrs,
		RemotePort:         4190,
		MasterSASLUsername: proxyMasterSASLUsername,
		MasterSASLPassword: proxyMasterSASLPassword,
		InsecureAuth:       true, // Allow authentication over non-TLS for testing
		ConnectTimeout:     10 * time.Second,
		AuthIdleTimeout:    30 * time.Minute,
		CommandTimeout:     5 * time.Minute,
		AuthRateLimit:      rateLimitConfig,
		// No TrustedProxies: the proxy passes that list to the auth rate limiter as
		// its exemption list, and the loopback test client would then be exempt from
		// all IP-based blocking.
	}

	proxy, err := managesieveproxy.New(context.Background(), rdb, "test-managesieve-proxy-rate-limit", opts)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve proxy: %v", err)
	}

	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("ManageSieve proxy error: %v", err)
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

// TestManageSieveProxy_RateLimiting_Tier1_KeyIsCanonical proves the ManageSieve proxy
// canonicalises the Tier-1 (IP+username) key at BOTH the check and the record sites:
// it checked the raw submitted username while recording a mix of raw username, base
// address and resolved email, so varying the case or the +detail sidestepped Tier 1.
func TestManageSieveProxy_RateLimiting_Tier1_KeyIsCanonical(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backendServer, account := common.SetupManageSieveServerWithMaster(t)
	defer backendServer.Close()

	proxyAddr := common.GetRandomAddress(t)
	// Tier 1 only; Tier 2 and progressive delays disabled so the assertion is on
	// blocking alone and never on timing.
	proxy := setupManageSieveProxyWithRateLimiting(t, backendServer.ResilientDB, proxyAddr, []string{backendServer.Address}, server.AuthRateLimiterConfig{
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

	authPlain := func(authnID, password string) string {
		client, err := NewManageSieveClient(proxyAddr)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		defer client.Close()

		encoded := base64.StdEncoding.EncodeToString([]byte("\x00" + authnID + "\x00" + password))
		if err := client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", encoded)); err != nil {
			t.Fatalf("AUTHENTICATE: %v", err)
		}
		resp, err := client.ReadResponse()
		if err != nil {
			// A rate-limited proxy may drop the connection instead of replying.
			return fmt.Sprintf("NO (connection closed: %v)", err)
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
		if resp := authPlain(variant, fmt.Sprintf("wrong-password-%d", i)); strings.HasPrefix(resp, "OK") {
			t.Fatalf("attempt %d (%q): authentication should have failed, got %q", i+1, variant, resp)
		}
	}

	// A fourth, again-unseen raw form of the same account — with the CORRECT
	// password. It must be refused: the failures above belong to the same
	// canonical key.
	if resp := authPlain(withTag("t3"), account.Password); strings.HasPrefix(resp, "OK") {
		t.Fatalf("authentication allowed after 3 failures for the same account: proxy Tier 1 is bypassable by varying case or +detail, got %q", resp)
	} else {
		t.Logf("✓ proxy Tier 1 blocked the canonical key regardless of the submitted form: %s", resp)
	}
}
