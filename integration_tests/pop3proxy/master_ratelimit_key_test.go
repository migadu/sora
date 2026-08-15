//go:build integration

package pop3proxy_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/pop3proxy"
)

// setupPOP3ProxyWithMasterRateLimit is the master-auth harness with the rate limiter ON.
//
// TrustedProxies is deliberately EMPTY: the proxy passes it to the auth limiter as the
// exempt-network list, so trusting loopback - as the other proxy harnesses do - exempts
// the test client from all IP-based rate limiting and makes every assertion here vacuously
// pass.
func setupPOP3ProxyWithMasterRateLimit(t *testing.T, rdb *common.TestServer, proxyAddr string, backendAddrs []string) *POP3ProxyWrapper {
	t.Helper()

	opts := pop3proxy.POP3ProxyServerOptions{
		Name:               "test-pop3-proxy-master-ratelimit",
		RemoteAddrs:        backendAddrs,
		RemotePort:         110,
		MasterUsername:     proxyMasterUsername,
		MasterPassword:     proxyMasterPassword,
		MasterSASLUsername: proxyMasterSASLUsername,
		MasterSASLPassword: proxyMasterSASLPassword,
		ConnectTimeout:     10 * time.Second,
		AuthIdleTimeout:    30 * time.Minute,
		EnableAffinity:     true,
		AuthRateLimit: server.AuthRateLimiterConfig{
			Enabled:                  true,
			MaxAttemptsPerIPUsername: 3,
			IPUsernameBlockDuration:  2 * time.Minute,
			IPUsernameWindowDuration: 5 * time.Minute,
			MaxAttemptsPerIP:         0, // Tier 2 off: a whole-IP block would mask the keying
			DelayStartThreshold:      100,
			CleanupInterval:          1 * time.Minute,
		},
	}

	proxy, err := pop3proxy.New(context.Background(), "test-pop3-proxy-master-ratelimit", proxyAddr, rdb.ResilientDB, opts)
	if err != nil {
		t.Fatalf("Failed to create POP3 proxy: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("POP3 proxy error: %w", err)
		}
	}()
	time.Sleep(200 * time.Millisecond)

	wrapper := &POP3ProxyWrapper{proxy: proxy, addr: proxyAddr, rdb: rdb.ResilientDB}
	t.Cleanup(func() { wrapper.Stop() })
	return wrapper
}

// pop3ProxyLogin runs one USER/PASS exchange on a fresh connection and reports whether it
// succeeded, along with the verbatim PASS response.
func pop3ProxyLogin(t *testing.T, addr, user, password string) (bool, string) {
	t.Helper()

	client, err := NewPOP3Client(addr)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()

	client.SendCommand("USER " + user)
	if resp, err := client.ReadResponse(); err != nil || !strings.HasPrefix(resp, "+OK") {
		return false, resp
	}
	client.SendCommand("PASS " + password)
	resp, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("read PASS response: %v", err)
	}
	return strings.HasPrefix(resp, "+OK"), resp
}

// TestPOP3Proxy_MasterFailuresDoNotLockOutTheNamedAccount is the POP3 proxy half of the
// master-credential keying contract. See the IMAP proxy test for the full rationale: the
// proxy accepts "user@domain.com@MASTERUSER" and validates the master password itself, so
// keying that attempt on the canonicalised TARGET charges an arbitrary account for an
// attempt that only named it.
func TestPOP3Proxy_MasterFailuresDoNotLockOutTheNamedAccount(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backendServer, account := common.SetupPOP3ServerWithMaster(t)
	defer backendServer.Close()

	proxyAddress := common.GetRandomAddress(t)
	proxy := setupPOP3ProxyWithMasterRateLimit(t, backendServer, proxyAddress, []string{backendServer.Address})
	defer proxy.Stop()

	for i := 0; i < 3; i++ {
		if ok, resp := pop3ProxyLogin(t, proxyAddress, account.Email+"@"+proxyMasterUsername, fmt.Sprintf("wrong-master-pw-%d", i)); ok {
			t.Fatalf("attempt %d: a wrong master password must not authenticate: %q", i+1, resp)
		}
	}

	if ok, resp := pop3ProxyLogin(t, proxyAddress, account.Email, account.Password); !ok {
		t.Errorf("the account was locked out of the proxy by master-password failures that merely NAMED it "+
			"(%q) - the master form's rate-limit key canonicalises to the impersonation target, so anyone "+
			"who can reach the port can lock out any account", resp)
	}
}

// TestPOP3Proxy_MasterBruteForceIsMeteredAcrossTargets pins that the master credential has
// ONE bucket, so guesses spread across targets cannot stay under the threshold forever.
func TestPOP3Proxy_MasterBruteForceIsMeteredAcrossTargets(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backendServer, account := common.SetupPOP3ServerWithMaster(t)
	defer backendServer.Close()

	proxyAddress := common.GetRandomAddress(t)
	proxy := setupPOP3ProxyWithMasterRateLimit(t, backendServer, proxyAddress, []string{backendServer.Address})
	defer proxy.Stop()

	for i := 0; i < 3; i++ {
		target := fmt.Sprintf("ghost%d@example.com", i)
		if ok, resp := pop3ProxyLogin(t, proxyAddress, target+"@"+proxyMasterUsername, fmt.Sprintf("wrong-master-pw-%d", i)); ok {
			t.Fatalf("attempt %d: a wrong master password must not authenticate: %q", i+1, resp)
		}
	}

	if ok, _ := pop3ProxyLogin(t, proxyAddress, account.Email+"@"+proxyMasterUsername, proxyMasterPassword); ok {
		t.Error("the proxy's master password is still usable after 3 failed guesses spread across " +
			"different targets - each guess got its own Tier-1 bucket, so the tenant-wide credential " +
			"is not rate limited at all")
	}
}
