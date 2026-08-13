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
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imapproxy"
)

// setupIMAPProxyWithMasterAuthAndRateLimit is setupIMAPProxyWithMasterAuth with the auth
// rate limiter turned on, so the accounting of master attempts is observable.
func setupIMAPProxyWithMasterAuthAndRateLimit(t *testing.T, rdb *common.TestServer, proxyAddr string, backendAddrs []string, rateLimit server.AuthRateLimiterConfig) *common.TestServer {
	t.Helper()

	opts := imapproxy.ServerOptions{
		Name:               "test-proxy-master-ratelimit",
		Addr:               proxyAddr,
		RemoteAddrs:        backendAddrs,
		RemotePort:         143,
		MasterUsername:     proxyMasterUsername,
		MasterPassword:     proxyMasterPassword,
		MasterSASLUsername: backendMasterSASLUsername,
		MasterSASLPassword: backendMasterSASLPassword,
		ConnectTimeout:     10 * time.Second,
		AuthIdleTimeout:    30 * time.Minute,
		EnableAffinity:     true,
		AuthRateLimit:      rateLimit,
		// TrustedProxies is deliberately EMPTY here. The proxy passes it to the auth
		// limiter as the exempt-network list, so trusting loopback - as the other proxy
		// harnesses do - exempts the test client from all IP-based rate limiting and
		// makes every assertion below vacuously pass. Verified with a control: with
		// loopback trusted, three wrong REGULAR passwords do not block either.
	}

	proxy, err := imapproxy.New(context.Background(), rdb.ResilientDB, "test-proxy-master-ratelimit", opts)
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

	return &common.TestServer{Address: proxyAddr, Server: proxy, ResilientDB: rdb.ResilientDB}
}

// masterRateLimitConfig blocks an (ip, username) pair after 3 failures. Tier 2 is off so
// the assertions cannot be satisfied by a whole-IP block, which would hide the difference
// between "the victim's key was charged" and "this IP was charged".
func masterRateLimitConfig() server.AuthRateLimiterConfig {
	return server.AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 3,
		IPUsernameBlockDuration:  2 * time.Minute,
		IPUsernameWindowDuration: 5 * time.Minute,
		MaxAttemptsPerIP:         0,
		DelayStartThreshold:      100, // delays disabled so the test does not sleep
		CleanupInterval:          1 * time.Minute,
	}
}

// TestIMAPProxy_MasterFailuresDoNotLockOutTheNamedAccount is the proxy half of the
// master-credential keying contract.
//
// The proxy accepts the same "user@domain.com@MASTERUSER" master form as the backends and
// validates the master password locally (imapproxy/session.go). Its rate-limit key is
// derived with server.AuthRateLimitKey, which canonicalises that form to the TARGET's
// address - so a failed master-password attempt was charged to whichever account the
// attacker chose to name. Reaching that record site needs only the master USERNAME, which
// the proxy's own error behaviour discloses; no password is required.
//
// Two consequences, both asserted below:
//   - anyone who can reach the port can lock an arbitrary account out of the proxy;
//   - varying the target hands every master-password guess a fresh Tier-1 bucket, so the
//     proxy's tenant-wide master password is never metered from a single IP.
func TestIMAPProxy_MasterFailuresDoNotLockOutTheNamedAccount(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backendServer, account := common.SetupIMAPServerWithMaster(t)
	defer backendServer.Close()

	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithMasterAuthAndRateLimit(t, backendServer, proxyAddress,
		[]string{backendServer.Address}, masterRateLimitConfig())
	defer proxy.Close()

	masterLogin := func(target, password string) error {
		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c.Close()
		return c.Login(target+"@"+proxyMasterUsername, password).Wait()
	}

	// Three wrong master passwords, all naming the same victim.
	for i := 0; i < 3; i++ {
		if err := masterLogin(account.Email, fmt.Sprintf("wrong-master-pw-%d", i)); err == nil {
			t.Fatalf("attempt %d: a wrong master password must not authenticate", i+1)
		}
	}

	// The named account must be unaffected: those failures belong to the master
	// credential, not to the address the attacker chose to type.
	c, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Logout()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Errorf("the account was locked out of the proxy by master-password failures that merely NAMED it "+
			"(%v) - the master form's rate-limit key canonicalises to the impersonation target, so anyone "+
			"who can reach the port can lock out any account", err)
	}
}

// TestIMAPProxy_MasterBruteForceIsMeteredAcrossTargets is the other half: the master
// credential must have ONE bucket, so guesses cannot be spread across targets to stay
// under the threshold forever.
func TestIMAPProxy_MasterBruteForceIsMeteredAcrossTargets(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backendServer, account := common.SetupIMAPServerWithMaster(t)
	defer backendServer.Close()

	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithMasterAuthAndRateLimit(t, backendServer, proxyAddress,
		[]string{backendServer.Address}, masterRateLimitConfig())
	defer proxy.Close()

	masterLogin := func(target, password string) error {
		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c.Close()
		return c.Login(target+"@"+proxyMasterUsername, password).Wait()
	}

	// Three guesses, each naming a DIFFERENT target - the shape that used to get a fresh
	// bucket every time.
	for i := 0; i < 3; i++ {
		target := fmt.Sprintf("ghost%d@example.com", i)
		if err := masterLogin(target, fmt.Sprintf("wrong-master-pw-%d", i)); err == nil {
			t.Fatalf("attempt %d: a wrong master password must not authenticate", i+1)
		}
	}

	// The master credential is now out of budget: even the CORRECT password must be
	// refused. That is only possible if all three guesses shared one bucket.
	if err := masterLogin(account.Email, proxyMasterPassword); err == nil {
		t.Error("the proxy's master password is still usable after 3 failed guesses spread across " +
			"different targets - each guess got its own Tier-1 bucket, so the tenant-wide credential " +
			"is not rate limited at all")
	}
}
