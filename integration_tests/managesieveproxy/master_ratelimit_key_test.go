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
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/managesieveproxy"
)

// setupManageSieveProxyWithMasterRateLimit is the master-auth harness with the rate limiter
// ON.
//
// TrustedProxies is deliberately EMPTY: the proxy passes it to the auth limiter as the
// exempt-network list, so trusting loopback - as the other proxy harnesses do - exempts the
// test client from all IP-based rate limiting and makes every assertion here vacuously pass.
func setupManageSieveProxyWithMasterRateLimit(t *testing.T, rdb *common.TestServer, proxyAddr string, backendAddrs []string) *common.TestServer {
	t.Helper()

	opts := managesieveproxy.ServerOptions{
		Name:               "test-managesieve-proxy-master-ratelimit",
		Addr:               proxyAddr,
		RemoteAddrs:        backendAddrs,
		RemotePort:         4190,
		MasterUsername:     proxyMasterUsername,
		MasterPassword:     proxyMasterPassword,
		MasterSASLUsername: proxyMasterSASLUsername,
		MasterSASLPassword: proxyMasterSASLPassword,
		InsecureAuth:       true,
		ConnectTimeout:     10 * time.Second,
		AuthIdleTimeout:    30 * time.Minute,
		CommandTimeout:     5 * time.Minute,
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

	proxy, err := managesieveproxy.New(context.Background(), rdb.ResilientDB, "test-managesieve-proxy-master-ratelimit", opts)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve proxy: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("ManageSieve proxy error: %w", err)
		}
	}()
	time.Sleep(200 * time.Millisecond)
	t.Cleanup(func() { proxy.Stop() })

	return &common.TestServer{Address: proxyAddr, Server: proxy, ResilientDB: rdb.ResilientDB}
}

// msProxyAuthPlain runs one AUTHENTICATE PLAIN on a fresh connection and returns whether it
// succeeded plus the verbatim response.
func msProxyAuthPlain(t *testing.T, addr, username, password string) (bool, string) {
	t.Helper()

	client, err := NewManageSieveClient(addr)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()

	encoded := base64.StdEncoding.EncodeToString([]byte("\x00" + username + "\x00" + password))
	if err := client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", encoded)); err != nil {
		t.Fatalf("AUTHENTICATE: %v", err)
	}
	resp, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return strings.HasPrefix(resp, "OK"), resp
}

// TestManageSieveProxy_MasterFailuresDoNotLockOutTheNamedAccount is the ManageSieve proxy
// half of the master-credential keying contract. See the IMAP proxy test for the full
// rationale: the proxy accepts "user@domain.com@MASTERUSER" and validates the master
// password itself, so keying that attempt on the canonicalised TARGET charges an arbitrary
// account for an attempt that only named it.
func TestManageSieveProxy_MasterFailuresDoNotLockOutTheNamedAccount(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backendServer, account := common.SetupManageSieveServerWithMaster(t)
	defer backendServer.Close()

	proxyAddress := common.GetRandomAddress(t)
	proxy := setupManageSieveProxyWithMasterRateLimit(t, backendServer, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	for i := 0; i < 3; i++ {
		if ok, resp := msProxyAuthPlain(t, proxyAddress, account.Email+"@"+proxyMasterUsername, fmt.Sprintf("wrong-master-pw-%d", i)); ok {
			t.Fatalf("attempt %d: a wrong master password must not authenticate: %q", i+1, resp)
		}
	}

	if ok, resp := msProxyAuthPlain(t, proxyAddress, account.Email, account.Password); !ok {
		t.Errorf("the account was locked out of the proxy by master-password failures that merely NAMED it "+
			"(%q) - the master form's rate-limit key canonicalises to the impersonation target, so anyone "+
			"who can reach the port can lock out any account", resp)
	}
}

// TestManageSieveProxy_MasterBruteForceIsMeteredAcrossTargets pins that the master
// credential has ONE bucket, so guesses spread across targets cannot stay under the
// threshold forever.
func TestManageSieveProxy_MasterBruteForceIsMeteredAcrossTargets(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backendServer, account := common.SetupManageSieveServerWithMaster(t)
	defer backendServer.Close()

	proxyAddress := common.GetRandomAddress(t)
	proxy := setupManageSieveProxyWithMasterRateLimit(t, backendServer, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	for i := 0; i < 3; i++ {
		target := fmt.Sprintf("ghost%d@example.com", i)
		if ok, resp := msProxyAuthPlain(t, proxyAddress, target+"@"+proxyMasterUsername, fmt.Sprintf("wrong-master-pw-%d", i)); ok {
			t.Fatalf("attempt %d: a wrong master password must not authenticate: %q", i+1, resp)
		}
	}

	if ok, _ := msProxyAuthPlain(t, proxyAddress, account.Email+"@"+proxyMasterUsername, proxyMasterPassword); ok {
		t.Error("the proxy's master password is still usable after 3 failed guesses spread across " +
			"different targets - each guess got its own Tier-1 bucket, so the tenant-wide credential " +
			"is not rate limited at all")
	}
}
