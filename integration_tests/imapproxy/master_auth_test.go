//go:build integration

package imapproxy_test

import (
	"context"

	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-sasl"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imapproxy"
)

const (
	// Master credentials for CLIENT→PROXY authentication
	proxyMasterUsername     = "proxy_admin"
	proxyMasterPassword     = "proxy_master_123"
	proxyMasterSASLUsername = "proxy_sasl_admin"
	proxyMasterSASLPassword = "proxy_sasl_456"

	// Master credentials for PROXY→BACKEND authentication
	// These MUST match what the backend server expects (from common.SetupIMAPServerWithMaster)
	backendMasterSASLUsername = "proxyuser"
	backendMasterSASLPassword = "proxypass"
)

// setupIMAPProxyWithMasterAuth creates IMAP proxy with master authentication configured
func setupIMAPProxyWithMasterAuth(t *testing.T, rdb *common.TestServer, proxyAddr string, backendAddrs []string) *common.TestServer {
	t.Helper()

	hostname := "test-proxy-master"

	opts := imapproxy.ServerOptions{
		Name:        "test-proxy-master",
		Addr:        proxyAddr,
		RemoteAddrs: backendAddrs,
		RemotePort:  143,
		// Master credentials for CLIENT→PROXY authentication (@ suffix format)
		MasterUsername: proxyMasterUsername,
		MasterPassword: proxyMasterPassword,
		// Master credentials for PROXY→BACKEND authentication (SASL)
		// MUST match what backend expects
		MasterSASLUsername: backendMasterSASLUsername,
		MasterSASLPassword: backendMasterSASLPassword,
		TLS:                false,
		TLSVerify:          false,
		RemoteTLS:          false,
		RemoteTLSVerify:    false,
		ConnectTimeout:     10 * time.Second,
		SessionTimeout:     30 * time.Minute,
		EnableAffinity:     true,
		AuthRateLimit: server.AuthRateLimiterConfig{
			Enabled: false,
		},
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
	}

	proxy, err := imapproxy.New(context.Background(), rdb.ResilientDB, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy with master auth: %v", err)
	}

	// Start proxy in background
	errChan := make(chan error, 1)
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("IMAP proxy error: %w", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	cleanup := func() {
		proxy.Stop()
		select {
		case err := <-errChan:
			if err != nil {
				t.Logf("IMAP proxy error during shutdown: %v", err)
			}
		case <-time.After(1 * time.Second):
		}
	}

	ts := &common.TestServer{
		Address:     proxyAddr,
		Server:      proxy,
		ResilientDB: rdb.ResilientDB,
	}
	t.Cleanup(cleanup)

	return ts
}

// TestIMAPProxy_MasterUsernameAuthentication tests proxy authentication with MasterUsername
func TestIMAPProxy_MasterUsernameAuthentication(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server with master SASL credentials (for proxy->backend auth)
	backendServer, account := common.SetupIMAPServerWithMaster(t)
	defer backendServer.Close()

	// Create proxy with master username/password for client authentication
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithMasterAuth(t, backendServer, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	t.Run("Login with MasterUsername suffix through proxy", func(t *testing.T) {
		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		// Login format: user@domain.com@PROXY_MASTER_USERNAME with PROXY_MASTER_PASSWORD
		loginUsername := account.Email + "@" + proxyMasterUsername
		if err := c.Login(loginUsername, proxyMasterPassword).Wait(); err != nil {
			t.Fatalf("Login with proxy master username failed: %v", err)
		}
		t.Log("✓ Successfully authenticated through proxy with MasterUsername")

		// Verify we can access the account
		mbox, err := c.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Select INBOX failed: %v", err)
		}
		t.Logf("✓ Successfully selected INBOX through proxy with %d messages", mbox.NumMessages)
	})

	t.Run("Login with wrong MasterUsername suffix", func(t *testing.T) {
		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		loginUsername := account.Email + "@wrongmaster"
		err = c.Login(loginUsername, proxyMasterPassword).Wait()
		if err == nil {
			t.Fatal("Expected login to fail with wrong master username through proxy")
		}
		t.Logf("✓ Login correctly failed with wrong master username: %v", err)
	})

	t.Run("Login with wrong MasterPassword", func(t *testing.T) {
		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		loginUsername := account.Email + "@" + proxyMasterUsername
		err = c.Login(loginUsername, "wrong_password").Wait()
		if err == nil {
			t.Fatal("Expected login to fail with wrong master password through proxy")
		}
		t.Logf("✓ Login correctly failed with wrong master password: %v", err)
	})
}

// TestIMAPProxy_MasterSASLAuthentication tests SASL authentication through proxy
func TestIMAPProxy_MasterSASLAuthentication(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server with master SASL credentials
	backendServer, account := common.SetupIMAPServerWithMaster(t)
	defer backendServer.Close()

	// Create proxy with master credentials
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithMasterAuth(t, backendServer, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	t.Run("SASL PLAIN with proxy MasterUsername suffix", func(t *testing.T) {
		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		// SASL PLAIN with master username suffix at proxy level
		loginUsername := account.Email + "@" + proxyMasterUsername
		saslClient := sasl.NewPlainClient("", loginUsername, proxyMasterPassword)
		if err := c.Authenticate(saslClient); err != nil {
			t.Fatalf("SASL PLAIN with proxy master username failed: %v", err)
		}
		t.Log("✓ Successfully authenticated through proxy with SASL PLAIN master username")

		// Verify access
		mbox, err := c.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Select INBOX failed: %v", err)
		}
		t.Logf("✓ Successfully selected INBOX with %d messages", mbox.NumMessages)
	})

	// NOTE: Master SASL authentication at the proxy level is not supported in the current architecture.
	// The proxy's MasterSASLUsername/Password are used for PROXY→BACKEND authentication only.
	// Clients should use Master Username format (user@domain@MASTER) or regular authentication.
}

// TestIMAPProxy_MasterAuthenticationPriority tests authentication priority through proxy
func TestIMAPProxy_MasterAuthenticationPriority(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server with master SASL credentials
	backendServer, account := common.SetupIMAPServerWithMaster(t)
	defer backendServer.Close()

	// Create proxy with master credentials
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithMasterAuth(t, backendServer, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	t.Run("Master username overrides regular auth at proxy", func(t *testing.T) {
		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		// Try proxy master username suffix with account password (should fail)
		loginUsername := account.Email + "@" + proxyMasterUsername
		err = c.Login(loginUsername, account.Password).Wait()
		if err == nil {
			t.Fatal("Expected login to fail when using account password with proxy master username suffix")
		}
		t.Log("✓ Correctly rejected account password when proxy master username suffix is present")
	})

	t.Run("Regular auth still works through proxy without suffix", func(t *testing.T) {
		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		// Regular login should still work
		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("Regular login through proxy failed: %v", err)
		}
		t.Log("✓ Regular authentication still works through proxy without master suffix")

		mbox, err := c.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Select INBOX failed: %v", err)
		}
		t.Logf("✓ Successfully selected INBOX with %d messages", mbox.NumMessages)
	})
}

// TestIMAPProxy_MasterAuthenticationMultipleAccounts tests proxy master auth with different accounts
func TestIMAPProxy_MasterAuthenticationMultipleAccounts(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server with master SASL credentials
	backendServer, account1 := common.SetupIMAPServerWithMaster(t)
	defer backendServer.Close()

	// Create a second account
	account2 := common.CreateTestAccount(t, backendServer.ResilientDB)

	// Create proxy with master credentials
	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithMasterAuth(t, backendServer, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	t.Run("Proxy master credentials work for different accounts", func(t *testing.T) {
		// Test with account 1
		c1, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c1.Logout()

		loginUsername1 := account1.Email + "@" + proxyMasterUsername
		if err := c1.Login(loginUsername1, proxyMasterPassword).Wait(); err != nil {
			t.Fatalf("Login through proxy failed for account1: %v", err)
		}
		t.Logf("✓ Proxy master auth successful for account1: %s", account1.Email)

		// Test with account 2
		c2, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c2.Logout()

		loginUsername2 := account2.Email + "@" + proxyMasterUsername
		if err := c2.Login(loginUsername2, proxyMasterPassword).Wait(); err != nil {
			t.Fatalf("Login through proxy failed for account2: %v", err)
		}
		t.Logf("✓ Proxy master auth successful for account2: %s", account2.Email)

		// Verify both can access their respective accounts
		mbox1, err := c1.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Select INBOX failed for account1: %v", err)
		}
		t.Logf("✓ Account1 INBOX through proxy: %d messages", mbox1.NumMessages)

		mbox2, err := c2.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Select INBOX failed for account2: %v", err)
		}
		t.Logf("✓ Account2 INBOX through proxy: %d messages", mbox2.NumMessages)
	})
}

// plainSASLClient is a custom SASL PLAIN client that supports authorization identity
type plainSASLClient struct {
	identity string // authorization identity (who to impersonate)
	username string // authentication identity (who is authenticating)
	password string
}

func (c *plainSASLClient) Start() (mech string, ir []byte, err error) {
	mech = "PLAIN"
	ir = []byte(c.identity + "\x00" + c.username + "\x00" + c.password)
	return
}

func (c *plainSASLClient) Next(challenge []byte) ([]byte, error) {
	return nil, fmt.Errorf("unexpected server challenge")
}
