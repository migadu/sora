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

// TestIMAPProxy_MasterUsernameWithAtSign tests master username containing @ character
func TestIMAPProxy_MasterUsernameWithAtSign(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server with master SASL credentials
	backendServer, account := common.SetupIMAPServerWithMaster(t)
	defer backendServer.Close()

	// Create proxy with master username containing @ sign
	masterUsernameWithAt := "master@admin.com"
	masterPasswordWithAt := "master_pass_123"

	proxyAddress := common.GetRandomAddress(t)

	// Backend server master SASL credentials (from SetupIMAPServerWithMaster)
	backendMasterSASLUsername := "proxyuser"
	backendMasterSASLPassword := "proxypass"

	// Setup proxy server with master username containing @ sign
	hostname := "test-master-at"
	opts := imapproxy.ServerOptions{
		Name:                   hostname,
		Addr:                   proxyAddress,
		Debug:                  true,
		RemoteAddrs:            []string{backendServer.Address},
		RemotePort:             143,
		MasterUsername:         masterUsernameWithAt,      // Client uses this in username: user@domain@master@admin.com
		MasterPassword:         masterPasswordWithAt,      // Client provides this as password
		MasterSASLUsername:     backendMasterSASLUsername, // Proxy uses this to auth to backend
		MasterSASLPassword:     backendMasterSASLPassword, // Proxy uses this to auth to backend
		TLS:                    false,
		TLSVerify:              false,
		RemoteTLS:              false,
		RemoteTLSVerify:        false,
		RemoteUseProxyProtocol: false, // Backend doesn't use PROXY protocol (uses ID command instead)
		RemoteUseIDCommand:     true,  // Backend uses ID command for client IP
		ConnectTimeout:         10 * time.Second,
		AuthIdleTimeout:        30 * time.Minute,
		EnableAffinity:         true,
		AuthRateLimit: server.AuthRateLimiterConfig{
			Enabled: false,
		},
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
	}

	// Create proxy server
	proxyServer, err := imapproxy.New(context.Background(), backendServer.ResilientDB, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy: %v", err)
	}

	// Start proxy in background
	go func() {
		if err := proxyServer.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("IMAP proxy error: %v", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	defer proxyServer.Stop()

	t.Run("Login with master username containing @ sign", func(t *testing.T) {
		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		// Login format: user@domain.com@master@admin.com with MASTER_PASSWORD
		loginUsername := fmt.Sprintf("%s@%s", account.Email, masterUsernameWithAt)
		t.Logf("Attempting login with username: %s", loginUsername)

		if err := c.Login(loginUsername, masterPasswordWithAt).Wait(); err != nil {
			t.Fatalf("Login with @ in master username failed: %v", err)
		}
		t.Log("✓ Successfully authenticated with master username containing @")
	})
}
