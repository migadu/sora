//go:build integration

package imapproxy_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imapproxy"
	"golang.org/x/crypto/bcrypt"
)

// TestIMAPProxyMasterToken tests master token authentication through prelookup
func TestIMAPProxyMasterToken(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Set up prelookup test data in database
	setupMasterTokenTestData(t, backendServer.ResilientDB, account.Email, account.Password, backendServer.Address)

	// Set up IMAP proxy with prelookup and master token enabled
	proxyAddress := common.GetRandomAddress(t)
	proxyServer := setupIMAPProxyWithMasterToken(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
	defer func() {
		if srv, ok := proxyServer.Server.(*imapproxy.Server); ok {
			srv.Stop()
		}
	}()

	t.Run("NormalAuthentication", func(t *testing.T) {
		// Test normal authentication (without master token)
		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		err = c.Login(account.Email, account.Password).Wait()
		if err != nil {
			t.Fatalf("Normal authentication failed: %v", err)
		}
		t.Logf("✓ Normal authentication successful for %s", account.Email)
	})

	t.Run("MasterTokenAuthentication", func(t *testing.T) {
		// Test master token authentication
		masterToken := "supersecretmastertoken"
		emailWithToken := fmt.Sprintf("%s@%s", account.Email, masterToken)

		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		// Login using email@TOKEN format
		// Password field should contain the master token, not the user password
		err = c.Login(emailWithToken, masterToken).Wait()
		if err != nil {
			t.Fatalf("Master token authentication failed: %v", err)
		}
		t.Logf("✓ Master token authentication successful for %s", emailWithToken)
	})

	t.Run("MasterTokenWrongPassword", func(t *testing.T) {
		// Test master token with wrong token
		// Use correct email with WRONG token appended
		wrongToken := "wrongtoken"
		emailWithWrongToken := fmt.Sprintf("%s@%s", account.Email, wrongToken)

		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		// Pass the wrong token as the password (since that's what gets verified)
		err = c.Login(emailWithWrongToken, wrongToken).Wait()
		if err == nil {
			t.Fatal("Expected master token authentication to fail with wrong token, but it succeeded")
		}
		t.Logf("✓ Master token correctly rejected wrong token: %v", err)
	})

	t.Run("InvalidMasterToken", func(t *testing.T) {
		// Test with invalid master token
		emailWithToken := fmt.Sprintf("%s@%s", account.Email, "invalidtoken")

		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		err = c.Login(emailWithToken, "invalidtoken").Wait()
		if err == nil {
			t.Fatal("Expected authentication to fail with invalid master token, but it succeeded")
		}
		t.Logf("✓ Invalid master token correctly rejected: %v", err)
	})

	t.Run("ResolvedAddress", func(t *testing.T) {
		// Test that resolved_address is used for routing
		// The prelookup setup includes a resolved_address that points to the backend
		masterToken := "supersecretmastertoken"
		emailWithToken := fmt.Sprintf("%s@%s", account.Email, masterToken)

		c, err := imapclient.DialInsecure(proxyAddress, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP proxy: %v", err)
		}
		defer c.Logout()

		err = c.Login(emailWithToken, masterToken).Wait()
		if err != nil {
			t.Fatalf("Master token authentication with resolved address failed: %v", err)
		}
		t.Logf("✓ Resolved address routing successful")
	})
}

// TestIMAPProxyMasterTokenAddressValidation tests that emails with multiple @ work
func TestIMAPProxyMasterTokenAddressValidation(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend IMAP server
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	// Set up prelookup test data
	setupMasterTokenTestData(t, backendServer.ResilientDB, account.Email, account.Password, backendServer.Address)

	// Set up IMAP proxy
	proxyAddress := common.GetRandomAddress(t)
	proxyServer := setupIMAPProxyWithMasterToken(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
	defer func() {
		if srv, ok := proxyServer.Server.(*imapproxy.Server); ok {
			srv.Stop()
		}
	}()

	// Test that email with multiple @ symbols doesn't get rejected by address validation
	masterToken := "token123"
	emailWithToken := fmt.Sprintf("%s@%s", account.Email, masterToken)

	// Count @ symbols to verify we're testing the right scenario
	atCount := strings.Count(emailWithToken, "@")
	if atCount < 2 {
		t.Fatalf("Test email should have at least 2 @ symbols, got %d in: %s", atCount, emailWithToken)
	}
	t.Logf("Testing email with %d @ symbols: %s", atCount, emailWithToken)

	c, err := imapclient.DialInsecure(proxyAddress, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP proxy: %v", err)
	}
	defer c.Logout()

	// Note: We need to create test data for this token too
	tokenHash, err := bcrypt.GenerateFromPassword([]byte(masterToken), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash token: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = backendServer.ResilientDB.ExecWithRetry(ctx, `
		UPDATE user_routing_test_master
		SET master_token_hash = $1
		WHERE email = $2
	`, string(tokenHash), account.Email)
	if err != nil {
		t.Fatalf("Failed to update token: %v", err)
	}

	err = c.Login(emailWithToken, masterToken).Wait()
	if err != nil {
		t.Fatalf("Authentication failed for email with multiple @ symbols: %v", err)
	}
	t.Logf("✓ Email with multiple @ symbols (%d) accepted successfully", atCount)
}

// setupMasterTokenTestData creates test data for master token authentication
func setupMasterTokenTestData(t *testing.T, rdb *resilient.ResilientDatabase, userEmail, userPassword, backendAddr string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Drop and recreate prelookup test table to ensure clean state
	dropTable := `DROP TABLE IF EXISTS user_routing_test_master;`
	if _, err := rdb.ExecWithRetry(ctx, dropTable); err != nil {
		t.Fatalf("Failed to drop prelookup test table: %v", err)
	}

	// Create prelookup test table with all required columns
	schema := `
	CREATE TABLE user_routing_test_master (
		email TEXT PRIMARY KEY,
		password_hash TEXT NOT NULL,
		master_token_hash TEXT,
		server_address TEXT NOT NULL,
		resolved_address TEXT,
		account_id BIGINT NOT NULL,
		master_access_enabled BOOLEAN DEFAULT false,
		remote_use_proxy_protocol BOOLEAN DEFAULT true
	);
	`
	if _, err := rdb.ExecWithRetry(ctx, schema); err != nil {
		t.Fatalf("Failed to create prelookup test table: %v", err)
	}

	// Hash user password
	userHash, err := bcrypt.GenerateFromPassword([]byte(userPassword), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash user password: %v", err)
	}

	// Hash master token
	masterToken := "supersecretmastertoken"
	masterHash, err := bcrypt.GenerateFromPassword([]byte(masterToken), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash master token: %v", err)
	}

	// Insert test user with master token support
	// Note: remote_use_proxy_protocol=true to match the backend server setup
	_, err = rdb.ExecWithRetry(ctx, `
		INSERT INTO user_routing_test_master (email, password_hash, master_token_hash, server_address, resolved_address, account_id, master_access_enabled, remote_use_proxy_protocol)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (email) DO UPDATE SET
			password_hash = EXCLUDED.password_hash,
			master_token_hash = EXCLUDED.master_token_hash,
			server_address = EXCLUDED.server_address,
			resolved_address = EXCLUDED.resolved_address,
			master_access_enabled = EXCLUDED.master_access_enabled,
			remote_use_proxy_protocol = EXCLUDED.remote_use_proxy_protocol
	`, userEmail, string(userHash), string(masterHash), backendAddr, backendAddr, 1, true, true)
	if err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}

	t.Logf("Created master token test data for %s", userEmail)
}

// setupIMAPProxyWithMasterToken creates IMAP proxy with prelookup and master token support
func setupIMAPProxyWithMasterToken(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string) *common.TestServer {
	t.Helper()

	hostname := "test-master-token"
	masterUsername := "proxyuser"
	masterPassword := "proxypass"

	// Build prelookup query with master token logic
	prelookupQuery := `
SELECT
  CASE
    WHEN master_access_enabled AND
         (SELECT count(*) FROM regexp_matches($1, '@', 'g')) >= 2
    THEN master_token_hash
    ELSE password_hash
  END AS password_hash,
  server_address AS server_address,
  resolved_address AS resolved_address,
  account_id AS account_id,
  remote_use_proxy_protocol AS remote_use_proxy_protocol
FROM user_routing_test_master
WHERE email = (
  CASE
    WHEN (SELECT count(*) FROM regexp_matches($1, '@', 'g')) >= 2
    THEN regexp_replace($1, '@[^@]+$', '')
    ELSE $1
  END
)
`

	// Configure prelookup with master token support
	prelookupConfig := &config.PreLookupConfig{
		Enabled:                true,
		Hosts:                  []string{"localhost"},
		Port:                   "5432",
		User:                   "postgres",
		Name:                   "sora_mail_db",
		TLS:                    false,
		MaxConns:               10,
		MinConns:               2,
		MaxConnLifetime:        "30m",
		MaxConnIdleTime:        "5m",
		CacheTTL:               "5m",
		Query:                  prelookupQuery,
		AllowMasterToken:       true,
		MasterTokenSeparator:   "@",
		RemoteUseProxyProtocol: true, // Match the backend server configuration
	}

	opts := imapproxy.ServerOptions{
		Name:                   hostname,
		Addr:                   proxyAddr,
		RemoteAddrs:            backendAddrs,
		RemotePort:             143,
		MasterSASLUsername:     masterUsername,
		MasterSASLPassword:     masterPassword,
		TLS:                    false,
		TLSVerify:              false,
		RemoteTLS:              false,
		RemoteTLSVerify:        false,
		RemoteUseProxyProtocol: true,
		RemoteUseIDCommand:     false,
		ConnectTimeout:         10 * time.Second,
		SessionTimeout:         30 * time.Minute,
		EnableAffinity:         true,
		AffinityValidity:       24 * time.Hour,
		AffinityStickiness:     0.9,
		PreLookup:              prelookupConfig,
		AuthRateLimit: server.AuthRateLimiterConfig{
			Enabled: false,
		},
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
	}

	// Create proxy server
	proxyServer, err := imapproxy.New(context.Background(), rdb, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy with master token: %v", err)
	}

	// Start proxy in background
	errChan := make(chan error, 1)
	go func() {
		if err := proxyServer.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("IMAP proxy error: %w", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	return &common.TestServer{
		Server:      proxyServer,
		Address:     proxyAddr,
		ResilientDB: rdb,
	}
}
