//go:build integration

package imap_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-sasl"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

const (
	masterUsername     = "admin"
	masterPassword     = "master_secret_123"
	masterSASLUsername = "sasl_admin"
	masterSASLPassword = "sasl_secret_456"
)

// setupIMAPServerWithMasterAuth creates an IMAP server with master authentication configured
func setupIMAPServerWithMasterAuth(t *testing.T) (*common.TestServer, common.TestAccount) {
	t.Helper()

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	// Create a temporary directory for the uploader
	tempDir, err := os.MkdirTemp("", "sora-test-upload-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	// Create error channel for uploader
	errCh := make(chan error, 1)

	// Create UploadWorker for testing
	uploadWorker, err := uploader.New(
		context.Background(),
		tempDir,
		10,
		1,
		3,
		time.Second,
		"test-instance",
		rdb,
		&storage.S3Storage{},
		nil,
		errCh,
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}

	// Create test config with shared mailboxes enabled
	testConfig := &config.Config{
		SharedMailboxes: config.SharedMailboxesConfig{
			Enabled:               true,
			NamespacePrefix:       "Shared/",
			AllowUserCreate:       true,
			DefaultRights:         "lrswipkxtea",
			AllowAnyoneIdentifier: true,
		},
	}

	server, err := imap.New(
		context.Background(),
		"test",
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		uploadWorker,
		nil,
		imap.IMAPServerOptions{
			InsecureAuth:       true, // Allow PLAIN auth (no TLS in tests)
			Config:             testConfig,
			MasterUsername:     []byte(masterUsername),
			MasterPassword:     []byte(masterPassword),
			MasterSASLUsername: []byte(masterSASLUsername),
			MasterSASLPassword: []byte(masterSASLPassword),
		},
	)
	if err != nil {
		t.Fatalf("Failed to create IMAP server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		if err := server.Serve(address); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("IMAP server error: %w", err)
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	cleanup := func() {
		server.Close()
		select {
		case err := <-errChan:
			if err != nil {
				t.Logf("Server error during cleanup: %v", err)
			}
		default:
		}
		os.RemoveAll(tempDir)
	}

	// Note: TestServer.cleanup is a private field, but we can still create the struct
	// and the Close() method will call it
	ts := &common.TestServer{
		Address:     address,
		Server:      server,
		ResilientDB: rdb,
	}
	// Use reflection or call server.Close() manually when ts.Close() is called
	// For now, register cleanup with t.Cleanup()
	t.Cleanup(cleanup)

	return ts, account
}

// TestIMAP_MasterUsernameAuthentication tests authentication using MasterUsername@
func TestIMAP_MasterUsernameAuthentication(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := setupIMAPServerWithMasterAuth(t)
	defer server.Close()

	t.Run("Login with MasterUsername suffix", func(t *testing.T) {
		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP server: %v", err)
		}
		defer c.Logout()

		// Login format: user@domain.com@MASTER_USERNAME with MASTER_PASSWORD
		loginUsername := account.Email + "@" + masterUsername
		if err := c.Login(loginUsername, masterPassword).Wait(); err != nil {
			t.Fatalf("Login with master username failed: %v", err)
		}
		t.Log("✓ Successfully authenticated with MasterUsername")

		// Verify we can access the account
		mbox, err := c.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Select INBOX failed: %v", err)
		}
		t.Logf("✓ Successfully selected INBOX with %d messages", mbox.NumMessages)
	})

	t.Run("Login with wrong MasterUsername suffix", func(t *testing.T) {
		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP server: %v", err)
		}
		defer c.Logout()

		// Try with wrong master username suffix
		loginUsername := account.Email + "@wrongmaster"
		err = c.Login(loginUsername, masterPassword).Wait()
		if err == nil {
			t.Fatal("Expected login to fail with wrong master username, but it succeeded")
		}
		t.Logf("✓ Login correctly failed with wrong master username: %v", err)
	})

	t.Run("Login with wrong MasterPassword", func(t *testing.T) {
		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP server: %v", err)
		}
		defer c.Logout()

		// Try with correct master username but wrong password
		loginUsername := account.Email + "@" + masterUsername
		err = c.Login(loginUsername, "wrong_password").Wait()
		if err == nil {
			t.Fatal("Expected login to fail with wrong master password, but it succeeded")
		}
		t.Logf("✓ Login correctly failed with wrong master password: %v", err)
	})
}

// TestIMAP_MasterSASLAuthentication tests SASL PLAIN authentication with master credentials
func TestIMAP_MasterSASLAuthentication(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := setupIMAPServerWithMasterAuth(t)
	defer server.Close()

	t.Run("SASL PLAIN with MasterUsername impersonation", func(t *testing.T) {
		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP server: %v", err)
		}
		defer c.Logout()

		// SASL PLAIN format with suffix: user@domain.com@MASTER_USERNAME authenticates as master
		loginUsername := account.Email + "@" + masterUsername
		saslClient := sasl.NewPlainClient("", loginUsername, masterPassword)
		if err := c.Authenticate(saslClient); err != nil {
			t.Fatalf("SASL PLAIN with master username failed: %v", err)
		}
		t.Log("✓ Successfully authenticated with SASL PLAIN master username")

		// Verify we can access the account
		mbox, err := c.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Select INBOX failed: %v", err)
		}
		t.Logf("✓ Successfully selected INBOX with %d messages", mbox.NumMessages)
	})

	t.Run("SASL PLAIN with MasterSASLUsername impersonation", func(t *testing.T) {
		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP server: %v", err)
		}
		defer c.Logout()

		// SASL PLAIN with authorization identity (impersonation)
		// Format: authorization-id \0 authentication-id \0 password
		authString := account.Email + "\x00" + masterSASLUsername + "\x00" + masterSASLPassword

		// Create custom SASL client with base64 encoding
		encoded := base64.StdEncoding.EncodeToString([]byte(authString))

		// We need to use the raw IMAP client to send AUTHENTICATE command
		// For now, use go-sasl with a custom client that handles authorization identity
		saslClient := &plainSASLClient{
			identity: account.Email,
			username: masterSASLUsername,
			password: masterSASLPassword,
		}

		if err := c.Authenticate(saslClient); err != nil {
			t.Fatalf("SASL PLAIN with master SASL credentials failed: %v (encoded: %s)", err, encoded)
		}
		t.Log("✓ Successfully authenticated with SASL PLAIN master SASL username")

		// Verify we can access the account
		mbox, err := c.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Select INBOX failed: %v", err)
		}
		t.Logf("✓ Successfully selected INBOX with %d messages", mbox.NumMessages)
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

// TestIMAP_MasterAuthenticationPriority tests that master authentication has priority
func TestIMAP_MasterAuthenticationPriority(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := setupIMAPServerWithMasterAuth(t)
	defer server.Close()

	t.Run("Master username overrides regular auth", func(t *testing.T) {
		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP server: %v", err)
		}
		defer c.Logout()

		// Even if we provide the account's real password, master username should use master password
		loginUsername := account.Email + "@" + masterUsername

		// This should fail because we're using the account password instead of master password
		err = c.Login(loginUsername, account.Password).Wait()
		if err == nil {
			t.Fatal("Expected login to fail when using account password with master username suffix")
		}
		t.Log("✓ Correctly rejected account password when master username suffix is present")
	})

	t.Run("Regular auth still works without suffix", func(t *testing.T) {
		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP server: %v", err)
		}
		defer c.Logout()

		// Regular login should still work
		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("Regular login failed: %v", err)
		}
		t.Log("✓ Regular authentication still works without master suffix")

		mbox, err := c.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Select INBOX failed: %v", err)
		}
		t.Logf("✓ Successfully selected INBOX with %d messages", mbox.NumMessages)
	})
}

// TestIMAP_MasterAuthenticationMultipleAccounts tests master auth with different accounts
func TestIMAP_MasterAuthenticationMultipleAccounts(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := setupIMAPServerWithMasterAuth(t)
	defer server.Close()

	// Create a second account
	account2 := common.CreateTestAccount(t, server.ResilientDB)

	t.Run("Master credentials work for different accounts", func(t *testing.T) {
		// Test with account 1
		c1, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP server: %v", err)
		}
		defer c1.Logout()

		loginUsername1 := account1.Email + "@" + masterUsername
		if err := c1.Login(loginUsername1, masterPassword).Wait(); err != nil {
			t.Fatalf("Login with master username failed for account1: %v", err)
		}
		t.Logf("✓ Master auth successful for account1: %s", account1.Email)

		// Test with account 2
		c2, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP server: %v", err)
		}
		defer c2.Logout()

		loginUsername2 := account2.Email + "@" + masterUsername
		if err := c2.Login(loginUsername2, masterPassword).Wait(); err != nil {
			t.Fatalf("Login with master username failed for account2: %v", err)
		}
		t.Logf("✓ Master auth successful for account2: %s", account2.Email)

		// Verify both can access their respective accounts
		mbox1, err := c1.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Select INBOX failed for account1: %v", err)
		}
		t.Logf("✓ Account1 INBOX: %d messages", mbox1.NumMessages)

		mbox2, err := c2.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Select INBOX failed for account2: %v", err)
		}
		t.Logf("✓ Account2 INBOX: %d messages", mbox2.NumMessages)
	})
}
