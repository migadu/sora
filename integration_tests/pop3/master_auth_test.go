//go:build integration

package pop3_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/pop3"
	"github.com/migadu/sora/storage"
)

const (
	masterUsername     = "admin"
	masterPassword     = "master_secret_123"
	masterSASLUsername = "sasl_admin"
	masterSASLPassword = "sasl_secret_456"
)

// setupPOP3ServerWithMasterAuth creates a POP3 server with master authentication configured
func setupPOP3ServerWithMasterAuth(t *testing.T) (*common.TestServer, common.TestAccount) {
	t.Helper()

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	// Create minimal S3 storage
	s3Storage := &storage.S3Storage{}

	testConfig := &config.Config{}

	server, err := pop3.New(
		context.Background(),
		"test",
		"localhost",
		address,
		s3Storage,
		rdb,
		nil, // uploadWorker
		nil, // cache
		pop3.POP3ServerOptions{
			InsecureAuth:       true, // Allow PLAIN auth (no TLS in tests)
			Config:             testConfig,
			MasterUsername:     masterUsername,
			MasterPassword:     masterPassword,
			MasterSASLUsername: masterSASLUsername,
			MasterSASLPassword: masterSASLPassword,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create POP3 server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		server.Start(errChan)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	cleanup := func() {
		server.Close()
		select {
		case err := <-errChan:
			if err != nil {
				t.Logf("POP3 server error during shutdown: %v", err)
			}
		case <-time.After(1 * time.Second):
			// Timeout waiting for server to shut down
		}
	}

	ts := &common.TestServer{
		Address:     address,
		Server:      server,
		ResilientDB: rdb,
	}
	t.Cleanup(cleanup)

	return ts, account
}

// TestPOP3_MasterUsernameAuthentication tests USER/PASS with MasterUsername
func TestPOP3_MasterUsernameAuthentication(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := setupPOP3ServerWithMasterAuth(t)
	defer server.Close()

	t.Run("USER PASS with MasterUsername suffix", func(t *testing.T) {
		client, err := NewPOP3Client(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 server: %v", err)
		}
		defer client.Close()

		// USER format: user@domain.com@MASTER_USERNAME
		username := account.Email + "@" + masterUsername
		if err := client.SendCommand("USER " + username); err != nil {
			t.Fatalf("USER command failed: %v", err)
		}
		response, err := client.ReadResponse()
		if err != nil || !strings.HasPrefix(response, "+OK") {
			t.Fatalf("USER command rejected: %s (err: %v)", response, err)
		}
		t.Logf("USER accepted: %s", response)

		// PASS with MASTER_PASSWORD
		if err := client.SendCommand("PASS " + masterPassword); err != nil {
			t.Fatalf("PASS command failed: %v", err)
		}
		response, err = client.ReadResponse()
		if err != nil || !strings.HasPrefix(response, "+OK") {
			t.Fatalf("Authentication failed: %s (err: %v)", response, err)
		}
		t.Log("✓ Successfully authenticated with MasterUsername")

		// Verify we can use STAT command
		if err := client.SendCommand("STAT"); err != nil {
			t.Fatalf("STAT command failed: %v", err)
		}
		response, err = client.ReadResponse()
		if err != nil || !strings.HasPrefix(response, "+OK") {
			t.Fatalf("STAT command failed: %s", response)
		}
		t.Logf("✓ STAT successful: %s", response)
	})

	t.Run("USER PASS with wrong MasterUsername suffix", func(t *testing.T) {
		client, err := NewPOP3Client(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 server: %v", err)
		}
		defer client.Close()

		username := account.Email + "@wrongmaster"
		client.SendCommand("USER " + username)
		client.ReadResponse()

		client.SendCommand("PASS " + masterPassword)
		response, _ := client.ReadResponse()
		if strings.HasPrefix(response, "+OK") {
			t.Fatal("Expected authentication to fail with wrong master username")
		}
		t.Logf("✓ Authentication correctly failed with wrong master username: %s", response)
	})

	t.Run("USER PASS with wrong MasterPassword", func(t *testing.T) {
		client, err := NewPOP3Client(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 server: %v", err)
		}
		defer client.Close()

		username := account.Email + "@" + masterUsername
		client.SendCommand("USER " + username)
		client.ReadResponse()

		client.SendCommand("PASS wrong_password")
		response, _ := client.ReadResponse()
		if strings.HasPrefix(response, "+OK") {
			t.Fatal("Expected authentication to fail with wrong master password")
		}
		t.Logf("✓ Authentication correctly failed with wrong master password: %s", response)
	})
}

// TestPOP3_MasterSASLAuthentication tests AUTH PLAIN with master credentials
func TestPOP3_MasterSASLAuthentication(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := setupPOP3ServerWithMasterAuth(t)
	defer server.Close()

	t.Run("AUTH PLAIN with MasterUsername suffix", func(t *testing.T) {
		client, err := NewPOP3Client(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 server: %v", err)
		}
		defer client.Close()

		// AUTH PLAIN with master username suffix
		username := account.Email + "@" + masterUsername
		authString := "\x00" + username + "\x00" + masterPassword
		encoded := base64.StdEncoding.EncodeToString([]byte(authString))

		if err := client.SendCommand("AUTH PLAIN " + encoded); err != nil {
			t.Fatalf("AUTH PLAIN command failed: %v", err)
		}
		response, err := client.ReadResponse()
		if err != nil || !strings.HasPrefix(response, "+OK") {
			t.Fatalf("Authentication failed: %s (err: %v)", response, err)
		}
		t.Log("✓ Successfully authenticated with AUTH PLAIN master username")

		// Verify we can use STAT command
		if err := client.SendCommand("STAT"); err != nil {
			t.Fatalf("STAT command failed: %v", err)
		}
		response, err = client.ReadResponse()
		if err != nil || !strings.HasPrefix(response, "+OK") {
			t.Fatalf("STAT command failed: %s", response)
		}
		t.Logf("✓ STAT successful: %s", response)
	})

	t.Run("AUTH PLAIN with MasterSASLUsername impersonation", func(t *testing.T) {
		client, err := NewPOP3Client(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 server: %v", err)
		}
		defer client.Close()

		// AUTH PLAIN with authorization identity (impersonation)
		// Format: authorization-id \0 authentication-id \0 password
		authString := account.Email + "\x00" + masterSASLUsername + "\x00" + masterSASLPassword
		encoded := base64.StdEncoding.EncodeToString([]byte(authString))

		if err := client.SendCommand("AUTH PLAIN " + encoded); err != nil {
			t.Fatalf("AUTH PLAIN command failed: %v", err)
		}
		response, err := client.ReadResponse()
		if err != nil || !strings.HasPrefix(response, "+OK") {
			t.Fatalf("Authentication failed: %s (err: %v)", response, err)
		}
		t.Log("✓ Successfully authenticated with AUTH PLAIN master SASL username")

		// Verify we can use STAT command
		if err := client.SendCommand("STAT"); err != nil {
			t.Fatalf("STAT command failed: %v", err)
		}
		response, err = client.ReadResponse()
		if err != nil || !strings.HasPrefix(response, "+OK") {
			t.Fatalf("STAT command failed: %s", response)
		}
		t.Logf("✓ STAT successful: %s", response)
	})
}

// TestPOP3_MasterAuthenticationPriority tests authentication priority
func TestPOP3_MasterAuthenticationPriority(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := setupPOP3ServerWithMasterAuth(t)
	defer server.Close()

	t.Run("Master username overrides regular auth", func(t *testing.T) {
		client, err := NewPOP3Client(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 server: %v", err)
		}
		defer client.Close()

		// Try master username suffix with account password (should fail)
		username := account.Email + "@" + masterUsername
		client.SendCommand("USER " + username)
		client.ReadResponse()

		client.SendCommand("PASS " + account.Password)
		response, _ := client.ReadResponse()
		if strings.HasPrefix(response, "+OK") {
			t.Fatal("Expected authentication to fail when using account password with master username suffix")
		}
		t.Log("✓ Correctly rejected account password when master username suffix is present")
	})

	t.Run("Regular auth still works without suffix", func(t *testing.T) {
		client, err := NewPOP3Client(server.Address)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 server: %v", err)
		}
		defer client.Close()

		// Regular authentication should work
		client.SendCommand("USER " + account.Email)
		client.ReadResponse()

		client.SendCommand("PASS " + account.Password)
		response, err := client.ReadResponse()
		if err != nil || !strings.HasPrefix(response, "+OK") {
			t.Fatalf("Regular authentication failed: %s", response)
		}
		t.Log("✓ Regular authentication still works without master suffix")

		// Verify STAT works
		client.SendCommand("STAT")
		response, _ = client.ReadResponse()
		if !strings.HasPrefix(response, "+OK") {
			t.Fatalf("STAT failed: %s", response)
		}
		t.Logf("✓ STAT successful: %s", response)
	})
}
