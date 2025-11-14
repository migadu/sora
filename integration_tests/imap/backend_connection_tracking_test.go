//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/server/proxy"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// SetupIMAPServerWithConnectionTracking creates an IMAP server with local connection tracking enabled
func SetupIMAPServerWithConnectionTracking(t *testing.T, maxConnectionsPerUser int) (*common.TestServer, common.TestAccount, *proxy.ConnectionTracker) {
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

	// Create test config
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
			Config: testConfig,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create IMAP server: %v", err)
	}

	// Create and set connection tracker in local mode (no cluster manager)
	tracker := proxy.NewConnectionTracker("IMAP", "test-backend-instance", nil, maxConnectionsPerUser, 0, 0)
	if tracker == nil {
		t.Fatal("Failed to create connection tracker")
	}
	server.SetConnTracker(tracker)

	// Start server in background
	errChan := make(chan error, 1)
	go func() {
		if err := server.Serve(address); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("IMAP server error: %w", err)
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	return &common.TestServer{
		Address:     address,
		Server:      server,
		ResilientDB: rdb,
	}, account, tracker
}

// TestBackendConnectionTracking tests connection tracking on a backend IMAP server (local mode, no cluster)
func TestBackendConnectionTracking(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Helper to get account ID
	getAccountID := func(server *common.TestServer, email string) int64 {
		accountID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(context.Background(), email)
		if err != nil {
			t.Fatalf("Failed to get account ID: %v", err)
		}
		return accountID
	}

	// Helper to connect and authenticate
	connectClient := func(addr, email, password string) (*imapclient.Client, error) {
		c, err := imapclient.DialInsecure(addr, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to dial: %w", err)
		}

		if err := c.Login(email, password).Wait(); err != nil {
			c.Close()
			return nil, fmt.Errorf("failed to login: %w", err)
		}

		return c, nil
	}

	t.Run("track_connections", func(t *testing.T) {
		server, account, tracker := SetupIMAPServerWithConnectionTracking(t, 5)
		defer tracker.Stop()
		defer server.Server.(*imap.IMAPServer).Close()
		defer server.Close()

		AccountID := getAccountID(server, account.Email)

		// Connect first client
		client1, err := connectClient(server.Address, account.Email, account.Password)
		if err != nil {
			t.Fatalf("Failed to connect client1: %v", err)
		}
		defer client1.Close()

		// Check tracker has 1 connection
		time.Sleep(200 * time.Millisecond) // Give time for registration
		count := tracker.GetConnectionCount(AccountID)
		if count != 1 {
			t.Errorf("Expected 1 connection, got %d", count)
		}

		// Connect second client
		client2, err := connectClient(server.Address, account.Email, account.Password)
		if err != nil {
			t.Fatalf("Failed to connect client2: %v", err)
		}
		defer client2.Close()

		// Check tracker has 2 connections
		time.Sleep(200 * time.Millisecond)
		count = tracker.GetConnectionCount(AccountID)
		if count != 2 {
			t.Errorf("Expected 2 connections, got %d", count)
		}

		// Disconnect client1
		client1.Close()
		time.Sleep(200 * time.Millisecond)

		// Check tracker has 1 connection
		count = tracker.GetConnectionCount(AccountID)
		if count != 1 {
			t.Errorf("Expected 1 connection after disconnect, got %d", count)
		}

		t.Log("✓ Backend connection tracking works")
	})

	t.Run("enforce_connection_limit", func(t *testing.T) {
		server, account, tracker := SetupIMAPServerWithConnectionTracking(t, 2) // Limit of 2
		defer tracker.Stop()
		defer server.Server.(*imap.IMAPServer).Close()
		defer server.Close()

		AccountID := getAccountID(server, account.Email)

		// Connect 2 clients (should succeed)
		client1, err := connectClient(server.Address, account.Email, account.Password)
		if err != nil {
			t.Fatalf("Failed to connect client1: %v", err)
		}
		defer client1.Close()

		client2, err := connectClient(server.Address, account.Email, account.Password)
		if err != nil {
			t.Fatalf("Failed to connect client2: %v", err)
		}
		defer client2.Close()

		time.Sleep(200 * time.Millisecond)

		// Verify we have 2 connections
		count := tracker.GetConnectionCount(AccountID)
		if count != 2 {
			t.Errorf("Expected 2 connections, got %d", count)
		}

		// Try to connect 3rd client (should fail during login)
		client3, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			// If we can't even dial, that's fine - connection limit enforced at TCP level
			t.Log("✓ 3rd connection rejected at TCP level (connection limit enforced)")
			return
		}
		defer client3.Close()

		// Try to login (should fail because limit reached)
		loginErr := client3.Login(account.Email, account.Password).Wait()
		if loginErr == nil {
			t.Error("Expected 3rd client login to fail due to connection limit, but it succeeded")

			// Verify count didn't increase
			time.Sleep(100 * time.Millisecond)
			count = tracker.GetConnectionCount(AccountID)
			if count > 2 {
				t.Errorf("Connection count should not exceed 2, got %d", count)
			}
		} else {
			t.Logf("✓ 3rd client login rejected: %v (connection limit enforced)", loginErr)
		}
	})

	t.Run("kick_user_disconnects_sessions", func(t *testing.T) {
		server, account, tracker := SetupIMAPServerWithConnectionTracking(t, 10)
		defer tracker.Stop()
		defer server.Server.(*imap.IMAPServer).Close()
		defer server.Close()

		AccountID := getAccountID(server, account.Email)

		// Connect 2 clients
		client1, err := connectClient(server.Address, account.Email, account.Password)
		if err != nil {
			t.Fatalf("Failed to connect client1: %v", err)
		}
		defer client1.Close()

		client2, err := connectClient(server.Address, account.Email, account.Password)
		if err != nil {
			t.Fatalf("Failed to connect client2: %v", err)
		}
		defer client2.Close()

		time.Sleep(200 * time.Millisecond)

		// Verify both connected
		count := tracker.GetConnectionCount(AccountID)
		if count != 2 {
			t.Errorf("Expected 2 connections before kick, got %d", count)
		}

		// Kick the user
		err = tracker.KickUser(AccountID, "IMAP")
		if err != nil {
			t.Fatalf("Failed to kick user: %v", err)
		}

		// Give time for kick to propagate and connections to close
		time.Sleep(500 * time.Millisecond)

		// Try to use client1 (should fail because connection was closed)
		_, err1 := client1.Select("INBOX", nil).Wait()
		_, err2 := client2.Select("INBOX", nil).Wait()

		if err1 == nil && err2 == nil {
			t.Error("Expected at least one client to be disconnected after kick")
		} else {
			if err1 != nil {
				t.Logf("✓ Client1 connection closed after kick: %v", err1)
			}
			if err2 != nil {
				t.Logf("✓ Client2 connection closed after kick: %v", err2)
			}
		}

		t.Log("✓ Kick successfully disconnected user sessions")
	})
}
