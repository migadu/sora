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

// setupServerWithPerUserPerIPLimit creates a test server with per-user-per-IP limiting
func setupServerWithPerUserPerIPLimit(t *testing.T, maxPerUser, maxPerUserPerIP int) (*common.TestServer, common.TestAccount, *proxy.ConnectionTracker) {
	t.Helper()

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	// Create temp directory for uploader
	tempDir, err := os.MkdirTemp("", "sora-test-upload-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	errCh := make(chan error, 1)

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

	testConfig := &config.Config{
		SharedMailboxes: config.SharedMailboxesConfig{
			Enabled:               false,
			NamespacePrefix:       "Shared/",
			AllowUserCreate:       false,
			DefaultRights:         "lrswipkxtea",
			AllowAnyoneIdentifier: false,
		},
	}

	server, err := imap.New(
		context.Background(),
		"test-per-user-per-ip",
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

	// Create connection tracker with per-user-per-IP limit
	instanceID := fmt.Sprintf("test-per-user-per-ip-%d", time.Now().UnixNano())
	tracker := proxy.NewConnectionTracker("IMAP", instanceID, nil, maxPerUser, maxPerUserPerIP, 0)
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
	time.Sleep(200 * time.Millisecond)

	return &common.TestServer{
		Server:      server,
		Address:     address,
		ResilientDB: rdb,
	}, account, tracker
}

// TestPerUserPerIPLimit tests that max_connections_per_user_per_ip is enforced
func TestPerUserPerIPLimit(t *testing.T) {
	testServer, account, tracker := setupServerWithPerUserPerIPLimit(t, 10, 3)
	defer testServer.Close()
	defer tracker.Stop()

	addr := testServer.Address

	// Helper to get account ID
	getAccountID := func() int64 {
		accountID, err := testServer.ResilientDB.GetAccountIDByEmailWithRetry(context.Background(), account.Email)
		if err != nil {
			t.Fatalf("Failed to get account ID: %v", err)
		}
		return accountID
	}

	t.Logf("IMAP server listening on %s", addr)
	t.Logf("Testing per-user-per-IP limit: max 3 connections from same IP for same user")

	// Test 1: Open 3 connections from same "IP" (localhost) - should all succeed
	var clients []*imapclient.Client
	defer func() {
		for _, c := range clients {
			if c != nil {
				c.Close()
			}
		}
	}()

	for i := 1; i <= 3; i++ {
		client, err := imapclient.DialInsecure(addr, nil)
		if err != nil {
			t.Fatalf("Failed to connect (connection %d): %v", i, err)
		}

		err = client.Login(account.Email, account.Password).Wait()
		if err != nil {
			t.Fatalf("Failed to login (connection %d): %v", i, err)
		}

		clients = append(clients, client)
		t.Logf("✓ Connection %d established and authenticated", i)
	}

	// Give a moment for connection tracking to register
	time.Sleep(100 * time.Millisecond)

	// Verify tracker shows 3 connections
	count := tracker.GetConnectionCount(getAccountID())
	if count != 3 {
		t.Errorf("Expected connection count = 3, got %d", count)
	}

	// Test 2: Try to open 4th connection - should be rejected
	client4, err := imapclient.DialInsecure(addr, nil)
	if err != nil {
		t.Fatalf("Failed to connect (4th connection): %v", err)
	}
	defer client4.Close()

	t.Log("Attempting 4th connection (should be rejected at login)...")
	err = client4.Login(account.Email, account.Password).Wait()
	if err == nil {
		t.Fatal("4th connection should have been rejected due to per-user-per-IP limit")
	}

	// Verify it's the right error
	t.Logf("4th connection rejected with error: %v", err)
	// The error should indicate connection limit was reached
	// Note: The actual error message might vary, so we just check it failed

	// Test 3: Close one connection and verify we can open a new one
	t.Log("Closing one connection...")
	clients[0].Close()
	clients[0] = nil

	// Wait for unregister to propagate
	time.Sleep(100 * time.Millisecond)

	// Verify count decreased
	count = tracker.GetConnectionCount(getAccountID())
	if count != 2 {
		t.Errorf("After closing one connection, count should be 2, got %d", count)
	}

	// Now 4th connection should succeed
	t.Log("Attempting new connection after closing one (should succeed)...")
	client5, err := imapclient.DialInsecure(addr, nil)
	if err != nil {
		t.Fatalf("Failed to connect after closing one: %v", err)
	}
	defer client5.Close()

	err = client5.Login(account.Email, account.Password).Wait()
	if err != nil {
		t.Fatalf("Connection should succeed after closing one: %v", err)
	}

	t.Log("✓ New connection succeeded after closing one")

	// Verify final count
	count = tracker.GetConnectionCount(getAccountID())
	if count != 3 {
		t.Errorf("Final connection count should be 3, got %d", count)
	}

	t.Log("✓ Per-user-per-IP limiting works correctly")
}

// TestPerUserPerIPLimit_MultipleUsers tests that per-user-per-IP limits are independent per user
func TestPerUserPerIPLimit_MultipleUsers(t *testing.T) {
	// This test needs two accounts, so we set up manually
	rdb := common.SetupTestDatabase(t)
	account1 := common.CreateTestAccount(t, rdb)
	account2 := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	// Create temp directory for uploader
	tempDir, err := os.MkdirTemp("", "sora-test-upload-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	errCh := make(chan error, 1)

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

	testConfig := &config.Config{
		SharedMailboxes: config.SharedMailboxesConfig{
			Enabled: false,
		},
	}

	server, err := imap.New(
		context.Background(),
		"test-multi-user",
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

	instanceID := fmt.Sprintf("test-multi-user-%d", time.Now().UnixNano())
	tracker := proxy.NewConnectionTracker("IMAP", instanceID, nil, 20, 2, 0)
	if tracker == nil {
		t.Fatal("Failed to create connection tracker")
	}
	defer tracker.Stop()

	server.SetConnTracker(tracker)

	// Start server
	errChan := make(chan error, 1)
	go func() {
		if err := server.Serve(address); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("IMAP server error: %w", err)
		}
	}()
	defer server.Close()

	time.Sleep(200 * time.Millisecond)

	addr := address

	// Helpers to get account IDs
	getAccountID1 := func() int64 {
		accountID, err := rdb.GetAccountIDByEmailWithRetry(context.Background(), account1.Email)
		if err != nil {
			t.Fatalf("Failed to get account1 ID: %v", err)
		}
		return accountID
	}
	getAccountID2 := func() int64 {
		accountID, err := rdb.GetAccountIDByEmailWithRetry(context.Background(), account2.Email)
		if err != nil {
			t.Fatalf("Failed to get account2 ID: %v", err)
		}
		return accountID
	}

	t.Logf("Testing per-user-per-IP with multiple users (each can have 2 connections from same IP)")

	var clients []*imapclient.Client
	defer func() {
		for _, c := range clients {
			if c != nil {
				c.Close()
			}
		}
	}()

	// User 1: Open 2 connections (should succeed)
	for i := 1; i <= 2; i++ {
		client, err := imapclient.DialInsecure(addr, nil)
		if err != nil {
			t.Fatalf("User1 connection %d failed to connect: %v", i, err)
		}

		err = client.Login(account1.Email, account1.Password).Wait()
		if err != nil {
			t.Fatalf("User1 connection %d failed to login: %v", i, err)
		}

		clients = append(clients, client)
		t.Logf("✓ User1 connection %d established", i)
	}

	// User 2: Open 2 connections (should succeed - different user)
	for i := 1; i <= 2; i++ {
		client, err := imapclient.DialInsecure(addr, nil)
		if err != nil {
			t.Fatalf("User2 connection %d failed to connect: %v", i, err)
		}

		err = client.Login(account2.Email, account2.Password).Wait()
		if err != nil {
			t.Fatalf("User2 connection %d failed to login: %v", i, err)
		}

		clients = append(clients, client)
		t.Logf("✓ User2 connection %d established", i)
	}

	time.Sleep(100 * time.Millisecond)

	// Verify counts
	count1 := tracker.GetConnectionCount(getAccountID1())
	if count1 != 2 {
		t.Errorf("User1 should have 2 connections, got %d", count1)
	}

	count2 := tracker.GetConnectionCount(getAccountID2())
	if count2 != 2 {
		t.Errorf("User2 should have 2 connections, got %d", count2)
	}

	// User 1: Try 3rd connection (should fail)
	client3, err := imapclient.DialInsecure(addr, nil)
	if err != nil {
		t.Fatalf("User1 3rd connection failed to connect: %v", err)
	}
	defer client3.Close()

	err = client3.Login(account1.Email, account1.Password).Wait()
	if err == nil {
		t.Fatal("User1 3rd connection should have been rejected")
	}
	t.Logf("✓ User1 3rd connection rejected as expected")

	// User 2: Try 3rd connection (should also fail)
	client4, err := imapclient.DialInsecure(addr, nil)
	if err != nil {
		t.Fatalf("User2 3rd connection failed to connect: %v", err)
	}
	defer client4.Close()

	err = client4.Login(account2.Email, account2.Password).Wait()
	if err == nil {
		t.Fatal("User2 3rd connection should have been rejected")
	}
	t.Logf("✓ User2 3rd connection rejected as expected")

	t.Log("✓ Per-user-per-IP limits are independent per user")
}

// TestPerUserPerIPLimit_Disabled tests that per-user-per-IP limiting can be disabled
func TestPerUserPerIPLimit_Disabled(t *testing.T) {
	testServer, account, tracker := setupServerWithPerUserPerIPLimit(t, 20, 0)
	defer testServer.Close()
	defer tracker.Stop()

	addr := testServer.Address

	// Helper to get account ID
	getAccountID := func() int64 {
		accountID, err := testServer.ResilientDB.GetAccountIDByEmailWithRetry(context.Background(), account.Email)
		if err != nil {
			t.Fatalf("Failed to get account ID: %v", err)
		}
		return accountID
	}

	t.Log("Testing with per-user-per-IP limit disabled (should allow many connections)")

	var clients []*imapclient.Client
	defer func() {
		for _, c := range clients {
			if c != nil {
				c.Close()
			}
		}
	}()

	// Open 10 connections from same IP (should all succeed when disabled)
	for i := 1; i <= 10; i++ {
		client, err := imapclient.DialInsecure(addr, nil)
		if err != nil {
			t.Fatalf("Connection %d failed to connect: %v", i, err)
		}

		err = client.Login(account.Email, account.Password).Wait()
		if err != nil {
			t.Fatalf("Connection %d failed to login: %v", i, err)
		}

		clients = append(clients, client)
	}

	time.Sleep(100 * time.Millisecond)

	// Verify all 10 connections are tracked
	count := tracker.GetConnectionCount(getAccountID())
	if count != 10 {
		t.Errorf("Expected 10 connections with limit disabled, got %d", count)
	}

	t.Log("✓ Per-user-per-IP limiting can be disabled (0 = unlimited)")
}
