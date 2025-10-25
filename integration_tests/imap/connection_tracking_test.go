//go:build integration

package imap_test

import (
	"context"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
)

func TestIMAP_ConnectionTracking(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Connect and login
	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	t.Logf("Logged in as %s", account.Email)

	// Give the connection tracker a moment to register the connection
	time.Sleep(2 * time.Second)

	// Check that the connection was tracked
	ctx := context.Background()
	connections, err := server.ResilientDB.GetActiveConnectionsWithRetry(ctx)
	if err != nil {
		t.Fatalf("Failed to get active connections: %v", err)
	}

	// Find our connection
	var found *db.ConnectionInfo
	for i := range connections {
		if connections[i].Email == account.Email && connections[i].Protocol == "IMAP" {
			found = &connections[i]
			break
		}
	}

	if found == nil {
		t.Fatalf("Connection not found in active connections. Email: %s, Protocol: IMAP", account.Email)
	}

	// Verify connection details
	t.Logf("Found connection: Email=%s, Protocol=%s, IsProxy=%v, ClientAddr=%s, ServerAddr=%s",
		found.Email, found.Protocol, found.IsProxy, found.ClientAddr, found.ServerAddr)

	if found.Email != account.Email {
		t.Errorf("Expected email %s, got %s", account.Email, found.Email)
	}

	if found.Protocol != "IMAP" {
		t.Errorf("Expected protocol IMAP, got %s", found.Protocol)
	}

	if found.IsProxy {
		t.Errorf("Expected IsProxy=false for direct backend connection, got true")
	}

	if found.ClientAddr == "" {
		t.Error("ClientAddr should not be empty")
	}

	if found.ServerAddr == "" {
		t.Error("ServerAddr should not be empty")
	}

	t.Log("✓ Connection tracking verified: email is recorded and IsProxy=false")

	// Logout
	if err := c.Logout().Wait(); err != nil {
		t.Logf("Logout error (expected): %v", err)
	}

	// Give the connection tracker a moment to unregister
	time.Sleep(2 * time.Second)

	// Verify connection was removed
	connections, err = server.ResilientDB.GetActiveConnectionsWithRetry(ctx)
	if err != nil {
		t.Fatalf("Failed to get active connections after logout: %v", err)
	}

	for _, conn := range connections {
		if conn.Email == account.Email && conn.Protocol == "IMAP" {
			t.Errorf("Connection still active after logout: %+v", conn)
		}
	}

	t.Log("✓ Connection properly unregistered after logout")
}

func TestIMAP_KickConnection(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Connect and login
	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Close()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	t.Logf("Logged in as %s", account.Email)

	// Give the connection tracker a moment to register the connection
	time.Sleep(2 * time.Second)

	// Verify connection is active
	ctx := context.Background()
	connections, err := server.ResilientDB.GetActiveConnectionsWithRetry(ctx)
	if err != nil {
		t.Fatalf("Failed to get active connections: %v", err)
	}

	var found *db.ConnectionInfo
	for i := range connections {
		if connections[i].Email == account.Email && connections[i].Protocol == "IMAP" {
			found = &connections[i]
			break
		}
	}

	if found == nil {
		t.Fatalf("Connection not found before kick")
	}

	t.Logf("Connection found: AccountID=%d, ClientAddr=%s", found.AccountID, found.ClientAddr)

	// Mark connection for termination (simulate kick command)
	criteria := db.TerminationCriteria{
		Email: account.Email,
	}

	affected, err := server.ResilientDB.MarkConnectionsForTerminationWithRetry(ctx, criteria)
	if err != nil {
		t.Fatalf("Failed to mark connection for termination: %v", err)
	}

	if affected == 0 {
		t.Fatal("No connections marked for termination")
	}

	t.Logf("Marked %d connection(s) for termination", affected)

	// The connection should be kicked within 10-15 seconds (termination poller interval)
	// Try to execute a command - it should fail
	kicked := false
	maxWait := 20 * time.Second
	checkInterval := 1 * time.Second
	deadline := time.Now().Add(maxWait)

	for time.Now().Before(deadline) {
		// Try a simple command (NOOP)
		err := c.Noop().Wait()
		if err != nil {
			t.Logf("Connection kicked! Command failed with: %v", err)
			kicked = true
			break
		}
		time.Sleep(checkInterval)
	}

	if !kicked {
		t.Errorf("Connection was not kicked within %v", maxWait)
	} else {
		t.Log("✓ Connection successfully kicked")
	}

	// Verify connection was removed from database
	time.Sleep(1 * time.Second)
	connections, err = server.ResilientDB.GetActiveConnectionsWithRetry(ctx)
	if err != nil {
		t.Fatalf("Failed to get active connections after kick: %v", err)
	}

	for _, conn := range connections {
		if conn.Email == account.Email && conn.Protocol == "IMAP" {
			t.Errorf("Connection still active in database after kick: %+v", conn)
		}
	}

	t.Log("✓ Connection removed from database after kick")
}

func TestIMAP_MultipleConnectionsTracking(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Create 3 connections
	var clients []*imapclient.Client
	for i := 0; i < 3; i++ {
		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP server (connection %d): %v", i+1, err)
		}
		defer c.Close()

		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("Login failed (connection %d): %v", i+1, err)
		}

		clients = append(clients, c)
		t.Logf("Created connection %d", i+1)
	}

	// Give the connection tracker a moment to register all connections
	time.Sleep(2 * time.Second)

	// Check that all 3 connections are tracked
	ctx := context.Background()
	connections, err := server.ResilientDB.GetActiveConnectionsWithRetry(ctx)
	if err != nil {
		t.Fatalf("Failed to get active connections: %v", err)
	}

	count := 0
	for _, conn := range connections {
		if conn.Email == account.Email && conn.Protocol == "IMAP" {
			count++
			t.Logf("Found connection: ClientAddr=%s, IsProxy=%v", conn.ClientAddr, conn.IsProxy)
		}
	}

	if count != 3 {
		t.Errorf("Expected 3 connections, found %d", count)
	}

	t.Logf("✓ All 3 connections tracked correctly")

	// Close all connections
	for i, c := range clients {
		if err := c.Logout().Wait(); err != nil {
			t.Logf("Logout error for connection %d (expected): %v", i+1, err)
		}
	}

	// Give the connection tracker a moment to unregister all
	time.Sleep(2 * time.Second)

	// Verify all connections were removed
	connections, err = server.ResilientDB.GetActiveConnectionsWithRetry(ctx)
	if err != nil {
		t.Fatalf("Failed to get active connections after logout: %v", err)
	}

	count = 0
	for _, conn := range connections {
		if conn.Email == account.Email && conn.Protocol == "IMAP" {
			count++
		}
	}

	if count != 0 {
		t.Errorf("Expected 0 connections after logout, found %d", count)
	}

	t.Log("✓ All connections properly unregistered")
}
