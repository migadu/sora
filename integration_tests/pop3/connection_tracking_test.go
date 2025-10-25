//go:build integration

package pop3_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
)

func TestPOP3_ConnectionTracking(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupPOP3Server(t)
	defer server.Close()

	// Connect
	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to POP3 server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	t.Logf("Greeting: %s", strings.TrimSpace(greeting))

	// Send USER
	fmt.Fprintf(conn, "USER %s\r\n", account.Email)
	userResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read USER response: %v", err)
	}
	if !strings.HasPrefix(userResp, "+OK") {
		t.Fatalf("USER command failed: %s", userResp)
	}
	t.Logf("USER response: %s", strings.TrimSpace(userResp))

	// Send PASS
	fmt.Fprintf(conn, "PASS %s\r\n", account.Password)
	passResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read PASS response: %v", err)
	}
	if !strings.HasPrefix(passResp, "+OK") {
		t.Fatalf("PASS command failed: %s", passResp)
	}
	t.Logf("PASS response: %s", strings.TrimSpace(passResp))
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
		if connections[i].Email == account.Email && connections[i].Protocol == "POP3" {
			found = &connections[i]
			break
		}
	}

	if found == nil {
		t.Fatalf("Connection not found in active connections. Email: %s, Protocol: POP3", account.Email)
	}

	// Verify connection details
	t.Logf("Found connection: Email=%s, Protocol=%s, IsProxy=%v, ClientAddr=%s, ServerAddr=%s",
		found.Email, found.Protocol, found.IsProxy, found.ClientAddr, found.ServerAddr)

	if found.Email != account.Email {
		t.Errorf("Expected email %s, got %s", account.Email, found.Email)
	}

	if found.Protocol != "POP3" {
		t.Errorf("Expected protocol POP3, got %s", found.Protocol)
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

	// Send QUIT
	fmt.Fprintf(conn, "QUIT\r\n")
	quitResp, err := reader.ReadString('\n')
	if err != nil {
		t.Logf("QUIT response error (expected): %v", err)
	} else {
		t.Logf("QUIT response: %s", strings.TrimSpace(quitResp))
	}

	conn.Close()

	// Give the connection tracker a moment to unregister
	time.Sleep(2 * time.Second)

	// Verify connection was removed
	connections, err = server.ResilientDB.GetActiveConnectionsWithRetry(ctx)
	if err != nil {
		t.Fatalf("Failed to get active connections after logout: %v", err)
	}

	for _, conn := range connections {
		if conn.Email == account.Email && conn.Protocol == "POP3" {
			t.Errorf("Connection still active after logout: %+v", conn)
		}
	}

	t.Log("✓ Connection properly unregistered after logout")
}

func TestPOP3_KickConnection(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupPOP3Server(t)
	defer server.Close()

	// Connect
	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to POP3 server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	t.Logf("Greeting: %s", strings.TrimSpace(greeting))

	// Login
	fmt.Fprintf(conn, "USER %s\r\n", account.Email)
	userResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read USER response: %v", err)
	}
	if !strings.HasPrefix(userResp, "+OK") {
		t.Fatalf("USER command failed: %s", userResp)
	}

	fmt.Fprintf(conn, "PASS %s\r\n", account.Password)
	passResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read PASS response: %v", err)
	}
	if !strings.HasPrefix(passResp, "+OK") {
		t.Fatalf("PASS command failed: %s", passResp)
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
		if connections[i].Email == account.Email && connections[i].Protocol == "POP3" {
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
	// Try to send a command - it should fail
	kicked := false
	maxWait := 20 * time.Second
	checkInterval := 1 * time.Second
	deadline := time.Now().Add(maxWait)

	for time.Now().Before(deadline) {
		// Set a short read timeout
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))

		// Try a simple command (NOOP)
		fmt.Fprintf(conn, "NOOP\r\n")
		_, err := reader.ReadString('\n')
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
		if conn.Email == account.Email && conn.Protocol == "POP3" {
			t.Errorf("Connection still active in database after kick: %+v", conn)
		}
	}

	t.Log("✓ Connection removed from database after kick")
}

func TestPOP3_MultipleConnectionsTracking(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupPOP3Server(t)
	defer server.Close()

	// Create 3 connections
	var conns []net.Conn
	for i := 0; i < 3; i++ {
		conn, err := net.Dial("tcp", server.Address)
		if err != nil {
			t.Fatalf("Failed to connect to POP3 server (connection %d): %v", i+1, err)
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)

		// Read greeting
		if _, err := reader.ReadString('\n'); err != nil {
			t.Fatalf("Failed to read greeting (connection %d): %v", i+1, err)
		}

		// Login
		fmt.Fprintf(conn, "USER %s\r\n", account.Email)
		if _, err := reader.ReadString('\n'); err != nil {
			t.Fatalf("Failed to read USER response (connection %d): %v", i+1, err)
		}

		fmt.Fprintf(conn, "PASS %s\r\n", account.Password)
		passResp, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read PASS response (connection %d): %v", i+1, err)
		}
		if !strings.HasPrefix(passResp, "+OK") {
			t.Fatalf("PASS command failed (connection %d): %s", i+1, passResp)
		}

		conns = append(conns, conn)
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
		if conn.Email == account.Email && conn.Protocol == "POP3" {
			count++
			t.Logf("Found connection: ClientAddr=%s, IsProxy=%v", conn.ClientAddr, conn.IsProxy)
		}
	}

	if count != 3 {
		t.Errorf("Expected 3 connections, found %d", count)
	}

	t.Logf("✓ All 3 connections tracked correctly")

	// Close all connections
	for i, conn := range conns {
		fmt.Fprintf(conn, "QUIT\r\n")
		conn.Close()
		t.Logf("Closed connection %d", i+1)
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
		if conn.Email == account.Email && conn.Protocol == "POP3" {
			count++
		}
	}

	if count != 0 {
		t.Errorf("Expected 0 connections after logout, found %d", count)
	}

	t.Log("✓ All connections properly unregistered")
}
