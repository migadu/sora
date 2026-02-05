package server

import (
	"context"
	"testing"
	"time"
)

func TestLocalConnectionTracker_RegisterAndUnregister(t *testing.T) {
	// Create tracker in local mode (no cluster manager)
	tracker := NewConnectionTracker("IMAP", "", "", "test-instance", nil, 5, 0, 0, false)
	if tracker == nil {
		t.Fatal("NewConnectionTracker returned nil for local mode")
	}
	defer tracker.Stop()

	ctx := context.Background()
	accountID := int64(123)
	username := "user@example.com"

	// Register a connection
	err := tracker.RegisterConnection(ctx, accountID, username, "IMAP", "192.168.1.1:12345")
	if err != nil {
		t.Fatalf("Failed to register connection: %v", err)
	}

	// Check count
	count := tracker.GetConnectionCount(accountID)
	if count != 1 {
		t.Errorf("Expected count=1, got %d", count)
	}

	// Register another connection for same user
	err = tracker.RegisterConnection(ctx, accountID, username, "IMAP", "192.168.1.1:12346")
	if err != nil {
		t.Fatalf("Failed to register second connection: %v", err)
	}

	count = tracker.GetConnectionCount(accountID)
	if count != 2 {
		t.Errorf("Expected count=2, got %d", count)
	}

	// Unregister one
	err = tracker.UnregisterConnection(ctx, accountID, "IMAP", "192.168.1.1:12345")
	if err != nil {
		t.Fatalf("Failed to unregister connection: %v", err)
	}

	count = tracker.GetConnectionCount(accountID)
	if count != 1 {
		t.Errorf("Expected count=1 after unregister, got %d", count)
	}

	// Unregister last connection
	err = tracker.UnregisterConnection(ctx, accountID, "IMAP", "192.168.1.1:12346")
	if err != nil {
		t.Fatalf("Failed to unregister last connection: %v", err)
	}

	count = tracker.GetConnectionCount(accountID)
	if count != 0 {
		t.Errorf("Expected count=0 after all unregistered, got %d", count)
	}

	t.Log("✓ Local tracker register/unregister works correctly")
}

func TestLocalConnectionTracker_EnforceLimit(t *testing.T) {
	// Create tracker with limit of 3 connections per user
	tracker := NewConnectionTracker("IMAP", "", "", "test-instance", nil, 3, 0, 0, false)
	if tracker == nil {
		t.Fatal("NewConnectionTracker returned nil")
	}
	defer tracker.Stop()

	ctx := context.Background()
	accountID := int64(456)
	username := "limited@example.com"

	// Register 3 connections (should succeed)
	for i := 0; i < 3; i++ {
		clientAddr := "192.168.1.1:" + string(rune(10000+i))
		err := tracker.RegisterConnection(ctx, accountID, username, "IMAP", clientAddr)
		if err != nil {
			t.Fatalf("Failed to register connection %d: %v", i+1, err)
		}
	}

	count := tracker.GetConnectionCount(accountID)
	if count != 3 {
		t.Errorf("Expected count=3, got %d", count)
	}

	// Try to register 4th connection (should fail)
	err := tracker.RegisterConnection(ctx, accountID, username, "IMAP", "192.168.1.1:10004")
	if err == nil {
		t.Error("Expected error when exceeding limit, got nil")
	}

	if err != nil && err.Error() != "user limited@example.com has reached maximum connections (3/3 on this server)" {
		t.Errorf("Unexpected error message: %v", err)
	}

	// Verify count didn't increase
	count = tracker.GetConnectionCount(accountID)
	if count != 3 {
		t.Errorf("Expected count=3 after rejected connection, got %d", count)
	}

	// Unregister one connection
	err = tracker.UnregisterConnection(ctx, accountID, "IMAP", "192.168.1.1:10000")
	if err != nil {
		t.Fatalf("Failed to unregister: %v", err)
	}

	// Now 4th connection should succeed
	err = tracker.RegisterConnection(ctx, accountID, username, "IMAP", "192.168.1.1:10004")
	if err != nil {
		t.Errorf("Expected connection to succeed after unregister, got error: %v", err)
	}

	count = tracker.GetConnectionCount(accountID)
	if count != 3 {
		t.Errorf("Expected count=3, got %d", count)
	}

	t.Log("✓ Local tracker enforces connection limits correctly")
}

func TestLocalConnectionTracker_KickUser(t *testing.T) {
	tracker := NewConnectionTracker("IMAP", "", "", "test-instance", nil, 10, 0, 0, false)
	if tracker == nil {
		t.Fatal("NewConnectionTracker returned nil")
	}
	defer tracker.Stop()

	ctx := context.Background()
	accountID := int64(789)
	username := "kickme@example.com"

	// Register connections
	err := tracker.RegisterConnection(ctx, accountID, username, "IMAP", "192.168.1.1:12345")
	if err != nil {
		t.Fatalf("Failed to register connection: %v", err)
	}

	// Register 2 sessions for kick notifications
	kickChan1 := tracker.RegisterSession(accountID)
	kickChan2 := tracker.RegisterSession(accountID)

	// Verify channels are open
	select {
	case <-kickChan1:
		t.Error("kickChan1 should not be closed yet")
	default:
	}

	select {
	case <-kickChan2:
		t.Error("kickChan2 should not be closed yet")
	default:
	}

	// Kick the user
	err = tracker.KickUser(accountID, "IMAP")
	if err != nil {
		t.Fatalf("Failed to kick user: %v", err)
	}

	// Give a moment for channels to close
	time.Sleep(50 * time.Millisecond)

	// Verify both channels are closed
	select {
	case <-kickChan1:
		// Good - channel closed
	default:
		t.Error("kickChan1 should be closed after kick")
	}

	select {
	case <-kickChan2:
		// Good - channel closed
	default:
		t.Error("kickChan2 should be closed after kick")
	}

	t.Log("✓ Local tracker kick functionality works correctly")
}

func TestLocalConnectionTracker_MultipleUsers(t *testing.T) {
	tracker := NewConnectionTracker("IMAP", "", "", "test-instance", nil, 5, 0, 0, false)
	if tracker == nil {
		t.Fatal("NewConnectionTracker returned nil")
	}
	defer tracker.Stop()

	ctx := context.Background()

	// Register connections for 3 different users
	users := []struct {
		accountID int64
		username  string
		count     int
	}{
		{100, "user1@example.com", 2},
		{200, "user2@example.com", 3},
		{300, "user3@example.com", 1},
	}

	for _, user := range users {
		for i := 0; i < user.count; i++ {
			clientAddr := "192.168.1.1:" + string(rune(10000+int(user.accountID)+i))
			err := tracker.RegisterConnection(ctx, user.accountID, user.username, "IMAP", clientAddr)
			if err != nil {
				t.Fatalf("Failed to register connection for %s: %v", user.username, err)
			}
		}
	}

	// Verify counts for each user
	for _, user := range users {
		count := tracker.GetConnectionCount(user.accountID)
		if count != user.count {
			t.Errorf("User %s: expected count=%d, got %d", user.username, user.count, count)
		}
	}

	// Kick one user
	err := tracker.KickUser(200, "IMAP")
	if err != nil {
		t.Fatalf("Failed to kick user: %v", err)
	}

	// Verify other users' counts unchanged
	if count := tracker.GetConnectionCount(100); count != 2 {
		t.Errorf("User1 count should still be 2, got %d", count)
	}
	if count := tracker.GetConnectionCount(300); count != 1 {
		t.Errorf("User3 count should still be 1, got %d", count)
	}

	t.Log("✓ Local tracker handles multiple users independently")
}

func TestLocalConnectionTracker_GetAllConnections(t *testing.T) {
	tracker := NewConnectionTracker("POP3", "", "", "test-instance", nil, 10, 0, 0, false)
	if tracker == nil {
		t.Fatal("NewConnectionTracker returned nil")
	}
	defer tracker.Stop()

	ctx := context.Background()

	// Register some connections
	tracker.RegisterConnection(ctx, 100, "user1@example.com", "POP3", "192.168.1.1:12345")
	tracker.RegisterConnection(ctx, 100, "user1@example.com", "POP3", "192.168.1.1:12346")
	tracker.RegisterConnection(ctx, 200, "user2@example.com", "POP3", "192.168.1.2:12345")

	// Get all connections
	connections := tracker.GetAllConnections()

	if len(connections) != 2 { // 2 distinct users
		t.Errorf("Expected 2 users, got %d", len(connections))
	}

	// Verify user1 has 2 connections
	found := false
	for _, conn := range connections {
		if conn.AccountID == 100 {
			found = true
			localCount := conn.GetLocalCount(tracker.GetInstanceID())
			if localCount != 2 {
				t.Errorf("User1 should have LocalCount=2, got %d", localCount)
			}
			totalCount := conn.GetTotalCount()
			if totalCount != 2 {
				t.Errorf("User1 should have TotalCount=2 (local mode), got %d", totalCount)
			}
			if conn.Username != "user1@example.com" {
				t.Errorf("User1 username mismatch: %s", conn.Username)
			}
		}
	}

	if !found {
		t.Error("User1 (accountID=100) not found in connections list")
	}

	t.Log("✓ Local tracker GetAllConnections works correctly")
}

func TestLocalConnectionTracker_ZeroLimit(t *testing.T) {
	// Create tracker with limit of 0 (unlimited)
	tracker := NewConnectionTracker("IMAP", "", "", "test-instance", nil, 0, 0, 0, false)
	if tracker == nil {
		t.Fatal("NewConnectionTracker returned nil")
	}
	defer tracker.Stop()

	ctx := context.Background()
	accountID := int64(999)
	username := "unlimited@example.com"

	// Register many connections (should all succeed with unlimited)
	for i := 0; i < 100; i++ {
		clientAddr := "192.168.1.1:" + string(rune(10000+i))
		err := tracker.RegisterConnection(ctx, accountID, username, "IMAP", clientAddr)
		if err != nil {
			t.Fatalf("Failed to register connection %d with unlimited: %v", i+1, err)
		}
	}

	count := tracker.GetConnectionCount(accountID)
	if count != 100 {
		t.Errorf("Expected count=100 with unlimited, got %d", count)
	}

	t.Log("✓ Local tracker with zero limit (unlimited) works correctly")
}
