package server

import (
	"context"
	"strings"
	"testing"
)

func TestConnectionTracker_PerUserPerIPLimit(t *testing.T) {
	// Create tracker with per-user limit of 10 but per-user-per-IP limit of 2
	tracker := NewConnectionTracker("IMAP", "test-instance", nil, 10, 2, 0, false)
	if tracker == nil {
		t.Fatal("NewConnectionTracker returned nil")
	}
	defer tracker.Stop()

	ctx := context.Background()
	accountID := int64(123)
	username := "user@example.com"
	ip1 := "192.168.1.100"
	ip2 := "192.168.1.101"

	// Test 1: Register 2 connections from IP1 (should succeed)
	err := tracker.RegisterConnection(ctx, accountID, username, "IMAP", ip1+":10001")
	if err != nil {
		t.Fatalf("First connection from IP1 should succeed: %v", err)
	}

	err = tracker.RegisterConnection(ctx, accountID, username, "IMAP", ip1+":10002")
	if err != nil {
		t.Fatalf("Second connection from IP1 should succeed: %v", err)
	}

	// Test 2: Third connection from same IP should fail (exceeds per-IP limit)
	err = tracker.RegisterConnection(ctx, accountID, username, "IMAP", ip1+":10003")
	if err == nil {
		t.Fatal("Third connection from same IP should be rejected")
	}

	if !strings.Contains(err.Error(), "maximum connections from IP") {
		t.Errorf("Expected per-user-per-IP error, got: %v", err)
	}

	// Test 3: Connections from different IP should succeed (different IP counter)
	err = tracker.RegisterConnection(ctx, accountID, username, "IMAP", ip2+":20001")
	if err != nil {
		t.Fatalf("First connection from IP2 should succeed: %v", err)
	}

	err = tracker.RegisterConnection(ctx, accountID, username, "IMAP", ip2+":20002")
	if err != nil {
		t.Fatalf("Second connection from IP2 should succeed: %v", err)
	}

	// Total count should be 4 (2 from IP1, 2 from IP2)
	count := tracker.GetConnectionCount(accountID)
	if count != 4 {
		t.Errorf("Expected total count=4, got %d", count)
	}

	// Test 4: Third connection from IP2 should also fail
	err = tracker.RegisterConnection(ctx, accountID, username, "IMAP", ip2+":20003")
	if err == nil {
		t.Fatal("Third connection from IP2 should be rejected")
	}

	// Test 5: Unregister one connection from IP1, then new connection from IP1 should succeed
	err = tracker.UnregisterConnection(ctx, accountID, "IMAP", ip1+":10001")
	if err != nil {
		t.Fatalf("Unregister should succeed: %v", err)
	}

	err = tracker.RegisterConnection(ctx, accountID, username, "IMAP", ip1+":10003")
	if err != nil {
		t.Errorf("Connection should succeed after unregister from same IP: %v", err)
	}

	// Final count should still be 4 (1 unregistered, 1 registered)
	count = tracker.GetConnectionCount(accountID)
	if count != 4 {
		t.Errorf("Expected final count=4, got %d", count)
	}

	t.Log("✓ Per-user-per-IP limiting works correctly")
}

func TestConnectionTracker_PerUserPerIPWithMultipleUsers(t *testing.T) {
	// Test that per-user-per-IP is tracked separately for each user
	tracker := NewConnectionTracker("IMAP", "test-instance", nil, 20, 3, 0, false)
	if tracker == nil {
		t.Fatal("NewConnectionTracker returned nil")
	}
	defer tracker.Stop()

	ctx := context.Background()
	user1ID := int64(100)
	user2ID := int64(200)
	user1Name := "user1@example.com"
	user2Name := "user2@example.com"
	sharedIP := "192.168.1.100"

	// Register 3 connections from same IP for user1 (should all succeed)
	for i := 1; i <= 3; i++ {
		err := tracker.RegisterConnection(ctx, user1ID, user1Name, "IMAP", sharedIP+":10000"+string(rune('0'+i)))
		if err != nil {
			t.Fatalf("User1 connection %d should succeed: %v", i, err)
		}
	}

	// Register 3 connections from same IP for user2 (should all succeed - different user)
	for i := 1; i <= 3; i++ {
		err := tracker.RegisterConnection(ctx, user2ID, user2Name, "IMAP", sharedIP+":20000"+string(rune('0'+i)))
		if err != nil {
			t.Fatalf("User2 connection %d should succeed (different user): %v", i, err)
		}
	}

	// Fourth connection for user1 from same IP should fail
	err := tracker.RegisterConnection(ctx, user1ID, user1Name, "IMAP", sharedIP+":10004")
	if err == nil {
		t.Fatal("Fourth connection for user1 should be rejected")
	}

	// Fourth connection for user2 from same IP should also fail
	err = tracker.RegisterConnection(ctx, user2ID, user2Name, "IMAP", sharedIP+":20004")
	if err == nil {
		t.Fatal("Fourth connection for user2 should be rejected")
	}

	// Verify counts
	if count := tracker.GetConnectionCount(user1ID); count != 3 {
		t.Errorf("User1 count should be 3, got %d", count)
	}
	if count := tracker.GetConnectionCount(user2ID); count != 3 {
		t.Errorf("User2 count should be 3, got %d", count)
	}

	t.Log("✓ Per-user-per-IP limiting is independent per user")
}

func TestConnectionTracker_PerUserPerIPDisabled(t *testing.T) {
	// Create tracker with per-user-per-IP limit disabled (0)
	tracker := NewConnectionTracker("IMAP", "test-instance", nil, 10, 0, 0, false)
	if tracker == nil {
		t.Fatal("NewConnectionTracker returned nil")
	}
	defer tracker.Stop()

	ctx := context.Background()
	accountID := int64(123)
	username := "user@example.com"
	ip := "192.168.1.100"

	// Register many connections from same IP (should all succeed when disabled)
	for i := 1; i <= 10; i++ {
		err := tracker.RegisterConnection(ctx, accountID, username, "IMAP", ip+":10000"+string(rune('0'+i)))
		if err != nil {
			t.Fatalf("Connection %d should succeed when per-IP limit disabled: %v", i, err)
		}
	}

	count := tracker.GetConnectionCount(accountID)
	if count != 10 {
		t.Errorf("Expected count=10, got %d", count)
	}

	t.Log("✓ Per-user-per-IP limiting can be disabled (0 = unlimited)")
}

func TestConnectionTracker_PerUserPerIPCleanup(t *testing.T) {
	// Test that per-IP counters are cleaned up when connections are unregistered
	tracker := NewConnectionTracker("IMAP", "test-instance", nil, 10, 2, 0, false)
	if tracker == nil {
		t.Fatal("NewConnectionTracker returned nil")
	}
	defer tracker.Stop()

	ctx := context.Background()
	accountID := int64(123)
	username := "user@example.com"
	ip := "192.168.1.100"

	// Register 2 connections
	tracker.RegisterConnection(ctx, accountID, username, "IMAP", ip+":10001")
	tracker.RegisterConnection(ctx, accountID, username, "IMAP", ip+":10002")

	// Verify limit is enforced
	err := tracker.RegisterConnection(ctx, accountID, username, "IMAP", ip+":10003")
	if err == nil {
		t.Fatal("Third connection should be rejected")
	}

	// Unregister both connections
	tracker.UnregisterConnection(ctx, accountID, "IMAP", ip+":10001")
	tracker.UnregisterConnection(ctx, accountID, "IMAP", ip+":10002")

	// Should be able to register 2 new connections again (counter was cleaned up)
	err = tracker.RegisterConnection(ctx, accountID, username, "IMAP", ip+":10004")
	if err != nil {
		t.Errorf("Should be able to register after cleanup: %v", err)
	}

	err = tracker.RegisterConnection(ctx, accountID, username, "IMAP", ip+":10005")
	if err != nil {
		t.Errorf("Should be able to register second after cleanup: %v", err)
	}

	t.Log("✓ Per-user-per-IP counters are cleaned up correctly")
}
