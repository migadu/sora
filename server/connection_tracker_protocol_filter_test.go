package server

import (
	"context"
	"testing"
	"time"
)

// TestConnectionTrackerProtocolFiltering verifies that connection trackers only
// process events for their own protocol, preventing cross-protocol contamination.
func TestConnectionTrackerProtocolFiltering(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create two trackers for different protocols sharing the same cluster
	imapTracker := NewConnectionTracker("IMAP", "instance-1", nil, 0, 0, 1000)
	defer imapTracker.Stop()

	lmtpTracker := NewConnectionTracker("LMTP", "instance-2", nil, 0, 0, 1000)
	defer lmtpTracker.Stop()

	// Register an IMAP connection
	err := imapTracker.RegisterConnection(ctx, 123, "user@example.com", "IMAP", "192.0.2.1:12345")
	if err != nil {
		t.Fatalf("Failed to register IMAP connection: %v", err)
	}

	// Verify IMAP tracker has the connection
	imapCount := imapTracker.GetConnectionCount(123)
	if imapCount != 1 {
		t.Errorf("Expected IMAP tracker to have 1 connection, got %d", imapCount)
	}

	// Simulate broadcasting IMAP event to LMTP tracker (this happens in production via gossip)
	// Create the event that would be broadcast
	event := ConnectionEvent{
		Type:       ConnectionEventRegister,
		AccountID:  123,
		Username:   "user@example.com",
		Protocol:   "IMAP", // Event is for IMAP
		ClientAddr: "192.0.2.1:12345",
		Timestamp:  time.Now(),
		NodeID:     "node-1",
		InstanceID: "instance-1",
	}

	// Encode and decode to simulate network transmission
	data, err := encodeConnectionEvent(event)
	if err != nil {
		t.Fatalf("Failed to encode event: %v", err)
	}

	// LMTP tracker receives IMAP event (this is the bug scenario)
	lmtpTracker.HandleClusterEvent(data)

	// CRITICAL: LMTP tracker should NOT have counted the IMAP connection
	lmtpCount := lmtpTracker.GetConnectionCount(123)
	if lmtpCount != 0 {
		t.Errorf("❌ CROSS-PROTOCOL CONTAMINATION: LMTP tracker counted IMAP connection! Expected 0, got %d", lmtpCount)
	} else {
		t.Logf("✓ Protocol filtering works: LMTP tracker correctly ignored IMAP event")
	}

	// Now register an actual LMTP connection
	err = lmtpTracker.RegisterConnection(ctx, 456, "user2@example.com", "LMTP", "192.0.2.2:12346")
	if err != nil {
		t.Fatalf("Failed to register LMTP connection: %v", err)
	}

	// LMTP tracker should have its own connection
	lmtpCount = lmtpTracker.GetConnectionCount(456)
	if lmtpCount != 1 {
		t.Errorf("Expected LMTP tracker to have 1 connection for user 456, got %d", lmtpCount)
	}

	// IMAP tracker should NOT have LMTP connection
	imapCount = imapTracker.GetConnectionCount(456)
	if imapCount != 0 {
		t.Errorf("❌ IMAP tracker incorrectly counted LMTP connection! Expected 0, got %d", imapCount)
	}

	// Test state snapshot filtering
	t.Run("state_snapshot_filtering", func(t *testing.T) {
		// Create a state snapshot event from IMAP tracker
		snapshot := &ConnectionStateSnapshot{
			InstanceID: "instance-1",
			Timestamp:  time.Now(),
			Connections: map[int64]UserConnectionData{
				789: {
					AccountID: 789,
					Username:  "user3@example.com",
					LocalInstances: map[string]int{
						"instance-1": 5,
					},
				},
			},
		}

		snapshotEvent := ConnectionEvent{
			Type:          ConnectionEventStateSnapshot,
			Protocol:      "IMAP", // Snapshot is for IMAP
			Timestamp:     time.Now(),
			InstanceID:    "instance-1",
			StateSnapshot: snapshot,
		}

		data, err := encodeConnectionEvent(snapshotEvent)
		if err != nil {
			t.Fatalf("Failed to encode snapshot: %v", err)
		}

		// LMTP tracker receives IMAP state snapshot
		lmtpTracker.HandleClusterEvent(data)

		// LMTP tracker should NOT have reconciled IMAP snapshot
		lmtpCount := lmtpTracker.GetConnectionCount(789)
		if lmtpCount != 0 {
			t.Errorf("❌ LMTP tracker reconciled IMAP state snapshot! Expected 0, got %d", lmtpCount)
		} else {
			t.Logf("✓ State snapshot filtering works: LMTP tracker ignored IMAP snapshot")
		}
	})
}

// TestConnectionTrackerProtocolLeakScenario simulates the production bug where
// LMTP tracker accumulated thousands of ghost IMAP connections.
func TestConnectionTrackerProtocolLeakScenario(t *testing.T) {

	lmtpTracker := NewConnectionTracker("LMTP", "lmtp-instance", nil, 0, 0, 1000)
	defer lmtpTracker.Stop()

	// Simulate 1000 IMAP connections being broadcast to LMTP tracker
	// This simulates what happens in production when all trackers receive all gossip messages
	for i := 0; i < 1000; i++ {
		event := ConnectionEvent{
			Type:       ConnectionEventRegister,
			AccountID:  int64(i),
			Username:   "user@example.com",
			Protocol:   "IMAP", // These are IMAP events
			ClientAddr: "192.0.2.1:12345",
			Timestamp:  time.Now(),
			NodeID:     "node-1",
			InstanceID: "imap-instance",
		}

		data, _ := encodeConnectionEvent(event)
		lmtpTracker.HandleClusterEvent(data)
	}

	// Count total users in LMTP tracker
	lmtpTracker.mu.RLock()
	totalUsers := len(lmtpTracker.connections)
	lmtpTracker.mu.RUnlock()

	if totalUsers != 0 {
		t.Errorf("❌ MASSIVE LEAK: LMTP tracker has %d ghost users from IMAP events (expected 0)", totalUsers)
		t.Errorf("   This is the production bug: LMTP shows 3,420 users but 0 active sessions")
	} else {
		t.Logf("✓ No leak: LMTP tracker correctly has 0 users (ignored all %d IMAP events)", 1000)
	}
}
