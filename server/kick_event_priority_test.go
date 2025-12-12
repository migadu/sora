package server

import (
	"testing"
)

// TestKickEventPriority_NeverDropped verifies that kick events are never dropped
// even when the queue overflows
func TestKickEventPriority_NeverDropped(t *testing.T) {
	// Create tracker with very small queue for testing
	tracker := NewConnectionTracker("test", "instance-1", nil, 0, 0, 10, false)
	defer tracker.Stop()

	// Fill queue with register events (9 events, leaving 1 slot)
	for i := 0; i < 9; i++ {
		tracker.queueEvent(ConnectionEvent{
			Type:      ConnectionEventRegister,
			AccountID: int64(i),
			Username:  "user@example.com",
		})
	}

	// Add a kick event
	tracker.queueEvent(ConnectionEvent{
		Type:      ConnectionEventKick,
		AccountID: 100,
		Username:  "kicked@example.com",
	})

	// Queue should now be at capacity (10 events)
	tracker.queueMu.Lock()
	queueLen := len(tracker.broadcastQueue)
	tracker.queueMu.Unlock()

	if queueLen != 10 {
		t.Fatalf("Expected queue length 10, got %d", queueLen)
	}

	// Now overflow the queue with more register events
	// This should trigger dropping of register events, but NOT the kick event
	for i := 0; i < 20; i++ {
		tracker.queueEvent(ConnectionEvent{
			Type:      ConnectionEventRegister,
			AccountID: int64(i + 200),
			Username:  "overflow@example.com",
		})
	}

	// Verify kick event is still in queue
	tracker.queueMu.Lock()
	defer tracker.queueMu.Unlock()

	kickEventFound := false
	for _, event := range tracker.broadcastQueue {
		if event.Type == ConnectionEventKick && event.AccountID == 100 {
			kickEventFound = true
			break
		}
	}

	if !kickEventFound {
		t.Error("❌ FAILED: Kick event was dropped (security issue!)")
		t.Logf("Queue contents (%d events):", len(tracker.broadcastQueue))
		for i, event := range tracker.broadcastQueue {
			t.Logf("  [%d] Type=%s AccountID=%d", i, event.Type, event.AccountID)
		}
	} else {
		t.Log("✅ PASS: Kick event preserved despite queue overflow")
	}
}

// TestKickEventPriority_RegisterEventsDropped verifies that register events
// are dropped before kick events when queue overflows
func TestKickEventPriority_RegisterEventsDropped(t *testing.T) {
	tracker := NewConnectionTracker("test", "instance-1", nil, 0, 0, 10, false)
	defer tracker.Stop()

	// Fill queue completely with non-critical events first
	for i := 0; i < 10; i++ {
		tracker.queueEvent(ConnectionEvent{
			Type:      ConnectionEventRegister,
			AccountID: int64(i),
			Username:  "user@example.com",
		})
	}

	// Now add 3 kick events - should trigger dropping of register events
	for i := 0; i < 3; i++ {
		tracker.queueEvent(ConnectionEvent{
			Type:      ConnectionEventKick,
			AccountID: int64(i + 100),
			Username:  "kicked@example.com",
		})
	}

	// Check final queue composition
	tracker.queueMu.Lock()
	defer tracker.queueMu.Unlock()

	kickCount := 0
	registerCount := 0

	for _, event := range tracker.broadcastQueue {
		switch event.Type {
		case ConnectionEventKick:
			kickCount++
		case ConnectionEventRegister:
			registerCount++
		}
	}

	t.Logf("Queue composition: %d kicks, %d registers (total: %d)",
		kickCount, registerCount, len(tracker.broadcastQueue))

	// All 3 kick events should be present
	if kickCount != 3 {
		t.Errorf("❌ FAILED: Expected 3 kick events, got %d", kickCount)
	} else {
		t.Log("✅ PASS: All kick events preserved")
	}

	// Some register events should have been dropped
	if registerCount == 10 {
		t.Error("❌ FAILED: No register events were dropped")
	} else {
		t.Logf("✅ PASS: %d register events dropped", 10-registerCount)
	}
}

// TestKickEventPriority_AllKicksQueue verifies behavior when queue is full of kick events
func TestKickEventPriority_AllKicksQueue(t *testing.T) {
	tracker := NewConnectionTracker("test", "instance-1", nil, 0, 0, 10, false)
	defer tracker.Stop()

	// Fill entire queue with kick events
	for i := 0; i < 10; i++ {
		tracker.queueEvent(ConnectionEvent{
			Type:      ConnectionEventKick,
			AccountID: int64(i),
			Username:  "kicked@example.com",
		})
	}

	tracker.queueMu.Lock()
	queueLen := len(tracker.broadcastQueue)
	tracker.queueMu.Unlock()

	if queueLen != 10 {
		t.Fatalf("Expected queue length 10, got %d", queueLen)
	}

	// Try to add another kick event
	tracker.queueEvent(ConnectionEvent{
		Type:      ConnectionEventKick,
		AccountID: 100,
		Username:  "another_kick@example.com",
	})

	// This kick should be queued even over limit (security critical)
	tracker.queueMu.Lock()
	newQueueLen := len(tracker.broadcastQueue)
	tracker.queueMu.Unlock()

	if newQueueLen != 11 {
		t.Errorf("❌ FAILED: Kick event not queued when queue full of kicks (got length %d)", newQueueLen)
	} else {
		t.Log("✅ PASS: Kick event queued even when queue full of kicks")
	}

	// Try to add a register event when queue is full of kicks
	tracker.queueEvent(ConnectionEvent{
		Type:      ConnectionEventRegister,
		AccountID: 200,
		Username:  "register@example.com",
	})

	// This register should be dropped (not critical)
	tracker.queueMu.Lock()
	finalQueueLen := len(tracker.broadcastQueue)
	hasRegister := false
	for _, event := range tracker.broadcastQueue {
		if event.Type == ConnectionEventRegister {
			hasRegister = true
			break
		}
	}
	tracker.queueMu.Unlock()

	if hasRegister {
		t.Error("❌ FAILED: Register event was queued when queue full of kicks")
	} else {
		t.Log("✅ PASS: Register event dropped when queue full of kicks")
	}

	if finalQueueLen != 11 {
		t.Errorf("Expected queue length to remain 11, got %d", finalQueueLen)
	}
}

// TestKickEventPriority_LargeScaleOverflow tests behavior with many events
func TestKickEventPriority_LargeScaleOverflow(t *testing.T) {
	tracker := NewConnectionTracker("test", "instance-1", nil, 0, 0, 100, false)
	defer tracker.Stop()

	// Add 50 kick events
	for i := 0; i < 50; i++ {
		tracker.queueEvent(ConnectionEvent{
			Type:      ConnectionEventKick,
			AccountID: int64(i),
			Username:  "kicked@example.com",
		})
	}

	// Add 200 register events (will cause overflow)
	for i := 0; i < 200; i++ {
		tracker.queueEvent(ConnectionEvent{
			Type:      ConnectionEventRegister,
			AccountID: int64(i + 1000),
			Username:  "user@example.com",
		})
	}

	// Count event types in queue
	tracker.queueMu.Lock()
	defer tracker.queueMu.Unlock()

	kickCount := 0
	registerCount := 0

	for _, event := range tracker.broadcastQueue {
		switch event.Type {
		case ConnectionEventKick:
			kickCount++
		case ConnectionEventRegister:
			registerCount++
		}
	}

	t.Logf("Final queue: %d kicks, %d registers (total: %d, capacity: 100)",
		kickCount, registerCount, len(tracker.broadcastQueue))

	// All 50 kick events should be preserved
	if kickCount != 50 {
		t.Errorf("❌ FAILED: Expected all 50 kick events, got %d", kickCount)
	} else {
		t.Log("✅ PASS: All 50 kick events preserved despite massive overflow")
	}

	// Queue should be near capacity but may exceed slightly due to kick priority
	if len(tracker.broadcastQueue) > 120 {
		t.Errorf("❌ WARNING: Queue grew too large: %d (capacity: 100)", len(tracker.broadcastQueue))
	}
}

// TestDropNonCriticalEvents tests the dropNonCriticalEvents helper function
func TestDropNonCriticalEvents(t *testing.T) {
	tracker := NewConnectionTracker("test", "instance-1", nil, 0, 0, 100, false)
	defer tracker.Stop()

	// Populate queue with known events
	tracker.queueMu.Lock()
	tracker.broadcastQueue = []ConnectionEvent{
		{Type: ConnectionEventRegister, AccountID: 1},
		{Type: ConnectionEventKick, AccountID: 2},
		{Type: ConnectionEventUnregister, AccountID: 3},
		{Type: ConnectionEventKick, AccountID: 4},
		{Type: ConnectionEventRegister, AccountID: 5},
		{Type: ConnectionEventStateSnapshot},
		{Type: ConnectionEventKick, AccountID: 6},
	}

	// Drop 3 non-critical events
	dropped := tracker.dropNonCriticalEvents(3)
	tracker.queueMu.Unlock()

	if dropped != 3 {
		t.Errorf("Expected to drop 3 events, dropped %d", dropped)
	}

	tracker.queueMu.Lock()
	defer tracker.queueMu.Unlock()

	// Should have 4 events left (3 kicks + remaining events)
	if len(tracker.broadcastQueue) != 4 {
		t.Errorf("Expected 4 events remaining, got %d", len(tracker.broadcastQueue))
	}

	// All remaining events should include all kicks
	kickCount := 0
	for _, event := range tracker.broadcastQueue {
		if event.Type == ConnectionEventKick {
			kickCount++
		}
	}

	if kickCount != 3 {
		t.Errorf("Expected 3 kick events to remain, got %d", kickCount)
	} else {
		t.Log("✅ PASS: dropNonCriticalEvents preserved all kick events")
	}
}

// TestKickEventPriority_RealWorldScenario simulates a realistic overflow scenario
func TestKickEventPriority_RealWorldScenario(t *testing.T) {
	tracker := NewConnectionTracker("test", "instance-1", nil, 0, 0, 50, false)
	defer tracker.Stop()

	// Simulate normal operation: queue register events
	for i := 0; i < 30; i++ {
		tracker.queueEvent(ConnectionEvent{
			Type:      ConnectionEventRegister,
			AccountID: int64(i),
			Username:  "user@example.com",
		})
	}

	// Simulate some disconnects: queue unregister events
	for i := 0; i < 15; i++ {
		tracker.queueEvent(ConnectionEvent{
			Type:      ConnectionEventUnregister,
			AccountID: int64(i),
			Username:  "user@example.com",
		})
	}

	// Simulate admin kicking 5 users - directly queue kick events
	kickedUsers := []int64{100, 101, 102, 103, 104}
	for _, accountID := range kickedUsers {
		tracker.queueEvent(ConnectionEvent{
			Type:      ConnectionEventKick,
			AccountID: accountID,
			Username:  "kicked@example.com",
		})
	}

	// Simulate burst of connections (overflow scenario) - 50 more events
	for i := 200; i < 250; i++ {
		tracker.queueEvent(ConnectionEvent{
			Type:      ConnectionEventRegister,
			AccountID: int64(i),
			Username:  "burst@example.com",
		})
	}

	// Verify all kick events are still in queue
	tracker.queueMu.Lock()
	defer tracker.queueMu.Unlock()

	kickEventsFound := make(map[int64]bool)
	for _, event := range tracker.broadcastQueue {
		if event.Type == ConnectionEventKick {
			kickEventsFound[event.AccountID] = true
		}
	}

	allKicksPresent := true
	for _, accountID := range kickedUsers {
		if !kickEventsFound[accountID] {
			t.Errorf("❌ FAILED: Kick event for user %d was dropped", accountID)
			allKicksPresent = false
		}
	}

	if allKicksPresent {
		t.Logf("✅ PASS: All %d kick events preserved in real-world scenario", len(kickedUsers))
	}

	t.Logf("Final queue: %d events (capacity: 50)", len(tracker.broadcastQueue))
}
