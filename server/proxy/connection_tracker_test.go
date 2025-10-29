package proxy

import (
	"testing"
	"time"
)

func TestConnectionTracker_RegisterSession(t *testing.T) {
	// Create a tracker without cluster manager (nil is ok for this test)
	tracker := &ConnectionTracker{
		name:         "TEST",
		instanceID:   "test-instance",
		kickSessions: make(map[int64][]chan struct{}),
	}

	accountID := int64(123)

	// Register a session
	kickChan := tracker.RegisterSession(accountID)
	if kickChan == nil {
		t.Fatal("RegisterSession returned nil channel")
	}

	// Verify session was added to map
	tracker.kickSessionsMu.RLock()
	sessions := tracker.kickSessions[accountID]
	tracker.kickSessionsMu.RUnlock()

	if len(sessions) != 1 {
		t.Errorf("Expected 1 session, got %d", len(sessions))
	}

	// Channel should not be closed yet
	select {
	case <-kickChan:
		t.Error("Channel should not be closed yet")
	default:
		// Good - channel is still open
	}

	t.Log("✓ Session registered successfully")
}

func TestConnectionTracker_UnregisterSession(t *testing.T) {
	tracker := &ConnectionTracker{
		name:         "TEST",
		instanceID:   "test-instance",
		kickSessions: make(map[int64][]chan struct{}),
	}

	accountID := int64(123)

	// Register and then unregister
	kickChan := tracker.RegisterSession(accountID)
	tracker.UnregisterSession(accountID, kickChan)

	// Verify session was removed
	tracker.kickSessionsMu.RLock()
	sessions := tracker.kickSessions[accountID]
	tracker.kickSessionsMu.RUnlock()

	if len(sessions) != 0 {
		t.Errorf("Expected 0 sessions after unregister, got %d", len(sessions))
	}

	t.Log("✓ Session unregistered successfully")
}

func TestConnectionTracker_MultipleSessionsPerUser(t *testing.T) {
	tracker := &ConnectionTracker{
		name:         "TEST",
		instanceID:   "test-instance",
		kickSessions: make(map[int64][]chan struct{}),
	}

	accountID := int64(123)

	// Register 3 sessions for same user
	chan1 := tracker.RegisterSession(accountID)
	chan2 := tracker.RegisterSession(accountID)
	chan3 := tracker.RegisterSession(accountID)

	// Verify all sessions registered
	tracker.kickSessionsMu.RLock()
	sessions := tracker.kickSessions[accountID]
	tracker.kickSessionsMu.RUnlock()

	if len(sessions) != 3 {
		t.Errorf("Expected 3 sessions, got %d", len(sessions))
	}

	// Unregister middle one
	tracker.UnregisterSession(accountID, chan2)

	tracker.kickSessionsMu.RLock()
	sessions = tracker.kickSessions[accountID]
	tracker.kickSessionsMu.RUnlock()

	if len(sessions) != 2 {
		t.Errorf("Expected 2 sessions after unregister, got %d", len(sessions))
	}

	// Verify the remaining channels are still open
	select {
	case <-chan1:
		t.Error("chan1 should not be closed")
	default:
	}

	select {
	case <-chan3:
		t.Error("chan3 should not be closed")
	default:
	}

	t.Log("✓ Multiple sessions per user handled correctly")
}

func TestConnectionTracker_KickClosesChannels(t *testing.T) {
	tracker := &ConnectionTracker{
		name:         "TEST",
		instanceID:   "test-instance",
		kickSessions: make(map[int64][]chan struct{}),
	}

	accountID := int64(123)

	// Register 2 sessions
	chan1 := tracker.RegisterSession(accountID)
	chan2 := tracker.RegisterSession(accountID)

	// Simulate receiving a kick event (directly call handleKick)
	event := ConnectionEvent{
		Type:       ConnectionEventKick,
		AccountID:  accountID,
		Protocol:   "IMAP",
		InstanceID: "other-instance",
	}

	tracker.handleKick(event)

	// Wait a moment for channels to close
	time.Sleep(100 * time.Millisecond)

	// Verify both channels are closed
	select {
	case <-chan1:
		// Good - channel closed
	default:
		t.Error("chan1 should be closed after kick")
	}

	select {
	case <-chan2:
		// Good - channel closed
	default:
		t.Error("chan2 should be closed after kick")
	}

	// Verify sessions were cleared from map
	tracker.kickSessionsMu.RLock()
	sessions := tracker.kickSessions[accountID]
	tracker.kickSessionsMu.RUnlock()

	if len(sessions) != 0 {
		t.Errorf("Expected 0 sessions after kick, got %d", len(sessions))
	}

	t.Log("✓ Kick closes all channels for user")
}

func TestConnectionTracker_HandleRegisterIncrementsCounts(t *testing.T) {
	tracker := &ConnectionTracker{
		name:         "TEST",
		instanceID:   "test-instance",
		connections:  make(map[int64]*UserConnectionInfo),
		kickSessions: make(map[int64][]chan struct{}),
	}

	accountID := int64(123)
	username := "test@example.com"

	// Simulate receiving register events from cluster
	event1 := ConnectionEvent{
		Type:       ConnectionEventRegister,
		AccountID:  accountID,
		Username:   username,
		Protocol:   "IMAP",
		InstanceID: "instance-1",
	}

	tracker.handleRegister(event1)

	// Check counts
	tracker.mu.RLock()
	info := tracker.connections[accountID]
	tracker.mu.RUnlock()

	if info == nil {
		t.Fatal("Connection info not found")
	}

	if info.TotalCount != 1 {
		t.Errorf("Expected TotalCount=1, got %d", info.TotalCount)
	}

	// Register second connection from different instance
	event2 := ConnectionEvent{
		Type:       ConnectionEventRegister,
		AccountID:  accountID,
		Username:   username,
		Protocol:   "IMAP",
		InstanceID: "instance-2",
	}

	tracker.handleRegister(event2)

	tracker.mu.RLock()
	info = tracker.connections[accountID]
	tracker.mu.RUnlock()

	if info.TotalCount != 2 {
		t.Errorf("Expected TotalCount=2, got %d", info.TotalCount)
	}

	// Check per-instance counts
	if info.LocalInstances["instance-1"] != 1 {
		t.Errorf("Expected instance-1 count=1, got %d", info.LocalInstances["instance-1"])
	}

	if info.LocalInstances["instance-2"] != 1 {
		t.Errorf("Expected instance-2 count=1, got %d", info.LocalInstances["instance-2"])
	}

	t.Log("✓ Connection counts incremented correctly via gossip events")
}

func TestConnectionTracker_HandleUnregisterDecrementsCounts(t *testing.T) {
	tracker := &ConnectionTracker{
		name:         "TEST",
		instanceID:   "test-instance",
		connections:  make(map[int64]*UserConnectionInfo),
		kickSessions: make(map[int64][]chan struct{}),
	}

	accountID := int64(123)
	username := "test@example.com"

	// Register two connections
	tracker.handleRegister(ConnectionEvent{
		Type:       ConnectionEventRegister,
		AccountID:  accountID,
		Username:   username,
		Protocol:   "IMAP",
		InstanceID: "instance-1",
	})

	tracker.handleRegister(ConnectionEvent{
		Type:       ConnectionEventRegister,
		AccountID:  accountID,
		Username:   username,
		Protocol:   "IMAP",
		InstanceID: "instance-1",
	})

	// Unregister one
	tracker.handleUnregister(ConnectionEvent{
		Type:       ConnectionEventUnregister,
		AccountID:  accountID,
		Username:   username,
		Protocol:   "IMAP",
		InstanceID: "instance-1",
	})

	// Check counts
	tracker.mu.RLock()
	info := tracker.connections[accountID]
	tracker.mu.RUnlock()

	if info == nil {
		t.Fatal("Connection info not found after unregister")
	}

	if info.TotalCount != 1 {
		t.Errorf("Expected TotalCount=1 after unregister, got %d", info.TotalCount)
	}

	// Unregister the last one
	tracker.handleUnregister(ConnectionEvent{
		Type:       ConnectionEventUnregister,
		AccountID:  accountID,
		Username:   username,
		Protocol:   "IMAP",
		InstanceID: "instance-1",
	})

	// Connection info should be cleaned up
	tracker.mu.RLock()
	info = tracker.connections[accountID]
	tracker.mu.RUnlock()

	if info != nil {
		t.Errorf("Expected connection info to be cleaned up, but still exists: %+v", info)
	}

	t.Log("✓ Connection counts decremented and cleaned up correctly via gossip events")
}
