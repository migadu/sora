package server

import (
	"testing"
	"time"
)

// The guarantee under test, unchanged since the hand-rolled queues: a kick
// event is never dropped for want of room taken by ordinary traffic. Kicks live
// in a memberlist queue of their own, bounded only by maxCriticalQueued, which
// the volumes here stay far below; ordinary events are pruned to the configured
// queue size. The assertions read the events the tracker actually hands to
// memberlist rather than a slice field.

// drainConnectionEvents collects every distinct event a tracker hands out until
// its queues are empty. memberlist asks once per gossip target, so the same
// event comes back several times; this keys them by event ID.
func drainConnectionEvents(t *testing.T, ct *ConnectionTracker) []ConnectionEvent {
	t.Helper()

	var events []ConnectionEvent
	seen := make(map[string]bool)

	for rounds := 0; ct.queue.numQueued()+ct.criticalQueue.numQueued() > 0; rounds++ {
		if rounds > 10000 {
			t.Fatalf("tracker queues did not drain: %d normal, %d critical left",
				ct.queue.numQueued(), ct.criticalQueue.numQueued())
		}

		for _, msg := range ct.GetBroadcasts(gossipPerMsgOverhead, 65535) {
			event, err := decodeConnectionEvent(msg)
			if err != nil {
				t.Fatalf("decode broadcast: %v", err)
			}
			if seen[event.EventID] {
				continue
			}
			seen[event.EventID] = true
			events = append(events, event)
		}
	}

	return events
}

func kickedAccounts(events []ConnectionEvent) map[int64]bool {
	kicked := make(map[int64]bool)
	for _, event := range events {
		if event.Type == ConnectionEventKick {
			kicked[event.AccountID] = true
		}
	}
	return kicked
}

func countType(events []ConnectionEvent, eventType ConnectionEventType) int {
	count := 0
	for _, event := range events {
		if event.Type == eventType {
			count++
		}
	}
	return count
}

// TestKickEventPriority_NeverDropped verifies that a kick event still reaches
// the cluster after the tracker has been flooded far past its queue limit.
func TestKickEventPriority_NeverDropped(t *testing.T) {
	tracker := NewConnectionTracker("test", "", "", "instance-1", nil, 0, 0, 10, false)
	defer tracker.Stop()

	for i := 0; i < 9; i++ {
		tracker.queueEvent(ConnectionEvent{
			Type:      ConnectionEventRegister,
			AccountID: int64(i),
			Username:  "user@example.com",
		})
	}

	tracker.queueEvent(ConnectionEvent{
		Type:      ConnectionEventKick,
		AccountID: 100,
		Username:  "kicked@example.com",
	})

	// Overflow the ordinary queue many times over.
	for i := 0; i < 200; i++ {
		tracker.queueEvent(ConnectionEvent{
			Type:      ConnectionEventRegister,
			AccountID: int64(i + 200),
			Username:  "overflow@example.com",
		})
	}

	if queued := tracker.queue.numQueued(); queued > 10 {
		t.Errorf("ordinary queue grew to %d events, limit is 10", queued)
	}

	events := drainConnectionEvents(t, tracker)
	if !kickedAccounts(events)[100] {
		t.Error("kick event was dropped by queue overflow (security issue)")
	}
	if registers := countType(events, ConnectionEventRegister); registers > 10 {
		t.Errorf("expected register events to be pruned to the queue limit, %d were broadcast", registers)
	}
}

// TestKickEventPriority_RegisterEventsDropped verifies that overflow costs
// register events and never kicks.
func TestKickEventPriority_RegisterEventsDropped(t *testing.T) {
	tracker := NewConnectionTracker("test", "", "", "instance-1", nil, 0, 0, 10, false)
	defer tracker.Stop()

	for i := 0; i < 100; i++ {
		tracker.queueEvent(ConnectionEvent{
			Type:      ConnectionEventRegister,
			AccountID: int64(i),
			Username:  "user@example.com",
		})
	}

	for i := 0; i < 3; i++ {
		tracker.queueEvent(ConnectionEvent{
			Type:      ConnectionEventKick,
			AccountID: int64(i + 100),
			Username:  "kicked@example.com",
		})
	}

	events := drainConnectionEvents(t, tracker)
	kicked := kickedAccounts(events)
	registers := countType(events, ConnectionEventRegister)

	t.Logf("broadcast: %d kicks, %d of 100 registers", len(kicked), registers)

	for _, accountID := range []int64{100, 101, 102} {
		if !kicked[accountID] {
			t.Errorf("kick for account %d was dropped", accountID)
		}
	}
	if registers == 100 {
		t.Error("no register events were dropped despite a 10-event queue limit")
	}
}

// TestKickEventPriority_AllKicksQueue verifies that kicks past the ordinary
// queue's limit are all still queued, while ordinary events stay bounded.
func TestKickEventPriority_AllKicksQueue(t *testing.T) {
	tracker := NewConnectionTracker("test", "", "", "instance-1", nil, 0, 0, 10, false)
	defer tracker.Stop()

	for i := 0; i < 11; i++ {
		tracker.queueEvent(ConnectionEvent{
			Type:      ConnectionEventKick,
			AccountID: int64(i),
			Username:  "kicked@example.com",
		})
	}

	if queued := tracker.criticalQueue.numQueued(); queued != 11 {
		t.Errorf("kick queue holds %d events, want all 11 - the ordinary queue's 10-event limit does not apply here", queued)
	}

	tracker.queueEvent(ConnectionEvent{
		Type:      ConnectionEventRegister,
		AccountID: 200,
		Username:  "register@example.com",
	})

	events := drainConnectionEvents(t, tracker)
	if got := len(kickedAccounts(events)); got != 11 {
		t.Errorf("broadcast %d distinct kicks, want 11", got)
	}
	if countType(events, ConnectionEventRegister) != 1 {
		t.Error("a register event queued alongside kicks was lost")
	}
}

// TestKickEventPriority_LargeScaleOverflow tests behavior with many events
func TestKickEventPriority_LargeScaleOverflow(t *testing.T) {
	tracker := NewConnectionTracker("test", "", "", "instance-1", nil, 0, 0, 100, false)
	defer tracker.Stop()

	for i := 0; i < 50; i++ {
		tracker.queueEvent(ConnectionEvent{
			Type:      ConnectionEventKick,
			AccountID: int64(i),
			Username:  "kicked@example.com",
		})
	}

	for i := 0; i < 2000; i++ {
		tracker.queueEvent(ConnectionEvent{
			Type:      ConnectionEventRegister,
			AccountID: int64(i + 1000),
			Username:  "user@example.com",
		})
	}

	if queued := tracker.queue.numQueued(); queued > 100 {
		t.Errorf("ordinary queue grew to %d events under a 100-event limit", queued)
	}

	kicked := kickedAccounts(drainConnectionEvents(t, tracker))
	if len(kicked) != 50 {
		t.Errorf("broadcast %d of 50 kicks after a 2000-event flood", len(kicked))
	}
}

// TestKickEventPriority_RealWorldScenario simulates a realistic overflow scenario
func TestKickEventPriority_RealWorldScenario(t *testing.T) {
	tracker := NewConnectionTracker("test", "", "", "instance-1", nil, 0, 0, 50, false)
	defer tracker.Stop()

	for i := 0; i < 30; i++ {
		tracker.queueEvent(ConnectionEvent{
			Type:      ConnectionEventRegister,
			AccountID: int64(i),
			Username:  "user@example.com",
			Timestamp: time.Now(),
		})
	}

	for i := 0; i < 15; i++ {
		tracker.queueEvent(ConnectionEvent{
			Type:      ConnectionEventUnregister,
			AccountID: int64(i),
			Username:  "user@example.com",
			Timestamp: time.Now(),
		})
	}

	kickedUsers := []int64{100, 101, 102, 103, 104}
	for _, accountID := range kickedUsers {
		tracker.queueEvent(ConnectionEvent{
			Type:      ConnectionEventKick,
			AccountID: accountID,
			Username:  "kicked@example.com",
			Timestamp: time.Now(),
		})
	}

	for i := 200; i < 300; i++ {
		tracker.queueEvent(ConnectionEvent{
			Type:      ConnectionEventRegister,
			AccountID: int64(i),
			Username:  "burst@example.com",
			Timestamp: time.Now(),
		})
	}

	kicked := kickedAccounts(drainConnectionEvents(t, tracker))
	for _, accountID := range kickedUsers {
		if !kicked[accountID] {
			t.Errorf("kick event for user %d was dropped", accountID)
		}
	}
}
