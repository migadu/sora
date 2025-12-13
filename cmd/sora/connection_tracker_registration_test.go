package main

import (
	"fmt"
	"sync"
	"testing"

	"github.com/migadu/sora/server"
)

// TestMultipleProxyTrackersOverwrite_BugDemo demonstrates the BUG where multiple
// proxy instances of the same type overwrite each other's trackers.
//
// This test intentionally uses the BUGGY approach (generic key) to document
// the problem that was fixed.
func TestMultipleProxyTrackersOverwrite_BugDemo(t *testing.T) {
	// Simulate the deps.connectionTrackers map
	connectionTrackers := make(map[string]*server.ConnectionTracker)
	connectionTrackersMux := sync.Mutex{}

	// Simulate two LMTP proxy servers starting
	// (This mimics what happens in startDynamicLMTPProxyServer)

	// First LMTP proxy: "lmtp-proxy-1"
	tracker1 := server.NewConnectionTracker("LMTP", "lmtp-proxy-1", nil, 0, 0, 0, false)
	if tracker1 != nil {
		defer tracker1.Stop()
		connectionTrackersMux.Lock()
		// BUG: Uses generic "LMTP" key instead of "LMTP-lmtp-proxy-1"
		connectionTrackers["LMTP"] = tracker1
		connectionTrackersMux.Unlock()
	}

	// Second LMTP proxy: "lmtp-proxy-2"
	tracker2 := server.NewConnectionTracker("LMTP", "lmtp-proxy-2", nil, 0, 0, 0, false)
	if tracker2 != nil {
		defer tracker2.Stop()
		connectionTrackersMux.Lock()
		// BUG: Uses same "LMTP" key, OVERWRITES tracker1!
		connectionTrackers["LMTP"] = tracker2
		connectionTrackersMux.Unlock()
	}

	// Verify the bug: Only one tracker is registered
	connectionTrackersMux.Lock()
	trackerCount := len(connectionTrackers)
	connectionTrackersMux.Unlock()

	// BUG ASSERTION: With buggy code, only 1 tracker exists
	if trackerCount == 1 {
		t.Logf("BUG DEMONSTRATED: Only 1 tracker registered (expected 2)")
		t.Logf("Second tracker overwrote the first!")
	} else if trackerCount == 2 {
		t.Errorf("Expected to demonstrate bug with 1 tracker, but got 2 - bug may be fixed!")
	}

	// Verify tracker1 was overwritten
	connectionTrackersMux.Lock()
	registeredTracker := connectionTrackers["LMTP"]
	connectionTrackersMux.Unlock()

	if registeredTracker == tracker1 {
		t.Errorf("Expected tracker2 to be registered (overwrote tracker1), but found tracker1")
	}
	if registeredTracker != tracker2 {
		t.Errorf("Expected tracker2 to be registered as the final value")
	}

	t.Logf("Registered trackers: %v", getTrackerNames(connectionTrackers))
}

// TestMultipleProxyTrackersWithUniqueKeys tests the FIX where each proxy
// uses a unique key that includes the hostname and server name.
func TestMultipleProxyTrackersWithUniqueKeys(t *testing.T) {
	// Simulate the deps.connectionTrackers map
	connectionTrackers := make(map[string]*server.ConnectionTracker)
	connectionTrackersMux := sync.Mutex{}

	// Simulate two LMTP proxy servers on DIFFERENT hosts with SAME server name
	// This is the real-world scenario that was broken!

	hostname1 := "host1"
	hostname2 := "host2"
	serverName := "lmtp-proxy" // SAME name on both hosts

	// First LMTP proxy: host1 with name "lmtp-proxy"
	instanceID1 := fmt.Sprintf("%s-%s", hostname1, serverName)
	tracker1 := server.NewConnectionTracker("LMTP", instanceID1, nil, 0, 0, 0, false)
	if tracker1 != nil {
		defer tracker1.Stop()
		connectionTrackersMux.Lock()
		// FIX: Use unique key with protocol-instanceID (includes hostname!)
		mapKey1 := "LMTP-" + instanceID1
		connectionTrackers[mapKey1] = tracker1
		connectionTrackersMux.Unlock()
	}

	// Second LMTP proxy: host2 with name "lmtp-proxy" (SAME server name!)
	instanceID2 := fmt.Sprintf("%s-%s", hostname2, serverName)
	tracker2 := server.NewConnectionTracker("LMTP", instanceID2, nil, 0, 0, 0, false)
	if tracker2 != nil {
		defer tracker2.Stop()
		connectionTrackersMux.Lock()
		// FIX: Use unique key with protocol-instanceID (includes hostname!)
		mapKey2 := "LMTP-" + instanceID2
		connectionTrackers[mapKey2] = tracker2
		connectionTrackersMux.Unlock()
	}

	// Verify the fix: Both trackers are registered despite having same server name
	connectionTrackersMux.Lock()
	trackerCount := len(connectionTrackers)
	connectionTrackersMux.Unlock()

	if trackerCount != 2 {
		t.Errorf("Expected 2 trackers to be registered, got %d", trackerCount)
	}

	// Verify both trackers are present with unique keys (hostname differentiates them)
	connectionTrackersMux.Lock()
	tracker1Present := connectionTrackers["LMTP-host1-lmtp-proxy"] != nil
	tracker2Present := connectionTrackers["LMTP-host2-lmtp-proxy"] != nil
	connectionTrackersMux.Unlock()

	if !tracker1Present {
		t.Errorf("Expected tracker1 to be registered with key 'LMTP-host1-lmtp-proxy'")
	}
	if !tracker2Present {
		t.Errorf("Expected tracker2 to be registered with key 'LMTP-host2-lmtp-proxy'")
	}

	t.Logf("SUCCESS: Both trackers registered with unique keys (hostname-based)")
	t.Logf("Registered trackers: %v", getTrackerNames(connectionTrackers))
}

// getTrackerNames returns a list of tracker keys for logging
func getTrackerNames(trackers map[string]*server.ConnectionTracker) []string {
	names := make([]string, 0, len(trackers))
	for name := range trackers {
		names = append(names, name)
	}
	return names
}
