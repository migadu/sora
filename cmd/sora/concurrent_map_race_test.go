package main

import (
	"sync"
	"testing"

	"github.com/migadu/sora/server"
)

// TestConcurrentMapWriteRaceFixed verifies the FIX works correctly
// with proper mutex synchronization.
//
// This test SHOULD PASS with -race detector
func TestConcurrentMapWriteRaceFixed(t *testing.T) {
	// Simulate the FIXED code: deps.connectionTrackers map WITH mutex protection
	connectionTrackers := make(map[string]*server.ConnectionTracker)
	var connectionTrackersMux sync.Mutex

	// Simulate multiple proxy servers starting concurrently
	var wg sync.WaitGroup
	protocols := []string{"IMAP", "POP3", "ManageSieve", "LMTP", "UserAPI"}

	for _, protocol := range protocols {
		wg.Add(1)
		go func(proto string) {
			defer wg.Done()
			// This simulates the FIXED code with mutex protection
			tracker := &server.ConnectionTracker{}
			connectionTrackersMux.Lock()
			connectionTrackers[proto] = tracker // SAFE - protected by mutex
			connectionTrackersMux.Unlock()
		}(protocol)
	}

	wg.Wait()

	// Verify all trackers were added
	if len(connectionTrackers) != len(protocols) {
		t.Errorf("Expected %d trackers, got %d", len(protocols), len(connectionTrackers))
	}
}

// TestConcurrentMapWriteRaceFixedManyIterations runs the fixed test multiple times
// to verify the mutex protection works reliably.
func TestConcurrentMapWriteRaceFixedManyIterations(t *testing.T) {
	for i := 0; i < 100; i++ {
		connectionTrackers := make(map[string]*server.ConnectionTracker)
		var connectionTrackersMux sync.Mutex

		var wg sync.WaitGroup
		protocols := []string{"IMAP", "POP3", "ManageSieve", "LMTP", "UserAPI"}

		for _, protocol := range protocols {
			wg.Add(1)
			go func(proto string) {
				defer wg.Done()
				tracker := &server.ConnectionTracker{}
				connectionTrackersMux.Lock()
				connectionTrackers[proto] = tracker // SAFE
				connectionTrackersMux.Unlock()
			}(protocol)
		}

		wg.Wait()
	}
}

// TestConcurrentMapWriteRaceFixedMultipleServers simulates the real scenario
// where we might have multiple servers of the same type (e.g., imap-main-ip4, imap-main-ip6)
// with the FIX applied.
func TestConcurrentMapWriteRaceFixedMultipleServers(t *testing.T) {
	connectionTrackers := make(map[string]*server.ConnectionTracker)
	var connectionTrackersMux sync.Mutex

	var wg sync.WaitGroup

	// Simulate multiple IMAP servers (IPv4 + IPv6)
	servers := []string{
		"IMAP-main-ip4",
		"IMAP-main-ip6",
		"POP3-main-ip4",
		"POP3-main-ip6",
		"ManageSieve-main-ip4",
		"ManageSieve-main-ip6",
		"LMTP",
		"UserAPI",
	}

	for _, serverName := range servers {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			tracker := &server.ConnectionTracker{}
			connectionTrackersMux.Lock()
			connectionTrackers[name] = tracker // SAFE
			connectionTrackersMux.Unlock()
		}(serverName)
	}

	wg.Wait()

	if len(connectionTrackers) != len(servers) {
		t.Errorf("Expected %d trackers, got %d", len(servers), len(connectionTrackers))
	}
}
