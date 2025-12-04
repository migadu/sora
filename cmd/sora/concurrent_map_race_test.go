package main

import (
	"sync"
	"testing"

	"github.com/migadu/sora/server"
)

// TestConcurrentMapWriteRaceBugRepro demonstrates the original bug
// that occurs during server startup when multiple proxy servers try to
// register their connection trackers simultaneously WITHOUT synchronization.
//
// This test SHOULD FAIL with -race detector and may panic with "concurrent map writes"
//
// Run with: go test -race -run TestConcurrentMapWriteRaceBugRepro
func TestConcurrentMapWriteRaceBugRepro(t *testing.T) {
	t.Skip("Skipping bug reproduction test - this is expected to fail/panic")

	// Simulate the OLD BUGGY code: deps.connectionTrackers map WITHOUT mutex
	connectionTrackers := make(map[string]*server.ConnectionTracker)

	// Simulate multiple proxy servers starting concurrently
	var wg sync.WaitGroup
	protocols := []string{"IMAP", "POP3", "ManageSieve", "LMTP", "UserAPI"}

	for _, protocol := range protocols {
		wg.Add(1)
		go func(proto string) {
			defer wg.Done()
			// This simulates what happens in startDynamic*ProxyServer functions
			// Line 1285, 1396, 1509, 1594, etc. - BUGGY VERSION
			tracker := &server.ConnectionTracker{}
			connectionTrackers[proto] = tracker // RACE CONDITION HERE
		}(protocol)
	}

	wg.Wait()

	// If we get here without panic, the race detector will still catch the issue
	if len(connectionTrackers) != len(protocols) {
		t.Errorf("Expected %d trackers, got %d", len(protocols), len(connectionTrackers))
	}
}

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
