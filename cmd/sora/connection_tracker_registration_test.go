package main

import (
	"testing"

	"github.com/migadu/sora/server"
)

// TestProxyConnectionTrackerMapKeysAreUnique: every proxy registers its connection
// tracker in deps.connectionTrackers under the key startConnectionTrackerForProxy
// returns. That key must be unique per proxy instance, including two proxies with the
// same server name on different hosts. A per-protocol key ("LMTP") made the second
// proxy overwrite the first one's tracker, hiding its connections from the Admin API.
func TestProxyConnectionTrackerMapKeysAreUnique(t *testing.T) {
	deps := &serverDependencies{connectionTrackers: make(map[string]*server.ConnectionTracker)}
	proxies := []struct{ name, hostname, wantKey string }{
		{"lmtp-proxy", "host1", "LMTP-host1-lmtp-proxy"},
		{"lmtp-proxy", "host2", "LMTP-host2-lmtp-proxy"}, // same name, another host
		{"lmtp-proxy-2", "host1", "LMTP-host1-lmtp-proxy-2"},
	}
	for _, p := range proxies {
		sink := &trackerSink{}
		tracker, key := startConnectionTrackerForProxy("LMTP", p.name, p.hostname, 0, 0, nil, nil, nil, sink)
		if tracker == nil {
			t.Fatalf("%s on %s: no LMTP tracker started", p.name, p.hostname)
		}
		t.Cleanup(tracker.Stop)
		if sink.tracker != tracker {
			t.Errorf("%s on %s: tracker not handed to the proxy server", p.name, p.hostname)
		}
		if key != p.wantKey {
			t.Errorf("%s on %s: map key %q, want %q", p.name, p.hostname, key, p.wantKey)
		}
		// As the start functions in main.go register it.
		deps.connectionTrackersMux.Lock()
		deps.connectionTrackers[key] = tracker
		deps.connectionTrackersMux.Unlock()
	}
	if len(deps.connectionTrackers) != len(proxies) {
		t.Errorf("%d trackers registered for %d proxies: a key collided and one tracker replaced another", len(deps.connectionTrackers), len(proxies))
	}
}
