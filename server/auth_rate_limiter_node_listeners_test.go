package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
)

// newNodeRateLimiter starts a proxy listener's auth rate limiter on node, joined
// to the cluster as the proxies join theirs.
func newNodeRateLimiter(t *testing.T, node *cluster.Manager, protocol, serverName string, cfg AuthRateLimiterConfig) *AuthRateLimiter {
	t.Helper()
	limiter := NewAuthRateLimiterWithTrustedNetworks(protocol, serverName, "mail", cfg, nil)
	t.Cleanup(limiter.Stop)
	limiter.JoinCluster(node, config.ClusterRateLimitSyncConfig{Enabled: true, SyncBlocks: true, SyncFailureCounts: true})
	if limiter.clusterLimiter == nil {
		t.Fatalf("%s did not join the cluster", serverName)
	}
	return limiter
}

func nodeRateLimiterConfig() AuthRateLimiterConfig {
	cfg := DefaultAuthRateLimiterConfig()
	cfg.Enabled = true
	cfg.MaxAttemptsPerIP = 3
	cfg.MaxAttemptsPerIPUsername = 100
	cfg.DelayStartThreshold = 1000
	cfg.CleanupInterval = time.Hour
	return cfg
}

// TestRateLimitersOfAProtocolOnOneNodeShareBlocks covers two proxy listeners of
// one protocol on one node (an IMAP proxy on 143 and one on 993). Each has its
// own limiter, and memberlist delivers no broadcast back to the node that sent
// it, so an address one listener blocked was refused by every listener of the
// protocol on every other node but still accepted, with a fresh failure budget,
// by the other listener on its own node.
func TestRateLimitersOfAProtocolOnOneNodeShareBlocks(t *testing.T) {
	node := newSingleNodeCluster(t, "node-1")
	cfg := nodeRateLimiterConfig()
	imap := newNodeRateLimiter(t, node, "IMAP-PROXY", "imap-proxy", cfg)
	imaps := newNodeRateLimiter(t, node, "IMAP-PROXY", "imaps-proxy", cfg)
	pop3 := newNodeRateLimiter(t, node, "POP3-PROXY", "pop3-proxy", cfg)

	ctx := context.Background()
	client := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 40000}
	for _, u := range []string{"a@example.com", "b@example.com", "c@example.com"} {
		imap.RecordAuthAttempt(ctx, client, u, false)
	}
	if !imap.IsIPBlocked(client) {
		t.Fatal("imap-proxy did not block the address after 3 failures")
	}

	if !imaps.IsIPBlocked(client) {
		t.Error("imaps-proxy on the same node accepts an address imap-proxy blocked")
	}
	var rlErr *RateLimitError
	if err := imaps.CanAttemptAuth(ctx, client, "d@example.com"); err == nil {
		t.Error("imaps-proxy on the same node lets an address imap-proxy blocked try to log in")
	} else if !errors.As(err, &rlErr) || rlErr.Reason != "ip_blocked" {
		t.Errorf("imaps-proxy refused the login with %v, want an ip_blocked RateLimitError", err)
	}
	if pop3.IsIPBlocked(client) {
		t.Error("an IMAP block was applied to the node's POP3 proxy")
	}
}

// TestRateLimitersOfAProtocolOnOneNodeShareFailureCounts: progressive-delay
// failure counts reach the node's other listeners of the protocol, as they reach
// every other node's.
func TestRateLimitersOfAProtocolOnOneNodeShareFailureCounts(t *testing.T) {
	node := newSingleNodeCluster(t, "node-1")
	cfg := nodeRateLimiterConfig()
	cfg.MaxAttemptsPerIP = 10
	cfg.DelayStartThreshold = 2
	cfg.InitialDelay = time.Second
	cfg.MaxDelay = 10 * time.Second
	imap := newNodeRateLimiter(t, node, "IMAP-PROXY", "imap-proxy", cfg)
	imaps := newNodeRateLimiter(t, node, "IMAP-PROXY", "imaps-proxy", cfg)

	ctx := context.Background()
	client := &net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 40000}
	for range 2 {
		imap.RecordAuthAttempt(ctx, client, "anna@example.com", false)
	}
	if got := imap.GetAuthenticationDelay(client); got != time.Second {
		t.Fatalf("imap-proxy delays the address by %v after 2 failures, want 1s", got)
	}
	if got := imaps.GetAuthenticationDelay(client); got != time.Second {
		t.Errorf("imaps-proxy on the same node delays the address by %v, want imap-proxy's 1s", got)
	}

	// The failure imaps-proxy now sees adds to the count it took over.
	imaps.RecordAuthAttempt(ctx, client, "anna@example.com", false)
	imaps.ipMu.RLock()
	got := 0
	if info := imaps.ipFailureCounts["192.0.2.2"]; info != nil {
		got = info.FailureCount
	}
	imaps.ipMu.RUnlock()
	if got != 3 {
		t.Errorf("imaps-proxy counts %d failures of the address, want 3 (2 seen by imap-proxy)", got)
	}
}

// TestRateLimitersOfAProtocolOnOneNodeShareUsernameFailures: username failures,
// and the success that clears them, reach the node's other listeners of the
// protocol. A listener does not pass on what it was handed by a sibling: every
// other node hears of a failure once, from the listener that saw it.
func TestRateLimitersOfAProtocolOnOneNodeShareUsernameFailures(t *testing.T) {
	node := newSingleNodeCluster(t, "node-1")
	cfg := nodeRateLimiterConfig()
	imap := newNodeRateLimiter(t, node, "IMAP-PROXY", "imap-proxy", cfg)
	imaps := newNodeRateLimiter(t, node, "IMAP-PROXY", "imaps-proxy", cfg)

	ctx := context.Background()
	client := &net.TCPAddr{IP: net.ParseIP("192.0.2.3"), Port: 40000}
	const user = "anna@example.com"
	imap.RecordAuthAttempt(ctx, client, user, false)

	if got := imaps.getUsernameFailureCount(user); got != 1 {
		t.Errorf("imaps-proxy on the same node counts %d failures of %s, want 1", got, user)
	}
	if got := queuedRateLimitEventTypes(t, imap.clusterLimiter); len(got) != 1 || got[0] != RateLimitEventUsernameFailure {
		t.Errorf("imap-proxy queued %v for the cluster, want its one USERNAME_FAILURE", got)
	}
	if got := queuedRateLimitEventTypes(t, imaps.clusterLimiter); len(got) != 0 {
		t.Errorf("imaps-proxy passed imap-proxy's failure on to the cluster: %v", got)
	}

	// The event's timestamp is taken when it is sent: let the success be later.
	time.Sleep(2 * time.Millisecond)
	imaps.RecordAuthAttempt(ctx, client, user, true)
	if got := imap.getUsernameFailureCount(user); got != 0 {
		t.Errorf("imap-proxy still counts %d failures of %s after a login on imaps-proxy", got, user)
	}
}

// TestRateLimitersOfAProtocolOnOneNodeRecordConcurrently: listeners of one
// protocol on one node record failures of one address at the same time. Each
// hands its events to the other, so neither may do so while holding its own
// locks.
func TestRateLimitersOfAProtocolOnOneNodeRecordConcurrently(t *testing.T) {
	node := newSingleNodeCluster(t, "node-1")
	cfg := nodeRateLimiterConfig()
	cfg.MaxAttemptsPerIP = 50
	cfg.DelayStartThreshold = 1
	cfg.InitialDelay = time.Millisecond
	cfg.MaxDelay = time.Second
	limiters := []*AuthRateLimiter{
		newNodeRateLimiter(t, node, "IMAP-PROXY", "imap-proxy", cfg),
		newNodeRateLimiter(t, node, "IMAP-PROXY", "imaps-proxy", cfg),
	}

	ctx := context.Background()
	client := &net.TCPAddr{IP: net.ParseIP("192.0.2.4"), Port: 40000}
	var wg sync.WaitGroup
	for _, limiter := range limiters {
		for w := range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range 50 {
					limiter.RecordAuthAttempt(ctx, client, fmt.Sprintf("user%d-%d@example.com", w, i), false)
				}
			}()
		}
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("listeners recording failures of one address deadlocked")
	}

	for _, limiter := range limiters {
		if !limiter.IsIPBlocked(client) {
			t.Errorf("%s did not block the address", limiter.serverName)
		}
	}
}

func TestMultiListenerNodeDeduplicatesBlockedIPsInRegistry(t *testing.T) {
	globalRateLimiterRegistry.mu.Lock()
	savedLimiters := globalRateLimiterRegistry.limiters
	globalRateLimiterRegistry.limiters = make(map[string]*AuthRateLimiter)
	globalRateLimiterRegistry.mu.Unlock()
	t.Cleanup(func() {
		globalRateLimiterRegistry.mu.Lock()
		globalRateLimiterRegistry.limiters = savedLimiters
		globalRateLimiterRegistry.mu.Unlock()
	})

	node := newSingleNodeCluster(t, "node-1")
	cfg := nodeRateLimiterConfig()
	cfg.MaxAttemptsPerIPUsername = 2

	imap := newNodeRateLimiter(t, node, "IMAP-PROXY", "imap-proxy", cfg)
	imaps := newNodeRateLimiter(t, node, "IMAP-PROXY", "imaps-proxy", cfg)
	pop3 := newNodeRateLimiter(t, node, "POP3-PROXY", "pop3-proxy", cfg)

	RegisterRateLimiter("imap_proxy", "imap-proxy", imap)
	RegisterRateLimiter("imap_proxy", "imaps-proxy", imaps)
	RegisterRateLimiter("pop3_proxy", "pop3-proxy", pop3)

	ctx := context.Background()
	sharedIP := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 40000}
	for _, u := range []string{"u1@example.com", "u2@example.com", "u3@example.com"} {
		imap.RecordAuthAttempt(ctx, sharedIP, u, false)
	}
	if !imap.IsIPBlocked(sharedIP) || !imaps.IsIPBlocked(sharedIP) {
		t.Fatal("expected both IMAP listeners on the node to hold the Tier-2 IP block")
	}

	// Same IP blocked independently on POP3-PROXY must remain distinct by protocol.
	for _, u := range []string{"p1@example.com", "p2@example.com", "p3@example.com"} {
		pop3.RecordAuthAttempt(ctx, sharedIP, u, false)
	}
	if !pop3.IsIPBlocked(sharedIP) {
		t.Fatal("expected POP3 listener to block the IP")
	}

	// Tier-1 ip_username blocks are listener-local and must not be collapsed as ip blocks.
	tier1Addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.20"), Port: 40001}
	imap.RecordAuthAttempt(ctx, tier1Addr, "alice@example.com", false)
	imap.RecordAuthAttempt(ctx, tier1Addr, "alice@example.com", false)
	imaps.RecordAuthAttempt(ctx, tier1Addr, "bob@example.com", false)
	imaps.RecordAuthAttempt(ctx, tier1Addr, "bob@example.com", false)

	// Simulate diverging metadata across sibling listeners for another blocked IP
	// (e.g. renewed block / higher failure count on one listener, earlier non-zero
	// FirstFailure on the other) to verify deterministic merge semantics.
	now := time.Now()
	earlierFirst := now.Add(-5 * time.Minute)
	laterFirst := now.Add(-3 * time.Minute)
	earlierLast := now.Add(-2 * time.Minute)
	laterLast := now.Add(-1 * time.Minute)
	shorterUntil := now.Add(5 * time.Minute)
	longerUntil := now.Add(10 * time.Minute)

	imap.ipMu.Lock()
	imap.blockedIPs["192.0.2.30"] = &BlockedIPInfo{
		BlockedUntil: shorterUntil,
		FailureCount: 4,
		FirstFailure: earlierFirst,
		LastFailure:  earlierLast,
		Protocol:     "IMAP-PROXY",
	}
	imap.ipMu.Unlock()

	imaps.ipMu.Lock()
	imaps.blockedIPs["192.0.2.30"] = &BlockedIPInfo{
		BlockedUntil: longerUntil,
		FailureCount: 7,
		FirstFailure: laterFirst,
		LastFailure:  laterLast,
		Protocol:     "IMAP-PROXY",
	}
	imaps.ipMu.Unlock()

	imapEntries := GetBlockedEntriesByProtocol("imap_proxy")
	imapIPCount := make(map[string]BlockedEntry)
	imapTier1Count := 0
	for _, e := range imapEntries {
		switch e.Type {
		case "ip":
			if _, dup := imapIPCount[e.IP]; dup {
				t.Errorf("GetBlockedEntriesByProtocol(imap_proxy) returned duplicate ip entry for %s: %+v", e.IP, imapEntries)
			}
			imapIPCount[e.IP] = e
		case "ip_username":
			imapTier1Count++
		}
	}
	if len(imapIPCount) != 2 {
		t.Errorf("GetBlockedEntriesByProtocol(imap_proxy) returned %d unique ip entries, want 2: %+v", len(imapIPCount), imapEntries)
	}
	if imapTier1Count != 2 {
		t.Errorf("GetBlockedEntriesByProtocol(imap_proxy) returned %d ip_username entries, want 2", imapTier1Count)
	}
	if merged, ok := imapIPCount["192.0.2.30"]; ok {
		if !merged.BlockedUntil.Equal(longerUntil) {
			t.Errorf("merged BlockedUntil = %v, want latest %v", merged.BlockedUntil, longerUntil)
		}
		if merged.FailureCount != 7 {
			t.Errorf("merged FailureCount = %d, want max 7", merged.FailureCount)
		}
		if !merged.FirstFailure.Equal(earlierFirst) {
			t.Errorf("merged FirstFailure = %v, want earliest non-zero %v", merged.FirstFailure, earlierFirst)
		}
		if !merged.LastFailure.Equal(laterLast) {
			t.Errorf("merged LastFailure = %v, want latest %v", merged.LastFailure, laterLast)
		}
	}

	allEntries := GetAllBlockedEntries()
	seenProtoIP := make(map[string]int)
	for _, e := range allEntries {
		if e.Type == "ip" {
			key := e.Protocol + "|" + e.IP
			seenProtoIP[key]++
		}
	}
	if seenProtoIP["IMAP-PROXY|192.0.2.10"] != 1 {
		t.Errorf("GetAllBlockedEntries() has %d entries for IMAP-PROXY|192.0.2.10, want 1", seenProtoIP["IMAP-PROXY|192.0.2.10"])
	}
	if seenProtoIP["IMAP-PROXY|192.0.2.30"] != 1 {
		t.Errorf("GetAllBlockedEntries() has %d entries for IMAP-PROXY|192.0.2.30, want 1", seenProtoIP["IMAP-PROXY|192.0.2.30"])
	}
	if seenProtoIP["POP3-PROXY|192.0.2.10"] != 1 {
		t.Errorf("GetAllBlockedEntries() has %d entries for POP3-PROXY|192.0.2.10, want 1", seenProtoIP["POP3-PROXY|192.0.2.10"])
	}
}

func TestStoppedNodeRateLimiterLeavesSiblingGroupIdempotently(t *testing.T) {
	node := newSingleNodeCluster(t, "node-1")
	cfg := nodeRateLimiterConfig()

	imap := newNodeRateLimiter(t, node, "IMAP-PROXY", "imap-proxy", cfg)

	imaps := NewAuthRateLimiterWithTrustedNetworks("IMAP-PROXY", "imaps-proxy", "mail", cfg, nil)
	imaps.JoinCluster(node, config.ClusterRateLimitSyncConfig{Enabled: true, SyncBlocks: true, SyncFailureCounts: true})
	if imaps.clusterLimiter == nil {
		t.Fatal("imaps-proxy did not join the cluster")
	}

	group := nodeRateLimitersOf(node, "IMAP-PROXY")
	group.mu.RLock()
	initialLen := len(group.limiters)
	group.mu.RUnlock()
	if initialLen != 2 {
		t.Fatalf("expected 2 limiters in node group before Stop, got %d", initialLen)
	}

	// Stopping AuthRateLimiter and ClusterRateLimiter must be idempotent (never panic)
	// and must remove the stopped limiter from nodeRateLimiters.
	stopSafely := func(label string, fn func()) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("%s panicked: %v", label, r)
			}
		}()
		fn()
	}
	stopSafely("first imaps.Stop()", imaps.Stop)
	stopSafely("second imaps.Stop()", imaps.Stop)
	stopSafely("first imaps.clusterLimiter.Stop()", imaps.clusterLimiter.Stop)
	stopSafely("second imaps.clusterLimiter.Stop()", imaps.clusterLimiter.Stop)

	group.mu.RLock()
	afterStopLen := len(group.limiters)
	group.mu.RUnlock()
	if afterStopLen != 1 {
		t.Errorf("expected 1 limiter in node group after stopping imaps-proxy, got %d", afterStopLen)
	}

	// Subsequent intra-node events from imap-proxy must not be delivered to stopped imaps-proxy.
	ctx := context.Background()
	client := &net.TCPAddr{IP: net.ParseIP("192.0.2.50"), Port: 40000}
	for _, u := range []string{"a@example.com", "b@example.com", "c@example.com"} {
		imap.RecordAuthAttempt(ctx, client, u, false)
	}
	if !imap.IsIPBlocked(client) {
		t.Fatal("imap-proxy should have blocked 192.0.2.50")
	}
	if imaps.IsIPBlocked(client) {
		t.Error("stopped imaps-proxy still received intra-node IP block delivery")
	}
	if got := imaps.getUsernameFailureCount("a@example.com"); got != 0 {
		t.Errorf("stopped imaps-proxy still received intra-node username failure (got %d, want 0)", got)
	}

	// Peer gossip events delivered after Stop must also be ignored by the stopped limiter.
	encoded, err := encodeRateLimitEvent(RateLimitEvent{
		Type:         RateLimitEventBlockIP,
		EventID:      "peer-event-after-stop",
		IP:           "192.0.2.51",
		Timestamp:    time.Now(),
		NodeID:       "node-2",
		Protocol:     "IMAP-PROXY",
		BlockedUntil: time.Now().Add(5 * time.Minute),
		FailureCount: 5,
		FirstFailure: time.Now().Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("encodeRateLimitEvent: %v", err)
	}
	imaps.clusterLimiter.HandleClusterEvent(encoded)
	if imaps.IsIPBlocked(&net.TCPAddr{IP: net.ParseIP("192.0.2.51"), Port: 40000}) {
		t.Error("stopped imaps-proxy applied a peer cluster event after Stop")
	}

	// A reloaded replacement listener joins cleanly alongside imap-proxy.
	imapsReloaded := newNodeRateLimiter(t, node, "IMAP-PROXY", "imaps-proxy", cfg)
	group.mu.RLock()
	afterReloadLen := len(group.limiters)
	group.mu.RUnlock()
	if afterReloadLen != 2 {
		t.Errorf("expected 2 limiters in node group after reload, got %d", afterReloadLen)
	}

	client2 := &net.TCPAddr{IP: net.ParseIP("192.0.2.52"), Port: 40000}
	for _, u := range []string{"d@example.com", "e@example.com", "f@example.com"} {
		imap.RecordAuthAttempt(ctx, client2, u, false)
	}
	if !imapsReloaded.IsIPBlocked(client2) {
		t.Error("reloaded imaps-proxy did not receive intra-node IP block from imap-proxy")
	}
}

// A stopped limiter must leave both manager callback registries as well as
// its sibling group, or those method values retain the limiter and its maps.
func TestStoppedRateLimiterReleasesManagerRegistrations(t *testing.T) {
	node := newSingleNodeCluster(t, "retention-node")
	counts := func() (int, int) {
		state := reflect.ValueOf(node).Elem()
		return state.FieldByName("rateLimitHandlers").Len(), state.FieldByName("rateLimitBroadcasts").Len()
	}
	handlers, broadcasters := counts()
	for range 10 {
		limiter := newNodeRateLimiter(t, node, "IMAP-PROXY", "temporary-listener", nodeRateLimiterConfig())
		if h, b := counts(); h != handlers+1 || b != broadcasters+1 {
			t.Fatalf("registration counts=%d/%d, want %d/%d", h, b, handlers+1, broadcasters+1)
		}
		limiter.Stop()
		if h, b := counts(); h != handlers || b != broadcasters {
			t.Fatalf("stopped limiter retained by %d handlers/%d broadcasters; baseline %d/%d", h, b, handlers, broadcasters)
		}
	}
}

func TestClusterRateLimiterStopWaitsForAdmittedSiblingApply(t *testing.T) {
	node := newSingleNodeCluster(t, "stop-apply")
	limiter := newNodeRateLimiter(t, node, "IMAP-PROXY", "stopping", nodeRateLimiterConfig())
	crl := limiter.clusterLimiter
	now := time.Now()
	event := RateLimitEvent{Type: RateLimitEventBlockIP, IP: "192.0.2.100", Protocol: "IMAP-PROXY", Timestamp: now, BlockedUntil: now.Add(time.Hour), FailureCount: 3, FirstFailure: now}
	// Hold the receiving map lock after apply takes its lifecycle read lock.
	limiter.ipMu.Lock()
	applied := make(chan struct{})
	go func() { defer close(applied); crl.apply(event) }()
	for deadline := time.Now().Add(5 * time.Second); ; {
		if !crl.eventMu.TryLock() {
			break
		}
		crl.eventMu.Unlock()
		if time.Now().After(deadline) {
			limiter.ipMu.Unlock()
			t.Fatal("apply did not start")
		}
		time.Sleep(time.Millisecond)
	}
	stopped := make(chan struct{})
	go func() { crl.Stop(); close(stopped) }()
	for !crl.stopped.Load() {
		time.Sleep(time.Millisecond)
	}
	select {
	case <-stopped:
		limiter.ipMu.Unlock()
		t.Fatal("Stop returned while an admitted apply was blocked")
	default:
	}
	limiter.ipMu.Unlock()
	<-applied
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not finish after apply")
	}
	event.IP = "192.0.2.101"
	crl.apply(event)
	if limiter.IsIPBlocked(&net.TCPAddr{IP: net.ParseIP(event.IP)}) {
		t.Error("stopped limiter applied new state")
	}
	if got := crl.GetBroadcasts(0, 1400); len(got) != 0 {
		t.Error("stopped limiter still broadcasts queued state")
	}
}

func TestRateLimiterStopAcceptsZeroValues(t *testing.T) {
	var nilCluster *ClusterRateLimiter
	nilCluster.Stop()
	crl := &ClusterRateLimiter{}
	crl.Stop()
	crl.Stop()
	crl.HandleClusterEvent(nil)
	crl.apply(RateLimitEvent{})
	if got := crl.GetBroadcasts(0, 100); len(got) != 0 {
		t.Fatal("zero stopped limiter broadcasts")
	}
	limiter := &AuthRateLimiter{}
	limiter.Stop()
	limiter.Stop()
}
