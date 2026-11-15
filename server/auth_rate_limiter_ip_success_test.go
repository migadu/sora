package server

import (
	"context"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/migadu/sora/config"
)

// A successful login clears the Tier 2 count of its address on the listener that
// saw it. With [cluster.rate_limit_sync] the count also reached every listener of
// the protocol (FAILURE_COUNT), and nothing cleared it there: they kept delaying
// the address, and counting its next failures from the old total towards
// max_attempts_per_ip, until ip_window_duration passed without a failure (#1337).

func ipSuccessTestConfig() AuthRateLimiterConfig {
	cfg := nodeRateLimiterConfig()
	cfg.MaxAttemptsPerIP = 10
	cfg.DelayStartThreshold = 2
	cfg.InitialDelay = time.Second
	cfg.MaxDelay = 10 * time.Second
	cfg.DelayMultiplier = 2
	return cfg
}

// takeRateLimitBroadcasts returns every event queued in crl's outgoing gossip,
// once each, and empties the queue.
func takeRateLimitBroadcasts(t *testing.T, crl *ClusterRateLimiter) [][]byte {
	t.Helper()
	var msgs [][]byte
	seen := make(map[string]bool)
	for range 1000 {
		batch := crl.GetBroadcasts(gossipPerMsgOverhead, gossipUDPLimit)
		if len(batch) == 0 {
			return msgs
		}
		for _, msg := range batch {
			if !seen[string(msg)] {
				seen[string(msg)] = true
				msgs = append(msgs, msg)
			}
		}
	}
	t.Fatal("outgoing gossip never drained")
	return nil
}

func rateLimitBroadcastTypes(t *testing.T, msgs [][]byte) []RateLimitEventType {
	t.Helper()
	var types []RateLimitEventType
	for _, msg := range msgs {
		event, err := decodeRateLimitEvent(msg)
		if err != nil {
			t.Fatalf("decode broadcast: %v", err)
		}
		types = append(types, event.Type)
	}
	return types
}

// deliverRateLimitBroadcasts hands msgs to crl as gossip from another node would.
func deliverRateLimitBroadcasts(crl *ClusterRateLimiter, msgs [][]byte) {
	for _, msg := range msgs {
		crl.HandleClusterEvent(msg)
	}
}

func ipFailureCountOf(limiter *AuthRateLimiter, ip string) int {
	limiter.ipMu.RLock()
	defer limiter.ipMu.RUnlock()
	if info := limiter.ipFailureCounts[ip]; info != nil {
		return info.FailureCount
	}
	return 0
}

// TestSuccessClearsSharedFailureCountOnSiblingListener is the report: two IMAP
// proxy listeners on one node, three failures and a success on one of them.
func TestSuccessClearsSharedFailureCountOnSiblingListener(t *testing.T) {
	node := newSingleNodeCluster(t, "node-1")
	cfg := ipSuccessTestConfig()
	imap := newNodeRateLimiter(t, node, "IMAP-PROXY", "imap-proxy", cfg)
	imaps := newNodeRateLimiter(t, node, "IMAP-PROXY", "imaps-proxy", cfg)

	ctx := context.Background()
	client := &net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 40000}
	for range 3 {
		imap.RecordAuthAttempt(ctx, client, "anna@example.com", false)
	}
	if got := imaps.GetAuthenticationDelay(client); got != 2*time.Second {
		t.Fatalf("imaps-proxy delays the address by %v after 3 failures on imap-proxy, want 2s", got)
	}

	// The event's timestamp is taken when it is sent: let the success be later.
	time.Sleep(2 * time.Millisecond)
	imap.RecordAuthAttempt(ctx, client, "anna@example.com", true)
	if got := imap.GetAuthenticationDelay(client); got != 0 {
		t.Errorf("imap-proxy delays the address by %v after a successful login, want 0s", got)
	}
	if got := imaps.GetAuthenticationDelay(client); got != 0 {
		t.Errorf("imaps-proxy delays the address by %v after a successful login on imap-proxy, want 0s", got)
	}

	// The next failure on imaps-proxy starts a new count.
	imaps.RecordAuthAttempt(ctx, client, "anna@example.com", false)
	if got := ipFailureCountOf(imaps, "192.0.2.9"); got != 1 {
		t.Errorf("imaps-proxy counts %d failures of the address after the success and one failure, want 1", got)
	}
}

// TestSuccessClearsSharedFailureCountOnOtherNode: the same over gossip, to the
// protocol's listener on another node.
func TestSuccessClearsSharedFailureCountOnOtherNode(t *testing.T) {
	cfg := ipSuccessTestConfig()
	a := newNodeRateLimiter(t, newSingleNodeCluster(t, "node-1"), "IMAP-PROXY", "imap-proxy", cfg)
	b := newNodeRateLimiter(t, newSingleNodeCluster(t, "node-2"), "IMAP-PROXY", "imap-proxy", cfg)

	ctx := context.Background()
	client := &net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 40000}
	for range 3 {
		a.RecordAuthAttempt(ctx, client, "anna@example.com", false)
	}
	deliverRateLimitBroadcasts(b.clusterLimiter, takeRateLimitBroadcasts(t, a.clusterLimiter))
	if got := b.GetAuthenticationDelay(client); got != 2*time.Second {
		t.Fatalf("node-2 delays the address by %v after 3 failures on node-1, want 2s", got)
	}

	time.Sleep(2 * time.Millisecond)
	a.RecordAuthAttempt(ctx, client, "anna@example.com", true)
	deliverRateLimitBroadcasts(b.clusterLimiter, takeRateLimitBroadcasts(t, a.clusterLimiter))
	if got := b.GetAuthenticationDelay(client); got != 0 {
		t.Errorf("node-2 delays the address by %v after a successful login on node-1, want 0s", got)
	}
	if got := ipFailureCountOf(b, "192.0.2.9"); got != 0 {
		t.Errorf("node-2 still counts %d failures of the address after a successful login on node-1", got)
	}
}

// TestFailureCountDeliveredAfterTheSuccessIsIgnored: gossip does not keep the
// order of events, so a count recorded before the success can arrive after it.
// It is the older of the two and must not bring the count back.
func TestFailureCountDeliveredAfterTheSuccessIsIgnored(t *testing.T) {
	cfg := ipSuccessTestConfig()
	a := newNodeRateLimiter(t, newSingleNodeCluster(t, "node-1"), "IMAP-PROXY", "imap-proxy", cfg)
	b := newNodeRateLimiter(t, newSingleNodeCluster(t, "node-2"), "IMAP-PROXY", "imap-proxy", cfg)

	ctx := context.Background()
	client := &net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 40000}
	for range 3 {
		a.RecordAuthAttempt(ctx, client, "anna@example.com", false)
	}
	failures := takeRateLimitBroadcasts(t, a.clusterLimiter)
	time.Sleep(2 * time.Millisecond)
	a.RecordAuthAttempt(ctx, client, "anna@example.com", true)
	success := takeRateLimitBroadcasts(t, a.clusterLimiter)

	deliverRateLimitBroadcasts(b.clusterLimiter, success)
	deliverRateLimitBroadcasts(b.clusterLimiter, failures)
	if got := b.GetAuthenticationDelay(client); got != 0 {
		t.Errorf("node-2 delays the address by %v: a count sent before the success, delivered after it, was applied", got)
	}
	if got := ipFailureCountOf(b, "192.0.2.9"); got != 0 {
		t.Errorf("node-2 counts %d failures of the address from a count sent before the success", got)
	}
}

// TestSuccessClearsACountReceivedUnderAHigherThreshold: listeners of one
// protocol may run with different limits (a rolling change, or two [[server]]
// entries of the protocol). A count received from a listener whose
// delay_start_threshold is lower is shared although it is below this listener's
// own threshold, so a success here must still clear it there.
func TestSuccessClearsACountReceivedUnderAHigherThreshold(t *testing.T) {
	low := ipSuccessTestConfig()
	high := ipSuccessTestConfig()
	high.DelayStartThreshold = 5
	a := newNodeRateLimiter(t, newSingleNodeCluster(t, "node-1"), "IMAP-PROXY", "imap-proxy", low)
	b := newNodeRateLimiter(t, newSingleNodeCluster(t, "node-2"), "IMAP-PROXY", "imap-proxy", high)

	ctx := context.Background()
	client := &net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 40000}
	for range 2 {
		a.RecordAuthAttempt(ctx, client, "anna@example.com", false)
	}
	deliverRateLimitBroadcasts(b.clusterLimiter, takeRateLimitBroadcasts(t, a.clusterLimiter))
	if got := ipFailureCountOf(b, "192.0.2.9"); got != 2 {
		t.Fatalf("node-2 counts %d failures of the address after 2 on node-1, want 2", got)
	}

	time.Sleep(2 * time.Millisecond)
	b.RecordAuthAttempt(ctx, client, "anna@example.com", true)
	deliverRateLimitBroadcasts(a.clusterLimiter, takeRateLimitBroadcasts(t, b.clusterLimiter))
	if got := a.GetAuthenticationDelay(client); got != 0 {
		t.Errorf("node-1 delays the address by %v after a successful login on node-2, want 0s", got)
	}
}

// TestSuccessDoesNotClearANewerPeerFailure: a listener that saw a failure of the
// address after the success keeps its count, as for the name statistics: the
// count cannot be split, and keeping it errs towards limiting.
func TestSuccessDoesNotClearANewerPeerFailure(t *testing.T) {
	cfg := ipSuccessTestConfig()
	a := newNodeRateLimiter(t, newSingleNodeCluster(t, "node-1"), "IMAP-PROXY", "imap-proxy", cfg)
	b := newNodeRateLimiter(t, newSingleNodeCluster(t, "node-2"), "IMAP-PROXY", "imap-proxy", cfg)

	ctx := context.Background()
	client := &net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 40000}
	for range 3 {
		a.RecordAuthAttempt(ctx, client, "anna@example.com", false)
	}
	deliverRateLimitBroadcasts(b.clusterLimiter, takeRateLimitBroadcasts(t, a.clusterLimiter))
	time.Sleep(2 * time.Millisecond)
	a.RecordAuthAttempt(ctx, client, "anna@example.com", true)
	success := takeRateLimitBroadcasts(t, a.clusterLimiter)

	time.Sleep(2 * time.Millisecond)
	b.RecordAuthAttempt(ctx, client, "bob@example.com", false)
	deliverRateLimitBroadcasts(b.clusterLimiter, success)
	if got := ipFailureCountOf(b, "192.0.2.9"); got != 4 {
		t.Errorf("node-2 counts %d failures of the address, want its 4 (a failure newer than the success)", got)
	}
}

// TestSuccessNeverLiftsAPeerBlock: a success never ends an active block
// (AUTHENTICATION.md 10.2), here or on the listeners it reaches. A listener
// that holds a block keeps it and the count behind it.
func TestSuccessNeverLiftsAPeerBlock(t *testing.T) {
	cfg := ipSuccessTestConfig()
	cfg.MaxAttemptsPerIP = 4
	a := newNodeRateLimiter(t, newSingleNodeCluster(t, "node-1"), "IMAP-PROXY", "imap-proxy", cfg)
	b := newNodeRateLimiter(t, newSingleNodeCluster(t, "node-2"), "IMAP-PROXY", "imap-proxy", cfg)

	ctx := context.Background()
	client := &net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 40000}
	for range 3 {
		a.RecordAuthAttempt(ctx, client, "anna@example.com", false)
	}
	deliverRateLimitBroadcasts(b.clusterLimiter, takeRateLimitBroadcasts(t, a.clusterLimiter))
	// node-2 blocks the address; its block has not reached node-1 yet.
	b.RecordAuthAttempt(ctx, client, "bob@example.com", false)
	if !b.IsIPBlocked(client) {
		t.Fatal("node-2 did not block the address at max_attempts_per_ip")
	}
	takeRateLimitBroadcasts(t, b.clusterLimiter)

	time.Sleep(2 * time.Millisecond)
	a.RecordAuthAttempt(ctx, client, "anna@example.com", true)
	deliverRateLimitBroadcasts(b.clusterLimiter, takeRateLimitBroadcasts(t, a.clusterLimiter))
	if !b.IsIPBlocked(client) {
		t.Error("a successful login on node-1 lifted node-2's block of the address")
	}
	if got := ipFailureCountOf(b, "192.0.2.9"); got != 4 {
		t.Errorf("node-2 counts %d failures of the blocked address after a success on node-1, want 4", got)
	}

	// A success on the listener holding the block clears nothing, so it has
	// nothing to tell the cluster but the name statistics.
	b.RecordAuthAttempt(ctx, client, "bob@example.com", true)
	if got := rateLimitBroadcastTypes(t, takeRateLimitBroadcasts(t, b.clusterLimiter)); !reflect.DeepEqual(got, []RateLimitEventType{RateLimitEventUsernameSuccess}) {
		t.Errorf("a success on node-2 during its block queued %v, want only %s", got, RateLimitEventUsernameSuccess)
	}
	if !b.IsIPBlocked(client) {
		t.Error("a successful login lifted node-2's own block of the address")
	}
}

// TestSuccessSendsNoIPGossipForACountNeverShared: counts below
// delay_start_threshold never leave the listener, so a login after a typo costs
// no IP gossip. With sync_failure_counts off the listener neither sends nor
// accepts the clear.
func TestSuccessSendsNoIPGossipForACountNeverShared(t *testing.T) {
	cfg := ipSuccessTestConfig()
	a := newNodeRateLimiter(t, newSingleNodeCluster(t, "node-1"), "IMAP-PROXY", "imap-proxy", cfg)

	ctx := context.Background()
	client := &net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 40000}
	a.RecordAuthAttempt(ctx, client, "anna@example.com", false)
	takeRateLimitBroadcasts(t, a.clusterLimiter)
	a.RecordAuthAttempt(ctx, client, "anna@example.com", true)
	if got := rateLimitBroadcastTypes(t, takeRateLimitBroadcasts(t, a.clusterLimiter)); !reflect.DeepEqual(got, []RateLimitEventType{RateLimitEventUsernameSuccess}) {
		t.Errorf("a login after one failure below delay_start_threshold queued %v, want only %s", got, RateLimitEventUsernameSuccess)
	}

	noCounts := NewAuthRateLimiterWithTrustedNetworks("IMAP-PROXY", "imap-proxy", "mail", cfg, nil)
	t.Cleanup(noCounts.Stop)
	noCounts.JoinCluster(newSingleNodeCluster(t, "node-2"), config.ClusterRateLimitSyncConfig{Enabled: true, SyncBlocks: true, SyncFailureCounts: false})
	for range 3 {
		noCounts.RecordAuthAttempt(ctx, client, "carol@example.com", false)
	}
	takeRateLimitBroadcasts(t, noCounts.clusterLimiter)

	// A clear from node-1 does not reach a count node-2 never shared...
	for range 3 {
		a.RecordAuthAttempt(ctx, client, "anna@example.com", false)
	}
	takeRateLimitBroadcasts(t, a.clusterLimiter)
	time.Sleep(2 * time.Millisecond)
	a.RecordAuthAttempt(ctx, client, "anna@example.com", true)
	deliverRateLimitBroadcasts(noCounts.clusterLimiter, takeRateLimitBroadcasts(t, a.clusterLimiter))
	if got := ipFailureCountOf(noCounts, "192.0.2.9"); got != 3 {
		t.Errorf("node-2 with sync_failure_counts off counts %d failures after a success on node-1, want its own 3", got)
	}

	// ...and node-2 sends none of its own.
	noCounts.RecordAuthAttempt(ctx, client, "carol@example.com", true)
	if got := rateLimitBroadcastTypes(t, takeRateLimitBroadcasts(t, noCounts.clusterLimiter)); !reflect.DeepEqual(got, []RateLimitEventType{RateLimitEventUsernameSuccess}) {
		t.Errorf("a login with sync_failure_counts off queued %v, want only %s", got, RateLimitEventUsernameSuccess)
	}
}
