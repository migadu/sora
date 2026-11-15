package server

import (
	"context"
	"errors"
	"fmt"
	"net"
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
