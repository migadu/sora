package server

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestLocalSuccessRejectsDelayedPeerCount(t *testing.T) {
	for _, localFailures := range []int{0, 1, 3} {
		t.Run(fmt.Sprintf("local-failures-%d", localFailures), func(t *testing.T) {
			cfg := ipSuccessTestConfig()
			a := newNodeRateLimiter(t, newSingleNodeCluster(t, "origin"), "IMAP-PROXY", "imap", cfg)
			b := newNodeRateLimiter(t, newSingleNodeCluster(t, "peer"), "IMAP-PROXY", "imap", cfg)
			ctx := context.Background()
			addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 12345}
			for range localFailures {
				a.RecordAuthAttempt(ctx, addr, "user@example.com", false)
			}
			takeRateLimitBroadcasts(t, a.clusterLimiter)
			for range 2 {
				b.RecordAuthAttempt(ctx, addr, "user@example.com", false)
			}
			pending := takeRateLimitBroadcasts(t, b.clusterLimiter)
			a.RecordAuthAttempt(ctx, addr, "user@example.com", true)
			if got := ipFailureCountOf(a, "192.0.2.9"); got != 0 {
				t.Fatalf("local success did not clear count: %d", got)
			}
			deliverRateLimitBroadcasts(a.clusterLimiter, pending)
			if got := ipFailureCountOf(a, "192.0.2.9"); got != 0 {
				t.Fatalf("old peer count resurrected locally cleared count: got %d, want 0", got)
			}
		})
	}
}

func TestCountBroadcastPausedAcrossSuccess(t *testing.T) {
	node := newSingleNodeCluster(t, "node")
	cfg := ipSuccessTestConfig()
	cfg.DelayStartThreshold = 1
	a := newNodeRateLimiter(t, node, "IMAP-PROXY", "imap", cfg)
	b := newNodeRateLimiter(t, node, "IMAP-PROXY", "imaps", cfg)
	ctx := context.Background()
	addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 12345}
	for range 2 {
		a.RecordAuthAttempt(ctx, addr, "user@example.com", false)
	}
	counted, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	// These are the two consecutive operations in updateFailureTracking. Gate
	// their gap to model its goroutine being descheduled after releasing ipMu.
	go func() {
		defer close(done)
		failures, delay, first, _, countedAt := a.countIPFailure("192.0.2.9", time.Now())
		close(counted)
		<-release
		a.clusterLimiter.BroadcastFailureCount("192.0.2.9", failures, delay, first, countedAt)
	}()
	<-counted
	a.RecordAuthAttempt(ctx, addr, "user@example.com", true)
	if got := ipFailureCountOf(b, "192.0.2.9"); got != 0 {
		t.Errorf("success did not clear sibling count: %d", got)
	}
	close(release)
	<-done
	if got := ipFailureCountOf(b, "192.0.2.9"); got != 0 {
		t.Fatalf("count recorded before success but broadcast afterward resurrected sibling count: got %d, want 0", got)
	}
	// A genuinely later count must still reach the sibling after the tombstone.
	a.RecordAuthAttempt(ctx, addr, "user@example.com", false)
	if got := ipFailureCountOf(b, "192.0.2.9"); got != 1 {
		t.Fatalf("failure counted after success was suppressed: got %d, want 1", got)
	}
}

// failureTime is taken before ipMu in RecordAuthAttempt. A failure counted
// after the success must survive its delayed gossip even if its call began first.
func TestFailureCountedAfterSuccessSurvivesItsDelayedGossip(t *testing.T) {
	cfg := ipSuccessTestConfig()
	a := newNodeRateLimiter(t, newSingleNodeCluster(t, "origin"), "IMAP-PROXY", "imap", cfg)
	b := newNodeRateLimiter(t, newSingleNodeCluster(t, "peer"), "IMAP-PROXY", "imap", cfg)
	ctx := context.Background()
	addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 12345}
	for range 3 {
		a.RecordAuthAttempt(ctx, addr, "user@example.com", false)
	}
	deliverRateLimitBroadcasts(b.clusterLimiter, takeRateLimitBroadcasts(t, a.clusterLimiter))
	failureStarted := time.Now()
	a.RecordAuthAttempt(ctx, addr, "user@example.com", true)
	success := takeRateLimitBroadcasts(t, a.clusterLimiter)
	b.countIPFailure("192.0.2.9", failureStarted)
	deliverRateLimitBroadcasts(b.clusterLimiter, success)
	if got := ipFailureCountOf(b, "192.0.2.9"); got != 4 {
		t.Fatalf("delayed success cleared a failure counted after it: got %d, want 4", got)
	}
}
