package server

import (
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/config"
)

func TestClusterFailureCountZeroFirstFailureDoesNotPinEvictionFront(t *testing.T) {
	node := newSingleNodeCluster(t, "node-1")

	cfg := config.DefaultAuthRateLimiterConfig()
	cfg.Enabled = true
	cfg.MaxIPEntries = 2
	cfg.MaxAttemptsPerIP = 50
	cfg.DelayStartThreshold = 2
	cfg.MaxDelay = 10 * time.Second

	limiter := NewAuthRateLimiter("IMAP", "test", "localhost", cfg)
	t.Cleanup(limiter.Stop)
	crl := NewClusterRateLimiter(limiter, node, true, true)

	now := time.Now()
	// 1. Insert an older IP entry (5 minutes old).
	crl.handleFailureCount(RateLimitEvent{
		Type:         RateLimitEventFailureCount,
		IP:           "198.51.100.1",
		NodeID:       "node-2",
		FailureCount: 3,
		LastDelay:    time.Second,
		FirstFailure: now.Add(-5 * time.Minute),
		Timestamp:    now.Add(-5 * time.Minute),
	})

	// 2. Insert a brand-new IP entry whose initial event omits FirstFailure (e.g.,
	// rolling upgrade peer), followed by an event carrying its real FirstFailure.
	crl.handleFailureCount(RateLimitEvent{
		Type:         RateLimitEventFailureCount,
		IP:           "198.51.100.2",
		NodeID:       "node-2",
		FailureCount: 4,
		LastDelay:    2 * time.Second,
		Timestamp:    now.Add(-5 * time.Second),
	})
	crl.handleFailureCount(RateLimitEvent{
		Type:         RateLimitEventFailureCount,
		IP:           "198.51.100.2",
		NodeID:       "node-3",
		FailureCount: 5,
		LastDelay:    3 * time.Second,
		FirstFailure: now.Add(-10 * time.Second),
		Timestamp:    now,
	})

	// 3. Insert a third IP at capacity: the 5-minute-old 198.51.100.1 must be
	// evicted, leaving recent 198.51.100.2 intact with its progressive delay.
	crl.handleFailureCount(RateLimitEvent{
		Type:         RateLimitEventFailureCount,
		IP:           "198.51.100.3",
		NodeID:       "node-2",
		FailureCount: 2,
		LastDelay:    500 * time.Millisecond,
		FirstFailure: now,
		Timestamp:    now,
	})

	delay := limiter.GetAuthenticationDelay(&net.TCPAddr{IP: net.ParseIP("198.51.100.2"), Port: 12345})
	if delay != 3*time.Second {
		t.Errorf("GetAuthenticationDelay(198.51.100.2) = %v, want 3s (recent IP was evicted ahead of 5-minute-old 198.51.100.1)", delay)
	}
	if oldDelay := limiter.GetAuthenticationDelay(&net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 12345}); oldDelay != 0 {
		t.Errorf("GetAuthenticationDelay(198.51.100.1) = %v, want 0 (oldest IP should have been evicted)", oldDelay)
	}
}

func TestClusterUsernameFailureOutOfOrderUpdatesEvictionOrder(t *testing.T) {
	node := newSingleNodeCluster(t, "node-1")

	cfg := config.DefaultAuthRateLimiterConfig()
	cfg.Enabled = true
	cfg.MaxUsernameEntries = 2

	limiter := NewAuthRateLimiter("IMAP", "test", "localhost", cfg)
	t.Cleanup(limiter.Stop)
	crl := NewClusterRateLimiter(limiter, node, true, true)

	now := time.Now()
	crl.handleUsernameFailure(RateLimitEvent{
		Type:      RateLimitEventUsernameFailure,
		Username:  "alice@example.com",
		NodeID:    "node-2",
		Timestamp: now.Add(-1 * time.Minute),
	})
	crl.handleUsernameFailure(RateLimitEvent{
		Type:      RateLimitEventUsernameFailure,
		Username:  "bob@example.com",
		NodeID:    "node-2",
		Timestamp: now.Add(-10 * time.Second),
	})
	// Out-of-order older failure for bob arrives from node-3 (5 minutes ago).
	crl.handleUsernameFailure(RateLimitEvent{
		Type:      RateLimitEventUsernameFailure,
		Username:  "bob@example.com",
		NodeID:    "node-3",
		Timestamp: now.Add(-5 * time.Minute),
	})

	// Insert carol at capacity (MaxUsernameEntries=2): bob (FirstFailure 5m ago)
	// must be evicted, keeping alice (FirstFailure 1m ago).
	crl.handleUsernameFailure(RateLimitEvent{
		Type:      RateLimitEventUsernameFailure,
		Username:  "carol@example.com",
		NodeID:    "node-2",
		Timestamp: now,
	})

	limiter.usernameMu.RLock()
	_, alicePresent := limiter.usernameFailureCounts["alice@example.com"]
	_, bobPresent := limiter.usernameFailureCounts["bob@example.com"]
	limiter.usernameMu.RUnlock()

	if !alicePresent || bobPresent {
		t.Errorf("username presence = (alice=%v, bob=%v), want (alice=true, bob=false)", alicePresent, bobPresent)
	}
}
