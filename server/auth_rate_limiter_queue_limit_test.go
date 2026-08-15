package server

import (
	"testing"
	"time"
)

// The property under test, unchanged since the hand-rolled queue: the outgoing
// rate-limit queue is bounded, and of events of the same size what it discards
// under pressure is the oldest, not the block that was just decided. The queue
// is now memberlist's own, so the assertions go through its API instead of
// indexing a slice, and equal-size events are what makes the discard order
// depend on age at all - see the note on maxCriticalQueued.

func newTestClusterRateLimiter(t *testing.T) *ClusterRateLimiter {
	t.Helper()

	limiter := NewAuthRateLimiter("test", "", "", AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 3,
		MaxAttemptsPerIP:         10,
		IPUsernameBlockDuration:  5 * time.Minute,
		IPBlockDuration:          15 * time.Minute,
		CleanupInterval:          1 * time.Hour,
	})
	t.Cleanup(limiter.Stop)

	return &ClusterRateLimiter{
		limiter: limiter,
		queue:   newGossipQueue("rate-limit:test", nil, maxRateLimitEventQueueSize),
	}
}

// TestClusterRateLimiter_BroadcastQueueSizeLimit tests that the broadcast queue
// is bounded once it reaches the limit.
func TestClusterRateLimiter_BroadcastQueueSizeLimit(t *testing.T) {
	crl := newTestClusterRateLimiter(t)

	for i := 0; i < maxRateLimitEventQueueSize; i++ {
		crl.queueEvent(RateLimitEvent{
			Type:      RateLimitEventBlockIP,
			IP:        "203.0.113.4",
			Timestamp: time.Now(),
			NodeID:    "test-node",
		})
	}

	if queued := crl.queue.numQueued(); queued != maxRateLimitEventQueueSize {
		t.Fatalf("Expected queue size %d, got %d", maxRateLimitEventQueueSize, queued)
	}

	crl.queueEvent(RateLimitEvent{
		Type:      RateLimitEventBlockIP,
		IP:        "203.0.113.8",
		Timestamp: time.Now(),
		NodeID:    "test-node",
	})

	if queued := crl.queue.numQueued(); queued > maxRateLimitEventQueueSize {
		t.Errorf("Queue size %d exceeded the limit %d", queued, maxRateLimitEventQueueSize)
	}
}

// TestClusterRateLimiter_QueueEvictionPreservesNewest tests that the events
// discarded on overflow are the oldest ones.
func TestClusterRateLimiter_QueueEvictionPreservesNewest(t *testing.T) {
	crl := newTestClusterRateLimiter(t)

	// Equal-length IPs so the events are the same size and eviction order is
	// decided purely by age.
	for i := 0; i < maxRateLimitEventQueueSize; i++ {
		crl.queueEvent(RateLimitEvent{
			Type:      RateLimitEventBlockIP,
			IP:        "203.0.113.7",
			Timestamp: time.Now(),
			NodeID:    "test-node",
		})
	}

	const newest = "198.51.100.9"
	for i := 0; i < 10; i++ {
		crl.queueEvent(RateLimitEvent{
			Type:      RateLimitEventBlockIP,
			IP:        newest,
			Timestamp: time.Now(),
			NodeID:    "test-node",
		})
	}

	found := 0
	for _, msg := range crl.GetBroadcasts(gossipPerMsgOverhead, 65535) {
		event, err := decodeRateLimitEvent(msg)
		if err != nil {
			t.Fatalf("decode broadcast: %v", err)
		}
		if event.IP == newest {
			found++
		}
	}

	if found != 10 {
		t.Errorf("the 10 newest events survived %d times, want 10: overflow must discard the oldest", found)
	}
}

// TestClusterRateLimiter_QueueDoesNotGrowUnbounded tests that queue stays bounded under sustained load
func TestClusterRateLimiter_QueueDoesNotGrowUnbounded(t *testing.T) {
	crl := newTestClusterRateLimiter(t)

	for i := 0; i < 5*maxRateLimitEventQueueSize; i++ {
		crl.queueEvent(RateLimitEvent{
			Type:      RateLimitEventBlockIP,
			IP:        "203.0.113.6",
			Timestamp: time.Now(),
			NodeID:    "test-node",
		})
	}

	queued := crl.queue.numQueued()
	if queued > maxRateLimitEventQueueSize {
		t.Errorf("Queue size %d exceeded limit %d - unbounded growth!", queued, maxRateLimitEventQueueSize)
	}
	if queued < maxRateLimitEventQueueSize {
		t.Errorf("Queue size %d is below the limit, eviction is too aggressive", queued)
	}

	t.Logf("Queue stabilized at %d entries after %d events (5x limit)", queued, 5*maxRateLimitEventQueueSize)
}
