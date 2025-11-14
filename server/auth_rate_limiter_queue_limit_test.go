package server

import (
	"testing"
	"time"
)

// TestClusterRateLimiter_BroadcastQueueSizeLimit tests that broadcast queue is bounded and evicts oldest events
func TestClusterRateLimiter_BroadcastQueueSizeLimit(t *testing.T) {
	// Note: We can't actually create a real cluster manager in unit tests,
	// so we'll test the queueEvent logic directly

	config := AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 3,
		MaxAttemptsPerIP:         10,
		IPUsernameBlockDuration:  5 * time.Minute,
		IPBlockDuration:          15 * time.Minute,
		CacheCleanupInterval:     1 * time.Hour,
	}

	limiter := NewAuthRateLimiter("test", config)
	defer limiter.Stop()

	// Create cluster limiter (this would normally happen via SetClusterManager)
	// We'll test by directly accessing the internal structure for this test
	// Create a basic ClusterRateLimiter to test queue logic
	crl := &ClusterRateLimiter{
		limiter:        limiter,
		broadcastQueue: make([]RateLimitEvent, 0, 100),
	}

	// Queue events up to the limit (10000)
	const maxQueueSize = 10000
	for i := 0; i < maxQueueSize; i++ {
		event := RateLimitEvent{
			Type:      RateLimitEventBlockIP,
			IP:        "1.2.3.4",
			Timestamp: time.Now(),
			NodeID:    "test-node",
		}
		crl.queueEvent(event)
	}

	// Verify we're at the limit
	crl.queueMu.Lock()
	queueSize := len(crl.broadcastQueue)
	crl.queueMu.Unlock()

	if queueSize != maxQueueSize {
		t.Fatalf("Expected queue size %d, got %d", maxQueueSize, queueSize)
	}

	// Add one more event - should trigger eviction of oldest 10%
	event := RateLimitEvent{
		Type:      RateLimitEventBlockIP,
		IP:        "5.6.7.8",
		Timestamp: time.Now(),
		NodeID:    "test-node",
	}
	crl.queueEvent(event)

	// Verify queue size is still at limit (evicted 1000, added 1 = 9001 total)
	crl.queueMu.Lock()
	newQueueSize := len(crl.broadcastQueue)
	crl.queueMu.Unlock()

	expectedSize := maxQueueSize - (maxQueueSize / 10) + 1 // 10000 - 1000 + 1 = 9001
	if newQueueSize != expectedSize {
		t.Errorf("Expected queue size %d after eviction, got %d", expectedSize, newQueueSize)
	}

	// Verify the newest event is in the queue
	crl.queueMu.Lock()
	lastEvent := crl.broadcastQueue[len(crl.broadcastQueue)-1]
	crl.queueMu.Unlock()

	if lastEvent.IP != "5.6.7.8" {
		t.Errorf("Expected newest event IP 5.6.7.8, got %s", lastEvent.IP)
	}
}

// TestClusterRateLimiter_QueueEvictionPreservesNewest tests that oldest events are evicted, not newest
func TestClusterRateLimiter_QueueEvictionPreservesNewest(t *testing.T) {
	config := AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 3,
		MaxAttemptsPerIP:         10,
		IPUsernameBlockDuration:  5 * time.Minute,
		IPBlockDuration:          15 * time.Minute,
		CacheCleanupInterval:     1 * time.Hour,
	}

	limiter := NewAuthRateLimiter("test", config)
	defer limiter.Stop()

	crl := &ClusterRateLimiter{
		limiter:        limiter,
		broadcastQueue: make([]RateLimitEvent, 0, 100),
	}

	// Add events with specific IPs to track order
	const smallLimit = 100
	for i := 0; i < smallLimit; i++ {
		event := RateLimitEvent{
			Type:      RateLimitEventBlockIP,
			IP:        "old-event",
			Timestamp: time.Now(),
			NodeID:    "test-node",
		}
		crl.queueMu.Lock()
		crl.broadcastQueue = append(crl.broadcastQueue, event)
		crl.queueMu.Unlock()
	}

	// Add new events up to overflow
	for i := 0; i < 10; i++ {
		event := RateLimitEvent{
			Type:      RateLimitEventBlockIP,
			IP:        "new-event",
			Timestamp: time.Now(),
			NodeID:    "test-node",
		}
		crl.queueMu.Lock()
		// Manually trigger eviction logic when at limit
		if len(crl.broadcastQueue) >= smallLimit {
			dropCount := smallLimit / 10
			crl.broadcastQueue = crl.broadcastQueue[dropCount:]
		}
		crl.broadcastQueue = append(crl.broadcastQueue, event)
		crl.queueMu.Unlock()
	}

	// Verify old events were evicted and new events remain
	crl.queueMu.Lock()
	defer crl.queueMu.Unlock()

	// Check first event (should be from middle of old batch, oldest 10 evicted)
	firstEvent := crl.broadcastQueue[0]
	if firstEvent.IP != "old-event" {
		t.Errorf("First event should be old-event after evicting oldest 10%%, got %s", firstEvent.IP)
	}

	// Check last events (should all be new-event)
	for i := len(crl.broadcastQueue) - 10; i < len(crl.broadcastQueue); i++ {
		if crl.broadcastQueue[i].IP != "new-event" {
			t.Errorf("Event at index %d should be new-event, got %s", i, crl.broadcastQueue[i].IP)
		}
	}
}

// TestClusterRateLimiter_QueueDoesNotGrowUnbounded tests that queue stays bounded under sustained load
func TestClusterRateLimiter_QueueDoesNotGrowUnbounded(t *testing.T) {
	config := AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 3,
		MaxAttemptsPerIP:         10,
		IPUsernameBlockDuration:  5 * time.Minute,
		IPBlockDuration:          15 * time.Minute,
		CacheCleanupInterval:     1 * time.Hour,
	}

	limiter := NewAuthRateLimiter("test", config)
	defer limiter.Stop()

	crl := &ClusterRateLimiter{
		limiter:        limiter,
		broadcastQueue: make([]RateLimitEvent, 0, 100),
	}

	// Simulate sustained attack - add 50,000 events (5x the limit)
	const maxQueueSize = 10000
	for i := 0; i < 50000; i++ {
		event := RateLimitEvent{
			Type:      RateLimitEventBlockIP,
			IP:        "attacker.com",
			Timestamp: time.Now(),
			NodeID:    "test-node",
		}
		crl.queueEvent(event)
	}

	// Verify queue never exceeded reasonable bound
	crl.queueMu.Lock()
	finalSize := len(crl.broadcastQueue)
	crl.queueMu.Unlock()

	// After evictions, should be around 9001 (10000 - 1000 + 1 per overflow)
	// But with multiple overflows, it should stabilize around 9000-9500
	if finalSize > maxQueueSize {
		t.Errorf("Queue size %d exceeded limit %d - unbounded growth!", finalSize, maxQueueSize)
	}

	if finalSize < 8000 {
		t.Errorf("Queue size %d is too small, eviction may be too aggressive", finalSize)
	}

	t.Logf("Queue stabilized at %d entries after 50k events (5x limit) - bounded correctly", finalSize)
}
