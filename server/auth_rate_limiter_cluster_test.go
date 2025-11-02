//go:build integration
// +build integration

package server

import (
	"context"
	"testing"
	"time"

	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
)

// TestClusterRateLimitSync tests that rate limit events are synchronized across cluster nodes
func TestClusterRateLimitSync(t *testing.T) {
	// Create 2-node test cluster
	cfg1 := config.ClusterConfig{
		Enabled:   true,
		Addr:      "127.0.0.1:17946",
		NodeID:    "test-node-1",
		Peers:     []string{"127.0.0.1:17947"},
		SecretKey: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=", // base64 encoded 32-byte key
		RateLimitSync: config.ClusterRateLimitSyncConfig{
			Enabled:           true,
			SyncBlocks:        true,
			SyncFailureCounts: true,
		},
	}

	cfg2 := config.ClusterConfig{
		Enabled:   true,
		Addr:      "127.0.0.1:17947",
		NodeID:    "test-node-2",
		Peers:     []string{"127.0.0.1:17946"},
		SecretKey: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=", // base64 encoded 32-byte key
		RateLimitSync: config.ClusterRateLimitSyncConfig{
			Enabled:           true,
			SyncBlocks:        true,
			SyncFailureCounts: true,
		},
	}

	// Start cluster managers
	cluster1, err := cluster.New(cfg1)
	if err != nil {
		t.Fatalf("Failed to create cluster 1: %v", err)
	}
	defer cluster1.Shutdown()

	cluster2, err := cluster.New(cfg2)
	if err != nil {
		t.Fatalf("Failed to create cluster 2: %v", err)
	}
	defer cluster2.Shutdown()

	// Wait for gossip to converge
	time.Sleep(500 * time.Millisecond)

	// Verify cluster membership
	if cluster1.GetMemberCount() < 2 {
		t.Fatalf("Cluster 1 member count: got %d, want >= 2", cluster1.GetMemberCount())
	}
	if cluster2.GetMemberCount() < 2 {
		t.Fatalf("Cluster 2 member count: got %d, want >= 2", cluster2.GetMemberCount())
	}

	// Create auth rate limiters
	rateLimitCfg := config.AuthRateLimiterConfig{
		Enabled:              true,
		FastBlockThreshold:   5, // Block after 5 failures
		FastBlockDuration:    5 * time.Minute,
		DelayStartThreshold:  2,
		MaxDelay:             30 * time.Second,
		InitialDelay:         2 * time.Second,
		DelayMultiplier:      2.0,
		CacheCleanupInterval: 1 * time.Minute,
		DBSyncInterval:       10 * time.Second,
		MaxPendingBatch:      100,
		DBErrorThreshold:     1 * time.Minute,
	}

	// Mock database (not testing database interaction here)
	mockDB := &mockAuthDatabase{}

	limiter1 := NewAuthRateLimiter("imap", rateLimitCfg, mockDB)
	if limiter1 == nil {
		t.Fatal("Failed to create limiter1")
	}
	defer limiter1.Stop()

	limiter2 := NewAuthRateLimiter("imap", rateLimitCfg, mockDB)
	if limiter2 == nil {
		t.Fatal("Failed to create limiter2")
	}
	defer limiter2.Stop()

	// Create cluster rate limiters
	clusterLimiter1 := NewClusterRateLimiter(limiter1, cluster1,
		cfg1.RateLimitSync.SyncBlocks, cfg1.RateLimitSync.SyncFailureCounts)
	if clusterLimiter1 == nil {
		t.Fatal("Failed to create cluster limiter1")
	}
	defer clusterLimiter1.Stop()
	limiter1.SetClusterLimiter(clusterLimiter1)

	clusterLimiter2 := NewClusterRateLimiter(limiter2, cluster2,
		cfg2.RateLimitSync.SyncBlocks, cfg2.RateLimitSync.SyncFailureCounts)
	if clusterLimiter2 == nil {
		t.Fatal("Failed to create cluster limiter2")
	}
	defer clusterLimiter2.Stop()
	limiter2.SetClusterLimiter(clusterLimiter2)

	// Test 1: Block IP on node 1, verify it's blocked on node 2
	t.Run("IPBlockSync", func(t *testing.T) {
		testIP := "192.168.1.100"
		ctx := context.Background()

		// Simulate 5 failed auth attempts on node 1 (triggers block)
		for i := 0; i < 5; i++ {
			limiter1.RecordAuthAttempt(ctx, &StringAddr{Addr: testIP + ":12345"}, "user@example.com", false)
		}

		// Wait for gossip to propagate
		time.Sleep(300 * time.Millisecond)

		// Verify IP is blocked on node 1 (local)
		err := limiter1.CanAttemptAuth(ctx, &StringAddr{Addr: testIP + ":12345"}, "user@example.com")
		if err == nil {
			t.Error("Expected IP to be blocked on node 1, but it's not")
		}

		// Verify IP is blocked on node 2 (via gossip)
		err = limiter2.CanAttemptAuth(ctx, &StringAddr{Addr: testIP + ":12345"}, "user@example.com")
		if err == nil {
			t.Error("Expected IP to be blocked on node 2 via cluster sync, but it's not")
		}
	})

	// Test 2: Progressive delay sync
	t.Run("FailureCountSync", func(t *testing.T) {
		testIP := "192.168.1.101"
		ctx := context.Background()

		// Simulate 3 failed auth attempts on node 1 (triggers progressive delay, not block)
		for i := 0; i < 3; i++ {
			limiter1.RecordAuthAttempt(ctx, &StringAddr{Addr: testIP + ":12345"}, "user2@example.com", false)
		}

		// Wait for gossip to propagate
		time.Sleep(300 * time.Millisecond)

		// Both nodes should have failure count for this IP
		// We can't directly check failure counts (private field), but we can verify
		// that auth attempts are allowed (not blocked) but would have delays applied

		// Verify IP is NOT blocked on node 1 (below threshold)
		err := limiter1.CanAttemptAuth(ctx, &StringAddr{Addr: testIP + ":12345"}, "user2@example.com")
		if err != nil {
			t.Errorf("Expected IP to NOT be blocked on node 1 (below threshold), but got: %v", err)
		}

		// Verify IP is NOT blocked on node 2 (via gossip)
		err = limiter2.CanAttemptAuth(ctx, &StringAddr{Addr: testIP + ":12345"}, "user2@example.com")
		if err != nil {
			t.Errorf("Expected IP to NOT be blocked on node 2 (below threshold), but got: %v", err)
		}
	})

	// Test 3: Stale event rejection
	t.Run("StaleEventRejection", func(t *testing.T) {
		// Create an event with old timestamp (6 minutes ago)
		staleEvent := RateLimitEvent{
			Type:         RateLimitEventBlockIP,
			IP:           "192.168.1.200",
			Timestamp:    time.Now().Add(-6 * time.Minute), // 6 minutes old
			NodeID:       "test-node-1",
			BlockedUntil: time.Now().Add(5 * time.Minute),
			FailureCount: 10,
			Protocol:     "imap",
		}

		// Encode event
		encoded, err := encodeRateLimitEvent(staleEvent)
		if err != nil {
			t.Fatalf("Failed to encode stale event: %v", err)
		}

		// Send directly to handler (bypassing gossip for testing)
		clusterLimiter2.HandleClusterEvent(encoded)

		// Wait a bit for processing
		time.Sleep(100 * time.Millisecond)

		// Verify IP is NOT blocked (stale event should be ignored)
		ctx := context.Background()
		err = limiter2.CanAttemptAuth(ctx, &StringAddr{Addr: "192.168.1.200:12345"}, "user@example.com")
		if err != nil {
			t.Errorf("Expected stale event to be ignored, but IP is blocked: %v", err)
		}
	})

	// Test 4: Expired block rejection
	t.Run("ExpiredBlockRejection", func(t *testing.T) {
		// Create an event with expired block time
		expiredEvent := RateLimitEvent{
			Type:         RateLimitEventBlockIP,
			IP:           "192.168.1.201",
			Timestamp:    time.Now(),
			NodeID:       "test-node-1",
			BlockedUntil: time.Now().Add(-1 * time.Minute), // Expired 1 minute ago
			FailureCount: 10,
			Protocol:     "imap",
		}

		// Encode event
		encoded, err := encodeRateLimitEvent(expiredEvent)
		if err != nil {
			t.Fatalf("Failed to encode expired event: %v", err)
		}

		// Send directly to handler (bypassing gossip for testing)
		clusterLimiter2.HandleClusterEvent(encoded)

		// Wait a bit for processing
		time.Sleep(100 * time.Millisecond)

		// Verify IP is NOT blocked (expired block should be ignored)
		ctx := context.Background()
		err = limiter2.CanAttemptAuth(ctx, &StringAddr{Addr: "192.168.1.201:12345"}, "user@example.com")
		if err != nil {
			t.Errorf("Expected expired block to be ignored, but IP is blocked: %v", err)
		}
	})
}

// mockAuthDatabase implements AuthDatabase for testing (no database operations)
type mockAuthDatabase struct{}

func (m *mockAuthDatabase) RecordAuthAttemptWithRetry(ctx context.Context, ipAddress, username, protocol string, success bool) error {
	return nil // No-op for testing
}

func (m *mockAuthDatabase) GetFailedAttemptsCountSeparateWindowsWithRetry(ctx context.Context, ipAddress, username string, ipWindowDuration, usernameWindowDuration time.Duration) (ipCount, usernameCount int, err error) {
	return 0, 0, nil // No database checks in cluster sync tests
}

func (m *mockAuthDatabase) CleanupOldAuthAttemptsWithRetry(ctx context.Context, maxAge time.Duration) (int64, error) {
	return 0, nil
}

func (m *mockAuthDatabase) GetAuthAttemptsStats(ctx context.Context, windowDuration time.Duration) (map[string]any, error) {
	return nil, nil
}
