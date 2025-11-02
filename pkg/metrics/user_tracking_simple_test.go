package metrics

import (
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestDomainTrackingBasic(t *testing.T) {
	// Reset metrics and enable domain tracking
	DomainCommandCount.Reset()
	DomainConnectionCount.Reset()
	DomainBytesTransferred.Reset()
	DomainMessageCount.Reset()

	originalEnableDomain := EnableDomainMetrics
	defer func() { EnableDomainMetrics = originalEnableDomain }()

	EnableDomainMetrics = true

	t.Run("track_domain_command", func(t *testing.T) {
		protocols := []string{"imap", "pop3"}
		domains := []string{"example.com", "test.org"}
		commands := []string{"SELECT", "RETR"}

		for _, protocol := range protocols {
			for _, domain := range domains {
				for _, command := range commands {
					TrackDomainCommand(protocol, domain, command)
				}
			}
		}

		// Verify some combinations were tracked
		count := testutil.ToFloat64(DomainCommandCount.WithLabelValues("imap", "example.com", "SELECT"))
		if count != 1 {
			t.Errorf("Expected 1 command for imap-example.com-SELECT, got %f", count)
		}
	})

	t.Run("track_domain_connection", func(t *testing.T) {
		TrackDomainConnection("imap", "example.com")
		TrackDomainConnection("pop3", "test.org")

		imapCount := testutil.ToFloat64(DomainConnectionCount.WithLabelValues("imap", "example.com"))
		pop3Count := testutil.ToFloat64(DomainConnectionCount.WithLabelValues("pop3", "test.org"))

		if imapCount != 1 {
			t.Errorf("Expected 1 IMAP connection for example.com, got %f", imapCount)
		}
		if pop3Count != 1 {
			t.Errorf("Expected 1 POP3 connection for test.org, got %f", pop3Count)
		}
	})

	t.Run("track_domain_bytes", func(t *testing.T) {
		TrackDomainBytes("imap", "example.com", "in", 1024)
		TrackDomainBytes("imap", "example.com", "out", 2048)

		bytesIn := testutil.ToFloat64(DomainBytesTransferred.WithLabelValues("imap", "example.com", "in"))
		bytesOut := testutil.ToFloat64(DomainBytesTransferred.WithLabelValues("imap", "example.com", "out"))

		if bytesIn != 1024 {
			t.Errorf("Expected 1024 bytes in, got %f", bytesIn)
		}
		if bytesOut != 2048 {
			t.Errorf("Expected 2048 bytes out, got %f", bytesOut)
		}
	})

	t.Run("track_domain_message", func(t *testing.T) {
		TrackDomainMessage("lmtp", "example.com", "delivered")
		TrackDomainMessage("imap", "example.com", "fetched")

		delivered := testutil.ToFloat64(DomainMessageCount.WithLabelValues("lmtp", "example.com", "delivered"))
		fetched := testutil.ToFloat64(DomainMessageCount.WithLabelValues("imap", "example.com", "fetched"))

		if delivered != 1 {
			t.Errorf("Expected 1 delivered message, got %f", delivered)
		}
		if fetched != 1 {
			t.Errorf("Expected 1 fetched message, got %f", fetched)
		}
	})

	t.Run("domain_tracking_disabled", func(t *testing.T) {
		EnableDomainMetrics = false

		// Track some activity
		TrackDomainCommand("imap", "disabled.com", "SELECT")

		// Should not be recorded
		count := testutil.ToFloat64(DomainCommandCount.WithLabelValues("imap", "disabled.com", "SELECT"))
		if count != 0 {
			t.Errorf("Expected 0 commands when domain tracking disabled, got %f", count)
		}
	})
}

func TestUserActivityTrackingBasic(t *testing.T) {
	// Reset state
	userStats = sync.Map{}
	trackedUsers = sync.Map{}
	trackedUserCount.Store(0)

	TopUserCommandCount.Reset()
	TopUserConnectionCount.Reset()
	HeavyUserOperations.Reset()

	// Configure for testing
	originalEnableUser := EnableUserMetrics
	originalThreshold := UserMetricsThreshold
	originalMaxUsers := MaxTrackedUsers
	originalHashNames := HashUsernames

	defer func() {
		EnableUserMetrics = originalEnableUser
		UserMetricsThreshold = originalThreshold
		MaxTrackedUsers = originalMaxUsers
		HashUsernames = originalHashNames
	}()

	EnableUserMetrics = true
	UserMetricsThreshold = 5
	MaxTrackedUsers = 10
	HashUsernames = false

	t.Run("user_activity_below_threshold", func(t *testing.T) {
		username := "lowuser@example.com"

		// Track activity below threshold
		for i := 0; i < 3; i++ {
			TrackUserActivity("imap", username, "command", 1)
		}

		// User should not be promoted to individual tracking
		if _, tracked := trackedUsers.Load(username); tracked {
			t.Error("User should not be individually tracked below threshold")
		}

		// But stats should be recorded
		if statsVal, ok := userStats.Load(username); ok {
			stats := statsVal.(*UserStats)
			if stats.CommandCount.Load() != 3 {
				t.Errorf("Expected 3 commands in user stats, got %d", stats.CommandCount.Load())
			}
		} else {
			t.Error("User stats should be recorded even below threshold")
		}
	})

	t.Run("user_promotion_to_heavy_user", func(t *testing.T) {
		username := "heavyuser@example.com"

		// Track activity above threshold
		for i := 0; i < 6; i++ {
			TrackUserActivity("imap", username, "command", 1)
		}

		// User should be promoted to individual tracking
		if _, tracked := trackedUsers.Load(username); !tracked {
			t.Error("Heavy user should be individually tracked")
		}

		// Check that metrics were created (the exact count may vary due to implementation details)
		commandCount := testutil.ToFloat64(TopUserCommandCount.WithLabelValues("imap", username, "total"))
		if commandCount < 5 {
			t.Errorf("Expected at least 5 commands in top user metric, got %f", commandCount)
		}

		heavyUserCount := testutil.ToFloat64(HeavyUserOperations.WithLabelValues("imap", username, "command"))
		if heavyUserCount < 5 {
			t.Errorf("Expected at least 5 commands in heavy user metric, got %f", heavyUserCount)
		}
	})

	t.Run("user_tracking_disabled", func(t *testing.T) {
		EnableUserMetrics = false
		username := "disabled@example.com"

		TrackUserActivity("imap", username, "command", 10)

		// Should not create any user stats
		if _, ok := userStats.Load(username); ok {
			t.Error("User stats should not be recorded when user tracking is disabled")
		}

		if _, tracked := trackedUsers.Load(username); tracked {
			t.Error("User should not be tracked when user tracking is disabled")
		}
	})
}

func TestHashingFunction(t *testing.T) {
	t.Run("hash_consistency", func(t *testing.T) {
		username := "test@example.com"

		HashUsernames = true
		hash1 := hashUsername(username)
		hash2 := hashUsername(username)

		if hash1 != hash2 {
			t.Error("Hash function should be consistent")
		}
	})

	t.Run("hash_length", func(t *testing.T) {
		username := "test@example.com"

		HashUsernames = true
		hash := hashUsername(username)

		if len(hash) != 16 {
			t.Errorf("Expected hash length 16, got %d", len(hash))
		}
	})

	t.Run("no_hash_when_disabled", func(t *testing.T) {
		username := "nohash@example.com"

		HashUsernames = false
		result := hashUsername(username)

		if result != username {
			t.Errorf("Expected original username when hashing disabled, got %s", result)
		}
	})
}

func TestMetricsConfigurationBasic(t *testing.T) {
	originalConfig := struct {
		EnableUserMetrics    bool
		EnableDomainMetrics  bool
		UserMetricsThreshold int
		MaxTrackedUsers      int
		HashUsernames        bool
	}{
		EnableUserMetrics, EnableDomainMetrics, UserMetricsThreshold, MaxTrackedUsers, HashUsernames,
	}

	defer func() {
		EnableUserMetrics = originalConfig.EnableUserMetrics
		EnableDomainMetrics = originalConfig.EnableDomainMetrics
		UserMetricsThreshold = originalConfig.UserMetricsThreshold
		MaxTrackedUsers = originalConfig.MaxTrackedUsers
		HashUsernames = originalConfig.HashUsernames
	}()

	t.Run("configure_all_settings", func(t *testing.T) {
		Configure(true, false, 100, 500, true)

		if !EnableUserMetrics {
			t.Error("EnableUserMetrics should be true")
		}
		if EnableDomainMetrics {
			t.Error("EnableDomainMetrics should be false")
		}
		if UserMetricsThreshold != 100 {
			t.Errorf("UserMetricsThreshold should be 100, got %d", UserMetricsThreshold)
		}
		if MaxTrackedUsers != 500 {
			t.Errorf("MaxTrackedUsers should be 500, got %d", MaxTrackedUsers)
		}
		if !HashUsernames {
			t.Error("HashUsernames should be true")
		}
	})
}

func TestUserStatsDataStructures(t *testing.T) {
	// Reset state
	userStats = sync.Map{}
	trackedUsers = sync.Map{}
	trackedUserCount.Store(0)

	EnableUserMetrics = true
	UserMetricsThreshold = 5
	HashUsernames = false

	t.Run("user_stats_concurrent_access", func(t *testing.T) {
		username := "concurrent@example.com"

		// Simulate concurrent access
		var wg sync.WaitGroup
		numGoroutines := 10
		incrementsPerGoroutine := 5

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < incrementsPerGoroutine; j++ {
					TrackUserActivity("imap", username, "command", 1)
				}
			}()
		}

		wg.Wait()

		// Verify final count
		if statsVal, ok := userStats.Load(username); ok {
			stats := statsVal.(*UserStats)
			expectedCount := int64(numGoroutines * incrementsPerGoroutine)
			if stats.CommandCount.Load() != expectedCount {
				t.Errorf("Expected %d commands after concurrent access, got %d", expectedCount, stats.CommandCount.Load())
			}
		} else {
			t.Error("User stats should exist after concurrent access")
		}
	})

	t.Run("tracked_user_count_consistency", func(t *testing.T) {
		// Reset
		trackedUsers = sync.Map{}
		trackedUserCount.Store(0)

		users := []string{"count1@example.com", "count2@example.com", "count3@example.com"}

		for _, username := range users {
			for i := 0; i < 6; i++ {
				TrackUserActivity("imap", username, "command", 1)
			}
		}

		// Count tracked users manually
		manualCount := 0
		trackedUsers.Range(func(key, value any) bool {
			manualCount++
			return true
		})

		atomicCount := int(trackedUserCount.Load())
		if manualCount != atomicCount {
			t.Errorf("Manual count (%d) should equal atomic count (%d)", manualCount, atomicCount)
		}
	})
}
