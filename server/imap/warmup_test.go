package imap

import (
	"testing"
	"time"
)

// TestWarmupInterval tests that warmup only runs after the configured interval passes
// This test validates the interval checking logic without actually running warmup
func TestWarmupInterval(t *testing.T) {
	server := &IMAPServer{
		// name:           "test-imap",
		warmupInterval: 100 * time.Millisecond,
	}

	AccountID := int64(123)
	now := time.Now()

	// Simulate first warmup - record timestamp
	server.lastWarmupTimes.Store(AccountID, now)

	// Check immediately - should be within interval
	if lastWarmupRaw, ok := server.lastWarmupTimes.Load(AccountID); ok {
		lastWarmup := lastWarmupRaw.(time.Time)
		timeSinceLastWarmup := time.Since(lastWarmup)
		if timeSinceLastWarmup >= server.warmupInterval {
			t.Error("Expected warmup to be skipped (within interval)")
		}
	} else {
		t.Error("Expected timestamp to be stored")
	}

	// Wait for interval to pass
	time.Sleep(150 * time.Millisecond)

	// Check after interval - should allow warmup
	if lastWarmupRaw, ok := server.lastWarmupTimes.Load(AccountID); ok {
		lastWarmup := lastWarmupRaw.(time.Time)
		timeSinceLastWarmup := time.Since(lastWarmup)
		if timeSinceLastWarmup < server.warmupInterval {
			t.Errorf("Expected interval to have passed, got %v (wanted >%v)", timeSinceLastWarmup, server.warmupInterval)
		}
	}
}

// TestWarmupIntervalPerUser tests that warmup intervals are tracked independently per user
func TestWarmupIntervalPerUser(t *testing.T) {
	server := &IMAPServer{
		// name:           "test-imap",
		// warmupInterval: 1 * time.Hour,
	}

	user1 := int64(123)
	user2 := int64(456)

	now := time.Now()

	// Record warmup for user1
	server.lastWarmupTimes.Store(user1, now)

	// Record warmup for user2 at different time
	server.lastWarmupTimes.Store(user2, now.Add(-30*time.Minute))

	// Verify user1 timestamp
	if lastWarmupRaw, ok := server.lastWarmupTimes.Load(user1); ok {
		lastWarmup := lastWarmupRaw.(time.Time)
		if !lastWarmup.Equal(now) {
			t.Error("User1 timestamp doesn't match")
		}
	} else {
		t.Error("Expected user1 to have timestamp")
	}

	// Verify user2 timestamp
	if lastWarmupRaw, ok := server.lastWarmupTimes.Load(user2); ok {
		lastWarmup := lastWarmupRaw.(time.Time)
		expected := now.Add(-30 * time.Minute)
		if !lastWarmup.Equal(expected) {
			t.Error("User2 timestamp doesn't match")
		}
	} else {
		t.Error("Expected user2 to have timestamp")
	}

	// Verify they're independent
	time1, _ := server.lastWarmupTimes.Load(user1)
	time2, _ := server.lastWarmupTimes.Load(user2)
	if time1 == time2 {
		t.Error("Expected different timestamps for different users")
	}
}

// TestWarmupIntervalConcurrentAccess tests that concurrent warmup calls for the same user
// are properly synchronized using sync.Map
func TestWarmupIntervalConcurrentAccess(t *testing.T) {
	server := &IMAPServer{
		name:           "test-imap",
		warmupInterval: 1 * time.Hour,
	}

	AccountID := int64(123)
	now := time.Now()

	// Simulate concurrent stores
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(offset time.Duration) {
			server.lastWarmupTimes.Store(AccountID, now.Add(offset))
			done <- true
		}(time.Duration(i) * time.Millisecond)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify we can load without panic
	if _, ok := server.lastWarmupTimes.Load(AccountID); !ok {
		t.Error("Expected timestamp to be stored after concurrent access")
	}
}
