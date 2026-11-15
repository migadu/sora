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

// countWarmupTimes returns the number of entries in s.lastWarmupTimes.
func countWarmupTimes(s *IMAPServer) int {
	n := 0
	s.lastWarmupTimes.Range(func(key, value any) bool {
		n++
		return true
	})
	return n
}

// TestWarmupTimesDropExpiredEntries checks that lastWarmupTimes does not keep every
// account warmed since start-up. An entry older than warmup_interval suppresses
// nothing, so recording a new warmup drops it; entries still inside the interval stay.
func TestWarmupTimesDropExpiredEntries(t *testing.T) {
	s := &IMAPServer{name: "test", warmupInterval: time.Hour}

	now := time.Now()
	for id := int64(1); id <= 100; id++ {
		s.lastWarmupTimes.Store(id, now.Add(-2*time.Hour)) // expired
	}
	s.lastWarmupTimes.Store(int64(500), now.Add(-30*time.Minute)) // still suppresses

	// The cache is nil, so executeWarmup records the warmup and returns.
	s.executeWarmup(warmupJob{accountID: 1000, mailboxNames: []string{"INBOX"}, messageCount: 10})

	for _, id := range []int64{500, 1000} {
		if _, ok := s.lastWarmupTimes.Load(id); !ok {
			t.Errorf("account %d is inside the interval but was dropped", id)
		}
	}
	if n := countWarmupTimes(s); n != 2 {
		t.Errorf("lastWarmupTimes has %d entries, want 2 (the 100 expired entries dropped)", n)
	}
}

// TestWarmupTimesNotKeptWithoutInterval checks that warmup_interval = 0, which warms
// at every login, keeps no entries at all: none of them could suppress a warmup.
func TestWarmupTimesNotKeptWithoutInterval(t *testing.T) {
	s := &IMAPServer{name: "test", warmupInterval: 0}

	for id := int64(1); id <= 50; id++ {
		s.executeWarmup(warmupJob{accountID: id, mailboxNames: []string{"INBOX"}, messageCount: 10})
	}

	if n := countWarmupTimes(s); n != 0 {
		t.Errorf("lastWarmupTimes has %d entries with a zero interval, want 0", n)
	}
}

// TestWarmupTimesSweptOncePerInterval checks that the sweep of expired entries runs at
// most once per interval rather than on every warmup: an entry that expires after a
// sweep stays until the interval has passed since that sweep.
func TestWarmupTimesSweptOncePerInterval(t *testing.T) {
	s := &IMAPServer{name: "test", warmupInterval: time.Hour}
	now := time.Now()

	s.recordWarmup(1, now) // the first warmup sweeps
	s.lastWarmupTimes.Store(int64(2), now.Add(-2*time.Hour))

	s.recordWarmup(3, now.Add(time.Minute))
	if _, ok := s.lastWarmupTimes.Load(int64(2)); !ok {
		t.Error("expired entry swept again within the interval of the last sweep")
	}

	s.recordWarmup(4, now.Add(time.Hour))
	if _, ok := s.lastWarmupTimes.Load(int64(2)); ok {
		t.Error("expired entry kept after the interval since the last sweep had passed")
	}
	for _, id := range []int64{3, 4} {
		if _, ok := s.lastWarmupTimes.Load(id); !ok {
			t.Errorf("account %d is inside the interval but was swept", id)
		}
	}
}
