package server

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionMemoryTracker_BasicAllocation(t *testing.T) {
	tracker := NewSessionMemoryTracker(0) // Unlimited
	require.NotNil(t, tracker)

	// Initially zero
	assert.Equal(t, int64(0), tracker.Current())
	assert.Equal(t, int64(0), tracker.Peak())

	// Allocate 1000 bytes
	err := tracker.Allocate(1000)
	assert.NoError(t, err)
	assert.Equal(t, int64(1000), tracker.Current())
	assert.Equal(t, int64(1000), tracker.Peak())

	// Allocate another 500 bytes
	err = tracker.Allocate(500)
	assert.NoError(t, err)
	assert.Equal(t, int64(1500), tracker.Current())
	assert.Equal(t, int64(1500), tracker.Peak())
}

func TestSessionMemoryTracker_FreeMemory(t *testing.T) {
	tracker := NewSessionMemoryTracker(0)

	// Allocate 1000 bytes
	tracker.Allocate(1000)
	assert.Equal(t, int64(1000), tracker.Current())

	// Free 300 bytes
	tracker.Free(300)
	assert.Equal(t, int64(700), tracker.Current())
	assert.Equal(t, int64(1000), tracker.Peak(), "Peak should remain at maximum")

	// Free remaining
	tracker.Free(700)
	assert.Equal(t, int64(0), tracker.Current())
	assert.Equal(t, int64(1000), tracker.Peak(), "Peak should still be 1000")
}

func TestSessionMemoryTracker_PeakTracking(t *testing.T) {
	tracker := NewSessionMemoryTracker(0)

	// Allocate and free in waves
	tracker.Allocate(1000)
	assert.Equal(t, int64(1000), tracker.Peak())

	tracker.Free(500)
	assert.Equal(t, int64(500), tracker.Current())
	assert.Equal(t, int64(1000), tracker.Peak())

	tracker.Allocate(2000)
	assert.Equal(t, int64(2500), tracker.Current())
	assert.Equal(t, int64(2500), tracker.Peak(), "Peak should update to new maximum")

	tracker.Free(2500)
	assert.Equal(t, int64(0), tracker.Current())
	assert.Equal(t, int64(2500), tracker.Peak(), "Peak should remain at highest value")
}

func TestSessionMemoryTracker_LimitEnforcement(t *testing.T) {
	tracker := NewSessionMemoryTracker(1000) // 1000 byte limit

	// Allocate within limit
	err := tracker.Allocate(500)
	assert.NoError(t, err)
	assert.Equal(t, int64(500), tracker.Current())

	// Allocate up to limit
	err = tracker.Allocate(500)
	assert.NoError(t, err)
	assert.Equal(t, int64(1000), tracker.Current())

	// Exceed limit
	err = tracker.Allocate(1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "memory limit exceeded")
	assert.Equal(t, int64(1000), tracker.Current(), "Should not have allocated")
}

func TestSessionMemoryTracker_NegativeAllocation(t *testing.T) {
	tracker := NewSessionMemoryTracker(0)

	err := tracker.Allocate(-100)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot allocate negative bytes")
	assert.Equal(t, int64(0), tracker.Current())
}

func TestSessionMemoryTracker_NegativeFree(t *testing.T) {
	tracker := NewSessionMemoryTracker(0)

	tracker.Allocate(1000)
	tracker.Free(-100) // Should be ignored
	assert.Equal(t, int64(1000), tracker.Current())
}

func TestSessionMemoryTracker_OverFree(t *testing.T) {
	tracker := NewSessionMemoryTracker(0)

	tracker.Allocate(100)
	tracker.Free(200) // Free more than allocated

	// Should not go negative
	current := tracker.Current()
	assert.GreaterOrEqual(t, current, int64(0), "Current should not be negative")
}

func TestSessionMemoryTracker_Reset(t *testing.T) {
	tracker := NewSessionMemoryTracker(0)

	tracker.Allocate(1000)
	assert.Equal(t, int64(1000), tracker.Current())
	assert.Equal(t, int64(1000), tracker.Peak())

	tracker.Reset()
	assert.Equal(t, int64(0), tracker.Current())
	assert.Equal(t, int64(0), tracker.Peak())
}

func TestSessionMemoryTracker_Stats(t *testing.T) {
	tracker := NewSessionMemoryTracker(5000)

	tracker.Allocate(1000)
	tracker.Allocate(500)
	tracker.Free(200)

	stats := tracker.Stats()
	assert.Equal(t, int64(1300), stats.Current)
	assert.Equal(t, int64(1500), stats.Peak)
	assert.Equal(t, int64(5000), stats.MaxAllowed)
}

func TestSessionMemoryTracker_MaxAllowed(t *testing.T) {
	tracker := NewSessionMemoryTracker(2000)
	assert.Equal(t, int64(2000), tracker.MaxAllowed())

	unlimitedTracker := NewSessionMemoryTracker(0)
	assert.Equal(t, int64(0), unlimitedTracker.MaxAllowed())
}

func TestSessionMemoryTracker_ConcurrentAllocations(t *testing.T) {
	tracker := NewSessionMemoryTracker(0) // Unlimited

	var wg sync.WaitGroup
	allocSize := int64(100)
	numGoroutines := 100
	allocsPerGoroutine := 10

	// Concurrent allocations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < allocsPerGoroutine; j++ {
				tracker.Allocate(allocSize)
			}
		}()
	}

	wg.Wait()

	expected := int64(numGoroutines * allocsPerGoroutine * int(allocSize))
	assert.Equal(t, expected, tracker.Current())
	assert.Equal(t, expected, tracker.Peak())
}

func TestSessionMemoryTracker_ConcurrentAllocationsAndFrees(t *testing.T) {
	tracker := NewSessionMemoryTracker(0)

	var wg sync.WaitGroup
	numGoroutines := 50

	// Half allocate, half free
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		if i%2 == 0 {
			// Allocator goroutine
			go func() {
				defer wg.Done()
				for j := 0; j < 100; j++ {
					tracker.Allocate(100)
				}
			}()
		} else {
			// Freer goroutine
			go func() {
				defer wg.Done()
				for j := 0; j < 100; j++ {
					tracker.Free(100)
				}
			}()
		}
	}

	wg.Wait()

	// Current could be anything due to race, but peak should be >= 0
	assert.GreaterOrEqual(t, tracker.Peak(), int64(0))
	assert.GreaterOrEqual(t, tracker.Current(), int64(0))
}

func TestSessionMemoryTracker_ConcurrentLimitEnforcement(t *testing.T) {
	limit := int64(10000)
	tracker := NewSessionMemoryTracker(limit)

	var wg sync.WaitGroup
	var successCount atomic.Int64
	var failureCount atomic.Int64

	numGoroutines := 100
	allocSize := int64(200)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := tracker.Allocate(allocSize)
			if err != nil {
				failureCount.Add(1)
			} else {
				successCount.Add(1)
			}
		}()
	}

	wg.Wait()

	// Total allocated should not exceed limit
	assert.LessOrEqual(t, tracker.Current(), limit)

	// Should have both successes and failures
	assert.Greater(t, successCount.Load(), int64(0), "Should have some successful allocations")
	assert.Greater(t, failureCount.Load(), int64(0), "Should have some failed allocations")

	t.Logf("Successes: %d, Failures: %d, Current: %d, Limit: %d",
		successCount.Load(), failureCount.Load(), tracker.Current(), limit)
}

func TestSessionMemoryTracker_RealWorldScenario(t *testing.T) {
	// Simulate a realistic IMAP FETCH scenario with streaming
	tracker := NewSessionMemoryTracker(50 * 1024 * 1024) // 50MB limit

	// Fetch messages one at a time (streaming pattern)
	messageSizes := []int64{
		1024,      // 1KB
		5120,      // 5KB
		102400,    // 100KB
		512000,    // 500KB
		1048576,   // 1MB
		2097152,   // 2MB
		5242880,   // 5MB
		10485760,  // 10MB
		15728640,  // 15MB
		20971520,  // 20MB
	}

	peakSeen := int64(0)
	for i, size := range messageSizes {
		// Allocate message
		err := tracker.Allocate(size)
		assert.NoError(t, err, "Message %d allocation should succeed", i)

		// Track peak
		if tracker.Current() > peakSeen {
			peakSeen = tracker.Current()
		}

		// Free immediately after processing (streaming)
		tracker.Free(size)
		assert.Equal(t, int64(0), tracker.Current(), "After free, current should be 0")
	}

	// Peak should be the largest message size
	assert.Equal(t, int64(20971520), tracker.Peak())
	assert.LessOrEqual(t, tracker.Peak(), tracker.MaxAllowed())
}

func TestSessionMemoryTracker_LargeBurst(t *testing.T) {
	tracker := NewSessionMemoryTracker(10 * 1024 * 1024) // 10MB limit

	// Try to allocate 20MB (should fail)
	err := tracker.Allocate(20 * 1024 * 1024)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "memory limit exceeded")
	assert.Equal(t, int64(0), tracker.Current(), "Should not have allocated anything")
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{0, "0 B"},
		{1, "1 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1572864, "1.5 MB"},
		{1073741824, "1.0 GB"},
		{5368709120, "5.0 GB"},
	}

	for _, tt := range tests {
		result := FormatBytes(tt.bytes)
		assert.Equal(t, tt.expected, result, "FormatBytes(%d)", tt.bytes)
	}
}

func BenchmarkSessionMemoryTracker_Allocate(b *testing.B) {
	tracker := NewSessionMemoryTracker(0)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		tracker.Allocate(1024)
	}
}

func BenchmarkSessionMemoryTracker_AllocateAndFree(b *testing.B) {
	tracker := NewSessionMemoryTracker(0)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		tracker.Allocate(1024)
		tracker.Free(1024)
	}
}

func BenchmarkSessionMemoryTracker_ConcurrentAllocate(b *testing.B) {
	tracker := NewSessionMemoryTracker(0)
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			tracker.Allocate(1024)
		}
	})
}
