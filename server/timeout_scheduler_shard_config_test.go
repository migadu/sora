package server

import (
	"runtime"
	"testing"
	"time"
)

func TestComputeShardCount(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected int
	}{
		{
			name:     "zero uses NumCPU",
			input:    0,
			expected: max(runtime.NumCPU(), 1),
		},
		{
			name:     "negative one uses NumCPU/2",
			input:    -1,
			expected: max(runtime.NumCPU()/2, 1),
		},
		{
			name:     "positive value uses as-is",
			input:    4,
			expected: 4,
		},
		{
			name:     "positive value 8",
			input:    8,
			expected: 8,
		},
		{
			name:     "positive value 1",
			input:    1,
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeShardCount(tt.input)
			if got != tt.expected {
				t.Errorf("computeShardCount(%d) = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}

func TestTimeoutSchedulerStartWithShardCount(t *testing.T) {
	tests := []struct {
		name        string
		shardCount  int
		expectError bool
	}{
		{
			name:        "zero shard count (default)",
			shardCount:  0,
			expectError: false,
		},
		{
			name:        "negative one (physical cores)",
			shardCount:  -1,
			expectError: false,
		},
		{
			name:        "positive shard count",
			shardCount:  4,
			expectError: false,
		},
		{
			name:        "invalid negative shard count",
			shardCount:  -2,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheduler := &TimeoutScheduler{}
			err := scheduler.Start(tt.shardCount, 100*time.Millisecond)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error for shardCount=%d, got nil", tt.shardCount)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error starting scheduler with shardCount=%d: %v", tt.shardCount, err)
			}

			// Verify scheduler is running
			scheduler.mu.Lock()
			running := scheduler.running
			actualShards := scheduler.shardCount
			scheduler.mu.Unlock()

			if !running {
				t.Error("scheduler should be running")
			}

			expectedShards := computeShardCount(tt.shardCount)
			if actualShards != expectedShards {
				t.Errorf("scheduler shardCount = %d, want %d", actualShards, expectedShards)
			}

			// Clean up
			if err := scheduler.Stop(); err != nil {
				t.Errorf("failed to stop scheduler: %v", err)
			}
		})
	}
}

func TestInitializeGlobalTimeoutScheduler(t *testing.T) {
	// Stop any existing scheduler first
	_ = globalScheduler.Stop()

	tests := []struct {
		name        string
		shardCount  int
		expectError bool
	}{
		{
			name:        "default config (0)",
			shardCount:  0,
			expectError: false,
		},
		{
			name:        "physical cores (-1)",
			shardCount:  -1,
			expectError: false,
		},
		{
			name:        "custom count (8)",
			shardCount:  8,
			expectError: false,
		},
		{
			name:        "invalid count (-2)",
			shardCount:  -2,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Stop scheduler before each test
			_ = globalScheduler.Stop()

			err := InitializeGlobalTimeoutScheduler(tt.shardCount)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error for shardCount=%d, got nil", tt.shardCount)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify global scheduler is running with correct shard count
			globalScheduler.mu.Lock()
			running := globalScheduler.running
			actualShards := globalScheduler.shardCount
			globalScheduler.mu.Unlock()

			if !running {
				t.Error("global scheduler should be running")
			}

			expectedShards := computeShardCount(tt.shardCount)
			if actualShards != expectedShards {
				t.Errorf("global scheduler shardCount = %d, want %d", actualShards, expectedShards)
			}
		})
	}

	// Clean up
	_ = globalScheduler.Stop()
}

func TestSchedulerShardCountPersistence(t *testing.T) {
	// Stop any existing scheduler
	_ = globalScheduler.Stop()

	// Initialize with custom shard count
	customCount := 3
	if err := InitializeGlobalTimeoutScheduler(customCount); err != nil {
		t.Fatalf("failed to initialize scheduler: %v", err)
	}

	// Verify shard count is set correctly
	globalScheduler.mu.Lock()
	actualShards := globalScheduler.shardCount
	globalScheduler.mu.Unlock()

	if actualShards != customCount {
		t.Errorf("scheduler shardCount = %d, want %d", actualShards, customCount)
	}

	// Verify that a second call doesn't change the shard count (idempotent)
	if err := InitializeGlobalTimeoutScheduler(8); err != nil {
		t.Fatalf("second initialization failed: %v", err)
	}

	// Shard count should remain unchanged (scheduler already running)
	globalScheduler.mu.Lock()
	unchangedShards := globalScheduler.shardCount
	globalScheduler.mu.Unlock()

	if unchangedShards != customCount {
		t.Errorf("scheduler shardCount changed from %d to %d, should remain unchanged", customCount, unchangedShards)
	}

	// Clean up
	_ = globalScheduler.Stop()
}
