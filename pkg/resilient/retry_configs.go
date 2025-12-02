package resilient

import (
	"time"

	"github.com/migadu/sora/pkg/retry"
)

// readRetryConfig provides a default retry strategy for read operations.
var readRetryConfig = retry.BackoffConfig{
	InitialInterval: 250 * time.Millisecond,
	MaxInterval:     3 * time.Second,
	Multiplier:      1.8,
	Jitter:          true,
	MaxRetries:      3,
	OperationName:   "db_read",
}

// writeRetryConfig provides a default retry strategy for write operations.
// Note: Deadlocks (40P01) are automatically retryable and safe to retry more aggressively
// since the transaction is rolled back and retried from the beginning. Retries happen at:
// 250ms, 450ms, 810ms, 1.4s, 2.5s (total ~5.4s across 5 attempts)
var writeRetryConfig = retry.BackoffConfig{
	InitialInterval: 250 * time.Millisecond,
	MaxInterval:     5 * time.Second,
	Multiplier:      1.8,
	Jitter:          true,
	MaxRetries:      4, // Increased from 2 to handle deadlocks more effectively
	OperationName:   "db_write",
}

// cleanupRetryConfig provides a default retry strategy for background cleanup tasks.
var cleanupRetryConfig = retry.BackoffConfig{
	InitialInterval: 1 * time.Second,
	MaxInterval:     30 * time.Second,
	Multiplier:      2.0,
	Jitter:          true,
	MaxRetries:      3,
	OperationName:   "db_cleanup",
}

// apiRetryConfig provides a default retry strategy for HTTP API handlers.
var apiRetryConfig = retry.BackoffConfig{
	InitialInterval: 200 * time.Millisecond,
	MaxInterval:     2 * time.Second,
	Multiplier:      1.8,
	Jitter:          true,
	MaxRetries:      3,
	OperationName:   "db_api",
}
