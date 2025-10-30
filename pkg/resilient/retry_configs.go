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
var writeRetryConfig = retry.BackoffConfig{
	InitialInterval: 250 * time.Millisecond,
	MaxInterval:     5 * time.Second,
	Multiplier:      1.8,
	Jitter:          true,
	MaxRetries:      2, // Writes are less safe to retry automatically
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
