// Package retry provides exponential backoff retry logic with jitter.
//
// This package implements configurable retry strategies for transient failures:
//   - Exponential backoff with optional jitter
//   - Maximum retry attempts
//   - Context-aware cancellation
//   - Customizable backoff parameters
//
// # Usage
//
//	cfg := retry.BackoffConfig{
//		InitialInterval: 100 * time.Millisecond,
//		MaxInterval:     5 * time.Second,
//		Multiplier:      2.0,
//		Jitter:          true,
//		MaxRetries:      5,
//	}
//
//	err := retry.WithBackoff(ctx, cfg, func() error {
//		return makeAPICall()
//	})
//
// # Jitter
//
// Jitter adds randomness to prevent thundering herd problems when
// multiple clients retry simultaneously. With jitter enabled, the
// actual delay is: baseDelay * (0.5 + random(0, 0.5))
//
// # Integration
//
// Used throughout the codebase for:
//   - Database connection retries
//   - S3 API call retries
//   - Network operation retries
package retry

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"time"

	"github.com/migadu/sora/logger"
)

type BackoffConfig struct {
	InitialInterval time.Duration
	MaxInterval     time.Duration
	Multiplier      float64
	Jitter          bool
	MaxRetries      int
}

func DefaultBackoffConfig() BackoffConfig {
	return BackoffConfig{
		InitialInterval: 1 * time.Second,
		MaxInterval:     30 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      5,
	}
}

func ExponentialBackoff(config BackoffConfig) func(int) time.Duration {
	return func(attempt int) time.Duration {
		if attempt <= 0 {
			return config.InitialInterval
		}

		interval := float64(config.InitialInterval) * math.Pow(config.Multiplier, float64(attempt-1))

		if interval > float64(config.MaxInterval) {
			interval = float64(config.MaxInterval)
		}

		duration := time.Duration(interval)

		if config.Jitter {
			jitter := time.Duration(rand.Int63n(int64(duration / 2)))
			duration = duration/2 + jitter
		}

		return duration
	}
}

type RetryableFunc func() error

func WithRetry(ctx context.Context, fn RetryableFunc, config BackoffConfig) error {
	backoff := ExponentialBackoff(config)

	var lastErr error
	var attempts int
	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		attempts = attempt + 1
		if attempt > 0 {
			delay := backoff(attempt)
			select {
			case <-ctx.Done():
				return fmt.Errorf("retry cancelled by context: %w", ctx.Err())
			case <-time.After(delay):
			}
		}

		if err := fn(); err != nil {
			lastErr = err
			if attempt < config.MaxRetries {
				continue
			}
		} else {
			return nil
		}
	}

	return fmt.Errorf("operation failed after %d attempts: %w", attempts, lastErr)
}

// StopError wraps an error to indicate that retries should stop immediately
type StopError struct {
	Err error
}

func (s StopError) Error() string {
	return s.Err.Error()
}

func (s StopError) Unwrap() error {
	return s.Err
}

// Stop wraps an error to indicate that retries should stop immediately
func Stop(err error) error {
	return StopError{Err: err}
}

// IsStopError checks if an error is a StopError
func IsStopError(err error) bool {
	var stopErr StopError
	return errors.As(err, &stopErr)
}

// WithRetryAdvanced is like WithRetry but respects StopError to halt retries immediately
func WithRetryAdvanced(ctx context.Context, fn RetryableFunc, config BackoffConfig) error {
	backoff := ExponentialBackoff(config)

	var lastErr error
	var attempts int
	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		attempts = attempt + 1
		if attempt > 0 {
			delay := backoff(attempt)
			select {
			case <-ctx.Done():
				return fmt.Errorf("retry cancelled by context: %w", ctx.Err())
			case <-time.After(delay):
			}
		}

		if err := fn(); err != nil {
			lastErr = err
			// Check if this is a StopError, which means we should not retry
			if IsStopError(err) {
				var stopErr StopError
				errors.As(err, &stopErr)
				logger.Infof("[RETRY-DEBUG] StopError detected on attempt %d, stopping retries: %v", attempts, stopErr.Err)
				return stopErr.Err
			}
			logger.Infof("[RETRY-DEBUG] Error on attempt %d (will retry if < %d): %v", attempts, config.MaxRetries+1, err)
			if attempt < config.MaxRetries {
				continue
			}
		} else {
			return nil
		}
	}

	return fmt.Errorf("operation failed after %d attempts: %w", attempts, lastErr)
}
