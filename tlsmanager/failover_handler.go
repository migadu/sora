package tlsmanager

import (
	"context"
	"time"

	"github.com/migadu/sora/logger"
	"golang.org/x/crypto/acme/autocert"
)

// FailoverAwareCache wraps a cluster-aware cache with automatic retry on leadership changes
// This ensures that if a non-leader node tries to get a certificate and it doesn't exist,
// it will wait for the leader to issue it and retry
type FailoverAwareCache struct {
	underlying autocert.Cache
	retryDelay time.Duration
	maxRetries int
}

// NewFailoverAwareCache creates a new failover-aware cache
func NewFailoverAwareCache(cache autocert.Cache) *FailoverAwareCache {
	return &FailoverAwareCache{
		underlying: cache,
		retryDelay: 2 * time.Second,
		maxRetries: 15, // 30 seconds total (2s * 15)
	}
}

// Get retrieves a certificate with automatic retry logic
// If certificate doesn't exist, it retries multiple times to allow the leader to issue it
func (c *FailoverAwareCache) Get(ctx context.Context, name string) ([]byte, error) {
	for attempt := 0; attempt < c.maxRetries; attempt++ {
		data, err := c.underlying.Get(ctx, name)
		if err == nil {
			// Certificate found
			if attempt > 0 {
				logger.Infof("Certificate found after %d retries: %s", attempt, name)
			}
			return data, nil
		}

		// Check if it's a cache miss (not found)
		if err == autocert.ErrCacheMiss {
			if attempt == 0 {
				logger.Debugf("Certificate not found, will retry in case leader is issuing it: %s", name)
			}

			// Wait before retrying
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(c.retryDelay):
				// Continue to next attempt
			}
			continue
		}

		// Other error (not cache miss)
		return nil, err
	}

	// Max retries exceeded, return cache miss
	logger.Debugf("Certificate still not found after %d retries: %s", c.maxRetries, name)
	return nil, autocert.ErrCacheMiss
}

// Put stores a certificate
func (c *FailoverAwareCache) Put(ctx context.Context, name string, data []byte) error {
	return c.underlying.Put(ctx, name, data)
}

// Delete removes a certificate
func (c *FailoverAwareCache) Delete(ctx context.Context, name string) error {
	return c.underlying.Delete(ctx, name)
}
