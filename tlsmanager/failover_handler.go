package tlsmanager

import (
	"context"
	"sync"
	"time"

	"github.com/migadu/sora/logger"
	"golang.org/x/crypto/acme/autocert"
)

// FailoverAwareCache wraps a cluster-aware cache with automatic retry on leadership changes
// This ensures that if a non-leader node tries to get a certificate and it doesn't exist,
// it will wait for the leader to issue it and retry
type FailoverAwareCache struct {
	underlying   autocert.Cache
	retryDelay   time.Duration
	maxRetries   int
	issuingCerts sync.Map // Track which certificates are currently being issued (key = cert name)
}

// NewFailoverAwareCache creates a new failover-aware cache
func NewFailoverAwareCache(cache autocert.Cache) *FailoverAwareCache {
	return &FailoverAwareCache{
		underlying: cache,
		retryDelay: 1 * time.Second,
		maxRetries: 5, // 5 seconds total (1s * 5) - reduced from 30s
	}
}

// Get retrieves a certificate with automatic retry logic
// ONLY retries if we detect a certificate is actively being issued by the leader.
// For normal TLS handshakes with existing certs, returns immediately.
func (c *FailoverAwareCache) Get(ctx context.Context, name string) ([]byte, error) {
	logger.Debugf("[FailoverCache] Get certificate: %s", name)

	// First attempt - immediate check
	data, err := c.underlying.Get(ctx, name)
	if err == nil {
		logger.Debugf("[FailoverCache] Certificate found: %s", name)
		return data, nil
	}

	// Not a cache miss - propagate error immediately
	if err != autocert.ErrCacheMiss {
		logger.Debugf("[FailoverCache] Error getting certificate %s: %v", name, err)
		return nil, err
	}

	// Certificate doesn't exist (ErrCacheMiss)
	// Check if this certificate is currently being issued
	if _, isBeingIssued := c.issuingCerts.Load(name); !isBeingIssued {
		// Not being issued - this is a first request, return miss immediately
		// autocert will trigger certificate issuance
		logger.Infof("[FailoverCache] Certificate not found (will be issued): %s", name)
		return nil, autocert.ErrCacheMiss
	}

	// Certificate IS being issued by leader - retry a few times
	logger.Infof("[FailoverCache] Certificate being issued by leader, will retry: %s", name)
	for attempt := 1; attempt <= c.maxRetries; attempt++ {
		// Wait before retrying
		select {
		case <-ctx.Done():
			logger.Debugf("[FailoverCache] Context cancelled while waiting for certificate: %s", name)
			return nil, ctx.Err()
		case <-time.After(c.retryDelay):
			// Continue to next attempt
		}

		data, err := c.underlying.Get(ctx, name)
		if err == nil {
			logger.Infof("[FailoverCache] Certificate found after %d retries: %s", attempt, name)
			return data, nil
		}

		if err != autocert.ErrCacheMiss {
			logger.Debugf("[FailoverCache] Error on retry %d for %s: %v", attempt, name, err)
			return nil, err
		}

		logger.Debugf("[FailoverCache] Retry %d/%d: certificate still not ready: %s", attempt, c.maxRetries, name)
	}

	// Max retries exceeded
	logger.Warnf("[FailoverCache] Certificate not ready after %d retries: %s", c.maxRetries, name)
	return nil, autocert.ErrCacheMiss
}

// Put stores a certificate
func (c *FailoverAwareCache) Put(ctx context.Context, name string, data []byte) error {
	logger.Infof("[FailoverCache] Storing certificate: %s (%d bytes)", name, len(data))

	// Mark that we're issuing this certificate (for retry logic in other nodes)
	c.issuingCerts.Store(name, true)
	defer c.issuingCerts.Delete(name)

	err := c.underlying.Put(ctx, name, data)
	if err != nil {
		logger.Errorf("[FailoverCache] Failed to store certificate %s: %v", name, err)
		return err
	}

	logger.Infof("[FailoverCache] Certificate stored successfully: %s", name)
	return nil
}

// Delete removes a certificate
func (c *FailoverAwareCache) Delete(ctx context.Context, name string) error {
	logger.Infof("[FailoverCache] Deleting certificate: %s", name)

	err := c.underlying.Delete(ctx, name)
	if err != nil {
		logger.Errorf("[FailoverCache] Failed to delete certificate %s: %v", name, err)
		return err
	}

	logger.Infof("[FailoverCache] Certificate deleted successfully: %s", name)
	return nil
}
