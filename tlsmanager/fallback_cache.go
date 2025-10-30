package tlsmanager

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/migadu/sora/logger"
	"golang.org/x/crypto/acme/autocert"
)

// FallbackCache wraps an S3 cache with a local filesystem fallback.
// If S3 operations fail, it falls back to a local directory cache.
// This provides resilience against S3 outages or connectivity issues.
type FallbackCache struct {
	primary       autocert.Cache // S3 cache
	fallback      autocert.Cache // Local directory cache
	fallbackDir   string
	s3Available   bool
	lastS3Check   time.Time
	checkInterval time.Duration // How often to retry S3 after failure
	mu            sync.RWMutex
}

// NewFallbackCache creates a cache that uses S3 as primary storage
// with a local filesystem fallback for resilience.
// If the fallback directory cannot be created, returns S3-only cache with a warning.
func NewFallbackCache(s3Cache autocert.Cache, fallbackDir string) (autocert.Cache, error) {
	// Try to ensure fallback directory exists
	if err := os.MkdirAll(fallbackDir, 0700); err != nil {
		logger.Warn("Cannot create fallback directory - fallback cache disabled, using S3-only", "dir", fallbackDir, "error", err)
		logger.Warn("Certificates will only be stored in S3. If S3 becomes unavailable, certificate operations will fail.")
		// Return S3-only cache instead of failing
		return s3Cache, nil
	}

	// Create local directory cache as fallback
	fallbackCache := autocert.DirCache(fallbackDir)

	fc := &FallbackCache{
		primary:       s3Cache,
		fallback:      fallbackCache,
		fallbackDir:   fallbackDir,
		s3Available:   true, // Assume S3 is available initially
		checkInterval: 30 * time.Second,
	}

	logger.Info("Fallback cache initialized", "dir", fallbackDir)
	return fc, nil
}

// isS3Available checks if S3 should be tried based on recent failures
func (fc *FallbackCache) isS3Available() bool {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	// If S3 is marked unavailable, check if enough time has passed to retry
	if !fc.s3Available {
		if time.Since(fc.lastS3Check) < fc.checkInterval {
			return false
		}
	}
	return true
}

// markS3Unavailable marks S3 as unavailable and records the time
func (fc *FallbackCache) markS3Unavailable() {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	if fc.s3Available {
		logger.Warn("S3 certificate cache unavailable - falling back to local filesystem", "dir", fc.fallbackDir)
	}
	fc.s3Available = false
	fc.lastS3Check = time.Now()
}

// markS3Available marks S3 as available again
func (fc *FallbackCache) markS3Available() {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	if !fc.s3Available {
		logger.Info("S3 certificate cache restored - resuming S3 operations")
	}
	fc.s3Available = true
}

// Get retrieves a certificate, trying local cache first (fast), then S3 (slow)
// This ensures TLS handshakes are fast when certificates are already cached locally.
func (fc *FallbackCache) Get(ctx context.Context, name string) ([]byte, error) {
	logger.Debug("FallbackCache: Get certificate (checking local cache first)", "name", name)

	// STEP 1: Try local cache first (FAST - no network call)
	data, err := fc.fallback.Get(ctx, name)
	if err == nil {
		logger.Debug("FallbackCache: Certificate found in local cache", "name", name)
		return data, nil
	}

	// Not in local cache or error reading
	if err != autocert.ErrCacheMiss {
		logger.Warn("FallbackCache: Error reading local cache (will try S3)", "name", name, "error", err)
	} else {
		logger.Debug("FallbackCache: Certificate not in local cache (checking S3)", "name", name)
	}

	// STEP 2: Try S3 (SLOW - network call)
	if fc.isS3Available() {
		logger.Debug("FallbackCache: Fetching certificate from S3", "name", name)
		data, err := fc.primary.Get(ctx, name)
		if err == nil {
			logger.Info("FallbackCache: Certificate found in S3 - syncing to local cache", "name", name)
			fc.markS3Available()
			// Store in local cache for future fast access
			go func() {
				if putErr := fc.fallback.Put(context.Background(), name, data); putErr != nil {
					logger.Warn("FallbackCache: Failed to sync certificate to local cache", "error", putErr)
				} else {
					logger.Debug("FallbackCache: Certificate synced to local cache", "name", name)
				}
			}()
			return data, nil
		}

		// If it's just a cache miss, don't mark S3 as unavailable
		if err == autocert.ErrCacheMiss {
			logger.Debug("FallbackCache: Certificate not found in S3 (cache miss)", "name", name)
			return nil, autocert.ErrCacheMiss
		}

		// S3 error - mark as unavailable
		logger.Warn("FallbackCache: S3 Get failed (S3 unavailable)", "name", name, "error", err)
		fc.markS3Unavailable()
		return nil, err
	}

	// S3 not available and not in local cache
	logger.Debug("FallbackCache: Certificate not found (S3 unavailable, not in local cache)", "name", name)
	return nil, autocert.ErrCacheMiss
}

// Put stores a certificate, trying S3 first, then falling back to local cache
func (fc *FallbackCache) Put(ctx context.Context, name string, data []byte) error {
	var s3Err error

	// Try S3 first if available
	if fc.isS3Available() {
		s3Err = fc.primary.Put(ctx, name, data)
		if s3Err == nil {
			fc.markS3Available()
			// Also store in fallback cache for future resilience
			if fallbackErr := fc.fallback.Put(ctx, name, data); fallbackErr != nil {
				logger.Warn("Failed to sync certificate to fallback cache", "error", fallbackErr)
			}
			return nil
		}

		// S3 error - mark as unavailable
		logger.Warn("S3 Put failed - using fallback cache", "name", name, "error", s3Err)
		fc.markS3Unavailable()
	}

	// Use fallback cache
	logger.Info("Storing certificate in fallback cache", "name", name)
	if err := fc.fallback.Put(ctx, name, data); err != nil {
		// Both failed - return the original S3 error if we have one
		if s3Err != nil {
			return fmt.Errorf("both S3 and fallback cache failed - S3 error: %w, fallback error: %v", s3Err, err)
		}
		return err
	}

	// Schedule S3 sync for later (best effort)
	go fc.syncToS3(name, data)

	return nil
}

// syncToS3 attempts to sync a certificate from fallback cache to S3 in the background
func (fc *FallbackCache) syncToS3(name string, data []byte) {
	// Wait a bit before retrying S3
	time.Sleep(fc.checkInterval)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := fc.primary.Put(ctx, name, data); err != nil {
		logger.Debug("Background S3 sync failed (will retry on next operation)", "name", name, "error", err)
	} else {
		logger.Info("Certificate synced from fallback cache to S3", "name", name)
		fc.markS3Available()
	}
}

// Delete removes a certificate from both S3 and fallback cache
func (fc *FallbackCache) Delete(ctx context.Context, name string) error {
	var s3Err error

	// Try S3 first if available
	if fc.isS3Available() {
		s3Err = fc.primary.Delete(ctx, name)
		if s3Err == nil {
			fc.markS3Available()
		} else {
			logger.Warn("S3 Delete failed", "name", name, "error", s3Err)
			fc.markS3Unavailable()
		}
	}

	// Also delete from fallback cache
	fallbackErr := fc.fallback.Delete(ctx, name)

	// Return error only if both failed
	if s3Err != nil && fallbackErr != nil {
		return fmt.Errorf("both S3 and fallback cache delete failed - S3 error: %w, fallback error: %v", s3Err, fallbackErr)
	}

	return nil
}

// GetFallbackDir returns the local fallback directory path
func (fc *FallbackCache) GetFallbackDir() string {
	return fc.fallbackDir
}

// SyncAllToS3 attempts to sync all certificates from fallback cache to S3.
// This can be called after S3 becomes available again to ensure consistency.
func (fc *FallbackCache) SyncAllToS3(ctx context.Context) error {
	// List all files in fallback directory
	entries, err := os.ReadDir(fc.fallbackDir)
	if err != nil {
		return fmt.Errorf("failed to read fallback directory: %w", err)
	}

	synced := 0
	failed := 0

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		path := filepath.Join(fc.fallbackDir, name)

		// Read from fallback
		data, err := os.ReadFile(path)
		if err != nil {
			logger.Warn("Failed to read fallback certificate", "name", name, "error", err)
			failed++
			continue
		}

		// Write to S3
		if err := fc.primary.Put(ctx, name, data); err != nil {
			logger.Warn("Failed to sync certificate to S3", "name", name, "error", err)
			failed++
			continue
		}

		synced++
		logger.Debug("Synced certificate to S3", "name", name)
	}

	if synced > 0 {
		logger.Info("Synced certificates from fallback cache to S3", "synced", synced, "failed", failed)
	}

	if failed > 0 {
		return fmt.Errorf("failed to sync %d certificates to S3", failed)
	}

	return nil
}
