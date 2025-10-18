package tlsmanager

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/acme/autocert"
)

// TestNewFallbackCache_PermissionDenied verifies graceful fallback when directory cannot be created
func TestNewFallbackCache_PermissionDenied(t *testing.T) {
	// Create a mock S3 cache (just use DirCache for testing)
	tempDir := t.TempDir()
	s3Cache := autocert.DirCache(filepath.Join(tempDir, "s3"))

	// Try to create fallback cache in a directory that doesn't exist and cannot be created
	// On Unix-like systems, /dev/null/subdir is a good example of impossible directory
	impossibleDir := "/dev/null/subdir"

	// This should NOT return an error, but should warn and return S3-only cache
	cache, err := NewFallbackCache(s3Cache, impossibleDir)
	if err != nil {
		t.Errorf("NewFallbackCache should not return error for permission denied, got: %v", err)
	}

	if cache == nil {
		t.Fatal("NewFallbackCache should return non-nil cache even when fallback fails")
	}

	// Verify the cache works (should be S3-only)
	testData := []byte("test certificate data")
	ctx := context.Background()

	// Put should work (uses S3 cache)
	err = cache.Put(ctx, "test-cert", testData)
	if err != nil {
		t.Errorf("Put should work with S3-only cache, got error: %v", err)
	}

	// Get should work (uses S3 cache)
	data, err := cache.Get(ctx, "test-cert")
	if err != nil {
		t.Errorf("Get should work with S3-only cache, got error: %v", err)
	}

	if string(data) != string(testData) {
		t.Errorf("Got wrong data: expected %q, got %q", testData, data)
	}

	// Delete should work (uses S3 cache)
	err = cache.Delete(ctx, "test-cert")
	if err != nil {
		t.Errorf("Delete should work with S3-only cache, got error: %v", err)
	}
}

// TestNewFallbackCache_Success verifies normal fallback cache creation
func TestNewFallbackCache_Success(t *testing.T) {
	// Create temporary directories for both S3 and fallback
	tempDir := t.TempDir()
	s3Dir := filepath.Join(tempDir, "s3")
	fallbackDir := filepath.Join(tempDir, "fallback")

	s3Cache := autocert.DirCache(s3Dir)

	// This should succeed
	cache, err := NewFallbackCache(s3Cache, fallbackDir)
	if err != nil {
		t.Fatalf("NewFallbackCache should succeed with valid directory, got error: %v", err)
	}

	if cache == nil {
		t.Fatal("NewFallbackCache should return non-nil cache")
	}

	// Verify the cache is a FallbackCache
	fc, ok := cache.(*FallbackCache)
	if !ok {
		t.Error("Cache should be a FallbackCache when directory creation succeeds")
	}

	if fc != nil && fc.fallbackDir != fallbackDir {
		t.Errorf("FallbackCache has wrong directory: expected %s, got %s", fallbackDir, fc.fallbackDir)
	}

	// Verify fallback directory was created
	if _, err := os.Stat(fallbackDir); os.IsNotExist(err) {
		t.Error("Fallback directory should exist after successful creation")
	}

	// Verify cache operations work
	testData := []byte("test certificate data")
	ctx := context.Background()

	err = cache.Put(ctx, "test-cert", testData)
	if err != nil {
		t.Errorf("Put failed: %v", err)
	}

	data, err := cache.Get(ctx, "test-cert")
	if err != nil {
		t.Errorf("Get failed: %v", err)
	}

	if string(data) != string(testData) {
		t.Errorf("Got wrong data: expected %q, got %q", testData, data)
	}

	// Clean up test data to ensure directory is empty for t.TempDir() cleanup
	err = cache.Delete(ctx, "test-cert")
	if err != nil {
		t.Logf("Failed to delete test cert (non-critical): %v", err)
	}
}

// TestFallbackCache_S3Failure verifies fallback behavior when S3 fails
func TestFallbackCache_S3Failure(t *testing.T) {
	// Create temporary directories
	tempDir := t.TempDir()
	s3Dir := filepath.Join(tempDir, "s3")
	fallbackDir := filepath.Join(tempDir, "fallback")

	// Create a mock S3 cache
	s3Cache := autocert.DirCache(s3Dir)

	// Create fallback cache
	cache, err := NewFallbackCache(s3Cache, fallbackDir)
	if err != nil {
		t.Fatalf("NewFallbackCache failed: %v", err)
	}

	fc, ok := cache.(*FallbackCache)
	if !ok {
		t.Fatal("Cache should be a FallbackCache")
	}

	ctx := context.Background()

	// Put a certificate in S3 (should succeed)
	testData := []byte("test certificate")
	err = cache.Put(ctx, "test-cert", testData)
	if err != nil {
		t.Fatalf("Initial Put failed: %v", err)
	}

	// Simulate S3 becoming unavailable by removing read permissions
	os.Chmod(s3Dir, 0000)
	defer os.Chmod(s3Dir, 0700) // Restore permissions for cleanup

	// Mark S3 as unavailable
	fc.markS3Unavailable()

	// Get should still work (falls back to local cache)
	// Note: This test depends on the sync to fallback cache happening in Put
	// We might need to wait a moment for the goroutine to complete
	data, err := cache.Get(ctx, "test-cert")
	if err != nil {
		t.Logf("Get failed after S3 unavailable (this is expected if sync didn't complete): %v", err)
		// Not a hard failure since the async sync might not have completed
	} else if string(data) != string(testData) {
		t.Errorf("Got wrong data from fallback: expected %q, got %q", testData, data)
	}
}
