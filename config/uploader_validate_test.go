package config

import (
	"strings"
	"testing"
)

// [uploader] concurrency, batch_size and max_attempts must be positive: 0 stops
// uploads (and the instance heartbeat), a negative concurrency panics in
// make(chan), a negative batch_size is rejected by PostgreSQL on every pass, and
// max_attempts <= 0 leases nothing and fails the cleaner's failed-upload pass (#288).
func TestUploaderConfigValidate(t *testing.T) {
	defaults := NewDefaultConfig().Uploader
	if err := defaults.Validate(); err != nil {
		t.Fatalf("default [uploader] config rejected: %v", err)
	}

	for _, key := range []string{"batch_size", "concurrency", "max_attempts"} {
		for _, v := range []int{0, -1} {
			c := NewDefaultConfig().Uploader
			switch key {
			case "batch_size":
				c.BatchSize = v
			case "concurrency":
				c.Concurrency = v
			case "max_attempts":
				c.MaxAttempts = v
			}
			err := c.Validate()
			if err == nil {
				t.Errorf("%s = %d accepted", key, v)
			} else if !strings.Contains(err.Error(), key) {
				t.Errorf("%s = %d: error %q does not name the key", key, v, err)
			}
		}
	}
}

// [uploader] cleanup_grace_period must be positive: with a negative value the orphan
// cleanup's cutoff lies in the future, so it removes staged bodies whose pending_uploads
// row is still in an uncommitted delivery transaction (#922). Empty means the 1h default.
func TestUploaderConfigValidateCleanupGracePeriod(t *testing.T) {
	for _, v := range []string{"", "1h", "30m", "2d"} {
		c := NewDefaultConfig().Uploader
		c.CleanupGracePeriod = v
		if err := c.Validate(); err != nil {
			t.Errorf("cleanup_grace_period = %q rejected: %v", v, err)
		}
	}
	// An unparseable value stops sora at start-up (it parses the key with
	// GetCleanupGracePeriod and exits), so config validate must refuse it too.
	for _, v := range []string{"0", "0s", "-1ns", "-1h", "-1d", "soon", "1x"} {
		c := NewDefaultConfig().Uploader
		c.CleanupGracePeriod = v
		err := c.Validate()
		if err == nil {
			t.Errorf("cleanup_grace_period = %q accepted", v)
		} else if !strings.Contains(err.Error(), "cleanup_grace_period") {
			t.Errorf("cleanup_grace_period = %q: error %q does not name the key", v, err)
		}
	}
}
