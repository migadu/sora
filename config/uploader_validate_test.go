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
