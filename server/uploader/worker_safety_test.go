package uploader

import (
	"fmt"
	"testing"
)

func TestIsTransientS3Error(t *testing.T) {
	w := &UploadWorker{}

	transientErrors := []string{
		"connection refused",
		"connection reset by peer",
		"i/o timeout",
		"network unreachable",
		"service unavailable",
		"bad gateway",
		"gateway timeout",
		"circuit breaker is open",
		"rate limit exceeded",
		"request throttling",
		"SlowDown: Please reduce your request rate",
	}

	for _, errStr := range transientErrors {
		err := fmt.Errorf("%s", errStr)
		if !w.isTransientS3Error(err) {
			t.Errorf("Expected transient for %q, got permanent", errStr)
		}
	}

	permanentErrors := []string{
		"access denied",
		"no such key",
		"invalid argument",
		"bucket not found",
		"signature mismatch",
	}

	for _, errStr := range permanentErrors {
		err := fmt.Errorf("%s", errStr)
		if w.isTransientS3Error(err) {
			t.Errorf("Expected permanent for %q, got transient", errStr)
		}
	}

	// nil error
	if w.isTransientS3Error(nil) {
		t.Error("Expected false for nil error")
	}

	t.Log("✓ isTransientS3Error correctly classifies transient vs permanent S3 errors")
}
