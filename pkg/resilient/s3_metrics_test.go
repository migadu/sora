package resilient

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/retry"
	"github.com/migadu/sora/storage"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRecordS3OperationClassification verifies that a logical S3 outcome maps to
// the right status label, and in particular that object-not-found and client
// cancellations are kept out of the "error" bucket so the error rate reflects
// only real S3 infrastructure failures.
func TestRecordS3OperationClassification(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus string
	}{
		{"success", nil, "success"},
		{"not_found_404", awsResponseError(http.StatusNotFound, "NoSuchKey"), "not_found"},
		{"canceled", context.Canceled, "canceled"},
		{"server_error_5xx", awsResponseError(http.StatusInternalServerError, "boom"), "error"},
		{"timeout", context.DeadlineExceeded, "error"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			metrics.S3OperationsTotal.Reset()
			RecordS3Operation("GET", tc.err)
			assert.Equal(t, float64(1),
				testutil.ToFloat64(metrics.S3OperationsTotal.WithLabelValues("GET", tc.wantStatus)),
				"expected one count under status %q", tc.wantStatus)
		})
	}
}

// TestExecuteS3OperationCountsOncePerLogicalOp is the core regression guard: an
// operation that fails transiently and is retried until it succeeds must record
// exactly one "success" and zero "error" — the retries must not inflate the count.
func TestExecuteS3OperationCountsOncePerLogicalOp(t *testing.T) {
	metrics.S3OperationsTotal.Reset()
	rs := NewResilientS3Storage(&storage.S3Storage{})

	var attempts int
	op := func() (any, error) {
		attempts++
		if attempts < 3 {
			// Transient 5xx — retryable.
			return nil, awsResponseError(http.StatusInternalServerError, "transient")
		}
		return io.NopCloser(strings.NewReader("ok")), nil
	}

	config := retry.BackoffConfig{
		InitialInterval: time.Millisecond,
		MaxInterval:     5 * time.Millisecond,
		Multiplier:      2.0,
		Jitter:          false,
		MaxRetries:      5,
		OperationName:   "s3_get_test",
	}

	res, err := rs.executeS3OperationWithRetry(
		context.Background(), rs.getBreaker, config, rs.isRetryableGetError, op, "key", "GET")
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, 3, attempts, "expected two failures then a success")

	assert.Equal(t, float64(1),
		testutil.ToFloat64(metrics.S3OperationsTotal.WithLabelValues("GET", "success")),
		"a retried-then-succeeded op must count as exactly one success")
	assert.Equal(t, float64(0),
		testutil.ToFloat64(metrics.S3OperationsTotal.WithLabelValues("GET", "error")),
		"failed attempts that were retried must not be counted as errors")
}

// TestExecuteS3OperationRecordsTerminalError verifies that an operation which
// exhausts retries records exactly one "error" outcome.
func TestExecuteS3OperationRecordsTerminalError(t *testing.T) {
	metrics.S3OperationsTotal.Reset()
	rs := NewResilientS3Storage(&storage.S3Storage{})

	op := func() (any, error) {
		return nil, awsResponseError(http.StatusInternalServerError, "always down")
	}

	config := retry.BackoffConfig{
		InitialInterval: time.Millisecond,
		MaxInterval:     5 * time.Millisecond,
		Multiplier:      2.0,
		Jitter:          false,
		MaxRetries:      2,
		OperationName:   "s3_get_test",
	}

	_, err := rs.executeS3OperationWithRetry(
		context.Background(), rs.getBreaker, config, rs.isRetryableGetError, op, "key", "GET")
	require.Error(t, err)

	assert.Equal(t, float64(1),
		testutil.ToFloat64(metrics.S3OperationsTotal.WithLabelValues("GET", "error")),
		"a permanently failing op must count as exactly one error")
	assert.Equal(t, float64(0),
		testutil.ToFloat64(metrics.S3OperationsTotal.WithLabelValues("GET", "success")))
}

// TestExecuteS3OperationCountsRetries: sora_s3_operations_total counts a retried
// operation once by design, so sora_storage_retries_total is where the attempts that
// failed and were tried again show up. Every attempt after the first is one retry; an
// operation that succeeds at once, or fails with an error that is not retried, has none.
func TestExecuteS3OperationCountsRetries(t *testing.T) {
	config := retry.BackoffConfig{
		InitialInterval: time.Millisecond,
		MaxInterval:     5 * time.Millisecond,
		Multiplier:      2.0,
		Jitter:          false,
		MaxRetries:      5,
		OperationName:   "s3_retry_count_test",
	}

	cases := []struct {
		name        string
		failures    int   // attempts that fail before one succeeds
		failWith    error // the failure
		wantRetries float64
	}{
		{"succeeds at once", 0, nil, 0},
		{"two transient failures", 2, awsResponseError(http.StatusInternalServerError, "transient"), 2},
		{"not retryable", 1, awsResponseError(http.StatusForbidden, "denied"), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			metrics.StorageRetries.Reset()
			rs := NewResilientS3Storage(&storage.S3Storage{})

			attempts := 0
			op := func() (any, error) {
				attempts++
				if attempts <= tc.failures {
					return nil, tc.failWith
				}
				return "ok", nil
			}
			_, _ = rs.executeS3OperationWithRetry(
				context.Background(), rs.getBreaker, config, rs.isRetryableGetError, op, "key", "GET")

			assert.Equal(t, tc.wantRetries,
				testutil.ToFloat64(metrics.StorageRetries.WithLabelValues("GET")),
				"sora_storage_retries_total{operation=\"GET\"} after %d attempts", attempts)
		})
	}
}
