package resilient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/circuitbreaker"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/retry"
	"github.com/migadu/sora/storage"
)

type ResilientS3Storage struct {
	storage       *storage.S3Storage
	getBreaker    *circuitbreaker.CircuitBreaker
	putBreaker    *circuitbreaker.CircuitBreaker
	deleteBreaker *circuitbreaker.CircuitBreaker
}

func NewResilientS3Storage(s3storage *storage.S3Storage) *ResilientS3Storage {
	getSettings := circuitbreaker.DefaultSettings("s3_get")
	getSettings.ReadyToTrip = func(counts circuitbreaker.Counts) bool {
		failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
		return counts.Requests >= 5 && failureRatio >= 0.6
	}
	getSettings.OnStateChange = func(name string, from circuitbreaker.State, to circuitbreaker.State) {
		logger.Info("S3 GET circuit breaker changed", "name", name, "from", from, "to", to)
	}

	// isSuccessfulFunc prevents non-system errors from tripping the circuit breaker.
	// Only actual S3 infrastructure failures (5xx, timeouts, connection errors) should
	// count as failures. Client disconnects and S3 client errors (4xx) are not S3 outages.
	isSuccessfulFunc := func(err error) bool {
		if err == nil {
			return true
		}

		// Client disconnected (not an S3 failure).
		// Note: context.DeadlineExceeded is NOT excluded — if S3 is consistently
		// timing out, that IS a system health issue and should trip the breaker.
		if errors.Is(err, context.Canceled) {
			return true
		}

		// Use proper AWS SDK error typing for S3 client errors (4xx).
		// These are data/config issues, not S3 infrastructure failures.
		var httpErr *awshttp.ResponseError
		if errors.As(err, &httpErr) {
			code := httpErr.HTTPStatusCode()
			// 4xx errors are client errors (not found, access denied, etc.)
			// 5xx errors are server errors — should trip the breaker
			if code >= 400 && code < 500 {
				return true
			}
		}

		// Otherwise, it's considered a system failure (connection errors, 5xx, etc.)
		return false
	}

	getSettings.IsSuccessful = isSuccessfulFunc

	putSettings := circuitbreaker.DefaultSettings("s3_put")
	putSettings.IsSuccessful = isSuccessfulFunc
	putSettings.ReadyToTrip = func(counts circuitbreaker.Counts) bool {
		failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
		return counts.Requests >= 3 && failureRatio >= 0.5
	}
	putSettings.OnStateChange = func(name string, from circuitbreaker.State, to circuitbreaker.State) {
		logger.Info("S3 PUT circuit breaker changed", "name", name, "from", from, "to", to)
	}

	deleteSettings := circuitbreaker.DefaultSettings("s3_delete")
	deleteSettings.ReadyToTrip = func(counts circuitbreaker.Counts) bool {
		failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
		return counts.Requests >= 3 && failureRatio >= 0.5
	}
	deleteSettings.OnStateChange = func(name string, from circuitbreaker.State, to circuitbreaker.State) {
		logger.Info("S3 DELETE circuit breaker changed", "name", name, "from", from, "to", to)
	}
	deleteSettings.IsSuccessful = isSuccessfulFunc

	return &ResilientS3Storage{
		storage:       s3storage,
		getBreaker:    circuitbreaker.NewCircuitBreaker(getSettings),
		putBreaker:    circuitbreaker.NewCircuitBreaker(putSettings),
		deleteBreaker: circuitbreaker.NewCircuitBreaker(deleteSettings),
	}
}

func (rs *ResilientS3Storage) GetStorage() *storage.S3Storage {
	return rs.storage
}

func (rs *ResilientS3Storage) isRetryableError(err error) bool {
	return rs.classifyRetryable(err, false)
}

// isRetryableGetError determines which errors are worth retrying for S3 GET
// operations.  HTTP 404 (NoSuchKey) is treated as a permanent error and is
// NOT retried — the object genuinely does not exist and retrying wastes time
// (up to 5 attempts with exponential backoff).  The circuit breaker's
// IsSuccessful function already excludes 4xx from tripping the breaker, so
// 404s during a real outage won't cause a cascade either.
func (rs *ResilientS3Storage) isRetryableGetError(err error) bool {
	return rs.classifyRetryable(err, false)
}

// IsNotFoundError reports whether err represents an S3 "object does not exist"
// condition (HTTP 404 / NoSuchKey), as opposed to a transient outage
// (network/timeout/5xx/circuit-open). Readers use it to distinguish permanent
// content loss from a retryable S3 unavailability: a missing object should degrade
// to an empty body, whereas a transient failure should ask the client to retry.
func IsNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	// Structured AWS SDK check first — most reliable.
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		// NoSuchBucket is a bucket configuration/system issue, not a missing object.
		if code == "NoSuchBucket" {
			return false
		}
		if code == "NoSuchKey" || code == "NotFound" {
			return true
		}
	}
	var httpErr *awshttp.ResponseError
	if errors.As(err, &httpErr) && httpErr.HTTPStatusCode() == 404 {
		return true
	}
	// Fallback to string matching for wrapped/flattened errors and S3-compatible
	// providers that don't surface a typed HTTP status.
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "nosuchkey") || strings.Contains(s, "notfound") {
		return true
	}
	if strings.Contains(s, "not found") {
		// Guard against false positives in network/DNS lookup or pgx errors
		if strings.Contains(s, "host not found") || strings.Contains(s, "address not found") || strings.Contains(s, "name not found") {
			return false
		}
		return true
	}
	return false
}

func (rs *ResilientS3Storage) classifyRetryable(err error, retry404 bool) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.EPIPE) || errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}

	// Check AWS SDK HTTP status codes — more reliable than string matching.
	var httpErr *awshttp.ResponseError
	if errors.As(err, &httpErr) {
		code := httpErr.HTTPStatusCode()
		// 5xx errors are always retryable (server-side issues).
		if code >= 500 {
			return true
		}
		// 429 Too Many Requests — back off and retry.
		if code == 429 {
			return true
		}
		// 404 during a GET is anomalous if the object is expected to exist.
		// Some providers (B2) return 404 during outages instead of 5xx.
		if retry404 && code == 404 {
			return true
		}
	}

	// Fallback to string matching for errors from external libraries
	// (network stack, DNS, TLS) that don't expose HTTP status codes.
	errStr := strings.ToLower(err.Error())

	retryableErrors := []string{
		"connection refused",
		"connection reset",
		"connection aborted",
		"connection timeout",
		"i/o timeout",
		"network unreachable",
		"no such host",
		"temporary failure",
		"service unavailable",
		"internal server error",
		"bad gateway",
		"gateway timeout",
		"timeout",
		"deadline exceeded",
		"canceled",
		"slowdown",
		"throttling",
		"rate limit",
		"closed network connection",
		"server closed idle connection",
		"eof",
		"broken pipe",
		"reset by peer",
	}

	for _, retryable := range retryableErrors {
		if strings.Contains(errStr, retryable) {
			return true
		}
	}

	return false
}

func (rs *ResilientS3Storage) GetWithRetry(ctx context.Context, key string) (io.ReadCloser, error) {
	config := retry.BackoffConfig{
		InitialInterval: 500 * time.Millisecond,
		MaxInterval:     10 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      4,
		OperationName:   "s3_get",
	}

	op := func() (any, error) {
		return rs.storage.Get(key)
	}
	result, err := rs.executeS3OperationWithRetry(ctx, rs.getBreaker, config, rs.isRetryableGetError, op, key, "GET")
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result.(io.ReadCloser), nil
}

func (rs *ResilientS3Storage) PutWithRetry(ctx context.Context, key string, body io.Reader, size int64) error {
	config := retry.BackoffConfig{
		InitialInterval: 1 * time.Second,
		MaxInterval:     30 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      3,
		OperationName:   "s3_put",
	}

	op := func() (any, error) {
		if seeker, ok := body.(io.Seeker); ok {
			if _, err := seeker.Seek(0, io.SeekStart); err != nil {
				return nil, fmt.Errorf("failed to rewind reader for S3 put retry: %w", err)
			}
		}
		return nil, rs.storage.Put(key, body, size)
	}
	_, err := rs.executeS3OperationWithRetry(ctx, rs.putBreaker, config, rs.isRetryableError, op, key, "PUT")
	return err
}

// IsHealthy returns true if S3 circuit breakers are not open (S3 is reachable).
// Used by the cleaner to skip destructive operations when S3 is down.
func (rs *ResilientS3Storage) IsHealthy() bool {
	return rs.putBreaker.State() != circuitbreaker.StateOpen &&
		rs.getBreaker.State() != circuitbreaker.StateOpen
}

func (rs *ResilientS3Storage) DeleteWithRetry(ctx context.Context, key string) error {
	config := retry.BackoffConfig{
		InitialInterval: 1 * time.Second,
		MaxInterval:     15 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      3,
		OperationName:   "s3_delete",
	}

	op := func() (any, error) {
		return nil, rs.storage.Delete(key)
	}
	_, err := rs.executeS3OperationWithRetry(ctx, rs.deleteBreaker, config, rs.isRetryableError, op, key, "DELETE")
	return err
}

func (rs *ResilientS3Storage) PutObjectWithRetry(ctx context.Context, key string, reader io.Reader, objectSize int64) (*s3.PutObjectOutput, error) {
	config := retry.BackoffConfig{
		InitialInterval: 1 * time.Second,
		MaxInterval:     30 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      3,
		OperationName:   "s3_put_object",
	}

	op := func() (any, error) {
		if seeker, ok := reader.(io.Seeker); ok {
			if _, err := seeker.Seek(0, io.SeekStart); err != nil {
				return nil, fmt.Errorf("failed to rewind reader for S3 put object retry: %w", err)
			}
		}
		input := &s3.PutObjectInput{
			Bucket: aws.String(rs.storage.BucketName),
			Key:    aws.String(key),
			Body:   reader,
		}
		return rs.storage.Client.PutObject(ctx, input)
	}
	result, err := rs.executeS3OperationWithRetry(ctx, rs.putBreaker, config, rs.isRetryableError, op, key, "PUT")
	if err != nil {
		return nil, err
	}
	output := result.(*s3.PutObjectOutput)
	return output, err
}

func (rs *ResilientS3Storage) GetObjectWithRetry(ctx context.Context, key string) (*s3.GetObjectOutput, error) {
	config := retry.BackoffConfig{
		InitialInterval: 500 * time.Millisecond,
		MaxInterval:     10 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      4,
		OperationName:   "s3_get_object",
	}

	op := func() (any, error) {
		input := &s3.GetObjectInput{
			Bucket: aws.String(rs.storage.BucketName),
			Key:    aws.String(key),
		}
		return rs.storage.Client.GetObject(ctx, input)
	}
	result, err := rs.executeS3OperationWithRetry(ctx, rs.getBreaker, config, rs.isRetryableGetError, op, key, "GET")
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	output := result.(*s3.GetObjectOutput)
	return output, err
}

// ExistsWithRetry returns true if an S3 object with the given key exists.
// A 404 response is treated as "does not exist" (returns false, nil).
// All other errors are returned as-is.
// This is used by the uploader to self-heal stuck uploads whose local file
// was deleted but whose content was already successfully stored in S3.
func (rs *ResilientS3Storage) ExistsWithRetry(ctx context.Context, key string) (bool, error) {
	_, err := rs.StatObjectWithRetry(ctx, key)
	if err != nil {
		// A 404 means the object simply isn't there — not an error condition.
		var httpErr *awshttp.ResponseError
		if errors.As(err, &httpErr) && httpErr.HTTPStatusCode() == 404 {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (rs *ResilientS3Storage) StatObjectWithRetry(ctx context.Context, key string) (*s3.HeadObjectOutput, error) {
	config := retry.BackoffConfig{
		InitialInterval: 500 * time.Millisecond,
		MaxInterval:     5 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      3,
		OperationName:   "s3_stat_object",
	}

	op := func() (any, error) {
		input := &s3.HeadObjectInput{
			Bucket: aws.String(rs.storage.BucketName),
			Key:    aws.String(key),
		}
		return rs.storage.Client.HeadObject(ctx, input)
	}
	result, err := rs.executeS3OperationWithRetry(ctx, rs.getBreaker, config, rs.isRetryableError, op, key, "STAT")
	if err != nil {
		return nil, err
	}
	output := result.(*s3.HeadObjectOutput)
	return output, err
}

// executeS3OperationWithRetry provides a generic wrapper for executing an S3 operation
// with retries and a circuit breaker.  The isRetryable function determines which errors
// are worth retrying.  Only transient errors (5xx, timeouts, connection issues) are
// retried; client errors like 404 NoSuchKey fail immediately.
func (rs *ResilientS3Storage) executeS3OperationWithRetry(ctx context.Context, breaker *circuitbreaker.CircuitBreaker, config retry.BackoffConfig, isRetryable func(error) bool, op func() (any, error), key string, operation string) (any, error) {
	var result any
	err := retry.WithRetryAdvanced(ctx, func() error {
		res, cbErr := breaker.Execute(op)
		if cbErr != nil {
			retryable := isRetryable(cbErr)
			// A 404/NoSuchKey is a benign, expected outcome for a GET (the caller decides
			// whether a missing object matters — e.g. it is normal during the not-yet-uploaded
			// fetch race) and never trips the breaker, so log it at Debug to avoid noise. Real
			// failures (transient outages, breaker trips) stay at Warn to remain diagnosable.
			if IsNotFoundError(cbErr) {
				logger.Debug("S3 object not found",
					"breaker", breaker.Name(),
					"key", key,
					"error", cbErr)
			} else {
				logger.Warn("S3 operation failed",
					"breaker", breaker.Name(),
					"key", key,
					"error", cbErr,
					"breaker_state", breaker.State(),
					"retryable", retryable)
			}

			if retryable {
				return cbErr // Signal to retry
			}
			// Use retry.Stop for non-retryable errors (e.g. circuit breaker open)
			// to stop the loop immediately. WithRetryAdvanced respects StopError.
			return retry.Stop(cbErr)
		}
		result = res
		return nil
	}, config)
	// Record exactly one outcome per logical operation, after all retries have
	// settled. err is the final result of the (possibly retried) call, so a
	// transient failure that eventually succeeds is counted as a single success
	// rather than several errors plus a success.
	RecordS3Operation(operation, err)
	return result, err
}

// RecordS3Operation records exactly one outcome for the sora_s3_operations_total
// error-rate metric per *logical* S3 operation. Callers invoke it once, after any
// retries have settled — never per attempt — so the error rate is not inflated by
// transient failures that ultimately succeed.
//
// Status mirrors the circuit breaker's notion of a genuine S3 failure: an object
// that does not exist (404 / NoSuchKey) and a client cancellation are recorded
// under their own statuses and excluded from "error", so the rate reflects only
// real infrastructure failures (timeouts, 5xx, throttling, network). Direct
// (non-retrying) callers such as the User API call this once per operation too.
func RecordS3Operation(operation string, err error) {
	var status string
	switch {
	case err == nil:
		status = "success"
	case IsNotFoundError(err):
		status = "not_found"
	case errors.Is(err, context.Canceled):
		status = "canceled"
	default:
		status = "error"
	}
	metrics.S3OperationsTotal.WithLabelValues(operation, status).Inc()
}

func (rs *ResilientS3Storage) GetGetBreakerState() circuitbreaker.State {
	return rs.getBreaker.State()
}

func (rs *ResilientS3Storage) GetPutBreakerState() circuitbreaker.State {
	return rs.putBreaker.State()
}

func (rs *ResilientS3Storage) GetDeleteBreakerState() circuitbreaker.State {
	return rs.deleteBreaker.State()
}
