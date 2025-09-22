package resilient

import (
	"context"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/migadu/sora/pkg/circuitbreaker"
	"github.com/migadu/sora/pkg/retry"
	"github.com/migadu/sora/storage"
	"github.com/minio/minio-go/v7"
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
		log.Printf("S3 GET circuit breaker '%s' changed from %s to %s", name, from, to)
	}

	putSettings := circuitbreaker.DefaultSettings("s3_put")
	putSettings.ReadyToTrip = func(counts circuitbreaker.Counts) bool {
		failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
		return counts.Requests >= 3 && failureRatio >= 0.5
	}
	putSettings.OnStateChange = func(name string, from circuitbreaker.State, to circuitbreaker.State) {
		log.Printf("S3 PUT circuit breaker '%s' changed from %s to %s", name, from, to)
	}

	deleteSettings := circuitbreaker.DefaultSettings("s3_delete")
	deleteSettings.ReadyToTrip = func(counts circuitbreaker.Counts) bool {
		failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
		return counts.Requests >= 3 && failureRatio >= 0.5
	}
	deleteSettings.OnStateChange = func(name string, from circuitbreaker.State, to circuitbreaker.State) {
		log.Printf("S3 DELETE circuit breaker '%s' changed from %s to %s", name, from, to)
	}

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
	if err == nil {
		return false
	}

	errStr := strings.ToLower(err.Error())

	retryableErrors := []string{
		"connection refused",
		"connection reset",
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
		"slowdown",
		"throttling",
		"rate limit",
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
	}

	var reader io.ReadCloser
	err := retry.WithRetry(ctx, func() error {
		result, cbErr := rs.getBreaker.Execute(func() (interface{}, error) {
			r, getErr := rs.storage.Get(key)
			return r, getErr
		})

		if cbErr != nil {
			if rs.isRetryableError(cbErr) {
				return cbErr
			}
			return fmt.Errorf("circuit breaker error: %w", cbErr)
		}

		reader = result.(io.ReadCloser)
		return nil
	}, config)

	return reader, err
}

func (rs *ResilientS3Storage) PutWithRetry(ctx context.Context, key string, body io.Reader, size int64) error {
	config := retry.BackoffConfig{
		InitialInterval: 1 * time.Second,
		MaxInterval:     30 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      3,
	}

	return retry.WithRetry(ctx, func() error {
		_, cbErr := rs.putBreaker.Execute(func() (interface{}, error) {
			putErr := rs.storage.Put(key, body, size)
			return nil, putErr
		})

		if cbErr != nil {
			if rs.isRetryableError(cbErr) {
				return cbErr
			}
			return fmt.Errorf("circuit breaker error: %w", cbErr)
		}

		return nil
	}, config)
}

func (rs *ResilientS3Storage) DeleteWithRetry(ctx context.Context, key string) error {
	config := retry.BackoffConfig{
		InitialInterval: 1 * time.Second,
		MaxInterval:     15 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      3,
	}

	return retry.WithRetry(ctx, func() error {
		_, cbErr := rs.deleteBreaker.Execute(func() (interface{}, error) {
			deleteErr := rs.storage.Delete(key)
			return nil, deleteErr
		})

		if cbErr != nil {
			if rs.isRetryableError(cbErr) {
				return cbErr
			}
			return fmt.Errorf("circuit breaker error: %w", cbErr)
		}

		return nil
	}, config)
}

func (rs *ResilientS3Storage) PutObjectWithRetry(ctx context.Context, key string, reader io.Reader, objectSize int64, opts minio.PutObjectOptions) (minio.UploadInfo, error) {
	config := retry.BackoffConfig{
		InitialInterval: 1 * time.Second,
		MaxInterval:     30 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      3,
	}

	var info minio.UploadInfo
	err := retry.WithRetry(ctx, func() error {
		result, cbErr := rs.putBreaker.Execute(func() (interface{}, error) {
			uploadInfo, putErr := rs.storage.Client.PutObject(ctx, rs.storage.BucketName, key, reader, objectSize, opts)
			return uploadInfo, putErr
		})

		if cbErr != nil {
			if rs.isRetryableError(cbErr) {
				return cbErr
			}
			return fmt.Errorf("circuit breaker error: %w", cbErr)
		}

		info = result.(minio.UploadInfo)
		return nil
	}, config)

	return info, err
}

func (rs *ResilientS3Storage) GetObjectWithRetry(ctx context.Context, key string, opts minio.GetObjectOptions) (*minio.Object, error) {
	config := retry.BackoffConfig{
		InitialInterval: 500 * time.Millisecond,
		MaxInterval:     10 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      4,
	}

	var object *minio.Object
	err := retry.WithRetry(ctx, func() error {
		result, cbErr := rs.getBreaker.Execute(func() (interface{}, error) {
			obj, getErr := rs.storage.Client.GetObject(ctx, rs.storage.BucketName, key, opts)
			return obj, getErr
		})

		if cbErr != nil {
			if rs.isRetryableError(cbErr) {
				return cbErr
			}
			return fmt.Errorf("circuit breaker error: %w", cbErr)
		}

		if result != nil {
			object = result.(*minio.Object)
		}
		return nil
	}, config)

	return object, err
}

func (rs *ResilientS3Storage) StatObjectWithRetry(ctx context.Context, key string, opts minio.StatObjectOptions) (minio.ObjectInfo, error) {
	config := retry.BackoffConfig{
		InitialInterval: 500 * time.Millisecond,
		MaxInterval:     5 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      3,
	}

	var info minio.ObjectInfo
	err := retry.WithRetry(ctx, func() error {
		result, cbErr := rs.getBreaker.Execute(func() (interface{}, error) {
			objInfo, statErr := rs.storage.Client.StatObject(ctx, rs.storage.BucketName, key, opts)
			return objInfo, statErr
		})

		if cbErr != nil {
			if rs.isRetryableError(cbErr) {
				return cbErr
			}
			return fmt.Errorf("circuit breaker error: %w", cbErr)
		}

		info = result.(minio.ObjectInfo)
		return nil
	}, config)

	return info, err
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
