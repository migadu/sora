// Package storage provides S3-compatible object storage for email message bodies.
//
// This package implements message body storage with features including:
//   - Client-side AES-256-GCM encryption
//   - Content deduplication using BLAKE3 hashes
//   - Circuit breaker for resilience
//   - Automatic retry with exponential backoff
//   - Health monitoring and metrics
//
// # Storage Architecture
//
// Message bodies are stored in S3 using content-addressable storage.
// Each message is identified by its BLAKE3 hash, enabling automatic
// deduplication when the same message is delivered to multiple recipients.
//
// # Encryption
//
// When encryption is enabled, messages are encrypted client-side using
// AES-256-GCM before upload. The encryption key is configured in config.toml
// and should be a 32-byte hex-encoded string.
//
// # Usage Example
//
//	// Initialize storage
//	s3, err := storage.New(
//		"s3.amazonaws.com",
//		"access-key",
//		"secret-key",
//		"my-bucket",
//		true,  // use TLS
//		false, // debug mode
//	)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Enable encryption (optional)
//	key, _ := hex.DecodeString("your-32-byte-hex-key")
//	s3.SetEncryptionKey(key)
//
//	// Store a message body
//	hash := "blake3-content-hash"
//	err = s3.PutObject(ctx, hash, messageBody)
//
//	// Retrieve a message body
//	body, err := s3.GetObject(ctx, hash)
//
// # Circuit Breaker
//
// The storage client includes a circuit breaker that prevents cascading
// failures when S3 becomes unavailable. The circuit opens after consecutive
// failures and enters a half-open state for testing recovery.
//
// # Health Monitoring
//
// Health status can be queried to determine if the storage backend is
// operational:
//
//	status := s3.HealthStatus()
//	if status.Status != "healthy" {
//		log.Printf("Storage unhealthy: %s", status.Message)
//	}
package storage

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
)

type S3Storage struct {
	Client        *s3.Client
	BucketName    string
	Encrypt       bool
	EncryptionKey []byte
	Timeout       time.Duration // Timeout for individual S3 operations
}

func New(endpoint, accessKeyID, secretAccessKey, bucketName string, useSSL bool, debug bool, timeout time.Duration) (*S3Storage, error) {
	// Build endpoint URL - accept either with or without protocol
	var endpointURL string
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		// Endpoint already includes protocol
		endpointURL = endpoint
	} else {
		// Add protocol based on useSSL flag
		if useSSL {
			endpointURL = "https://" + endpoint
		} else {
			endpointURL = "http://" + endpoint
		}
	}

	// Create AWS credentials
	creds := credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, "")

	// Create custom endpoint resolver
	customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		return aws.Endpoint{
			URL:               endpointURL,
			HostnameImmutable: true,
			Source:            aws.EndpointSourceCustom,
		}, nil
	})

	// Build AWS config
	cfg := aws.Config{
		Credentials:                 creds,
		Region:                      "us-east-1", // Default region, can be overridden
		EndpointResolverWithOptions: customResolver,
		RetryMaxAttempts:            1, // Disable SDK-level retries; the resilient layer (pkg/resilient) handles retries with circuit breaker and proper error classification
	}

	// Add debug logging if requested
	if debug {
		cfg.ClientLogMode = aws.LogRequest | aws.LogResponse | aws.LogRetries
	}

	// Create S3 client with path-style addressing for compatibility
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
	})

	// Default timeout if not provided
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	logger.Info("STORAGE: Initialized AWS S3 client", "endpoint", endpoint, "bucket", bucketName, "ssl", useSSL, "timeout", timeout)

	// Return the initialized storage client
	return &S3Storage{
		Client:     client,
		BucketName: bucketName,
		Encrypt:    false,
		Timeout:    timeout,
	}, nil
}

// EnableEncryption enables client-side encryption for S3 storage
func (s *S3Storage) EnableEncryption(encryptionKey string) error {
	if encryptionKey == "" {
		return fmt.Errorf("encryption key is required when encryption is enabled")
	}

	// Decode the hex-encoded encryption key
	masterKey, err := hex.DecodeString(encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to decode encryption key: %w", err)
	}

	// Check if the key is 32 bytes (256 bits)
	if len(masterKey) != 32 {
		return fmt.Errorf("encryption key must be 32 bytes (64 hex characters)")
	}

	s.Encrypt = true
	s.EncryptionKey = masterKey
	logger.Info("STORAGE: Client-side encryption enabled")

	return nil
}

// Exists checks if an object with the given key exists in the bucket.
func (s *S3Storage) Exists(key string) (bool, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()

	input := &s3.HeadObjectInput{
		Bucket: aws.String(s.BucketName),
		Key:    aws.String(key),
	}

	result, err := s.Client.HeadObject(ctx, input)
	if err == nil {
		versionID := ""
		if result.VersionId != nil {
			versionID = *result.VersionId
		}
		return true, versionID, nil // Object exists
	}

	// Check if the error is a 404 Not Found
	var responseError *awshttp.ResponseError
	if errors.As(err, &responseError) {
		if responseError.HTTPStatusCode() == http.StatusNotFound {
			return false, "", nil // Object does not exist
		}
	}

	// Other error occurred
	return false, "", fmt.Errorf("failed to stat object %s: %w", key, err)
}

func (s *S3Storage) Put(key string, body io.Reader, size int64) error {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()

	// If encryption is enabled, encrypt the data before uploading
	if s.Encrypt {
		data, err := io.ReadAll(body)
		if err != nil {
			metrics.StorageOperationErrors.WithLabelValues("PUT", "read_error").Inc()
			return fmt.Errorf("failed to read data for encryption: %w", err)
		}

		encryptedData, err := s.encryptData(data)
		if err != nil {
			metrics.StorageOperationErrors.WithLabelValues("PUT", "encryption_error").Inc()
			return fmt.Errorf("failed to encrypt data: %w", err)
		}

		input := &s3.PutObjectInput{
			Bucket: aws.String(s.BucketName),
			Key:    aws.String(key),
			Body:   bytes.NewReader(encryptedData),
		}

		_, err = s.Client.PutObject(ctx, input)
		if err != nil {
			metrics.StorageOperationErrors.WithLabelValues("PUT", classifyS3Error(err)).Inc()
		}
		// sora_s3_operations_total (the error-rate counter) is recorded once per
		// logical operation by the resilient layer (resilient.RecordS3Operation)
		// after retries settle, so it is intentionally not incremented per attempt
		// here. Duration stays per attempt as a true per-call latency sample.
		metrics.S3OperationDuration.WithLabelValues("PUT").Observe(time.Since(start).Seconds())
		return err
	}

	// No encryption, upload as-is
	input := &s3.PutObjectInput{
		Bucket: aws.String(s.BucketName),
		Key:    aws.String(key),
		Body:   body,
	}

	_, err := s.Client.PutObject(ctx, input)
	if err != nil {
		metrics.StorageOperationErrors.WithLabelValues("PUT", classifyS3Error(err)).Inc()
	}
	metrics.S3OperationDuration.WithLabelValues("PUT").Observe(time.Since(start).Seconds())
	return err
}

// encryptData encrypts data using AES-256-GCM
func (s *S3Storage) encryptData(plaintext []byte) ([]byte, error) {
	// Create a new AES cipher block using the key
	block, err := aes.NewCipher(s.EncryptionKey)
	if err != nil {
		return nil, err
	}

	// Create a new GCM cipher mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Create a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt the data
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decryptData decrypts data using AES-256-GCM
func (s *S3Storage) decryptData(ciphertext []byte) ([]byte, error) {
	// Create a new AES cipher block using the key
	block, err := aes.NewCipher(s.EncryptionKey)
	if err != nil {
		return nil, err
	}

	// Create a new GCM cipher mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Extract the nonce from the ciphertext
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]

	// Decrypt the data
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func (s *S3Storage) Get(key string) (io.ReadCloser, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)

	input := &s3.GetObjectInput{
		Bucket: aws.String(s.BucketName),
		Key:    aws.String(key),
	}

	// sora_s3_operations_total (the error-rate counter) is recorded once per
	// logical operation by the resilient layer (resilient.RecordS3Operation)
	// after retries settle, not per attempt here. Duration stays per attempt.
	result, err := s.Client.GetObject(ctx, input)
	if err != nil {
		cancel() // cancel immediately on error
		metrics.S3OperationDuration.WithLabelValues("GET").Observe(time.Since(start).Seconds())
		return nil, err
	}

	// If encryption is enabled, decrypt the data after downloading
	if s.Encrypt {
		// Encrypted path: read entire body within the timeout, then cancel
		encryptedData, err := io.ReadAll(result.Body)
		cancel() // done with the HTTP connection
		if err != nil {
			metrics.S3OperationDuration.WithLabelValues("GET").Observe(time.Since(start).Seconds())
			result.Body.Close()
			return nil, fmt.Errorf("failed to read encrypted data: %w", err)
		}

		logger.Debug("Storage: Read encrypted data from S3", "key", key, "encrypted_size", len(encryptedData))

		// Close the original reader since we've read all the data
		if err := result.Body.Close(); err != nil {
			logger.Warn("Storage: Failed to close S3 object", "error", err)
		}

		decryptedData, err := s.decryptData(encryptedData)
		if err != nil {
			metrics.S3OperationDuration.WithLabelValues("GET").Observe(time.Since(start).Seconds())
			logger.Error("Storage: Decryption failed", "key", key, "encrypted_size", len(encryptedData), "error", err)
			return nil, fmt.Errorf("failed to decrypt data: %w", err)
		}

		if len(decryptedData) == 0 {
			logger.Warn("Storage: Decryption returned empty data", "key", key, "encrypted_size", len(encryptedData))
			// Still return it, but log the warning so we know what happened
		} else {
			logger.Debug("Storage: Successfully decrypted data", "key", key, "decrypted_size", len(decryptedData))
		}

		metrics.S3OperationDuration.WithLabelValues("GET").Observe(time.Since(start).Seconds())
		return io.NopCloser(bytes.NewReader(decryptedData)), nil
	}

	// Non-encrypted path: body streams from the HTTP connection.
	// The timeout context must stay alive until the caller finishes reading,
	// so we wrap the body to cancel the context on Close().
	metrics.S3OperationDuration.WithLabelValues("GET").Observe(time.Since(start).Seconds())
	return &cancelOnCloseReader{ReadCloser: result.Body, cancel: cancel}, nil
}

// cancelOnCloseReader wraps an io.ReadCloser and calls a cancel function on Close.
// This keeps a context alive while the body is being streamed, ensuring the
// timeout applies to the full body read, not just the initial HTTP response.
type cancelOnCloseReader struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (r *cancelOnCloseReader) Close() error {
	err := r.ReadCloser.Close()
	r.cancel()
	return err
}

func (s *S3Storage) Delete(key string) error {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()

	input := &s3.DeleteObjectInput{
		Bucket: aws.String(s.BucketName),
		Key:    aws.String(key),
	}

	_, err := s.Client.DeleteObject(ctx, input)
	if err != nil {
		// S3: DeleteObject on non-existent keys returns 204 (success), so this
		// branch only fires on real errors. B2 returns 400 "InvalidRequest: File
		// not present" for non-existent keys — treat as success (idempotent delete).
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "InvalidRequest" {
			logger.Debug("STORAGE: Object does not exist in S3 - delete is no-op", "key", key)
			metrics.S3OperationDuration.WithLabelValues("DELETE").Observe(time.Since(start).Seconds())
			return nil
		}

		// Also handle 404 Not Found from other S3-compatible providers
		var httpErr *awshttp.ResponseError
		if errors.As(err, &httpErr) && httpErr.HTTPStatusCode() == http.StatusNotFound {
			logger.Debug("STORAGE: Object does not exist in S3 - delete is no-op", "key", key)
			metrics.S3OperationDuration.WithLabelValues("DELETE").Observe(time.Since(start).Seconds())
			return nil
		}

		metrics.S3OperationDuration.WithLabelValues("DELETE").Observe(time.Since(start).Seconds())
		return err
	}

	// sora_s3_operations_total (the error-rate counter) is recorded once per
	// logical operation by the resilient layer (resilient.RecordS3Operation)
	// after retries settle, not per attempt here.
	metrics.S3OperationDuration.WithLabelValues("DELETE").Observe(time.Since(start).Seconds())
	return nil
}

// DeleteBulk deletes multiple objects in a single S3 API call (up to 1000 objects)
// Returns a map of key -> error for any objects that failed to delete
// S3's DeleteObjects API is idempotent - deleting non-existent objects succeeds
func (s *S3Storage) DeleteBulk(keys []string) map[string]error {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()

	if len(keys) == 0 {
		return nil
	}

	if len(keys) > 1000 {
		logger.Warn("STORAGE: DeleteBulk called with more than 1000 keys, only first 1000 will be deleted", "count", len(keys))
		keys = keys[:1000]
	}

	// Build DeleteObjects input
	var objects []types.ObjectIdentifier
	for _, key := range keys {
		objects = append(objects, types.ObjectIdentifier{
			Key: aws.String(key),
		})
	}

	input := &s3.DeleteObjectsInput{
		Bucket: aws.String(s.BucketName),
		Delete: &types.Delete{
			Objects: objects,
			Quiet:   aws.Bool(true), // Only return errors, not successful deletes
		},
	}

	output, err := s.Client.DeleteObjects(ctx, input)

	metrics.S3OperationDuration.WithLabelValues("DELETE_BULK").Observe(time.Since(start).Seconds())

	if err != nil {
		// Entire operation failed
		logger.Error("STORAGE: Bulk delete failed", "count", len(keys), "error", err)
		metrics.S3OperationsTotal.WithLabelValues("DELETE_BULK", "error").Inc()

		// Return error for all keys
		errors := make(map[string]error)
		for _, key := range keys {
			errors[key] = err
		}
		return errors
	}

	// Check for partial failures
	errors := make(map[string]error)
	if len(output.Errors) > 0 {
		for _, deleteError := range output.Errors {
			key := aws.ToString(deleteError.Key)
			code := aws.ToString(deleteError.Code)
			message := aws.ToString(deleteError.Message)
			errors[key] = fmt.Errorf("S3 delete error: %s - %s", code, message)
			logger.Warn("STORAGE: Failed to delete object in bulk operation", "key", key, "code", code, "message", message)
		}
		metrics.S3OperationsTotal.WithLabelValues("DELETE_BULK", "partial").Inc()
	} else {
		metrics.S3OperationsTotal.WithLabelValues("DELETE_BULK", "success").Inc()
	}

	successCount := len(keys) - len(errors)
	logger.Info("STORAGE: Bulk delete completed", "total", len(keys), "success", successCount, "failed", len(errors))

	return errors
}

// classifyS3Error classifies S3 errors for metrics tracking
func classifyS3Error(err error) string {
	if err == nil {
		return "none"
	}

	errStr := err.Error()
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case contains(errStr, "AccessDenied") || contains(errStr, "Forbidden"):
		return "access_denied"
	case contains(errStr, "NoSuchKey") || contains(errStr, "NotFound"):
		return "not_found"
	case contains(errStr, "SlowDown") || contains(errStr, "RequestLimitExceeded"):
		return "throttled"
	case contains(errStr, "connection refused") || contains(errStr, "no such host"):
		return "network_error"
	default:
		return "unknown"
	}
}

func contains(s, substr string) bool {
	return bytes.Contains([]byte(s), []byte(substr))
}

func (s *S3Storage) Copy(sourcePath, destPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()

	// If encryption is enabled, we need to download, decrypt, and re-upload
	if s.Encrypt {
		// Get the source object
		sourceObj, err := s.Get(sourcePath)
		if err != nil {
			return fmt.Errorf("failed to get source object for copy: %w", err)
		}
		defer sourceObj.Close()

		// Read all data (it's already decrypted by Get if encryption is enabled)
		data, err := io.ReadAll(sourceObj)
		if err != nil {
			return fmt.Errorf("failed to read source object data: %w", err)
		}

		// Put the data to the destination (it will be encrypted by Put if encryption is enabled)
		err = s.Put(destPath, bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return fmt.Errorf("failed to put data to destination: %w", err)
		}

		return nil
	}

	// No encryption, use the standard copy operation
	copySource := fmt.Sprintf("%s/%s", s.BucketName, sourcePath)
	input := &s3.CopyObjectInput{
		Bucket:     aws.String(s.BucketName),
		CopySource: aws.String(copySource),
		Key:        aws.String(destPath),
	}

	_, err := s.Client.CopyObject(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to copy object from %s to %s: %w", sourcePath, destPath, err)
	}
	return nil
}

// S3Object represents an S3 object in list results
type S3Object struct {
	Key          string
	Size         int64
	LastModified time.Time
	ETag         string
}

// ListObjects lists objects in S3 with the given prefix
func (s *S3Storage) ListObjects(ctx context.Context, prefix string, recursive bool) (<-chan S3Object, <-chan error) {
	objectCh := make(chan S3Object)
	errCh := make(chan error, 1)

	go func() {
		defer close(objectCh)
		defer close(errCh)

		input := &s3.ListObjectsV2Input{
			Bucket: aws.String(s.BucketName),
			Prefix: aws.String(prefix),
		}

		if !recursive {
			input.Delimiter = aws.String("/")
		}

		paginator := s3.NewListObjectsV2Paginator(s.Client, input)

		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				errCh <- err
				return
			}

			for _, object := range page.Contents {
				objectCh <- S3Object{
					Key:          aws.ToString(object.Key),
					Size:         aws.ToInt64(object.Size),
					LastModified: aws.ToTime(object.LastModified),
					ETag:         strings.Trim(aws.ToString(object.ETag), "\""),
				}
			}
		}
	}()

	return objectCh, errCh
}
