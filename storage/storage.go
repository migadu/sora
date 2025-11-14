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
	"os"
	"time"

	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type S3Storage struct {
	Client        *minio.Client
	BucketName    string
	Encrypt       bool
	EncryptionKey []byte
}

func New(endpoint, accessKeyID, secretAccessKey, bucketName string, useSSL bool, debug bool) (*S3Storage, error) {
	// Initialize the MinIO client
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKeyID, secretAccessKey, ""),
		Secure: useSSL, // Use SSL (https) if true
	})
	if err != nil {
		logger.Error("STORAGE: Failed to initialize MinIO client", "error", err)
		return nil, fmt.Errorf("failed to initialize MinIO client: %w", err)
	}

	// Enable detailed tracing of requests and responses for debugging
	if debug {
		client.TraceOn(os.Stdout)
	}

	// Return the initialized storage client
	return &S3Storage{
		Client:     client,
		BucketName: bucketName,
		Encrypt:    false,
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
	objInfo, err := s.Client.StatObject(context.Background(), s.BucketName, key, minio.StatObjectOptions{})
	if err == nil {
		return true, objInfo.VersionID, nil // Object exists
	}

	// Check if the error is a minio.ErrorResponse
	var minioErr minio.ErrorResponse
	if errors.As(err, &minioErr) {
		if minioErr.StatusCode == 404 {
			return false, "", nil // Object does not exist
		}
	}

	// Other error occurred
	return false, "", fmt.Errorf("failed to stat object %s: %w", key, err)
}

func (s *S3Storage) Put(key string, body io.Reader, size int64) error {
	start := time.Now()

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

		_, err = s.Client.PutObject(
			context.Background(),
			s.BucketName,
			key,
			bytes.NewReader(encryptedData),
			int64(len(encryptedData)),
			minio.PutObjectOptions{SendContentMd5: true},
		)
		if err != nil {
			metrics.StorageOperationErrors.WithLabelValues("PUT", classifyS3Error(err)).Inc()
			metrics.S3OperationsTotal.WithLabelValues("PUT", "error").Inc()
		} else {
			metrics.S3OperationsTotal.WithLabelValues("PUT", "success").Inc()
		}
		metrics.S3OperationDuration.WithLabelValues("PUT").Observe(time.Since(start).Seconds())
		return err
	}

	// No encryption, upload as-is
	_, err := s.Client.PutObject(
		context.Background(),
		s.BucketName,
		key,
		body,
		size,
		minio.PutObjectOptions{SendContentMd5: true},
	)
	if err != nil {
		metrics.StorageOperationErrors.WithLabelValues("PUT", classifyS3Error(err)).Inc()
		metrics.S3OperationsTotal.WithLabelValues("PUT", "error").Inc()
	} else {
		metrics.S3OperationsTotal.WithLabelValues("PUT", "success").Inc()
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

	object, err := s.Client.GetObject(context.Background(), s.BucketName, key, minio.GetObjectOptions{})
	if err != nil {
		metrics.S3OperationsTotal.WithLabelValues("GET", "error").Inc()
		metrics.S3OperationDuration.WithLabelValues("GET").Observe(time.Since(start).Seconds())
		return nil, err
	}

	// If encryption is enabled, decrypt the data after downloading
	if s.Encrypt {
		encryptedData, err := io.ReadAll(object)
		if err != nil {
			metrics.S3OperationsTotal.WithLabelValues("GET", "error").Inc()
			metrics.S3OperationDuration.WithLabelValues("GET").Observe(time.Since(start).Seconds())
			return nil, fmt.Errorf("failed to read encrypted data: %w", err)
		}

		// Close the original reader since we've read all the data
		if err := object.Close(); err != nil {
			logger.Warn("Storage: Failed to close S3 object", "error", err)
		}

		decryptedData, err := s.decryptData(encryptedData)
		if err != nil {
			metrics.S3OperationsTotal.WithLabelValues("GET", "error").Inc()
			metrics.S3OperationDuration.WithLabelValues("GET").Observe(time.Since(start).Seconds())
			return nil, fmt.Errorf("failed to decrypt data: %w", err)
		}

		metrics.S3OperationsTotal.WithLabelValues("GET", "success").Inc()
		metrics.S3OperationDuration.WithLabelValues("GET").Observe(time.Since(start).Seconds())
		return io.NopCloser(bytes.NewReader(decryptedData)), nil
	}

	metrics.S3OperationsTotal.WithLabelValues("GET", "success").Inc()
	metrics.S3OperationDuration.WithLabelValues("GET").Observe(time.Since(start).Seconds())
	return object, nil
}

func (s *S3Storage) Delete(key string) error {
	start := time.Now()

	// Check if the object exists before attempting to delete.
	// This makes DeleteMessage idempotent.
	exists, versionId, err := s.Exists(key)
	if err != nil {
		logger.Error("STORAGE: Error checking existence of object", "key", key, "error", err)
		metrics.S3OperationsTotal.WithLabelValues("DELETE", "error").Inc()
		metrics.S3OperationDuration.WithLabelValues("DELETE").Observe(time.Since(start).Seconds())
		return err
	}
	if !exists {
		// Object does not exist, consider it successfully "deleted"
		logger.Info("STORAGE: Object does not exist in S3 - skipping deletion", "key", key)
		metrics.S3OperationsTotal.WithLabelValues("DELETE", "skipped").Inc()
		metrics.S3OperationDuration.WithLabelValues("DELETE").Observe(time.Since(start).Seconds())
		return nil
	}
	err = s.Client.RemoveObject(context.Background(), s.BucketName, key, minio.RemoveObjectOptions{VersionID: versionId})
	if err != nil {
		metrics.S3OperationsTotal.WithLabelValues("DELETE", "error").Inc()
	} else {
		metrics.S3OperationsTotal.WithLabelValues("DELETE", "success").Inc()
	}
	metrics.S3OperationDuration.WithLabelValues("DELETE").Observe(time.Since(start).Seconds())
	return err
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
	src := minio.CopySrcOptions{
		Bucket: s.BucketName,
		Object: sourcePath,
	}
	dst := minio.CopyDestOptions{
		Bucket: s.BucketName,
		Object: destPath,
	}

	_, err := s.Client.CopyObject(context.Background(), dst, src)
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

		opts := minio.ListObjectsOptions{
			Prefix:    prefix,
			Recursive: recursive,
		}

		for object := range s.Client.ListObjects(ctx, s.BucketName, opts) {
			if object.Err != nil {
				errCh <- object.Err
				return
			}

			objectCh <- S3Object{
				Key:          object.Key,
				Size:         object.Size,
				LastModified: object.LastModified,
				ETag:         object.ETag,
			}
		}
	}()

	return objectCh, errCh
}
