// Package tlsmanager provides automatic TLS certificate management using Let's Encrypt
// with S3-backed certificate storage.
package tlsmanager

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"golang.org/x/crypto/acme/autocert"
)

// S3Cache implements autocert.Cache using S3 for certificate storage.
// This allows certificates to be shared across multiple instances of the application.
type S3Cache struct {
	client *minio.Client
	bucket string
	prefix string // Key prefix for certificate storage (default: "autocert/")
}

// NewS3Cache creates a new S3-backed autocert cache using MinIO client.
func NewS3Cache(cfg config.TLSLetsEncryptS3Config) (*S3Cache, error) {
	ctx := context.Background()

	// Determine endpoint - use config value or default to AWS
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "s3.amazonaws.com"
	}

	// Determine if TLS should be used
	useSSL := !cfg.DisableTLS

	// Configure credentials
	var creds *credentials.Credentials
	if cfg.AccessKeyID != "" && cfg.SecretAccessKey != "" {
		// Use static credentials
		creds = credentials.NewStaticV4(cfg.AccessKeyID, cfg.SecretAccessKey, "")
	} else {
		// Use IAM credentials chain (environment vars, EC2 IAM role, etc.)
		creds = credentials.NewIAM("")
	}

	// Initialize MinIO client
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  creds,
		Secure: useSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize MinIO client: %w", err)
	}

	// Enable debug logging if requested
	if cfg.Debug {
		client.TraceOn(os.Stdout)
	}

	cache := &S3Cache{
		client: client,
		bucket: cfg.Bucket,
		prefix: "autocert/",
	}

	// Verify bucket access
	if err := cache.verifyBucketAccess(ctx); err != nil {
		return nil, fmt.Errorf("failed to verify S3 bucket access: %w", err)
	}

	logger.Infof("S3 autocert cache initialized with bucket: %s (endpoint: %s, tls: %v, debug: %v)",
		cfg.Bucket, endpoint, useSSL, cfg.Debug)
	return cache, nil
}

// verifyBucketAccess checks if the S3 bucket exists and is accessible.
func (c *S3Cache) verifyBucketAccess(ctx context.Context) error {
	exists, err := c.client.BucketExists(ctx, c.bucket)
	if err != nil {
		return fmt.Errorf("failed to check bucket existence: %w", err)
	}
	if !exists {
		return fmt.Errorf("bucket %s does not exist", c.bucket)
	}
	return nil
}

// Get retrieves a certificate data from S3.
func (c *S3Cache) Get(ctx context.Context, key string) ([]byte, error) {
	s3Key := c.prefix + hashKey(key)

	logger.Debugf("[S3-Cache] Getting certificate for key: %s (S3 key: %s)", key, s3Key)

	// Get object from S3
	obj, err := c.client.GetObject(ctx, c.bucket, s3Key, minio.GetObjectOptions{})
	if err != nil {
		logger.Errorf("[S3-Cache] Failed to get object from S3: %v", err)
		return nil, autocert.ErrCacheMiss
	}
	defer obj.Close()

	// Check if object exists (404 means cache miss)
	if _, err := obj.Stat(); err != nil {
		// MinIO returns error on stat if object doesn't exist
		if minio.ToErrorResponse(err).StatusCode == 404 {
			logger.Debugf("[S3-Cache] Certificate not found in S3 (cache miss): %s", key)
			return nil, autocert.ErrCacheMiss
		}
		logger.Errorf("[S3-Cache] Failed to stat object: %v", err)
		return nil, fmt.Errorf("failed to stat object: %w", err)
	}

	// Read object data
	data, err := io.ReadAll(obj)
	if err != nil {
		logger.Errorf("[S3-Cache] Failed to read object data: %v", err)
		return nil, fmt.Errorf("failed to read object: %w", err)
	}

	logger.Debugf("[S3-Cache] Successfully retrieved certificate from S3: %s (%d bytes)", key, len(data))
	return data, nil
}

// Put stores certificate data in S3.
func (c *S3Cache) Put(ctx context.Context, key string, data []byte) error {
	s3Key := c.prefix + hashKey(key)

	logger.Debugf("[S3-Cache] Putting certificate for key: %s (S3 key: %s, %d bytes)", key, s3Key, len(data))

	// Upload to S3
	_, err := c.client.PutObject(
		ctx,
		c.bucket,
		s3Key,
		bytes.NewReader(data),
		int64(len(data)),
		minio.PutObjectOptions{
			ContentType: "application/octet-stream",
		},
	)
	if err != nil {
		logger.Errorf("[S3-Cache] Failed to upload certificate to S3: %v", err)
		return fmt.Errorf("failed to upload to S3: %w", err)
	}

	logger.Debugf("[S3-Cache] Successfully stored certificate in S3: %s", key)
	return nil
}

// Delete removes certificate data from S3.
func (c *S3Cache) Delete(ctx context.Context, key string) error {
	s3Key := c.prefix + hashKey(key)

	logger.Debugf("[S3-Cache] Deleting certificate for key: %s (S3 key: %s)", key, s3Key)

	// Delete from S3
	err := c.client.RemoveObject(ctx, c.bucket, s3Key, minio.RemoveObjectOptions{})
	if err != nil {
		// Check if object doesn't exist (which is fine for Delete)
		if minio.ToErrorResponse(err).StatusCode == 404 {
			logger.Debugf("[S3-Cache] Certificate already deleted or doesn't exist: %s", key)
			return nil
		}
		logger.Errorf("[S3-Cache] Failed to delete certificate from S3: %v", err)
		return fmt.Errorf("failed to delete from S3: %w", err)
	}

	logger.Debugf("[S3-Cache] Successfully deleted certificate from S3: %s", key)
	return nil
}

// hashKey creates a deterministic hash of the certificate key for S3 storage.
// This prevents issues with special characters in certificate domain names.
func hashKey(key string) string {
	// Normalize the key
	key = strings.ToLower(strings.TrimSpace(key))

	// Hash the key for safe S3 storage
	h := sha256.New()
	h.Write([]byte(key))
	hash := hex.EncodeToString(h.Sum(nil))

	// Return hash with a readable prefix for debugging
	return fmt.Sprintf("cert-%s", hash)
}
