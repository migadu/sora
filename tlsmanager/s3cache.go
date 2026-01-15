// Package tlsmanager provides automatic TLS certificate management using Let's Encrypt
// with S3-backed certificate storage.
package tlsmanager

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
	"golang.org/x/crypto/acme/autocert"
)

// S3Cache implements autocert.Cache using S3 for certificate storage.
// This allows certificates to be shared across multiple instances of the application.
type S3Cache struct {
	client *s3.Client
	bucket string
	prefix string // Key prefix for certificate storage (default: "autocert/")
}

// NewS3Cache creates a new S3-backed autocert cache using AWS SDK.
func NewS3Cache(cfg config.TLSLetsEncryptS3Config) (*S3Cache, error) {
	ctx := context.Background()

	// Determine endpoint - use config value or default to AWS
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "s3.amazonaws.com"
	}

	// Determine if TLS should be used
	useSSL := !cfg.DisableTLS

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

	// Configure credentials
	var creds aws.CredentialsProvider
	if cfg.AccessKey != "" && cfg.SecretKey != "" {
		// Use static credentials
		creds = credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, "")
	} else {
		// Use default credentials chain (environment vars, EC2 IAM role, etc.)
		// This will be handled by the SDK automatically
		creds = nil
	}

	// Create custom endpoint resolver
	customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		return aws.Endpoint{
			URL:               endpointURL,
			HostnameImmutable: true,
			Source:            aws.EndpointSourceCustom,
		}, nil
	})

	// Build AWS config
	awsCfg := aws.Config{
		Region:                      "us-east-1", // Default region
		EndpointResolverWithOptions: customResolver,
	}

	if creds != nil {
		awsCfg.Credentials = creds
	}

	// Add debug logging if requested
	if cfg.Debug {
		awsCfg.ClientLogMode = aws.LogRequest | aws.LogResponse | aws.LogRetries
	}

	// Create S3 client with path-style addressing for compatibility
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.UsePathStyle = true
	})

	cache := &S3Cache{
		client: client,
		bucket: cfg.Bucket,
		prefix: "autocert/",
	}

	// Verify bucket access
	if err := cache.verifyBucketAccess(ctx); err != nil {
		return nil, fmt.Errorf("failed to verify S3 bucket access: %w", err)
	}

	logger.Info("S3 autocert cache initialized", "bucket", cfg.Bucket,
		"endpoint", endpoint, "tls", useSSL, "debug", cfg.Debug)
	return cache, nil
}

// verifyBucketAccess checks if the S3 bucket exists and is accessible.
func (c *S3Cache) verifyBucketAccess(ctx context.Context) error {
	input := &s3.HeadBucketInput{
		Bucket: aws.String(c.bucket),
	}
	_, err := c.client.HeadBucket(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to check bucket existence: %w", err)
	}
	return nil
}

// Get retrieves a certificate data from S3.
func (c *S3Cache) Get(ctx context.Context, key string) ([]byte, error) {
	s3Key := c.prefix + hashKey(key)

	logger.Debug("S3-Cache: Getting certificate", "key", key, "s3_key", s3Key)

	input := &s3.GetObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(s3Key),
	}

	// Get object from S3
	result, err := c.client.GetObject(ctx, input)
	if err != nil {
		// Check if the error is a 404 Not Found
		var responseError *awshttp.ResponseError
		if errors.As(err, &responseError) {
			if responseError.HTTPStatusCode() == http.StatusNotFound {
				logger.Debug("S3-Cache: Certificate not found (cache miss)", "key", key)
				return nil, autocert.ErrCacheMiss
			}
		}
		logger.Error("S3-Cache: Failed to get object from S3", "error", err)
		return nil, autocert.ErrCacheMiss
	}
	defer result.Body.Close()

	// Read object data
	data, err := io.ReadAll(result.Body)
	if err != nil {
		logger.Error("S3-Cache: Failed to read object data", "error", err)
		return nil, fmt.Errorf("failed to read object: %w", err)
	}

	logger.Debug("S3-Cache: Successfully retrieved certificate", "key", key, "bytes", len(data))
	return data, nil
}

// Put stores certificate data in S3.
func (c *S3Cache) Put(ctx context.Context, key string, data []byte) error {
	s3Key := c.prefix + hashKey(key)

	logger.Debug("S3-Cache: Putting certificate", "key", key, "s3_key", s3Key, "bytes", len(data))

	contentType := "application/octet-stream"
	input := &s3.PutObjectInput{
		Bucket:      aws.String(c.bucket),
		Key:         aws.String(s3Key),
		Body:        bytes.NewReader(data),
		ContentType: &contentType,
	}

	// Upload to S3
	_, err := c.client.PutObject(ctx, input)
	if err != nil {
		logger.Error("S3-Cache: Failed to upload certificate to S3", "error", err)
		return fmt.Errorf("failed to upload to S3: %w", err)
	}

	logger.Debug("S3-Cache: Successfully stored certificate", "key", key)
	return nil
}

// Delete removes certificate data from S3.
func (c *S3Cache) Delete(ctx context.Context, key string) error {
	s3Key := c.prefix + hashKey(key)

	logger.Debug("S3-Cache: Deleting certificate", "key", key, "s3_key", s3Key)

	input := &s3.DeleteObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(s3Key),
	}

	// Delete from S3
	_, err := c.client.DeleteObject(ctx, input)
	if err != nil {
		// Check if object doesn't exist (which is fine for Delete)
		var responseError *awshttp.ResponseError
		if errors.As(err, &responseError) {
			if responseError.HTTPStatusCode() == http.StatusNotFound {
				logger.Debug("S3-Cache: Certificate already deleted or doesn't exist", "key", key)
				return nil
			}
		}
		logger.Error("S3-Cache: Failed to delete certificate from S3", "error", err)
		return fmt.Errorf("failed to delete from S3: %w", err)
	}

	logger.Debug("S3-Cache: Successfully deleted certificate", "key", key)
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
