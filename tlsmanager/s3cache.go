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
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
	"golang.org/x/crypto/acme/autocert"
)

// s3OperationTimeout bounds a single S3 request. The TLS handshake path reaches S3
// through this cache and autocert allows it five minutes, so without a bound here a
// stalled endpoint parks every handshake goroutine on every listener.
const s3OperationTimeout = 5 * time.Second

// S3Cache implements autocert.Cache using S3 for certificate storage.
// This allows certificates to be shared across multiple instances of the application.
type S3Cache struct {
	client *s3.Client
	bucket string
	prefix string // Key prefix for certificate storage (default: "autocert/")
	// sseAlgorithm is the server-side encryption asked of the store on every write.
	// Empty sends no header.
	sseAlgorithm types.ServerSideEncryption
	sseKMSKeyID  string
}

// defaultSSEAlgorithm is what the cache asks for when the deployment says nothing.
// Every value it stores is private key material - the certificate PEM bundles end
// with the certificate key, and "acme_account+key" is the ACME account key - so the
// write must not leave protection at rest to a bucket default nobody enforces.
const defaultSSEAlgorithm = types.ServerSideEncryptionAes256

// S3CacheOption adjusts how the cache stores certificates.
type S3CacheOption func(*S3Cache)

// WithServerSideEncryption selects the server-side encryption the cache asks for.
// algorithm "AES256" is the store's own key management, "aws:kms" requires kmsKeyID,
// and "" sends no encryption header at all - needed for S3-compatible stores that
// reject one, at the price of storing private keys as the bucket leaves them.
func WithServerSideEncryption(algorithm, kmsKeyID string) S3CacheOption {
	return func(c *S3Cache) {
		c.sseAlgorithm = types.ServerSideEncryption(algorithm)
		c.sseKMSKeyID = kmsKeyID
	}
}

// encryptionOptions turns the configured encryption settings into cache options.
// A configuration that says nothing about encryption keeps defaultSSEAlgorithm; a
// stray KMS key id with no algorithm is passed through rather than dropped, so
// validateEncryption can reject it instead of the deployment believing it applies.
func encryptionOptions(cfg config.TLSLetsEncryptS3Config) []S3CacheOption {
	if cfg.ServerSideEncryption == nil && cfg.ServerSideEncryptionKMSKeyID == "" {
		return nil
	}
	algorithm := string(defaultSSEAlgorithm)
	if cfg.ServerSideEncryption != nil {
		algorithm = *cfg.ServerSideEncryption
	}
	return []S3CacheOption{WithServerSideEncryption(algorithm, cfg.ServerSideEncryptionKMSKeyID)}
}

// validateEncryption rejects settings that would not mean what they say, rather than
// writing private keys under them.
func (c *S3Cache) validateEncryption() error {
	switch c.sseAlgorithm {
	case "":
		// No header: the store's own default applies.
	case types.ServerSideEncryptionAes256, types.ServerSideEncryptionAwsKms:
	default:
		return fmt.Errorf("unsupported server-side encryption %q: use %q, %q or an empty value",
			c.sseAlgorithm, types.ServerSideEncryptionAes256, types.ServerSideEncryptionAwsKms)
	}
	if c.sseAlgorithm == types.ServerSideEncryptionAwsKms && c.sseKMSKeyID == "" {
		return fmt.Errorf("server-side encryption %q requires a KMS key id", c.sseAlgorithm)
	}
	if c.sseAlgorithm != types.ServerSideEncryptionAwsKms && c.sseKMSKeyID != "" {
		return fmt.Errorf("a KMS key id is only used by server-side encryption %q, not %q",
			types.ServerSideEncryptionAwsKms, c.sseAlgorithm)
	}
	return nil
}

// NewS3Cache creates a new S3-backed autocert cache using AWS SDK.
func NewS3Cache(cfg config.TLSLetsEncryptS3Config, opts ...S3CacheOption) (*S3Cache, error) {
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
		client:       client,
		bucket:       cfg.Bucket,
		prefix:       "autocert/",
		sseAlgorithm: defaultSSEAlgorithm,
	}
	for _, opt := range opts {
		opt(cache)
	}
	if err := cache.validateEncryption(); err != nil {
		return nil, err
	}

	// Verify bucket access
	if err := cache.verifyBucketAccess(ctx); err != nil {
		return nil, fmt.Errorf("failed to verify S3 bucket access: %w", err)
	}

	logger.Info("S3 autocert cache initialized", "bucket", cfg.Bucket,
		"endpoint", endpoint, "tls", useSSL, "debug", cfg.Debug,
		"server_side_encryption", cache.sseAlgorithm)
	return cache, nil
}

// verifyBucketAccess checks if the S3 bucket exists and is accessible.
func (c *S3Cache) verifyBucketAccess(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, s3OperationTimeout)
	defer cancel()

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

	ctx, cancel := context.WithTimeout(ctx, s3OperationTimeout)
	defer cancel()

	input := &s3.GetObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(s3Key),
	}

	// Get object from S3
	result, err := c.client.GetObject(ctx, input)
	if err != nil {
		// Only a 404 means the certificate is absent. Any other failure must surface as an
		// error: reported as a cache miss it tells autocert the certificate does not exist,
		// which orders a new one from Let's Encrypt for a domain that already has one.
		var responseError *awshttp.ResponseError
		if errors.As(err, &responseError) {
			if responseError.HTTPStatusCode() == http.StatusNotFound {
				logger.Debug("S3-Cache: Certificate not found (cache miss)", "key", key)
				return nil, autocert.ErrCacheMiss
			}
		}
		logger.Error("S3-Cache: Failed to get object from S3", "key", key, "error", err)
		return nil, fmt.Errorf("failed to get object from S3: %w", err)
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

	ctx, cancel := context.WithTimeout(ctx, s3OperationTimeout)
	defer cancel()

	contentType := "application/octet-stream"
	input := &s3.PutObjectInput{
		Bucket:      aws.String(c.bucket),
		Key:         aws.String(s3Key),
		Body:        bytes.NewReader(data),
		ContentType: &contentType,
	}
	if c.sseAlgorithm != "" {
		input.ServerSideEncryption = c.sseAlgorithm
		if c.sseKMSKeyID != "" {
			input.SSEKMSKeyId = aws.String(c.sseKMSKeyID)
		}
	}

	// Upload to S3
	_, err := c.client.PutObject(ctx, input)
	if err != nil {
		// The algorithm is logged because a store that does not implement it rejects the
		// write outright, and that reads as a plain upload failure otherwise.
		logger.Error("S3-Cache: Failed to upload certificate to S3", "key", key,
			"server_side_encryption", c.sseAlgorithm, "error", err)
		return fmt.Errorf("failed to upload to S3: %w", err)
	}

	logger.Debug("S3-Cache: Successfully stored certificate", "key", key)
	return nil
}

// Delete removes certificate data from S3.
func (c *S3Cache) Delete(ctx context.Context, key string) error {
	s3Key := c.prefix + hashKey(key)

	logger.Debug("S3-Cache: Deleting certificate", "key", key, "s3_key", s3Key)

	ctx, cancel := context.WithTimeout(ctx, s3OperationTimeout)
	defer cancel()

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
