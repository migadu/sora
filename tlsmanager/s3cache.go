// Package tlsmanager provides automatic TLS certificate management using Let's Encrypt
// with S3-backed certificate storage.
package tlsmanager

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
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

// NewS3Cache creates a new S3-backed autocert cache.
func NewS3Cache(cfg config.TLSLetsEncryptS3Config) (*S3Cache, error) {
	ctx := context.Background()

	var awsCfg aws.Config
	var err error

	// Configure AWS SDK
	if cfg.AccessKeyID != "" && cfg.SecretAccessKey != "" {
		// Use explicit credentials
		awsCfg, err = awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithRegion(cfg.Region),
			awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				cfg.AccessKeyID,
				cfg.SecretAccessKey,
				"",
			)),
		)
	} else {
		// Use default credential chain (environment, IAM role, etc.)
		awsCfg, err = awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithRegion(cfg.Region),
		)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg)

	cache := &S3Cache{
		client: client,
		bucket: cfg.Bucket,
		prefix: "autocert/",
	}

	// Verify bucket access
	if err := cache.verifyBucketAccess(ctx); err != nil {
		return nil, fmt.Errorf("failed to verify S3 bucket access: %w", err)
	}

	logger.Infof("S3 autocert cache initialized with bucket: %s", cfg.Bucket)

	return cache, nil
}

// verifyBucketAccess checks if the bucket is accessible
func (c *S3Cache) verifyBucketAccess(ctx context.Context) error {
	_, err := c.client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(c.bucket),
	})
	if err != nil {
		return fmt.Errorf("bucket %s is not accessible: %w", c.bucket, err)
	}
	return nil
}

// keyName generates the S3 key name for a given certificate key name.
// It creates a sanitized path-safe key with a hash-based subdirectory for distribution.
func (c *S3Cache) keyName(name string) string {
	// Sanitize the name to be S3-safe (remove any path separators)
	safeName := strings.ReplaceAll(name, "/", "_")
	safeName = strings.ReplaceAll(safeName, "\\", "_")

	// Create a hash of the name for distribution across S3 partitions
	// This improves S3 performance for high-throughput scenarios
	hash := sha256.Sum256([]byte(name))
	hashPrefix := hex.EncodeToString(hash[:2]) // Use first 2 bytes for 65k partitions

	return fmt.Sprintf("%s%s/%s", c.prefix, hashPrefix, safeName)
}

// Get retrieves a certificate from S3 storage.
// Returns autocert.ErrCacheMiss if the certificate doesn't exist.
func (c *S3Cache) Get(ctx context.Context, name string) ([]byte, error) {
	key := c.keyName(name)

	result, err := c.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
	})

	if err != nil {
		// Check if it's a "not found" error
		var noSuchKey *types.NoSuchKey
		if errors.As(err, &noSuchKey) {
			logger.Debugf("Certificate not found in S3: %s", name)
			return nil, autocert.ErrCacheMiss
		}
		return nil, fmt.Errorf("failed to get certificate from S3: %w", err)
	}
	defer result.Body.Close()

	data, err := io.ReadAll(result.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate data from S3: %w", err)
	}

	logger.Debugf("Retrieved certificate from S3: %s (%d bytes)", name, len(data))
	return data, nil
}

// Put stores a certificate in S3 storage.
func (c *S3Cache) Put(ctx context.Context, name string, data []byte) error {
	key := c.keyName(name)

	_, err := c.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:       aws.String(c.bucket),
		Key:          aws.String(key),
		Body:         strings.NewReader(string(data)),
		ContentType:  aws.String("application/octet-stream"),
		StorageClass: types.StorageClassStandard,
		// Add server-side encryption
		ServerSideEncryption: types.ServerSideEncryptionAes256,
	})

	if err != nil {
		return fmt.Errorf("failed to put certificate to S3: %w", err)
	}

	logger.Infof("Stored certificate in S3: %s (%d bytes)", name, len(data))
	return nil
}

// Delete removes a certificate from S3 storage.
func (c *S3Cache) Delete(ctx context.Context, name string) error {
	key := c.keyName(name)

	_, err := c.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
	})

	if err != nil {
		return fmt.Errorf("failed to delete certificate from S3: %w", err)
	}

	logger.Infof("Deleted certificate from S3: %s", name)
	return nil
}
