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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/storage"
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
	// sseAlgorithm is the server-side encryption asked of the store on every write.
	// Empty sends no header.
	sseAlgorithm types.ServerSideEncryption
	sseKMSKeyID  string
}

// defaultSSEAlgorithm is what the cache asks for when the deployment says nothing.
// Every value it stores is private key material - the certificate PEM bundles end
// with the certificate key, and "acme_account+key" is the ACME account key - so the
// write must not leave protection at rest to a bucket default nobody enforces.
const defaultSSEAlgorithm = types.ServerSideEncryption(config.CertificateSSEAES256)

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

// encryptionOptions turns the configured encryption settings into cache options. A
// configuration that says nothing about encryption keeps the default; a stray KMS key id
// with no algorithm is passed through rather than dropped, so validateEncryption can
// reject it instead of the deployment believing it applies.
func encryptionOptions(cfg config.TLSLetsEncryptS3Config) []S3CacheOption {
	return []S3CacheOption{WithServerSideEncryption(cfg.CertificateSSE())}
}

// validateEncryption rejects settings that would not mean what they say, rather than
// writing private keys under them. config.TLSConfig.Validate refuses such a
// [tls.letsencrypt.s3] with the file, by the same check.
func (c *S3Cache) validateEncryption() error {
	return config.ValidateCertificateSSE(string(c.sseAlgorithm), c.sseKMSKeyID)
}

// OpenS3Cache opens the certificate cache cfg describes as the server does, with the
// server-side encryption the configuration asks for.
func OpenS3Cache(cfg config.TLSLetsEncryptS3Config) (*S3Cache, error) {
	return NewS3Cache(cfg, encryptionOptions(cfg)...)
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

	clientCtx, cancel := context.WithTimeout(ctx, s3OperationTimeout)
	client, err := storage.NewClient(clientCtx, storage.ClientConfig{
		Endpoint:  endpoint,
		UseTLS:    useSSL,
		Region:    cfg.Region,
		AccessKey: cfg.AccessKey,
		SecretKey: cfg.SecretKey,
		Debug:     cfg.Debug,
		LogPrefix: "S3-Cache",
	})
	cancel()
	if err != nil {
		return nil, err
	}

	cache := &S3Cache{
		client:       client,
		bucket:       cfg.Bucket,
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
		"endpoint", endpoint, "region", client.Options().Region, "tls", useSSL, "debug", cfg.Debug,
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
	data, _, err := c.getSnapshot(ctx, key)
	return data, err
}

// getObject reads the object s3Key. A missing object is autocert.ErrCacheMiss.
func (c *S3Cache) getObject(ctx context.Context, s3Key string) ([]byte, error) {
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
		if missingS3Object(err) {
			return nil, autocert.ErrCacheMiss
		}
		return nil, fmt.Errorf("failed to get object from S3: %w", err)
	}
	defer result.Body.Close()

	// Read object data
	data, err := io.ReadAll(result.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read object: %w", err)
	}
	return data, nil
}

// Put stores certificate data in S3.
func (c *S3Cache) Put(ctx context.Context, key string, data []byte) error {
	ctx, cancel := context.WithTimeout(ctx, s3OperationTimeout)
	defer cancel()
	g, present := ctx.Value(publicationContextKey{}).(publicationGeneration)
	if !present {
		_, current, err := c.getSnapshot(ctx, key)
		if err != nil && !errors.Is(err, autocert.ErrCacheMiss) {
			return err
		}
		g = current
	}
	return c.putGeneration(ctx, key, data, g)
}

// putObject writes data to the object s3Key with the configured server-side encryption.
func (c *S3Cache) putObject(ctx context.Context, s3Key string, data []byte) error {
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
	if _, err := c.client.PutObject(ctx, input); err != nil {
		return fmt.Errorf("failed to upload to S3: %w", err)
	}
	return nil
}

func (c *S3Cache) putObjectConditional(ctx context.Context, s3Key string, data []byte, etag string, exists bool) error {
	ctx, cancel := context.WithTimeout(ctx, s3OperationTimeout)
	defer cancel()

	contentType := "application/octet-stream"
	input := &s3.PutObjectInput{
		Bucket:      aws.String(c.bucket),
		Key:         aws.String(s3Key),
		Body:        bytes.NewReader(data),
		ContentType: &contentType,
	}
	if exists {
		input.IfMatch = aws.String(etag)
	} else {
		input.IfNoneMatch = aws.String("*")
	}
	if c.sseAlgorithm != "" {
		input.ServerSideEncryption = c.sseAlgorithm
		if c.sseKMSKeyID != "" {
			input.SSEKMSKeyId = aws.String(c.sseKMSKeyID)
		}
	}

	// Upload to S3
	if _, err := c.client.PutObject(ctx, input); err != nil {
		return fmt.Errorf("failed to upload to S3: %w", err)
	}
	return nil
}

// MarkDeleted records in the bucket that the certificate stored under the object key
// certKey (see S3ObjectKey) was deleted, at the given time. sora-admin calls it before it
// deletes the object: every node holds the certificate in its local fallback cache too,
// and its certificate sync writes a certificate that S3 lacks back to S3 unless the
// marker shows it was deleted after the node stored its copy. A key that holds no
// certificate cache entry has no marker and is ignored.
func (c *S3Cache) MarkDeleted(ctx context.Context, certKey string, at time.Time) error {
	marker, ok := deletionMarkerKey(certKey)
	if !ok {
		return nil
	}
	if err := c.revokeObject(ctx, certKey, at); err != nil {
		return err
	}
	// Keep the old marker for diagnosing legacy local files during upgrade. It is
	// not the publication fence; the CAS-protected entry above is authoritative.
	return c.putObject(ctx, marker, []byte(at.UTC().Format(time.RFC3339Nano)))
}

// DeletedAt reports when the certificate cached under name was last deleted from the
// bucket by sora-admin, and the zero time if it never was.
func (c *S3Cache) DeletedAt(ctx context.Context, name string) (time.Time, error) {
	marker, _ := deletionMarkerKey(S3ObjectKey(name))
	data, err := c.getObject(ctx, marker)
	if errors.Is(err, autocert.ErrCacheMiss) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	at, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(data)))
	if err != nil {
		return time.Time{}, fmt.Errorf("deletion marker %s: %w", marker, err)
	}
	return at, nil
}

// Delete removes certificate data from S3.
func (c *S3Cache) Delete(ctx context.Context, key string) error {
	return c.MarkDeleted(ctx, S3ObjectKey(key), time.Now())
}

const (
	// s3KeyPrefix is the bucket prefix every S3 cache entry is stored under.
	s3KeyPrefix = "autocert/"
	// certKeyPrefix and deletionMarkerPrefix name, followed by the hash of a cache entry
	// name, the object that holds the entry and the one that records its deletion.
	certKeyPrefix        = s3KeyPrefix + "cert-"
	deletionMarkerPrefix = s3KeyPrefix + "deleted-"
)

// S3ObjectKey returns the bucket key the S3 cache stores the autocert cache entry name
// under. autocert names a domain's ECDSA certificate "<domain>" and its RSA one
// "<domain>+rsa" (lowercase, Punycode, no trailing dot). Tools that manage the bucket
// use this so that they address exactly the objects the server reads and writes.
func S3ObjectKey(name string) string {
	return s3KeyPrefix + hashKey(name)
}

// deletionMarkerKey returns the key of the object that records the deletion of the cache
// entry stored under certKey. The marker carries the same hash, so that a certificate
// deleted by its object key alone is marked as well as one deleted by name.
func deletionMarkerKey(certKey string) (string, bool) {
	hash, ok := strings.CutPrefix(certKey, certKeyPrefix)
	if !ok || hash == "" {
		return "", false
	}
	return deletionMarkerPrefix + hash, true
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
