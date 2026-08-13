package tlsmanager

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/migadu/sora/config"
)

// Autocert cache values are not opaque blobs: each certificate entry is a PEM bundle
// that ends with the certificate's private key, and "acme_account+key" is the ACME
// account key. Read access to the bucket must not be read access to every mail
// endpoint's TLS private key, and bucket-level encryption defaults cannot be relied
// on — MinIO and Garage, the stores this cache is routinely pointed at, apply none.

// encryptionRecorder is an S3 endpoint that remembers the encryption headers of the
// last PUT it served.
type encryptionRecorder struct {
	mu        sync.Mutex
	algorithm string
	kmsKeyID  string
	puts      int
}

func newEncryptionRecorder(t *testing.T) (*encryptionRecorder, string) {
	t.Helper()

	rec := &encryptionRecorder{}
	srv := httptest.NewServer(rec)
	t.Cleanup(srv.Close)
	return rec, srv.URL
}

func (r *encryptionRecorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPut {
		r.mu.Lock()
		r.puts++
		r.algorithm = req.Header.Get("X-Amz-Server-Side-Encryption")
		r.kmsKeyID = req.Header.Get("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id")
		r.mu.Unlock()
	}
	w.WriteHeader(http.StatusOK)
}

func (r *encryptionRecorder) lastPut(t *testing.T) (algorithm, kmsKeyID string) {
	t.Helper()

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.puts == 0 {
		t.Fatal("no PUT reached the S3 endpoint")
	}
	return r.algorithm, r.kmsKeyID
}

func newEncryptionTestCache(t *testing.T, endpoint string, opts ...S3CacheOption) *S3Cache {
	t.Helper()

	cache, err := NewS3Cache(config.TLSLetsEncryptS3Config{
		Bucket:     "certs",
		Endpoint:   endpoint,
		DisableTLS: true,
		AccessKey:  "test",
		SecretKey:  "test",
	}, opts...)
	if err != nil {
		t.Fatalf("NewS3Cache: %v", err)
	}
	return cache
}

// TestS3CachePutEncryptsAtRestByDefault is the default a deployment gets without
// saying anything about encryption.
func TestS3CachePutEncryptsAtRestByDefault(t *testing.T) {
	rec, endpoint := newEncryptionRecorder(t)
	cache := newEncryptionTestCache(t, endpoint)

	if err := cache.Put(context.Background(), "mail.example.com", []byte("-----BEGIN PRIVATE KEY-----")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	algorithm, _ := rec.lastPut(t)
	if algorithm != "AES256" {
		t.Errorf("PUT server-side encryption = %q, want %q: the object holds a TLS private key and "+
			"its protection at rest must not depend on an unenforced bucket default", algorithm, "AES256")
	}
}

// TestS3CachePutUsesConfiguredKMSKey covers a deployment that owns its key material.
func TestS3CachePutUsesConfiguredKMSKey(t *testing.T) {
	rec, endpoint := newEncryptionRecorder(t)
	cache := newEncryptionTestCache(t, endpoint, WithServerSideEncryption("aws:kms", "arn:aws:kms:eu-west-1:1:key/abc"))

	if err := cache.Put(context.Background(), "mail.example.com", []byte("-----BEGIN PRIVATE KEY-----")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	algorithm, kmsKeyID := rec.lastPut(t)
	if algorithm != "aws:kms" {
		t.Errorf("PUT server-side encryption = %q, want %q", algorithm, "aws:kms")
	}
	if kmsKeyID != "arn:aws:kms:eu-west-1:1:key/abc" {
		t.Errorf("PUT KMS key id = %q, want the configured key", kmsKeyID)
	}
}

// TestS3CachePutEncryptionCanBeDisabled keeps the escape hatch for stores that reject
// the header outright: certificates that cannot be written are certificates the
// cluster has to re-order.
func TestS3CachePutEncryptionCanBeDisabled(t *testing.T) {
	rec, endpoint := newEncryptionRecorder(t)
	cache := newEncryptionTestCache(t, endpoint, WithServerSideEncryption("", ""))

	if err := cache.Put(context.Background(), "mail.example.com", []byte("-----BEGIN PRIVATE KEY-----")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	algorithm, _ := rec.lastPut(t)
	if algorithm != "" {
		t.Errorf("PUT server-side encryption = %q, want no header", algorithm)
	}
}

// TestNewS3CacheRejectsUnusableEncryption fails the deployment loudly rather than
// silently writing private keys under settings that do not mean what they say.
func TestNewS3CacheRejectsUnusableEncryption(t *testing.T) {
	_, endpoint := newEncryptionRecorder(t)

	tests := []struct {
		name      string
		algorithm string
		kmsKeyID  string
	}{
		{"unknown algorithm", "rot13", ""},
		{"kms without key id", "aws:kms", ""},
		{"key id without kms", "AES256", "arn:aws:kms:eu-west-1:1:key/abc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewS3Cache(config.TLSLetsEncryptS3Config{
				Bucket:     "certs",
				Endpoint:   endpoint,
				DisableTLS: true,
				AccessKey:  "test",
				SecretKey:  "test",
			}, WithServerSideEncryption(tt.algorithm, tt.kmsKeyID))
			if err == nil {
				t.Fatalf("NewS3Cache with algorithm=%q kms_key_id=%q: err = nil, want a configuration error", tt.algorithm, tt.kmsKeyID)
			}
		})
	}
}
