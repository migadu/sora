package tlsmanager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// generateTestCertificate creates a self-signed certificate for testing
func generateTestCertificate(notBefore, notAfter time.Time, serial int64) ([]byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "test.example.com",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return certPEM, nil
}

func TestParseCertificate(t *testing.T) {
	now := time.Now()
	expiry := now.Add(90 * 24 * time.Hour)

	certPEM, err := generateTestCertificate(now, expiry, 12345)
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	info, err := parseCertificate(certPEM)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	if info.SerialNumber != "12345" {
		t.Errorf("Expected serial number 12345, got %s", info.SerialNumber)
	}

	// Check times are approximately correct (within 1 second)
	if info.NotBefore.Sub(now).Abs() > time.Second {
		t.Errorf("NotBefore time mismatch: expected %v, got %v", now, info.NotBefore)
	}

	if info.NotAfter.Sub(expiry).Abs() > time.Second {
		t.Errorf("NotAfter time mismatch: expected %v, got %v", expiry, info.NotAfter)
	}
}

func TestShouldUpdateCertificate(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		local    *CertificateInfo
		s3       *CertificateInfo
		expected bool
	}{
		{
			name: "S3 certificate is newer (later NotBefore)",
			local: &CertificateInfo{
				SerialNumber: "123",
				NotBefore:    now,
				NotAfter:     now.Add(90 * 24 * time.Hour),
			},
			s3: &CertificateInfo{
				SerialNumber: "456",
				NotBefore:    now.Add(24 * time.Hour),
				NotAfter:     now.Add(90 * 24 * time.Hour),
			},
			expected: true,
		},
		{
			name: "S3 certificate has later expiry (renewed)",
			local: &CertificateInfo{
				SerialNumber: "123",
				NotBefore:    now,
				NotAfter:     now.Add(30 * 24 * time.Hour),
			},
			s3: &CertificateInfo{
				SerialNumber: "456",
				NotBefore:    now,
				NotAfter:     now.Add(90 * 24 * time.Hour),
			},
			expected: true,
		},
		{
			name: "Local certificate is newer",
			local: &CertificateInfo{
				SerialNumber: "456",
				NotBefore:    now.Add(24 * time.Hour),
				NotAfter:     now.Add(90 * 24 * time.Hour),
			},
			s3: &CertificateInfo{
				SerialNumber: "123",
				NotBefore:    now,
				NotAfter:     now.Add(90 * 24 * time.Hour),
			},
			expected: false,
		},
		{
			name: "Certificates are identical",
			local: &CertificateInfo{
				SerialNumber: "123",
				NotBefore:    now,
				NotAfter:     now.Add(90 * 24 * time.Hour),
			},
			s3: &CertificateInfo{
				SerialNumber: "123",
				NotBefore:    now,
				NotAfter:     now.Add(90 * 24 * time.Hour),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldUpdateCertificate(tt.local, tt.s3)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestExtractFallbackCache(t *testing.T) {
	// Create mock caches
	s3Cache := &S3Cache{}
	fallbackCache := &FallbackCache{
		primary:  s3Cache,
		fallback: nil, // Not needed for this test
	}

	// Test direct FallbackCache
	result := extractFallbackCache(fallbackCache)
	if result != fallbackCache {
		t.Errorf("Failed to extract direct FallbackCache")
	}

	// Test wrapped in ClusterAwareCache
	clusterCache := &ClusterAwareCache{
		underlying:     fallbackCache,
		clusterManager: nil,
	}
	result = extractFallbackCache(clusterCache)
	if result != fallbackCache {
		t.Errorf("Failed to extract FallbackCache from ClusterAwareCache")
	}

	// Test wrapped in FailoverAwareCache
	failoverCache := &FailoverAwareCache{
		underlying: fallbackCache,
	}
	result = extractFallbackCache(failoverCache)
	if result != fallbackCache {
		t.Errorf("Failed to extract FallbackCache from FailoverAwareCache")
	}

	// Test double-wrapped (FailoverAwareCache -> ClusterAwareCache -> FallbackCache)
	doubleWrapped := &FailoverAwareCache{
		underlying: clusterCache,
	}
	result = extractFallbackCache(doubleWrapped)
	if result != fallbackCache {
		t.Errorf("Failed to extract FallbackCache from double-wrapped cache")
	}

	// Test with non-FallbackCache (should return nil)
	result = extractFallbackCache(s3Cache)
	if result != nil {
		t.Errorf("Expected nil for S3Cache, got %v", result)
	}
}

func TestSyncCertificateFromS3_SyncsRSAVariant(t *testing.T) {
	// This test verifies that both ECDSA and RSA certificates are synced from S3
	// to local cache, ensuring the fix for the missing RSA sync bug.

	// Create temporary directories for S3 and local caches
	s3Dir := t.TempDir()
	localDir := t.TempDir()

	// Use autocert.DirCache for both S3 (mock) and local
	s3Cache := autocert.DirCache(s3Dir)
	localCache := autocert.DirCache(localDir)

	// Create fallback cache
	fallbackCache := &FallbackCache{
		primary:     s3Cache,
		fallback:    localCache,
		fallbackDir: localDir,
	}

	// Generate test certificates
	now := time.Now()
	ecdsaCert, err := generateTestCertificate(now, now.Add(90*24*time.Hour), 1001)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA certificate: %v", err)
	}

	rsaCert, err := generateTestCertificate(now, now.Add(90*24*time.Hour), 1002)
	if err != nil {
		t.Fatalf("Failed to generate RSA certificate: %v", err)
	}

	// Store certificates in S3 (primary cache)
	domain := "test.example.com"
	ctx := context.Background()

	if err := s3Cache.Put(ctx, domain, ecdsaCert); err != nil {
		t.Fatalf("Failed to store ECDSA cert in S3: %v", err)
	}

	rsaDomain := domain + "+rsa"
	if err := s3Cache.Put(ctx, rsaDomain, rsaCert); err != nil {
		t.Fatalf("Failed to store RSA cert in S3: %v", err)
	}

	// Create a real autocert.Manager with the fallback cache
	acmeMgr := &autocert.Manager{
		Cache:      fallbackCache,
		HostPolicy: autocert.HostWhitelist(domain),
	}

	// Create a minimal manager
	mgr := &Manager{
		autocertMgr: acmeMgr,
	}

	// Sync ECDSA certificate
	if err := mgr.syncCertificateFromS3(ctx, domain); err != nil {
		t.Fatalf("Failed to sync ECDSA certificate: %v", err)
	}

	// Sync RSA certificate
	if err := mgr.syncCertificateFromS3(ctx, rsaDomain); err != nil {
		t.Fatalf("Failed to sync RSA certificate: %v", err)
	}

	// Verify both certificates are in local cache
	localECDSA, err := localCache.Get(ctx, domain)
	if err != nil {
		t.Errorf("ECDSA certificate not found in local cache: %v", err)
	} else if len(localECDSA) == 0 {
		t.Error("ECDSA certificate in local cache is empty")
	}

	localRSA, err := localCache.Get(ctx, rsaDomain)
	if err != nil {
		t.Errorf("RSA certificate not found in local cache: %v", err)
	} else if len(localRSA) == 0 {
		t.Error("RSA certificate in local cache is empty")
	}

	t.Logf("Successfully synced both ECDSA and RSA certificates to local cache")
}
