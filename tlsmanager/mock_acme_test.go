// +build integration

package tlsmanager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// mockACMEClient is a mock ACME client that doesn't contact real servers
// It simulates certificate issuance by returning cached certificates
type mockACMEClient struct {
	cache autocert.Cache
}

// TestWithMockACME tests pre-warming with a controlled environment
func TestWithMockACME(t *testing.T) {
	domain := "test.example.com"
	ctx := context.Background()

	// Create cache
	cache := newMockCache()

	// Generate a valid certificate and store it
	certData, err := generateValidCertificateWithKey(domain, 12345)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Store in cache BEFORE creating manager (simulates pre-existing cert)
	if err := cache.Put(ctx, domain, certData); err != nil {
		t.Fatalf("Failed to store certificate: %v", err)
	}

	t.Logf("Step 1: Certificate stored in cache (simulating previous issuance)")

	// Create autocert manager with our cache
	// Key insight: If cert is in cache and valid, autocert won't contact ACME at all!
	// IMPORTANT: Don't set Client field - this prevents ACME contact entirely
	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
		Cache:      cache,
		Client:     nil, // Explicitly nil - no ACME client
	}

	t.Logf("Step 2: Created autocert.Manager")

	// Simulate pre-warming by calling GetCertificate
	hello := &tls.ClientHelloInfo{
		ServerName: domain,
		SignatureSchemes: []tls.SignatureScheme{
			tls.ECDSAWithP256AndSHA256,
		},
		SupportedCurves: []tls.CurveID{
			tls.CurveP256,
		},
	}

	// This should load from cache without contacting ACME
	cert, err := manager.GetCertificate(hello)
	if err != nil {
		t.Fatalf("Pre-warming failed: %v", err)
	}

	t.Logf("Step 3: Certificate loaded from cache (no ACME contact)")

	// Verify certificate
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("Expected certificate, got nil")
	}

	parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	if parsedCert.SerialNumber.Int64() != 12345 {
		t.Errorf("Expected serial 12345, got %d", parsedCert.SerialNumber.Int64())
	}

	t.Logf("Step 4: Verified certificate serial=%d", parsedCert.SerialNumber.Int64())

	// Now test that subsequent calls use the in-memory state, not cache
	// We'll clear the cache and verify cert still works
	if err := cache.Delete(ctx, domain); err != nil {
		t.Fatalf("Failed to delete from cache: %v", err)
	}

	t.Logf("Step 5: Deleted certificate from cache")

	// This should still work because cert is in autocert's state!
	cert2, err := manager.GetCertificate(hello)
	if err != nil {
		t.Fatalf("Second GetCertificate failed (should use state): %v", err)
	}

	parsedCert2, err := x509.ParseCertificate(cert2.Certificate[0])
	if err != nil {
		t.Fatalf("Failed to parse second certificate: %v", err)
	}

	if parsedCert2.SerialNumber.Int64() != 12345 {
		t.Errorf("Expected serial 12345 from state, got %d", parsedCert2.SerialNumber.Int64())
	}

	t.Logf("Step 6: Certificate served from autocert's in-memory state (not cache)")
	t.Logf("SUCCESS: Confirmed pre-warming loads cert into autocert state!")
}

// generateValidCertificateWithKey generates a certificate that autocert will accept
func generateValidCertificateWithKey(domain string, serial int64) ([]byte, error) {
	// Generate ECDSA private key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Create certificate template
	// This mimics what Let's Encrypt issues
	template := x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(90 * 24 * time.Hour), // 90 days validity
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	// Encode private key to PKCS8 PEM
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Return in autocert cache format (private key first, then cert)
	return append(privPEM, certPEM...), nil
}

// TestPrewarmingPreventsACMERequest tests that pre-warming avoids ACME requests
func TestPrewarmingPreventsACMERequest(t *testing.T) {
	domain := "test.example.com"
	ctx := context.Background()

	// Create tracking cache to count operations
	cache := newTrackingCache()

	// Generate and store certificate
	certData, err := generateValidCertificateWithKey(domain, 99999)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	if err := cache.Put(ctx, domain, certData); err != nil {
		t.Fatalf("Failed to store certificate: %v", err)
	}

	t.Logf("Step 1: Certificate stored in cache")

	// Create manager
	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
		Cache:      cache,
	}

	// Reset counters before pre-warming
	cache.resetCounters()

	// Pre-warm
	hello := &tls.ClientHelloInfo{
		ServerName: domain,
		SignatureSchemes: []tls.SignatureScheme{
			tls.ECDSAWithP256AndSHA256,
		},
		SupportedCurves: []tls.CurveID{
			tls.CurveP256,
		},
	}

	_, err = manager.GetCertificate(hello)
	if err != nil {
		t.Fatalf("Pre-warming failed: %v", err)
	}

	// Check cache operations
	getCalls := cache.getCallCount()
	putCalls := cache.putCalls.Load()

	t.Logf("Step 2: Pre-warming complete - cache Get calls=%d, Put calls=%d", getCalls, putCalls)

	// Should have called Get at least once (to check cache)
	if getCalls == 0 {
		t.Error("Expected at least 1 cache Get call during pre-warming")
	}

	// Should NOT have called Put (no new cert issued)
	if putCalls > 0 {
		t.Errorf("Expected 0 cache Put calls (no ACME request), got %d", putCalls)
	}

	t.Logf("SUCCESS: Pre-warming loaded from cache without ACME request")
}

// TestNewCertificateIssuanceDuringRuntime tests detecting new certs
func TestNewCertificateIssuanceDuringRuntime(t *testing.T) {
	domain := "test.example.com"
	ctx := context.Background()

	cache := newTrackingCache()

	// Start with old certificate
	oldCert, err := generateValidCertificateWithKey(domain, 111)
	if err != nil {
		t.Fatalf("Failed to generate old certificate: %v", err)
	}

	if err := cache.Put(ctx, domain, oldCert); err != nil {
		t.Fatalf("Failed to store old certificate: %v", err)
	}

	t.Logf("Step 1: Old certificate stored (serial=111)")

	// Create manager and pre-warm
	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
		Cache:      cache,
	}

	hello := &tls.ClientHelloInfo{
		ServerName: domain,
		SignatureSchemes: []tls.SignatureScheme{
			tls.ECDSAWithP256AndSHA256,
		},
		SupportedCurves: []tls.CurveID{
			tls.CurveP256,
		},
	}

	cert1, err := manager.GetCertificate(hello)
	if err != nil {
		t.Fatalf("Failed to load old certificate: %v", err)
	}

	parsed1, _ := x509.ParseCertificate(cert1.Certificate[0])
	t.Logf("Step 2: Loaded old certificate (serial=%d)", parsed1.SerialNumber.Int64())

	// Simulate new certificate being issued to cache (by leader or renewal)
	newCert, err := generateValidCertificateWithKey(domain, 222)
	if err != nil {
		t.Fatalf("Failed to generate new certificate: %v", err)
	}

	if err := cache.Put(ctx, domain, newCert); err != nil {
		t.Fatalf("Failed to store new certificate: %v", err)
	}

	t.Logf("Step 3: New certificate issued to cache (serial=222)")

	// Current behavior: autocert will keep using old cert from state
	// (This is why we need the sync worker!)
	cert2, err := manager.GetCertificate(hello)
	if err != nil {
		t.Fatalf("Failed to get certificate after renewal: %v", err)
	}

	parsed2, _ := x509.ParseCertificate(cert2.Certificate[0])
	t.Logf("Step 4: GetCertificate returned serial=%d", parsed2.SerialNumber.Int64())

	// This demonstrates that autocert caches certs in memory
	// New cert in cache won't be picked up until:
	// 1. State expires/cleared, OR
	// 2. Cert renewal worker runs, OR
	// 3. Server restarts
	if parsed2.SerialNumber.Int64() == 111 {
		t.Logf("Note: autocert still using old cert from state (expected)")
		t.Logf("      This is why the sync worker is needed to update local cache")
		t.Logf("      On next restart, pre-warming will load the new cert (222)")
	} else if parsed2.SerialNumber.Int64() == 222 {
		t.Logf("Note: autocert picked up new cert (may happen depending on timing)")
	}

	t.Logf("SUCCESS: Demonstrated cert state behavior")
}

// TestPrewarmingWithExpiredCertificate tests behavior with expired cert in cache
func TestPrewarmingWithExpiredCertificate(t *testing.T) {
	domain := "test.example.com"
	ctx := context.Background()

	cache := newMockCache()

	// Generate expired certificate
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := x509.Certificate{
		SerialNumber: big.NewInt(999),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-100 * 24 * time.Hour), // 100 days ago
		NotAfter:     time.Now().Add(-10 * 24 * time.Hour),  // Expired 10 days ago
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{domain},
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	privBytes, _ := x509.MarshalPKCS8PrivateKey(priv)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	expiredCert := append(privPEM, certPEM...)

	if err := cache.Put(ctx, domain, expiredCert); err != nil {
		t.Fatalf("Failed to store expired certificate: %v", err)
	}

	t.Logf("Step 1: Expired certificate stored in cache")

	// Create manager
	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
		Cache:      cache,
	}

	hello := &tls.ClientHelloInfo{
		ServerName: domain,
		SignatureSchemes: []tls.SignatureScheme{
			tls.ECDSAWithP256AndSHA256,
		},
		SupportedCurves: []tls.CurveID{
			tls.CurveP256,
		},
	}

	// Try to get certificate - autocert should detect it's expired
	// and try to get new one (which will fail in tests, but that's okay)
	_, err := manager.GetCertificate(hello)

	// We expect this to fail because:
	// 1. Cached cert is expired
	// 2. autocert will try to get new cert
	// 3. No ACME server available
	if err == nil {
		t.Error("Expected error with expired certificate, got nil")
	} else {
		t.Logf("Step 2: Expired cert rejected as expected: %v", err)
		t.Logf("SUCCESS: autocert correctly validates certificate expiry")
	}
}
