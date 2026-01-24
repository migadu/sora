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

// generateFullTestCertificate generates a complete certificate with private key
// suitable for use with autocert
// Note: This generates a valid certificate structure, but autocert will still try to
// validate it and may reject it because it's self-signed. This test demonstrates the
// flow but can't fully test autocert without a mock ACME server.
func generateFullTestCertificate(domain string, serial int64) ([]byte, error) {
	// Generate private key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Create certificate template with longer validity
	// autocert checks if cert is valid for at least 30 days
	template := x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   domain,
		},
		NotBefore: time.Now().Add(-1 * time.Hour), // Ensure it's valid now
		NotAfter:  time.Now().Add(90 * 24 * time.Hour), // Valid for 90 days
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth, // May be required by autocert
		},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
		IsCA:                  false,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	// Encode private key to PEM (PKCS8 format preferred by autocert)
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Combine private key and certificate (format expected by autocert)
	return append(privPEM, certPEM...), nil
}

// TestAutocertPrewarmingIntegration tests the full pre-warming flow with real autocert
func TestAutocertPrewarmingIntegration(t *testing.T) {
	domain := "test.example.com"
	ctx := context.Background()

	// Create mock cache
	cache := newMockCache()

	// Generate and store a certificate in cache (simulating previous issuance)
	certData, err := generateFullTestCertificate(domain, 999)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	if err := cache.Put(ctx, domain, certData); err != nil {
		t.Fatalf("Failed to store certificate: %v", err)
	}

	t.Logf("Step 1: Certificate stored in cache (serial=999)")

	// Create autocert manager
	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
		Cache:      cache,
	}

	t.Logf("Step 2: Created autocert.Manager")

	// Simulate pre-warming: call GetCertificate to load cert into manager's state
	hello := &tls.ClientHelloInfo{
		ServerName: domain,
		SignatureSchemes: []tls.SignatureScheme{
			tls.ECDSAWithP256AndSHA256,
		},
		SupportedCurves: []tls.CurveID{
			tls.CurveP256,
		},
	}

	cert, err := manager.GetCertificate(hello)
	if err != nil {
		t.Fatalf("Pre-warming failed: %v", err)
	}

	t.Logf("Step 3: Pre-warming loaded certificate from cache")

	// Verify the certificate
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("Expected certificate, got nil")
	}

	// Parse the certificate to verify serial number
	parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	if parsedCert.SerialNumber.Int64() != 999 {
		t.Errorf("Expected serial 999, got %d", parsedCert.SerialNumber.Int64())
	}

	t.Logf("Step 4: Certificate verified (serial=%d)", parsedCert.SerialNumber.Int64())

	// Now simulate a TLS handshake - should use the already-loaded certificate
	// without hitting the cache again
	cert2, err := manager.GetCertificate(hello)
	if err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}

	// Should be the same certificate (from autocert's internal state, not cache)
	if cert2 == nil || len(cert2.Certificate) == 0 {
		t.Fatal("Expected certificate from handshake, got nil")
	}

	parsedCert2, _ := x509.ParseCertificate(cert2.Certificate[0])
	if parsedCert2.SerialNumber.Int64() != 999 {
		t.Errorf("Expected serial 999 on handshake, got %d", parsedCert2.SerialNumber.Int64())
	}

	t.Logf("Step 5: TLS handshake used pre-warmed certificate (serial=%d)", parsedCert2.SerialNumber.Int64())

	t.Logf("SUCCESS: Pre-warming flow verified - cert loaded before handshake and reused")
}

// TestAutocertWithoutPrewarming shows what happens without pre-warming
func TestAutocertWithoutPrewarming(t *testing.T) {
	domain := "test.example.com"
	ctx := context.Background()

	// Create mock cache
	cache := newMockCache()

	// Store certificate (but DON'T pre-warm)
	certData, err := generateFullTestCertificate(domain, 888)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	if err := cache.Put(ctx, domain, certData); err != nil {
		t.Fatalf("Failed to store certificate: %v", err)
	}

	t.Logf("Step 1: Certificate stored in cache (serial=888)")

	// Create autocert manager
	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
		Cache:      cache,
	}

	t.Logf("Step 2: Created autocert.Manager (NO pre-warming)")

	// Simulate TLS handshake arriving immediately
	// autocert has to load cert from cache ON-DEMAND
	hello := &tls.ClientHelloInfo{
		ServerName: domain,
		SignatureSchemes: []tls.SignatureScheme{
			tls.ECDSAWithP256AndSHA256,
		},
		SupportedCurves: []tls.CurveID{
			tls.CurveP256,
		},
	}

	t.Logf("Step 3: TLS handshake arrives (triggering on-demand cert load)")

	cert, err := manager.GetCertificate(hello)
	if err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}

	// Certificate loaded successfully, but only because cache was fast
	// If cache had been slow/unavailable, this would have failed
	parsedCert, _ := x509.ParseCertificate(cert.Certificate[0])
	t.Logf("Step 4: Certificate loaded on-demand (serial=%d)", parsedCert.SerialNumber.Int64())

	t.Logf("NOTE: Without pre-warming, certificate load happens during TLS handshake")
	t.Logf("      If S3/cache is slow, handshake will timeout/fail")
}

// TestAutocertStateAfterPrewarming verifies that autocert's internal state is populated
func TestAutocertStateAfterPrewarming(t *testing.T) {
	domain := "test.example.com"
	ctx := context.Background()

	// Create mock cache
	cache := newMockCache()

	// Store certificate
	certData, err := generateFullTestCertificate(domain, 777)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	if err := cache.Put(ctx, domain, certData); err != nil {
		t.Fatalf("Failed to store certificate: %v", err)
	}

	// Create autocert manager
	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
		Cache:      cache,
	}

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

	t.Logf("Step 1: Pre-warmed certificate")

	// Remove certificate from cache (simulate cache clear)
	if err := cache.Delete(ctx, domain); err != nil {
		t.Fatalf("Failed to delete from cache: %v", err)
	}

	t.Logf("Step 2: Removed certificate from cache")

	// TLS handshake should still work because cert is in autocert's state!
	cert, err := manager.GetCertificate(hello)
	if err != nil {
		t.Fatalf("TLS handshake failed after cache clear: %v", err)
	}

	parsedCert, _ := x509.ParseCertificate(cert.Certificate[0])
	if parsedCert.SerialNumber.Int64() != 777 {
		t.Errorf("Expected serial 777, got %d", parsedCert.SerialNumber.Int64())
	}

	t.Logf("Step 3: TLS handshake succeeded using autocert's in-memory state (serial=%d)", parsedCert.SerialNumber.Int64())
	t.Logf("SUCCESS: Proves cert is loaded into autocert's state, not just cache")
}
