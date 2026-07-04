package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// GenerateTestTLSCert mints an ephemeral self-signed TLS certificate at test
// runtime, writes the PEM pair into t.TempDir() (server options take file
// paths), and returns the file paths together with an x509.CertPool holding
// the certificate — so test clients (and the proxy's remote_tls_ca_file) can
// run with verification ENABLED instead of InsecureSkipVerify.
//
// With nil dnsNames and ips the certificate is valid for localhost, 127.0.0.1
// and ::1. Pass explicit SANs to mint a certificate for a different identity,
// e.g. to prove that hostname verification actually rejects a mismatched
// backend. Nothing is checked into the repo and nothing ever expires under
// the test's feet (24h validity from now).
func GenerateTestTLSCert(t *testing.T, dnsNames []string, ips []net.IP) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()

	if dnsNames == nil && ips == nil {
		dnsNames = []string{"localhost"}
		ips = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateTestTLSCert: key generation failed: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("GenerateTestTLSCert: serial generation failed: %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "sora-test"},
		NotBefore:             time.Now().Add(-1 * time.Hour), // tolerate clock skew
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("GenerateTestTLSCert: certificate creation failed: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("GenerateTestTLSCert: key marshaling failed: %v", err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatalf("GenerateTestTLSCert: writing cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("GenerateTestTLSCert: writing key file: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("GenerateTestTLSCert: parsing generated certificate: %v", err)
	}
	pool = x509.NewCertPool()
	pool.AddCert(cert)

	return certFile, keyFile, pool
}
