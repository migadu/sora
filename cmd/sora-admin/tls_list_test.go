package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/tlsmanager"
)

// expiredAutocertEntry returns a certificate for name that expired a day ago, encoded
// as autocert caches it: the private key, then the certificate chain.
func expiredAutocertEntry(t *testing.T, name string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	entry := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return append(entry, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
}

// noPanic turns a panic in f into an error, so that captureStdout restores os.Stdout
// and the test reports it instead of the whole binary dying.
func noPanic(f func() error) func() error {
	return func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic: %v", r)
			}
		}()
		return f()
	}
}

// TestTLSTryDecodeDomainShortNames: an object name after autocert/cert- shorter than
// the 16 characters tryDecodeDomain shows must not panic, and an undecoded name keeps
// the "..." marker, which tells parseCertificateData to take the certificate's own name
// and keeps checkLocalCache and tls clean away from local files.
func TestTLSTryDecodeDomainShortNames(t *testing.T) {
	serverKey := tlsmanager.S3ObjectKey("mail.example.com")
	for key, want := range map[string]string{
		"autocert/cert-":                 "...",
		"autocert/cert-test":             "test...",
		"autocert/cert-0123456789abcdef": "0123456789abcdef...",
		serverKey:                        strings.TrimPrefix(serverKey, "autocert/cert-")[:16] + "...",
	} {
		t.Run(key, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("tryDecodeDomain(%q) panicked: %v", key, r)
				}
			}()
			if got := tryDecodeDomain(key); got != want {
				t.Errorf("tryDecodeDomain(%q) = %q, want %q", key, got, want)
			}
		})
	}
}

// TestTLSListShortCertName: tls list shows an object with a short name after
// autocert/cert- under the name of the certificate it holds, and does not take the
// object name for a local cache file.
func TestTLSListShortCertName(t *testing.T) {
	stub, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	cacheDir := t.TempDir()
	putServerCertificates(t, cfg, "mail.example.com")
	stub.put("certs", "autocert/cert-test", expiredAutocertEntry(t, "old.example.com"))
	writeLocalCertificates(t, cacheDir, "test")

	out := captureStdout(t, noPanic(func() error {
		return listTLSCertificates(context.Background(), cfg, cacheDir, false, true)
	}))

	type listedCert struct {
		Domain       string `json:"domain"`
		S3Key        string `json:"s3Key"`
		InLocalCache bool   `json:"inLocalCache"`
	}
	var listed []listedCert
	if err := json.Unmarshal([]byte(out), &listed); err != nil {
		t.Fatalf("tls list --json printed invalid JSON: %v\n%s", err, out)
	}
	i := slices.IndexFunc(listed, func(c listedCert) bool { return c.S3Key == "autocert/cert-test" })
	if i < 0 {
		t.Fatalf("autocert/cert-test not listed:\n%s", out)
	}
	if got := listed[i]; got.Domain != "old.example.com" || got.InLocalCache {
		t.Errorf("autocert/cert-test listed as domain %q, in local cache %t; want old.example.com, false", got.Domain, got.InLocalCache)
	}
	if len(listed) != 2 {
		t.Errorf("listed %d certificates, want 2:\n%s", len(listed), out)
	}
}

// TestTLSCleanShortCertName: tls clean finds an expired certificate stored under a short
// name after autocert/cert-, deletes that object, and leaves alone a local file that
// merely shares the object's name.
func TestTLSCleanShortCertName(t *testing.T) {
	stub, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	cacheDir := t.TempDir()
	putServerCertificates(t, cfg, "mail.example.com")
	stub.put("certs", "autocert/cert-test", expiredAutocertEntry(t, "old.example.com"))
	writeLocalCertificates(t, cacheDir, "test")
	before := stub.keys()

	out := captureStdout(t, noPanic(func() error {
		return cleanTLSCertificates(context.Background(), cfg, cacheDir, true, false)
	}))
	if !strings.Contains(out, "Found 1 expired certificate(s)") || !strings.Contains(out, "old.example.com") {
		t.Errorf("tls clean --dry-run did not report the expired certificate:\n%s", out)
	}
	if got := stub.keys(); !slices.Equal(got, before) {
		t.Fatalf("dry run changed S3 objects: %v, want %v", got, before)
	}

	captureStdout(t, noPanic(func() error {
		return cleanTLSCertificates(context.Background(), cfg, cacheDir, false, true)
	}))
	want := slices.DeleteFunc(slices.Clone(before), func(k string) bool { return k == "/certs/autocert/cert-test" })
	if got := stub.keys(); !slices.Equal(got, want) {
		t.Errorf("S3 objects after clean = %v, want %v", got, want)
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "test")); err != nil {
		t.Errorf("tls clean removed the unrelated local file %q: %v", "test", err)
	}
}
