package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/migadu/sora/tlsmanager"
)

// autocertEntry returns a cache entry as autocert writes one (the private key PEM, then
// the certificate PEM) holding a self-signed certificate for domain that expires at
// notAfter, with an RSA key when useRSA is set and an ECDSA P-256 key otherwise.
func tlsCleanAutocertEntry(t *testing.T, domain string, useRSA bool, notAfter time.Time) []byte {
	t.Helper()
	var key crypto.Signer
	var keyBlock *pem.Block
	if useRSA {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		key, keyBlock = k, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	} else {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		key, keyBlock = k, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return append(pem.EncodeToMemory(keyBlock), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
}

// putServerEntry publishes valid entries through the server cache. Historical
// expired fixtures are seeded directly: the upgraded publisher refuses them.
func putServerEntry(t *testing.T, cfg AdminConfig, name string, data []byte) {
	t.Helper()
	var info CertificateInfo
	if parseCertificate(data, &info) == nil && !time.Now().Before(info.Expiry) {
		// This represents bytes published while valid and inspected after expiry.
		c := cfg.TLS.LetsEncrypt.S3
		req, err := http.NewRequest(http.MethodPut, c.Endpoint+"/"+c.Bucket+"/"+tlsmanager.S3ObjectKey(name), bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("historical fixture seed status=%d", resp.StatusCode)
		}
		return
	}
	cache, err := tlsmanager.NewS3Cache(cfg.TLS.LetsEncrypt.S3)
	if err != nil {
		t.Fatalf("NewS3Cache: %v", err)
	}
	if err := cache.Put(context.Background(), name, data); err != nil {
		t.Fatalf("Put %s: %v", name, err)
	}
}

// putExpiredEntries stores an expired ECDSA certificate for domain under "<domain>" and
// an expired RSA one under "<domain>+rsa", in S3 and, as the fallback cache (an
// autocert.DirCache) keeps them, in cacheDir.
func putExpiredEntries(t *testing.T, cfg AdminConfig, cacheDir, domain string) {
	t.Helper()
	expired := time.Now().Add(-24 * time.Hour)
	for name, data := range map[string][]byte{
		domain:          tlsCleanAutocertEntry(t, domain, false, expired),
		domain + "+rsa": tlsCleanAutocertEntry(t, domain, true, expired),
	} {
		putServerEntry(t, cfg, name, data)
		if err := os.WriteFile(filepath.Join(cacheDir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestTLSCleanRemovesExpiredLocalCopies: clean removes an expired certificate's local
// fallback copy for both of autocert's cache names, the RSA "<domain>+rsa" included,
// and leaves a valid domain's certificates alone in S3 and on disk.
func TestTLSCleanRemovesExpiredLocalCopies(t *testing.T) {
	stub, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	cacheDir := t.TempDir()

	valid := time.Now().Add(60 * 24 * time.Hour)
	for name, data := range map[string][]byte{
		"other.example.com":     tlsCleanAutocertEntry(t, "other.example.com", false, valid),
		"other.example.com+rsa": tlsCleanAutocertEntry(t, "other.example.com", true, valid),
	} {
		putServerEntry(t, cfg, name, data)
		if err := os.WriteFile(filepath.Join(cacheDir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	unexpired := stub.keys()
	putExpiredEntries(t, cfg, cacheDir, "mail.example.com")

	if err := cleanTLSCertificates(context.Background(), cfg, cacheDir, false, true); err != nil {
		t.Fatalf("cleanTLSCertificates: %v", err)
	}

	if got := stub.activeKeys(); !slices.Equal(got, unexpired) {
		t.Errorf("S3 objects after clean = %v, want only the valid domain's %v", got, unexpired)
	}
	if got, want := localNames(t, cacheDir), []string{"other.example.com", "other.example.com+rsa"}; !slices.Equal(got, want) {
		t.Errorf("local cache after clean = %v, want %v", got, want)
	}
}

// TestTLSCleanKeepsValidLocalCopy: the fallback cache can hold a renewal that has not
// reached S3 yet (the server wrote it locally while S3 was down). Clean deletes only
// expired certificates, so the expired S3 objects go and the valid local copies stay.
func TestTLSCleanKeepsValidLocalCopy(t *testing.T) {
	stub, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	cacheDir := t.TempDir()

	putExpiredEntries(t, cfg, cacheDir, "mail.example.com")
	valid := time.Now().Add(60 * 24 * time.Hour)
	renewals := map[string][]byte{
		"mail.example.com":     tlsCleanAutocertEntry(t, "mail.example.com", false, valid),
		"mail.example.com+rsa": tlsCleanAutocertEntry(t, "mail.example.com", true, valid),
	}
	for name, data := range renewals {
		if err := os.WriteFile(filepath.Join(cacheDir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}

	if err := cleanTLSCertificates(context.Background(), cfg, cacheDir, false, true); err != nil {
		t.Fatalf("cleanTLSCertificates: %v", err)
	}

	if got := stub.activeKeys(); len(got) != 0 {
		t.Errorf("S3 objects after clean = %v, want none", got)
	}
	for name, want := range renewals {
		got, err := os.ReadFile(filepath.Join(cacheDir, name))
		if err != nil {
			t.Errorf("valid local copy %s: %v", name, err)
		} else if !slices.Equal(got, want) {
			t.Errorf("valid local copy %s was changed", name)
		}
	}
}

// TestTLSCleanFailsWhenS3ConditionalWriteFails: a failed S3 conditional clear must fail the command, as it
// does for tls delete, instead of printing "Deleted 0 expired certificate(s)".
func TestTLSCleanFailsWhenS3ConditionalWriteFails(t *testing.T) {
	stub, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	putExpiredEntries(t, cfg, t.TempDir(), "mail.example.com")
	stub.mu.Lock()
	stub.putStatus = http.StatusInternalServerError
	stub.mu.Unlock()

	if err := cleanTLSCertificates(context.Background(), cfg, t.TempDir(), false, true); err == nil {
		t.Fatal("cleanTLSCertificates succeeded although the conditional S3 clear failed")
	}
}

// TestTLSCleanFailsWhenLocalDeleteFails: an expired local copy that cannot be removed
// must fail the command too.
func TestTLSCleanFailsWhenLocalDeleteFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	_, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	cacheDir := t.TempDir()
	putExpiredEntries(t, cfg, cacheDir, "mail.example.com")
	if err := os.Chmod(cacheDir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(cacheDir, 0700) })

	if err := cleanTLSCertificates(context.Background(), cfg, cacheDir, false, true); err == nil {
		t.Fatal("cleanTLSCertificates succeeded although the expired local copies could not be removed")
	}
}

// TestTLSCleanStaysInTheCacheDir: the local file clean removes is named by an autocert
// cache name, never by whatever name an expired certificate in the bucket carries. A
// certificate for "../victim" stored under that name's key must not make clean remove
// a file next to the cache directory (#937).
func TestTLSCleanStaysInTheCacheDir(t *testing.T) {
	stub, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	parent := t.TempDir()
	cacheDir := filepath.Join(parent, "certs")
	if err := os.Mkdir(cacheDir, 0700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(parent, "victim")
	if err := os.WriteFile(victim, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	stub.put("certs", tlsmanager.S3ObjectKey("../victim"), tlsCleanAutocertEntry(t, "../victim", false, time.Now().Add(-24*time.Hour)))

	if err := cleanTLSCertificates(context.Background(), cfg, cacheDir, false, true); err != nil {
		t.Fatalf("cleanTLSCertificates: %v", err)
	}

	if got := stub.activeKeys(); len(got) != 0 {
		t.Errorf("S3 objects after clean = %v, want none", got)
	}
	if _, err := os.Stat(victim); err != nil {
		t.Errorf("file outside the cache directory: %v", err)
	}
}

// TestTLSCleanFailsWhenACertificateCannotBeRead: clean cannot tell whether a certificate
// it failed to download has expired, so it must not report success; the certificates it
// did read are still cleaned.
func TestTLSCleanFailsWhenACertificateCannotBeRead(t *testing.T) {
	stub := &tlsStubS3{objects: make(map[string][]byte)}
	unreadable := "/certs/" + tlsmanager.S3ObjectKey("mail.example.com")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == unreadable {
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code><Message>stub failure</Message></Error>`)
			return
		}
		stub.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	cfg := tlsTestConfig(srv.URL)
	putExpiredEntries(t, cfg, t.TempDir(), "mail.example.com")

	if err := cleanTLSCertificates(context.Background(), cfg, t.TempDir(), false, true); err == nil {
		t.Fatal("cleanTLSCertificates succeeded although it could not read a certificate")
	}
	if got, want := stub.activeKeys(), []string{unreadable}; !slices.Equal(got, want) {
		t.Errorf("S3 objects after clean = %v, want only the unreadable %v", got, want)
	}
}
