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
	"io"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
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
	return autocertEntry(t, name, time.Now().Add(-24*time.Hour))
}

// autocertEntry returns a certificate for name valid until notAfter, encoded as
// autocert caches it: the private key, then the certificate chain.
func autocertEntry(t *testing.T, name string, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
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
			if got := tryDecodeDomain(key, nil); got != want {
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

// TestTLSListLocalCacheIsTheObjectsOwnCopy: a local fallback cache file is the copy of
// the one object the server's S3 cache keys by its name. An older certificate for the
// same domain kept under another key (here autocert/cert-old) is not in the local
// cache, although the domain's own entry is.
func TestTLSListLocalCacheIsTheObjectsOwnCopy(t *testing.T) {
	stub, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	cacheDir := t.TempDir()
	serverKey := tlsmanager.S3ObjectKey("mail.example.com")
	stub.put("certs", serverKey, autocertEntry(t, "mail.example.com", time.Now().Add(60*24*time.Hour)))
	stub.put("certs", "autocert/cert-old", expiredAutocertEntry(t, "mail.example.com"))
	writeLocalCertificates(t, cacheDir, "mail.example.com")

	out := captureStdout(t, func() error {
		return listTLSCertificates(context.Background(), cfg, cacheDir, false, true)
	})

	var listed []struct {
		Domain       string `json:"domain"`
		S3Key        string `json:"s3Key"`
		InLocalCache bool   `json:"inLocalCache"`
	}
	if err := json.Unmarshal([]byte(out), &listed); err != nil {
		t.Fatalf("tls list --json printed invalid JSON: %v\n%s", err, out)
	}
	inCache := make(map[string]bool)
	for _, c := range listed {
		if c.Domain != "mail.example.com" {
			t.Errorf("%s listed as domain %q, want mail.example.com", c.S3Key, c.Domain)
		}
		inCache[c.S3Key] = c.InLocalCache
	}
	want := map[string]bool{serverKey: true, "autocert/cert-old": false}
	if !maps.Equal(inCache, want) {
		t.Errorf("in local cache by S3 key = %v, want %v", inCache, want)
	}
}

// TestTLSCleanRemovesOnlyTheObjectsOwnLocalCopy: tls clean removes the local fallback
// cache file of an expired entry the server keeps under that name, but an expired
// certificate kept under another key (here an old copy of the domain's certificate at
// autocert/cert-old) does not take the local copy of the domain's current entry.
func TestTLSCleanRemovesOnlyTheObjectsOwnLocalCopy(t *testing.T) {
	stub, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	cacheDir := t.TempDir()
	currentKey := tlsmanager.S3ObjectKey("mail.example.com")
	expiredKey := tlsmanager.S3ObjectKey("gone.example.com")
	stub.put("certs", currentKey, autocertEntry(t, "mail.example.com", time.Now().Add(60*24*time.Hour)))
	stub.put("certs", expiredKey, expiredAutocertEntry(t, "gone.example.com"))
	stub.put("certs", "autocert/cert-old", expiredAutocertEntry(t, "mail.example.com"))
	writeLocalCertificates(t, cacheDir, "mail.example.com", "gone.example.com")

	captureStdout(t, func() error {
		return cleanTLSCertificates(context.Background(), cfg, cacheDir, false, true)
	})

	if got, want := stub.keys(), []string{"/certs/" + currentKey}; !slices.Equal(got, want) {
		t.Errorf("S3 objects after clean = %v, want %v", got, want)
	}
	if got, want := localNames(t, cacheDir), []string{"mail.example.com"}; !slices.Equal(got, want) {
		t.Errorf("local cache after clean = %v, want %v", got, want)
	}
}

// TestTLSListNamesConfiguredDomainsItCannotRead: tls list names an object by the
// configured domain whose cache entry the server keeps at its key, also when it cannot
// read a certificate from it (the download fails, or the object holds none), and finds
// that entry's local fallback copy. The certificate's own name is not there to fall back
// on in that case. An object no configured domain keeps there is still shown by a hash
// prefix, since its key cannot be turned back into a name.
func TestTLSListNamesConfiguredDomainsItCannotRead(t *testing.T) {
	ecdsaKey := tlsmanager.S3ObjectKey("mail.example.com")
	rsaKey := tlsmanager.S3ObjectKey("mail.example.com+rsa")
	otherKey := tlsmanager.S3ObjectKey("old.example.com")

	stub := &tlsStubS3{objects: make(map[string][]byte)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/certs/"+ecdsaKey {
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code><Message>stub: access denied</Message></Error>`)
			return
		}
		stub.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	cfg := tlsTestConfig(srv.URL) // [tls.letsencrypt] domains = ["mail.example.com"]
	cacheDir := t.TempDir()
	stub.put("certs", ecdsaKey, expiredAutocertEntry(t, "mail.example.com"))
	stub.put("certs", rsaKey, []byte("not a certificate"))
	stub.put("certs", otherKey, []byte("not a certificate"))
	writeLocalCertificates(t, cacheDir, "mail.example.com", "mail.example.com+rsa", "old.example.com")

	out := captureStdout(t, func() error {
		return listTLSCertificates(context.Background(), cfg, cacheDir, false, true)
	})

	type listedCert struct {
		Domain       string `json:"domain"`
		CertType     string `json:"certType"`
		S3Key        string `json:"s3Key"`
		InLocalCache bool   `json:"inLocalCache"`
		LocalPath    string `json:"localPath"`
	}
	var listed []listedCert
	if err := json.Unmarshal([]byte(out), &listed); err != nil {
		t.Fatalf("tls list --json printed invalid JSON: %v\n%s", err, out)
	}
	got := make(map[string]listedCert)
	for _, c := range listed {
		got[c.S3Key] = c
	}
	want := map[string]listedCert{
		ecdsaKey: {"mail.example.com", "Error", ecdsaKey, true, filepath.Join(cacheDir, "mail.example.com")},
		rsaKey:   {"mail.example.com (RSA)", "Invalid", rsaKey, true, filepath.Join(cacheDir, "mail.example.com+rsa")},
		otherKey: {strings.TrimPrefix(otherKey, "autocert/cert-")[:16] + "...", "Invalid", otherKey, false, ""},
	}
	if !maps.Equal(got, want) {
		for key, w := range want {
			if got[key] != w {
				t.Errorf("%s listed as %+v, want %+v", key, got[key], w)
			}
		}
		if len(got) != len(want) {
			t.Errorf("listed %d objects, want %d:\n%s", len(got), len(want), out)
		}
	}
}
