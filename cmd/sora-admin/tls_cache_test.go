package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
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

// validAutocertEntry returns a valid unexpired autocert cache entry for name ("<domain>"
// or "<domain>+rsa").
func validAutocertEntry(t *testing.T, name string) []byte {
	t.Helper()
	domain, useRSA := strings.CutSuffix(name, "+rsa")
	return tlsCleanAutocertEntry(t, domain, useRSA, time.Now().Add(60*24*time.Hour))
}

// tlsCacheStub serves the objects of a tlsStubS3 and answers a GET of the object at
// path with handle instead.
func tlsCacheStub(t *testing.T, path string, handle http.HandlerFunc) (*tlsStubS3, string) {
	t.Helper()
	stub := &tlsStubS3{objects: make(map[string][]byte)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == path {
			handle(w, r)
			return
		}
		stub.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return stub, srv.URL
}

// TestTLSCacheFailsWhenACertificateCannotBeDownloaded: a GET that fails with anything
// but NoSuchKey must fail tls cache and name the certificate, instead of a summary of
// "Cached: 0" and exit status 0 (#944). The other variant is still cached.
func TestTLSCacheFailsWhenACertificateCannotBeDownloaded(t *testing.T) {
	for _, tt := range []struct {
		status        int
		code, message string
	}{
		{http.StatusForbidden, "AccessDenied", "stub failure"},
		{http.StatusInternalServerError, "InternalError", "stub failure"},
		// The message is the provider's free text: an error that says "not found" but
		// is not NoSuchKey is a failure, not an absent certificate.
		{http.StatusNotFound, "NoSuchBucket", "Bucket not found"},
		{http.StatusForbidden, "AccessDenied", "Key not found in the allowed prefix"},
	} {
		t.Run(tt.code+"/"+tt.message, func(t *testing.T) {
			key := tlsmanager.S3ObjectKey("mail.example.com")
			_, endpoint := tlsCacheStub(t, "/certs/"+key, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message></Error>`, tt.code, tt.message)
			})
			cfg := tlsTestConfig(endpoint)
			putServerCertificates(t, cfg, "mail.example.com", "mail.example.com+rsa")
			cacheDir := t.TempDir()

			err := cacheTLSCertificates(context.Background(), cfg, cacheDir, "", false)
			if err == nil {
				t.Fatal("cacheTLSCertificates succeeded although a certificate could not be downloaded")
			}
			if !strings.Contains(err.Error(), key) {
				t.Errorf("error %q does not name the S3 object %s", err, key)
			}
			if got, want := localNames(t, cacheDir), []string{"mail.example.com+rsa"}; !slices.Equal(got, want) {
				t.Errorf("local cache = %v, want the readable variant %v", got, want)
			}
		})
	}
}

// TestTLSCacheFailsWhenACertificateCannotBeRead: a body that breaks off mid-read must
// fail tls cache too, and nothing may be written for it.
func TestTLSCacheFailsWhenACertificateCannotBeRead(t *testing.T) {
	key := tlsmanager.S3ObjectKey("mail.example.com")
	_, endpoint := tlsCacheStub(t, "/certs/"+key, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "4096")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "-----BEGIN")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		panic(http.ErrAbortHandler) // drop the connection before the declared length
	})
	cfg := tlsTestConfig(endpoint)
	putServerCertificates(t, cfg, "mail.example.com", "mail.example.com+rsa")
	cacheDir := t.TempDir()

	err := cacheTLSCertificates(context.Background(), cfg, cacheDir, "", false)
	if err == nil {
		t.Fatal("cacheTLSCertificates succeeded although a certificate could not be read")
	}
	if !strings.Contains(err.Error(), key) {
		t.Errorf("error %q does not name the S3 object %s", err, key)
	}
	if got, want := localNames(t, cacheDir), []string{"mail.example.com+rsa"}; !slices.Equal(got, want) {
		t.Errorf("local cache = %v, want the readable variant %v", got, want)
	}
}

// TestTLSCacheFailsWhenTheCacheDirIsNotWritable: certificates that cannot be written to
// the local cache must fail tls cache and name the files.
func TestTLSCacheFailsWhenTheCacheDirIsNotWritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	_, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	putServerCertificates(t, cfg, "mail.example.com", "mail.example.com+rsa")
	cacheDir := t.TempDir()
	if err := os.Chmod(cacheDir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(cacheDir, 0700) })

	err := cacheTLSCertificates(context.Background(), cfg, cacheDir, "", false)
	if err == nil {
		t.Fatal("cacheTLSCertificates succeeded although the cache directory is not writable")
	}
	for _, name := range []string{"mail.example.com", "mail.example.com+rsa"} {
		if path := filepath.Join(cacheDir, name); !strings.Contains(err.Error(), path) {
			t.Errorf("error %q does not name %s", err, path)
		}
	}
}

// TestTLSCacheMissingVariantIsNotAFailure: a variant that is not in S3 (autocert
// issues the RSA certificate only when a client asks for it) is no failure.
func TestTLSCacheMissingVariantIsNotAFailure(t *testing.T) {
	_, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	putServerCertificates(t, cfg, "mail.example.com")
	cacheDir := t.TempDir()

	if err := cacheTLSCertificates(context.Background(), cfg, cacheDir, "", false); err != nil {
		t.Fatalf("cacheTLSCertificates: %v", err)
	}
	if got, want := localNames(t, cacheDir), []string{"mail.example.com"}; !slices.Equal(got, want) {
		t.Errorf("local cache = %v, want %v", got, want)
	}
}

// TestTLSCacheDomainFailsWhenNothingIsInS3: tls cache --domain for a name with neither
// certificate in S3 must fail and name it, as tls delete --domain does, instead of
// "Not found: 2" and exit status 0 (#1759).
func TestTLSCacheDomainFailsWhenNothingIsInS3(t *testing.T) {
	_, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	cacheDir := t.TempDir()

	err := cacheTLSCertificates(context.Background(), cfg, cacheDir, "Mail.Example.com", false)
	if err == nil {
		t.Fatal("cacheTLSCertificates --domain succeeded although no certificate for the domain is in S3")
	}
	if !strings.Contains(err.Error(), "mail.example.com") {
		t.Errorf("error %q does not name the domain mail.example.com", err)
	}
	if got := localNames(t, cacheDir); len(got) != 0 {
		t.Errorf("local cache = %v, want it empty", got)
	}
}

// TestTLSCacheDomainFoundInS3IsNotAFailure: with --domain, one certificate of the name
// in S3 is enough, also an expired one that is therefore not cached; the RSA one is
// often absent.
func TestTLSCacheDomainFoundInS3IsNotAFailure(t *testing.T) {
	for _, tt := range []struct {
		name     string
		entry    string        // the one entry in S3
		notAfter time.Duration // its expiry, from now
		want     []string      // the local cache afterwards
	}{
		{"ECDSA only", "mail.example.com", 60 * 24 * time.Hour, []string{"mail.example.com"}},
		{"RSA only", "mail.example.com+rsa", 60 * 24 * time.Hour, []string{"mail.example.com+rsa"}},
		{"expired", "mail.example.com", -time.Hour, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, endpoint := newTLSStubS3(t)
			cfg := tlsTestConfig(endpoint)
			useRSA := strings.HasSuffix(tt.entry, "+rsa")
			putServerEntry(t, cfg, tt.entry, tlsCleanAutocertEntry(t, "mail.example.com", useRSA, time.Now().Add(tt.notAfter)))
			cacheDir := t.TempDir()

			if err := cacheTLSCertificates(context.Background(), cfg, cacheDir, "mail.example.com", false); err != nil {
				t.Fatalf("cacheTLSCertificates --domain: %v", err)
			}
			if got := localNames(t, cacheDir); !slices.Equal(got, tt.want) {
				t.Errorf("local cache = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestTLSCacheAllDomainsNotInS3IsNotAFailure: without --domain, a configured domain
// with no certificate in S3 (not issued yet) is no failure, even when no configured
// domain has one.
func TestTLSCacheAllDomainsNotInS3IsNotAFailure(t *testing.T) {
	for _, tt := range []struct {
		name   string
		stored []string // the entries in S3
	}{
		{"none issued", nil},
		{"one of two issued", []string{"mail.example.com"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, endpoint := newTLSStubS3(t)
			cfg := tlsTestConfig(endpoint)
			cfg.TLS.LetsEncrypt.Domains = []string{"mail.example.com", "imap.example.com"}
			putServerCertificates(t, cfg, tt.stored...)
			cacheDir := t.TempDir()

			if err := cacheTLSCertificates(context.Background(), cfg, cacheDir, "", false); err != nil {
				t.Fatalf("cacheTLSCertificates: %v", err)
			}
			if got := localNames(t, cacheDir); !slices.Equal(got, tt.stored) {
				t.Errorf("local cache = %v, want %v", got, tt.stored)
			}
		})
	}
}

// TestTLSCacheFailsWhenACertificateIsCorrupt: when S3 answers 200 OK with empty,
// truncated, or unparseable certificate bytes, tls cache must reject that entry,
// refuse to write the corrupt payload into the local fallback cache, name the S3
// object in its error, and still cache valid domains.
func TestTLSCacheFailsWhenACertificateIsCorrupt(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	keyOnlyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})
	corruptCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("corrupt der bytes")})

	cases := []struct {
		name string
		body []byte
	}{
		{"empty", []byte{}},
		{"non-pem", []byte("not a certificate")},
		{"private-key-only", keyOnlyPEM},
		{"corrupt-der", corruptCertPEM},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, endpoint := newTLSStubS3(t)
			cfg := tlsTestConfig(endpoint)
			cfg.TLS.LetsEncrypt.Domains = []string{"mail.example.com", "other.example.com"}

			s3Key := tlsmanager.S3ObjectKey("mail.example.com")
			putServerEntry(t, cfg, "mail.example.com", tc.body)
			validOther := validAutocertEntry(t, "other.example.com")
			putServerEntry(t, cfg, "other.example.com", validOther)

			cacheDir := t.TempDir()
			err := cacheTLSCertificates(context.Background(), cfg, cacheDir, "", false)
			if err == nil {
				t.Fatalf("cacheTLSCertificates succeeded although S3 returned %s certificate bytes", tc.name)
			}
			if !strings.Contains(err.Error(), s3Key) {
				t.Errorf("error %q does not name the S3 object %s", err, s3Key)
			}
			if got, want := localNames(t, cacheDir), []string{"other.example.com"}; !slices.Equal(got, want) {
				t.Errorf("local cache = %v, want only the valid domain %v", got, want)
			}
			gotOther, err := os.ReadFile(filepath.Join(cacheDir, "other.example.com"))
			if err != nil {
				t.Fatalf("reading cached valid domain: %v", err)
			}
			if !bytes.Equal(gotOther, validOther) {
				t.Error("cached valid domain does not match the S3 object")
			}
		})
	}
}

// TestTLSCacheForceDoesNotOverwriteValidLocalCopyWithCorruptS3Object: with --force, a
// corrupt S3 object must be rejected before touching localPath so an existing valid
// certificate in the local fallback cache is preserved.
func TestTLSCacheForceDoesNotOverwriteValidLocalCopyWithCorruptS3Object(t *testing.T) {
	_, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	cfg.TLS.LetsEncrypt.Domains = []string{"mail.example.com", "other.example.com"}

	cacheDir := t.TempDir()
	existingValid := validAutocertEntry(t, "mail.example.com")
	if err := os.WriteFile(filepath.Join(cacheDir, "mail.example.com"), existingValid, 0600); err != nil {
		t.Fatal(err)
	}

	s3Key := tlsmanager.S3ObjectKey("mail.example.com")
	corrupt := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("truncated der")})
	putServerEntry(t, cfg, "mail.example.com", corrupt)

	validOther := validAutocertEntry(t, "other.example.com")
	putServerEntry(t, cfg, "other.example.com", validOther)

	err := cacheTLSCertificates(context.Background(), cfg, cacheDir, "", true)
	if err == nil {
		t.Fatal("cacheTLSCertificates --force succeeded although S3 returned a corrupt certificate")
	}
	if !strings.Contains(err.Error(), s3Key) {
		t.Errorf("error %q does not name the S3 object %s", err, s3Key)
	}

	gotLocal, err := os.ReadFile(filepath.Join(cacheDir, "mail.example.com"))
	if err != nil {
		t.Fatalf("reading existing local copy: %v", err)
	}
	if !bytes.Equal(gotLocal, existingValid) {
		t.Error("--force overwrote the existing valid local certificate with corrupt S3 bytes")
	}

	gotOther, err := os.ReadFile(filepath.Join(cacheDir, "other.example.com"))
	if err != nil {
		t.Fatalf("reading cached valid domain: %v", err)
	}
	if !bytes.Equal(gotOther, validOther) {
		t.Error("cached valid domain does not match the S3 object")
	}
}
