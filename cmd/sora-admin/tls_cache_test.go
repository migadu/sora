package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/migadu/sora/tlsmanager"
)

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
