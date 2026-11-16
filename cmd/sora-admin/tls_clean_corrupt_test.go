package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/migadu/sora/tlsmanager"
)

func tlsCleanECPrivateKeyPEM(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// TestTLSCleanPreservesUnparseableLocalCacheCopy verifies that when S3 holds an expired
// certificate for a domain whose local fallback cache file cannot be parsed as an X.509
// certificate (truncated/non-PEM data, private-key-only PEM, or malformed X.509 DER),
// tls clean leaves the local file untouched, still cleans the expired S3 object and other
// expired entries, and exits with a non-nil error.
func TestTLSCleanPreservesUnparseableLocalCacheCopy(t *testing.T) {
	cases := []struct {
		name      string
		localData []byte
	}{
		{
			name:      "non-pem",
			localData: []byte("partially written or non-certificate data"),
		},
		{
			name:      "private-key-only",
			localData: tlsCleanECPrivateKeyPEM(t),
		},
		{
			name:      "corrupt-x509-der",
			localData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("corrupt der bytes")}),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub, endpoint := newTLSStubS3(t)
			cfg := tlsTestConfig(endpoint)
			cacheDir := t.TempDir()

			expired := time.Now().Add(-24 * time.Hour)
			putServerEntry(t, cfg, "mail.example.com", tlsCleanAutocertEntry(t, "mail.example.com", false, expired))
			localFile := filepath.Join(cacheDir, "mail.example.com")
			if err := os.WriteFile(localFile, tc.localData, 0600); err != nil {
				t.Fatal(err)
			}

			putExpiredEntries(t, cfg, cacheDir, "other.example.com")

			err := cleanTLSCertificates(context.Background(), cfg, cacheDir, false, true)
			if err == nil {
				t.Errorf("cleanTLSCertificates succeeded although local cache file %s could not be parsed", localFile)
			}

			gotLocal, statErr := os.ReadFile(localFile)
			if statErr != nil {
				t.Fatalf("unparseable local cache file was removed or unreadable: %v", statErr)
			}
			if !bytes.Equal(gotLocal, tc.localData) {
				t.Errorf("local cache file contents changed: got %q, want %q", gotLocal, tc.localData)
			}

			if got := stub.activeKeys(); len(got) != 0 {
				t.Errorf("S3 objects after clean = %v, want none (expired S3 objects should still be cleaned)", got)
			}
			if got, want := localNames(t, cacheDir), []string{"mail.example.com"}; !slices.Equal(got, want) {
				t.Errorf("local cache files after clean = %v, want %v", got, want)
			}
		})
	}
}

// TestTLSCleanFailsOnCorruptS3Certificate verifies that corrupt or unparseable
// autocert/cert-* objects in S3 are not silently ignored as non-expired: clean leaves the
// corrupt S3 object and its local copy alone, cleans any valid expired certificates, and
// returns a non-nil error (including in --dry-run mode).
func TestTLSCleanFailsOnCorruptS3Certificate(t *testing.T) {
	corruptCases := []struct {
		name string
		data []byte
	}{
		{
			name: "non-pem",
			data: []byte("truncated s3 upload"),
		},
		{
			name: "private-key-only",
			data: tlsCleanECPrivateKeyPEM(t),
		},
		{
			name: "corrupt-x509-der",
			data: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("corrupt der bytes")}),
		},
	}

	for _, tc := range corruptCases {
		t.Run("only-"+tc.name, func(t *testing.T) {
			stub, endpoint := newTLSStubS3(t)
			cfg := tlsTestConfig(endpoint)
			cacheDir := t.TempDir()

			putServerEntry(t, cfg, "mail.example.com", tc.data)
			stub.put("certs", tlsmanager.S3ObjectKey("unconfigured.example.com"), tc.data)
			wantKeys := stub.keys()

			if err := cleanTLSCertificates(context.Background(), cfg, cacheDir, false, true); err == nil {
				t.Fatal("cleanTLSCertificates returned nil despite corrupt S3 certificate object")
			}
			if got := stub.keys(); !slices.Equal(got, wantKeys) {
				t.Errorf("S3 objects after clean = %v, want %v (corrupt S3 object must not be deleted)", got, wantKeys)
			}
		})

		t.Run("alongside-expired-"+tc.name, func(t *testing.T) {
			stub, endpoint := newTLSStubS3(t)
			cfg := tlsTestConfig(endpoint)
			cacheDir := t.TempDir()

			putServerEntry(t, cfg, "mail.example.com", tc.data)
			corruptS3Keys := stub.keys()
			localMail := filepath.Join(cacheDir, "mail.example.com")
			validLocal := tlsCleanAutocertEntry(t, "mail.example.com", false, time.Now().Add(-24*time.Hour))
			if err := os.WriteFile(localMail, validLocal, 0600); err != nil {
				t.Fatal(err)
			}

			putExpiredEntries(t, cfg, cacheDir, "other.example.com")
			allBeforeDryRun := stub.keys()

			if err := cleanTLSCertificates(context.Background(), cfg, cacheDir, true, false); err == nil {
				t.Error("cleanTLSCertificates --dry-run returned nil despite corrupt S3 certificate object")
			}
			if got := stub.keys(); !slices.Equal(got, allBeforeDryRun) {
				t.Fatalf("dry run modified S3 objects: got %v, want %v", got, allBeforeDryRun)
			}

			if err := cleanTLSCertificates(context.Background(), cfg, cacheDir, false, true); err == nil {
				t.Error("cleanTLSCertificates returned nil despite corrupt S3 certificate object")
			}
			if got := stub.activeKeys(); !slices.Equal(got, corruptS3Keys) {
				t.Errorf("S3 objects after clean = %v, want only corrupt object %v", got, corruptS3Keys)
			}
			if got, want := localNames(t, cacheDir), []string{"mail.example.com"}; !slices.Equal(got, want) {
				t.Errorf("local cache after clean = %v, want %v", got, want)
			}
		})
	}
}

// TestTLSCleanSkipsAutocertAccountKeys verifies that autocert's ACME account key entries
// ("acme_account+key" and legacy "acme_account.key"), which S3Cache stores under
// autocert/cert-<sha256> containing only a private key PEM block, are not flagged as
// corrupt certificates during tls clean.
func TestTLSCleanSkipsAutocertAccountKeys(t *testing.T) {
	stub, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	cacheDir := t.TempDir()

	keyPEM := tlsCleanECPrivateKeyPEM(t)
	putServerEntry(t, cfg, "acme_account+key", keyPEM)
	putServerEntry(t, cfg, "acme_account.key", keyPEM)
	accountKeys := stub.keys()

	putExpiredEntries(t, cfg, cacheDir, "mail.example.com")

	if err := cleanTLSCertificates(context.Background(), cfg, cacheDir, false, true); err != nil {
		t.Fatalf("cleanTLSCertificates failed when ACME account keys were present: %v", err)
	}
	if got := stub.activeKeys(); !slices.Equal(got, accountKeys) {
		t.Errorf("S3 objects after clean = %v, want ACME account keys %v", got, accountKeys)
	}
	if got := localNames(t, cacheDir); len(got) != 0 {
		t.Errorf("local cache after clean = %v, want empty", got)
	}
}

// TestTLSCleanContinuesWhenLocalCacheReadFails verifies that a failure reading one
// expired certificate's local cache entry does not abort cleanTLSCertificates before it
// cleans S3 and the remaining expired certificates; the unreadable local entry is left
// alone and the command returns a non-nil error at the end.
func TestTLSCleanContinuesWhenLocalCacheReadFails(t *testing.T) {
	t.Run("directory-in-cache", func(t *testing.T) {
		stub, endpoint := newTLSStubS3(t)
		cfg := tlsTestConfig(endpoint)
		cacheDir := t.TempDir()

		// S3ObjectKey("a.example.com") ("autocert/cert-0963...") sorts before
		// S3ObjectKey("mail.example.com") ("autocert/cert-4062..."), so a.example.com is
		// inspected first in the local-cache loop.
		expired := time.Now().Add(-24 * time.Hour)
		putServerEntry(t, cfg, "a.example.com", tlsCleanAutocertEntry(t, "a.example.com", false, expired))
		dirEntry := filepath.Join(cacheDir, "a.example.com")
		if err := os.Mkdir(dirEntry, 0700); err != nil {
			t.Fatal(err)
		}

		putExpiredEntries(t, cfg, cacheDir, "mail.example.com")

		err := cleanTLSCertificates(context.Background(), cfg, cacheDir, false, true)
		if err == nil {
			t.Fatal("cleanTLSCertificates succeeded although reading a local cache entry failed")
		}

		if got := stub.activeKeys(); len(got) != 0 {
			t.Errorf("S3 objects after clean = %v, want none (early abort left expired S3 certs uncleaned)", got)
		}
		if got, want := localNames(t, cacheDir), []string{"a.example.com"}; !slices.Equal(got, want) {
			t.Errorf("local cache after clean = %v, want %v", got, want)
		}
	})

	t.Run("unreadable-file", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root ignores file read permissions")
		}
		stub, endpoint := newTLSStubS3(t)
		cfg := tlsTestConfig(endpoint)
		cacheDir := t.TempDir()

		expired := time.Now().Add(-24 * time.Hour)
		putServerEntry(t, cfg, "a.example.com", tlsCleanAutocertEntry(t, "a.example.com", false, expired))
		unreadable := filepath.Join(cacheDir, "a.example.com")
		if err := os.WriteFile(unreadable, tlsCleanAutocertEntry(t, "a.example.com", false, expired), 0000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(unreadable, 0600) })

		putExpiredEntries(t, cfg, cacheDir, "mail.example.com")

		err := cleanTLSCertificates(context.Background(), cfg, cacheDir, false, true)
		if err == nil {
			t.Fatal("cleanTLSCertificates succeeded although reading a local cache file failed")
		}

		if got := stub.activeKeys(); len(got) != 0 {
			t.Errorf("S3 objects after clean = %v, want none (early abort left expired S3 certs uncleaned)", got)
		}
		if got, want := localNames(t, cacheDir), []string{"a.example.com"}; !slices.Equal(got, want) {
			t.Errorf("local cache after clean = %v, want %v", got, want)
		}
	})
}
