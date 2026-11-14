package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/tlsmanager"
	"golang.org/x/crypto/acme/autocert"
)

// TestTLSCleanKeepsRenewalStoredWhileItRuns: a node renews an expired certificate after
// clean has read it and before clean deletes it (#954). The renewal must survive in the
// bucket and in the local cache. The bucket keeps versions, as a Backblaze B2 bucket
// always does. The node stores the renewal the way a running server does, through its S3
// cache and then autocert.DirCache, which renames a new file over the old one. It does so
// when clean's DELETE reaches the bucket, so after every read clean makes to decide.
func TestTLSCleanKeepsRenewalStoredWhileItRuns(t *testing.T) {
	stub, endpoint := newVersionedTLSStubS3(t)
	cacheDir := t.TempDir()
	expired := tlsCleanAutocertEntry(t, "mail.example.com", false, time.Now().Add(-time.Hour))
	renewal := tlsCleanAutocertEntry(t, "mail.example.com", false, time.Now().Add(60*24*time.Hour))
	putServerEntry(t, tlsTestConfig(endpoint), "mail.example.com", expired)
	if err := os.WriteFile(filepath.Join(cacheDir, "mail.example.com"), expired, 0600); err != nil {
		t.Fatal(err)
	}

	var renew sync.Once
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			renew.Do(func() {
				stub.put("certs", tlsmanager.S3ObjectKey("mail.example.com"), renewal)
				if err := autocert.DirCache(cacheDir).Put(context.Background(), "mail.example.com", renewal); err != nil {
					t.Error(err)
				}
			})
		}
		stub.ServeHTTP(w, r)
	}))
	t.Cleanup(node.Close)

	if err := cleanTLSCertificates(context.Background(), tlsTestConfig(node.URL), cacheDir, false, true); err != nil {
		t.Fatalf("cleanTLSCertificates: %v", err)
	}

	stub.mu.Lock()
	stored := stub.objects["/certs/"+tlsmanager.S3ObjectKey("mail.example.com")]
	stub.mu.Unlock()
	if !bytes.Equal(stored, renewal) {
		t.Error("clean deleted the renewal stored in S3 after it read the expired certificate")
	}
	local, err := os.ReadFile(filepath.Join(cacheDir, "mail.example.com"))
	if err != nil || !bytes.Equal(local, renewal) {
		t.Errorf("clean deleted the renewal stored in the local cache after it read the expired certificate (err = %v)", err)
	}
	if got, want := localNames(t, cacheDir), []string{"mail.example.com"}; !slices.Equal(got, want) {
		t.Errorf("local cache after clean = %v, want %v", got, want)
	}
}

// TestTLSCleanRemovesEveryExpiredVersion: deleting the version clean read brings back
// the version before it, an older certificate that has expired as well. Clean removes
// that one too, so the expired name is gone afterwards, as a plain delete leaves it,
// and the bucket does not serve an older expired certificate in its place.
func TestTLSCleanRemovesEveryExpiredVersion(t *testing.T) {
	stub, endpoint := newVersionedTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	putServerEntry(t, cfg, "other.example.com", tlsCleanAutocertEntry(t, "other.example.com", false, time.Now().Add(60*24*time.Hour)))
	valid := stub.keys()
	putServerEntry(t, cfg, "mail.example.com", tlsCleanAutocertEntry(t, "mail.example.com", false, time.Now().Add(-120*24*time.Hour)))
	putServerEntry(t, cfg, "mail.example.com", tlsCleanAutocertEntry(t, "mail.example.com", false, time.Now().Add(-24*time.Hour)))

	if err := cleanTLSCertificates(context.Background(), cfg, t.TempDir(), false, true); err != nil {
		t.Fatalf("cleanTLSCertificates: %v", err)
	}

	if got := stub.keys(); !slices.Equal(got, valid) {
		t.Errorf("S3 objects after clean = %v, want only the valid domain's %v", got, valid)
	}
}
