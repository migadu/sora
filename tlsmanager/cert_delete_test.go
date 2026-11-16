package tlsmanager

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"golang.org/x/crypto/acme/autocert"
)

// deleteFromBucket does to the bucket what sora-admin tls delete does to one cache entry:
// it leaves a deletion marker, autocert/deleted-<the entry's key hash>, holding the time
// of the deletion, and removes the certificate. The marker is a contract between
// sora-admin and every server that reads the bucket, which may run another version, so
// the test spells its format out instead of calling the code that writes it.
func deleteFromBucket(t *testing.T, stub *stubS3, name string, at time.Time) {
	t.Helper()

	certKey := S3ObjectKey(name)
	marker := "autocert/deleted-" + strings.TrimPrefix(certKey, "autocert/cert-")

	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.objects["/certs/"+marker] = []byte(at.UTC().Format(time.RFC3339Nano))
	delete(stub.objects, "/certs/"+certKey)
}

// TestCertificateDeletedFromS3IsNotWrittenBack: sora-admin tls delete removes a
// certificate from S3, and every other node still holds it in its local fallback cache.
// The sync worker read that as a certificate S3 never received and wrote it back, so the
// delete did not stick in a cluster. A node must drop a copy it stored before the
// deletion instead.
func TestCertificateDeletedFromS3IsNotWrittenBack(t *testing.T) {
	const domain = "mail.example.com"
	ctx := context.Background()

	for _, name := range []string{domain, domain + "+rsa"} {
		t.Run(name, func(t *testing.T) {
			stub, endpoint := newStubS3(t)
			fallbackDir := t.TempDir()
			m, _ := newTestLetsEncryptManager(t, endpoint, func(le *config.TLSLetsEncryptConfig) {
				le.FallbackDir = fallbackDir
			})
			shared := newStubS3Cache(t, endpoint)

			// The node holds the certificate the way every node does: its sync worker
			// copied it from S3 into the local fallback cache.
			cert := certCacheEntry(t, domain, 1, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
			if err := shared.Put(ctx, name, cert); err != nil {
				t.Fatalf("seeding S3: %v", err)
			}
			if err := m.syncCertificateFromS3(ctx, name); err != nil {
				t.Fatalf("initial sync: %v", err)
			}
			localPath := filepath.Join(fallbackDir, name)
			if _, err := os.Stat(localPath); err != nil {
				t.Fatalf("initial sync did not cache the certificate locally: %v", err)
			}

			deleteFromBucket(t, stub, name, time.Now())

			if err := m.syncCertificateFromS3(ctx, name); err != nil {
				t.Fatalf("sync after the deletion: %v", err)
			}

			if data, err := shared.Get(ctx, name); !errors.Is(err, autocert.ErrCacheMiss) {
				t.Errorf("S3 after the sync: %d bytes, err = %v; the deleted certificate was written back", len(data), err)
			}
			if _, err := os.Stat(localPath); !os.IsNotExist(err) {
				t.Errorf("local copy of the deleted certificate still in %s (stat err = %v)", fallbackDir, err)
			}
		})
	}
}

// TestCertificateStoredAfterDeletionReachesS3: a deletion marker covers only the copies
// stored before it. A certificate the node stores later while S3 refuses writes - such as
// the one issued to replace the deleted certificate - must still reach S3.
func TestCertificateStoredAfterDeletionReachesS3(t *testing.T) {
	const domain = "mail.example.com"
	ctx := context.Background()

	stub, endpoint := newStubS3(t)
	m, _ := newTestLetsEncryptManager(t, endpoint, func(le *config.TLSLetsEncryptConfig) {
		le.FallbackDir = t.TempDir()
	})
	shared := newStubS3Cache(t, endpoint)

	deleteFromBucket(t, stub, domain, time.Now().Add(-time.Hour))

	cert := certCacheEntry(t, domain, 2, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	stub.failPuts(http.StatusForbidden)
	if err := m.autocertMgr.Cache.Put(ctx, domain, cert); err != nil {
		t.Fatalf("storing certificate while S3 fails: %v", err)
	}
	stub.failPuts(0)

	if err := m.syncCertificateFromS3(ctx, domain); err != nil {
		t.Fatalf("certificate sync: %v", err)
	}

	got, err := shared.Get(ctx, domain)
	if err != nil {
		t.Fatalf("certificate stored after the deletion is not in S3 after a sync: %v", err)
	}
	if !bytes.Equal(got, cert) {
		t.Error("S3 holds something other than the certificate stored after the deletion")
	}
}

// TestExpiredCertificateIsNotWrittenBack: sora-admin tls clean removes expired
// certificates from S3 and leaves no deletion marker, since a node may hold a valid
// replacement under the same name that S3 has yet to receive. The sync must still not
// write an expired local copy back - it is of no use to any node - and drops it instead.
func TestExpiredCertificateIsNotWrittenBack(t *testing.T) {
	const domain = "mail.example.com"
	ctx := context.Background()

	stub, endpoint := newStubS3(t)
	fallbackDir := t.TempDir()
	m, _ := newTestLetsEncryptManager(t, endpoint, func(le *config.TLSLetsEncryptConfig) {
		le.FallbackDir = fallbackDir
	})
	shared := newStubS3Cache(t, endpoint)

	expired := certCacheEntry(t, domain, 1, time.Now().Add(-91*24*time.Hour), time.Now().Add(-24*time.Hour))
	// Seed a historical expired object directly; current publishers reject it.
	stub.mu.Lock()
	stub.objects["/certs/"+S3ObjectKey(domain)] = expired
	stub.mu.Unlock()
	if err := m.syncCertificateFromS3(ctx, domain); err != nil {
		t.Fatalf("initial sync: %v", err)
	}
	localPath := filepath.Join(fallbackDir, domain)
	if _, err := os.Stat(localPath); err != nil {
		t.Fatalf("initial sync did not cache the certificate locally: %v", err)
	}

	// What tls clean does to the bucket: the object goes, no marker is left.
	stub.mu.Lock()
	delete(stub.objects, "/certs/"+S3ObjectKey(domain))
	stub.mu.Unlock()

	if err := m.syncCertificateFromS3(ctx, domain); err != nil {
		t.Fatalf("sync after the clean: %v", err)
	}

	if data, err := shared.Get(ctx, domain); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Errorf("S3 after the sync: %d bytes, err = %v; the expired certificate was written back", len(data), err)
	}
	if _, err := os.Stat(localPath); !os.IsNotExist(err) {
		t.Errorf("expired local copy still in %s (stat err = %v)", fallbackDir, err)
	}
}
