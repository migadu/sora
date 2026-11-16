package tlsmanager

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"golang.org/x/crypto/acme/autocert"
)

type certificatePutBarrier struct {
	armed   atomic.Bool
	passed  atomic.Bool
	entered chan string
	release chan struct{}
	key     string
	store   *stubS3
}

func newCertificatePutBarrier(t *testing.T, name string) (*certificatePutBarrier, string) {
	t.Helper()
	b := &certificatePutBarrier{entered: make(chan string, 1), release: make(chan struct{}), key: "/certs/" + S3ObjectKey(name), store: &stubS3{objects: make(map[string][]byte)}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b.armed.Load() && r.Method == http.MethodPut && r.URL.Path == b.key && b.passed.CompareAndSwap(false, true) {
			b.entered <- r.Header.Get("If-Match")
			select {
			case <-b.release:
			case <-r.Context().Done():
				return
			}
		}
		b.store.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() {
		select {
		case <-b.release:
		default:
			close(b.release)
		}
	})
	return b, srv.URL
}
func waitCertificatePut(t *testing.T, b *certificatePutBarrier) {
	t.Helper()
	select {
	case etag := <-b.entered:
		if strings.TrimSpace(etag) == "" || etag == "*" {
			t.Fatal("publication did not carry an object-specific ETag")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("old publication did not reach HTTP barrier")
	}
}
func certificateTestValue(t *testing.T, serial int64) []byte {
	return certCacheEntry(t, "mail.example.com", serial, time.Now().Add(time.Duration(serial-10)*time.Hour), time.Now().Add(90*24*time.Hour))
}
func assertNoSharedCertificate(t *testing.T, c *S3Cache, name string) {
	t.Helper()
	data, err := c.Get(context.Background(), name)
	if !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("revoked shared entry visible: bytes=%d err=%v", len(data), err)
	}
}

func TestCertificateCASDeletionWinsInFlightPublication(t *testing.T) {
	const name = "mail.example.com"
	b, endpoint := newCertificatePutBarrier(t, name)
	c := newStubS3Cache(t, endpoint)
	ctx := context.Background()
	a := certificateTestValue(t, 1)
	if err := c.Put(ctx, name, a); err != nil {
		t.Fatal(err)
	}
	b.armed.Store(true)
	done := make(chan error, 1)
	go func() { done <- c.Put(ctx, name, a) }()
	waitCertificatePut(t, b)
	if err := c.MarkDeleted(ctx, S3ObjectKey(name), time.Now()); err != nil {
		t.Fatal(err)
	}
	close(b.release)
	select {
	case err := <-done:
		if !errors.Is(err, ErrCertificateRevoked) {
			t.Fatalf("old in-flight publication: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("old publisher did not finish")
	}
	assertNoSharedCertificate(t, c, name)
	b.store.mu.Lock()
	raw := append([]byte(nil), b.store.objects[b.key]...)
	b.store.mu.Unlock()
	data, state, err := decodeCertificateState(raw)
	if err != nil || len(data) != 0 || !state.Deleted {
		t.Fatalf("tombstone has an active payload: bytes=%d err=%v", len(data), err)
	}
	if bytes.Contains(raw, []byte("PRIVATE KEY")) {
		t.Fatal("tombstone retained private key material")
	}
}
func TestCertificateOldLeafCannotReturnAfterReplacementDeletion(t *testing.T) {
	const name = "mail.example.com"
	_, endpoint := newStubS3(t)
	c := newStubS3Cache(t, endpoint)
	ctx := context.Background()
	a, b := certificateTestValue(t, 1), certificateTestValue(t, 2)
	if err := c.Put(ctx, name, a); err != nil {
		t.Fatal(err)
	}
	_, oldGeneration, err := c.getSnapshot(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Put(ctx, name, b); err != nil {
		t.Fatal(err)
	}
	if err := c.MarkDeleted(ctx, S3ObjectKey(name), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := c.putGeneration(ctx, name, a, oldGeneration); !errors.Is(err, ErrCertificateRevoked) {
		t.Fatalf("old generation replay: %v", err)
	}
	if err := c.Put(ctx, name, a); !errors.Is(err, ErrCertificateRevoked) {
		t.Fatalf("previously published old leaf forgotten: %v", err)
	}
	assertNoSharedCertificate(t, c, name)
	replacement := certificateTestValue(t, 3)
	if err := c.Put(ctx, name, replacement); err != nil {
		t.Fatalf("post-barrier replacement refused: %v", err)
	}
	if err := c.putGeneration(ctx, name, a, oldGeneration); !errors.Is(err, ErrCertificateRevoked) {
		t.Fatalf("old leaf revived after replacement: %v", err)
	}
	got, err := c.Get(ctx, name)
	if err != nil || !bytes.Equal(got, replacement) {
		t.Fatalf("new replacement lost: bytes=%d err=%v", len(got), err)
	}
}
func TestQueuedFallbackPublicationHonorsLaterDeletion(t *testing.T) {
	const name = "mail.example.com"
	b, endpoint := newCertificatePutBarrier(t, name)
	c := newStubS3Cache(t, endpoint)
	ctx := context.Background()
	dir := t.TempDir()
	cache, err := NewFallbackCache(c, dir)
	if err != nil {
		t.Fatal(err)
	}
	fc := cache.(*FallbackCache)
	fc.checkInterval = 10 * time.Millisecond
	a := certificateTestValue(t, 1)
	if err := c.Put(ctx, name, a); err != nil {
		t.Fatal(err)
	}
	if _, err := fc.Get(ctx, name); err != nil {
		t.Fatal(err)
	}
	b.store.failPuts(http.StatusForbidden)
	if err := fc.Put(ctx, name, a); err != nil {
		t.Fatal(err)
	}
	b.store.failPuts(0)
	b.armed.Store(true)
	waitCertificatePut(t, b)
	if err := c.Put(ctx, name, certificateTestValue(t, 2)); err != nil {
		t.Fatal(err)
	}
	if err := c.MarkDeleted(ctx, S3ObjectKey(name), time.Now()); err != nil {
		t.Fatal(err)
	}
	close(b.release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, _, err := fc.localSnapshot(ctx, name)
		if errors.Is(err, autocert.ErrCacheMiss) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("queued revoked copy remained authoritative")
		}
		time.Sleep(5 * time.Millisecond)
	}
	assertNoSharedCertificate(t, c, name)
}
func TestUnknownLegacyCertificateCannotCrossBarrierOrRestart(t *testing.T) {
	const name = "mail.example.com"
	stub, endpoint := newStubS3(t)
	c := newStubS3Cache(t, endpoint)
	ctx := context.Background()
	dir := t.TempDir()
	a, b := certificateTestValue(t, 1), certificateTestValue(t, 2)
	// Older A was never observed by the new history. Only newer B is in S3.
	stub.mu.Lock()
	stub.objects["/certs/"+S3ObjectKey(name)] = b
	stub.mu.Unlock()
	if err := c.MarkDeleted(ctx, S3ObjectKey(name), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), a, 0644); err != nil {
		t.Fatal(err)
	}
	cache, err := NewFallbackCache(c, dir)
	if err != nil {
		t.Fatal(err)
	}
	fc := cache.(*FallbackCache)
	stub.failGets(http.StatusForbidden)
	if _, err := fc.Get(ctx, name); err == nil || errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("unverified outage copy was trusted or ordered anew: %v", err)
	}
	stub.failGets(0)
	if err := fc.SyncAllToS3(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
		t.Fatalf("unknown copy still authoritative: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	quarantined := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), localPrivatePrefix+"quarantine-") && !strings.HasSuffix(e.Name(), ".state") {
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil || !bytes.Equal(data, a) {
				t.Fatal("quarantine lost the unproven private copy")
			}
			info, err := e.Info()
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("quarantine copy is not private mode0600")
			}
			quarantined++
		}
	}
	if quarantined != 1 {
		t.Fatalf("quarantine copies=%d", quarantined)
	}
	// New manager and real autocert path must try fresh issuance, never return A.
	m, hits := newTestLetsEncryptManager(t, endpoint, func(le *config.TLSLetsEncryptConfig) { le.FallbackDir = dir })
	seedACMEAccountKey(t, m)
	cert, err := m.autocertMgr.GetCertificate(ecdsaClientHello(name))
	if err == nil || cert != nil {
		t.Fatal("restart served an unproven quarantined certificate")
	}
	if hits.Load() == 0 {
		t.Fatal("restart did not reach the fresh-issuance path")
	}
	assertNoSharedCertificate(t, c, name)
}
func TestFreshAutocertIssuanceAfterDeletionPublishesNewGeneration(t *testing.T) {
	const name = "mail.example.com"
	_, endpoint := newStubS3(t)
	c := newStubS3Cache(t, endpoint)
	ctx := context.Background()
	dir := t.TempDir()
	m, _ := newTestLetsEncryptManager(t, endpoint, func(le *config.TLSLetsEncryptConfig) { le.FallbackDir = dir })
	m.autocertMgr.Client.DirectoryURL = newIssuingACME(t)
	if err := c.Put(ctx, name, certificateTestValue(t, 1)); err != nil {
		t.Fatal(err)
	}
	if err := m.syncCertificateFromS3(ctx, name); err != nil {
		t.Fatal(err)
	}
	if err := c.MarkDeleted(ctx, S3ObjectKey(name), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := m.syncCertificateFromS3(ctx, name); err != nil {
		t.Fatal(err)
	}
	cert, err := m.autocertMgr.GetCertificate(ecdsaClientHello(name))
	if err != nil || cert == nil {
		t.Fatalf("fresh local ACME issuance: %v", err)
	}
	shared, err := c.Get(ctx, name)
	if err != nil {
		t.Fatalf("new generation was not published: %v", err)
	}
	if _, err := parseCertificate(shared); err != nil {
		t.Fatal(err)
	}
	// Account/challenge entries must remain usable through the same cache layers.
	account, err := m.autocertMgr.Cache.Get(ctx, "acme_account+key")
	if err != nil || len(account) == 0 {
		t.Fatalf("ACME account cache: bytes=%d err=%v", len(account), err)
	}
	if _, g, err := extractFallbackCache(m.autocertMgr.Cache).localSnapshot(ctx, name); err != nil || !g.Known || g.Value == "legacy" {
		t.Fatalf("new local publication provenance: %+v %v", g, err)
	}
}
