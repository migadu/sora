package tlsmanager

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

type certificateAfterDelete struct {
	*S3Cache
	after func() error
}

func (c *certificateAfterDelete) Delete(ctx context.Context, name string) error {
	if err := c.S3Cache.Delete(ctx, name); err != nil {
		return err
	}
	return c.after()
}

func TestFallbackDeletePreservesPostBarrierLocalPublication(t *testing.T) {
	for _, mode := range []string{"renewal", "initially_absent", "same_payload_new_generation", "account_key"} {
		t.Run(mode, func(t *testing.T) {
			const name = "mail.example.com"
			ctx := context.Background()
			_, endpoint := newStubS3(t)
			c := newStubS3Cache(t, endpoint)
			p := &certificateAfterDelete{S3Cache: c}
			cache, err := NewFallbackCache(p, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			fc := cache.(*FallbackCache)
			a, b := certificateTestValue(t, 1), certificateTestValue(t, 2)
			if mode == "account_key" {
				a, b = []byte("old-account-key-fixture"), []byte("new-account-key-fixture")
			}
			if err := fc.Put(ctx, name, a); err != nil {
				t.Fatal(err)
			}
			if mode == "initially_absent" {
				if err := fc.fallback.Delete(ctx, name); err != nil {
					t.Fatal(err)
				}
			}
			p.after = func() error {
				// This callback executes after the real HTTP CAS barrier, before Delete's
				// local phase. A separate new publication is allowed in that generation.
				if mode == "same_payload_new_generation" {
					_, g, err := c.getSnapshot(ctx, name)
					if err != autocert.ErrCacheMiss || !g.Known {
						return fmt.Errorf("missing deletion generation: %w", err)
					}
					b = a
					return fc.storeLocal(ctx, name, b, g)
				}
				return fc.Put(ctx, name, b)
			}
			if err := fc.Delete(ctx, name); err != nil {
				t.Fatal(err)
			}
			got, g, err := fc.localSnapshot(ctx, name)
			if err != nil || !bytes.Equal(got, b) || !g.Known || g.Value == "legacy" {
				t.Fatalf("new local publication lost: bytes=%d known=%v err=%v", len(got), g.Known, err)
			}
		})
	}
}

func TestSyncReconcilesGenerationBeforeEqualValidity(t *testing.T) {
	for _, known := range []bool{true, false} {
		t.Run(fmt.Sprintf("known_%v", known), func(t *testing.T) {
			const name = "mail.example.com"
			ctx := context.Background()
			_, endpoint := newStubS3(t)
			c := newStubS3Cache(t, endpoint)
			dir := t.TempDir()
			cache, err := NewFallbackCache(c, dir)
			if err != nil {
				t.Fatal(err)
			}
			fc := cache.(*FallbackCache)
			start, end := time.Now().Add(-time.Hour).Truncate(time.Second), time.Now().Add(24*time.Hour).Truncate(time.Second)
			a := certCacheEntry(t, name, 901, start, end)
			b := certCacheEntry(t, name, 902, start, end)
			if err := fc.Put(ctx, name, a); err != nil {
				t.Fatal(err)
			}
			if !known {
				if err := os.Remove(localEntryPath(dir, localMetadataName(name))); err != nil {
					t.Fatal(err)
				}
			}
			if err := c.Delete(ctx, name); err != nil {
				t.Fatal(err)
			}
			if err := c.Put(ctx, name, b); err != nil {
				t.Fatal(err)
			}
			m := &Manager{autocertMgr: &autocert.Manager{Cache: fc}}
			if err := m.syncCertificateFromS3(ctx, name); err != nil {
				t.Fatal(err)
			}
			got, localGeneration, err := fc.localSnapshot(ctx, name)
			_, sharedGeneration, sharedErr := c.getSnapshot(ctx, name)
			if err != nil || sharedErr != nil || !bytes.Equal(got, b) || localGeneration != sharedGeneration {
				t.Fatalf("generation reconciliation kept old equal-validity leaf: bytes=%d local=%v shared=%v err=%v/%v", len(got), localGeneration, sharedGeneration, err, sharedErr)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			quarantines := 0
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), localPrivatePrefix+"quarantine-") && !strings.HasSuffix(e.Name(), ".state") {
					quarantines++
				}
			}
			if known && quarantines != 0 || !known && quarantines != 1 {
				t.Fatalf("quarantine count=%d known=%v", quarantines, known)
			}
		})
	}
}

func TestLocalSnapshotActionsPreserveSamePayloadNewGeneration(t *testing.T) {
	ctx := context.Background()
	c := &localCertificateCache{dir: t.TempDir()}
	a, b := publicationGeneration{Known: true, Value: "old"}, publicationGeneration{Known: true, Value: "new"}
	for _, action := range []string{"remove", "replace", "quarantine"} {
		t.Run(action, func(t *testing.T) {
			data := []byte("unchanged-payload")
			if err := c.putSnapshot(ctx, "entry", data, b); err != nil {
				t.Fatal(err)
			}
			var err error
			switch action {
			case "remove":
				_, err = c.deleteIfSame(ctx, "entry", data, a)
			case "replace":
				_, err = c.replaceIfSame(ctx, "entry", data, true, []byte("stale-replacement"), a, a)
			case "quarantine":
				err = c.quarantineIfSame(ctx, "entry", data, a)
			}
			if err != nil {
				t.Fatal(err)
			}
			got, g, err := c.snapshot(ctx, "entry")
			if err != nil || !bytes.Equal(got, data) || g != b {
				t.Fatalf("new generation changed: bytes=%d generation=%v err=%v", len(got), g, err)
			}
		})
	}
}

func TestCleanupMetadataRejectsNonSpecificETag(t *testing.T) {
	for _, tag := range []string{"", "*"} {
		for _, op := range []string{"queue", "ack"} {
			t.Run(fmt.Sprintf("%s_%q", op, tag), func(t *testing.T) {
				state := certificateState{Version: 1, Generation: "legacy", Absent: true}
				pendingVersion(&state, "expired-v1", time.Now().Add(-time.Hour))
				raw, err := encodeCertificateState(nil, state)
				if err != nil {
					t.Fatal(err)
				}
				var puts atomic.Int32
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodHead {
						return
					}
					if r.Method == http.MethodPut {
						puts.Add(1)
						return
					}
					if r.URL.Query().Has("versions") {
						w.Header().Set("Content-Type", "application/xml")
						fmt.Fprint(w, `<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><IsTruncated>false</IsTruncated></ListVersionsResult>`)
						return
					}
					if tag != "" {
						w.Header().Set("ETag", tag)
					}
					w.Write(raw)
				}))
				defer srv.Close()
				c := newStubS3Cache(t, srv.URL)
				if op == "queue" {
					err = c.QueueExpiredVersion(context.Background(), S3ObjectKey("mail.example.com"), "expired-v2", time.Now())
				} else {
					_, err = c.CleanupExpiredVersions(context.Background(), S3ObjectKey("mail.example.com"), time.Now())
				}
				if err == nil || puts.Load() != 0 {
					t.Fatalf("non-specific ETag accepted: err=%v puts=%d", err, puts.Load())
				}
			})
		}
	}
}

func TestExpiredPublicationCannotCrossCleanConflict(t *testing.T) {
	const name = "mail.example.com"
	ctx := context.Background()
	b, endpoint := newCertificatePutBarrier(t, name)
	c := newStubS3Cache(t, endpoint)
	cache, err := NewFallbackCache(c, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fc := cache.(*FallbackCache)
	// The first publication is valid. The HTTP barrier then spans actual expiry,
	// a successful CLEAN CAS, and the old publisher's conditional retry.
	expiry := time.Now().Add(3 * time.Second).Truncate(time.Second)
	a := certCacheEntry(t, name, 950, time.Now().Add(-time.Hour), expiry)
	if err := fc.Put(ctx, name, a); err != nil {
		t.Fatal(err)
	}
	_, g, err := fc.localSnapshot(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	b.armed.Store(true)
	done := make(chan error, 1)
	go func() { done <- publishLocalSnapshot(ctx, fc, name, a, g) }()
	waitCertificatePut(t, b)
	timer := time.NewTimer(time.Until(expiry) + 20*time.Millisecond)
	defer timer.Stop()
	<-timer.C
	b.store.mu.Lock()
	current := append([]byte(nil), b.store.objects[b.key]...)
	b.store.mu.Unlock()
	// The stub's opaque ETag is computed exactly as for its GET response.
	etag := fmt.Sprintf(`"%x"`, sha256.Sum256(current))
	removed, err := c.ExpireObject(ctx, S3ObjectKey(name), etag, time.Now())
	if err != nil || !removed {
		t.Fatalf("clean did not establish vacancy: removed=%v err=%v", removed, err)
	}
	close(b.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("publisher did not finish")
	}
	assertNoSharedCertificate(t, c, name)
	if _, _, err := fc.localSnapshot(ctx, name); err != autocert.ErrCacheMiss {
		t.Fatalf("expired local snapshot remains: %v", err)
	}
	renewal := certificateTestValue(t, 3)
	if err := c.putGeneration(ctx, name, renewal, g); err != nil {
		t.Fatalf("valid same-generation renewal after CLEAN refused: %v", err)
	}
	got, err := c.Get(ctx, name)
	if err != nil || !bytes.Equal(got, renewal) {
		t.Fatalf("valid renewal lost: bytes=%d err=%v", len(got), err)
	}
}
