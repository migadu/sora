//go:build unix

package tlsmanager

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/sys/unix"
)

func TestS3CacheChallengeDeleteRemovesObjectsWithoutTombstones(t *testing.T) {
	ctx := context.Background()
	stub, endpoint := newStubS3(t)
	cache := newStubS3Cache(t, endpoint)

	now := time.Now().UTC().Truncate(time.Second)
	tokenCert := certCacheEntry(t, "mail.example.com", 1, now.Add(-time.Minute), now.Add(24*time.Hour))

	cases := []struct {
		name  string
		key   string
		value []byte
	}{
		{name: "tls-alpn-01 token", key: "mail.example.com+token", value: tokenCert},
		{name: "http-01 token", key: "abc123+http-01", value: []byte("abc123.thumbprint")},
		{name: "acme account key", key: "acme_account+key", value: []byte("-----BEGIN EC PRIVATE KEY-----\ntest\n-----END EC PRIVATE KEY-----\n")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := cache.Put(ctx, tc.key, tc.value); err != nil {
				t.Fatalf("Put(%q): %v", tc.key, err)
			}
			got, err := cache.Get(ctx, tc.key)
			if err != nil || !bytes.Equal(got, tc.value) {
				t.Fatalf("Get(%q) before Delete: bytes=%d err=%v", tc.key, len(got), err)
			}
			if err := cache.Delete(ctx, tc.key); err != nil {
				t.Fatalf("Delete(%q): %v", tc.key, err)
			}
			if _, err := cache.Get(ctx, tc.key); !errors.Is(err, autocert.ErrCacheMiss) {
				t.Fatalf("Get(%q) after Delete: err=%v, want autocert.ErrCacheMiss", tc.key, err)
			}

			objPath := "/certs/" + S3ObjectKey(tc.key)
			marker, _ := deletionMarkerKey(S3ObjectKey(tc.key))
			markerPath := "/certs/" + marker

			stub.mu.Lock()
			_, hasObj := stub.objects[objPath]
			_, hasMarker := stub.objects[markerPath]
			stub.mu.Unlock()

			if hasObj {
				t.Errorf("Delete(%q) left S3 tombstone object at %s", tc.key, objPath)
			}
			if hasMarker {
				t.Errorf("Delete(%q) left S3 deletion marker at %s", tc.key, markerPath)
			}
		})
	}

	// Real certificate keys must still record a deletion tombstone + marker.
	const domain = "mail.example.com"
	domainCert := certCacheEntry(t, domain, 10, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	if err := cache.Put(ctx, domain, domainCert); err != nil {
		t.Fatalf("Put(%q): %v", domain, err)
	}
	if err := cache.Delete(ctx, domain); err != nil {
		t.Fatalf("Delete(%q): %v", domain, err)
	}
	stub.mu.Lock()
	rawTombstone, hasDomainObj := stub.objects["/certs/"+S3ObjectKey(domain)]
	domainMarker, _ := deletionMarkerKey(S3ObjectKey(domain))
	_, hasDomainMarker := stub.objects["/certs/"+domainMarker]
	stub.mu.Unlock()
	if !hasDomainObj || !hasDomainMarker {
		t.Fatalf("Delete(%q) must keep certificate deletion fence: obj=%v marker=%v", domain, hasDomainObj, hasDomainMarker)
	}
	if data, state, err := decodeCertificateState(rawTombstone); err != nil || len(data) != 0 || !state.Deleted {
		t.Fatalf("Delete(%q) tombstone invalid: len=%d deleted=%v err=%v", domain, len(data), state.Deleted, err)
	}
}

func TestChallengeTokenRotationAcrossCacheStack(t *testing.T) {
	const domain = "mail.example.com"
	const tokenKey = domain + "+token"
	const httpKey = "probe-token+http-01"

	stub, endpoint := newStubS3(t)
	leaderDir := t.TempDir()
	followerDir := t.TempDir()

	leaderMgr, _ := newTestLetsEncryptManager(t, endpoint, func(le *config.TLSLetsEncryptConfig) {
		le.FallbackDir = leaderDir
	})
	followerMgr, _ := newTestLetsEncryptManager(t, endpoint, func(le *config.TLSLetsEncryptConfig) {
		le.FallbackDir = followerDir
	})
	leaderCache := leaderMgr.autocertMgr.Cache
	followerCache := followerMgr.autocertMgr.Cache

	now := time.Now().UTC().Truncate(time.Second)
	cert1 := certCacheEntry(t, domain, 101, now, now.Add(24*time.Hour))
	cert2 := certCacheEntry(t, domain, 102, now, now.Add(24*time.Hour))
	cert3 := certCacheEntry(t, domain, 103, now, now.Add(24*time.Hour))

	// Shared exchange deadline (e.g. retries or sibling orders within the same deadline).
	exchangeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Direct S3Cache back-to-back same-second Put -> Put and Put -> Delete -> Put
	// (including when a pre-Delete generation was already captured in ctx).
	s3Cache := newStubS3Cache(t, endpoint)
	if err := s3Cache.Put(context.Background(), tokenKey, cert1); err != nil {
		t.Fatalf("s3Cache first Put(%q): %v", tokenKey, err)
	}
	_, preDeleteGen, _ := s3Cache.getSnapshot(context.Background(), tokenKey)
	if err := s3Cache.Put(context.Background(), tokenKey, cert2); err != nil {
		t.Fatalf("s3Cache second same-second Put(%q): %v", tokenKey, err)
	}
	if got, err := s3Cache.Get(context.Background(), tokenKey); err != nil || !bytes.Equal(got, cert2) {
		t.Errorf("s3Cache Get(%q) after same-second overwrite: match_cert1=%v err=%v", tokenKey, bytes.Equal(got, cert1), err)
	}
	if err := s3Cache.Delete(context.Background(), tokenKey); err != nil {
		t.Fatalf("s3Cache Delete(%q): %v", tokenKey, err)
	}
	if err := s3Cache.Put(generationContext(context.Background(), preDeleteGen), tokenKey, cert3); err != nil {
		t.Errorf("s3Cache Put(%q) after Delete failed (revoked generation): %v", tokenKey, err)
	}
	_ = s3Cache.Delete(context.Background(), tokenKey)

	// 1. Same-second Put -> Put without Delete across full manager stack must replace cert1 with cert2.
	if err := leaderCache.Put(exchangeCtx, tokenKey, cert1); err != nil {
		t.Fatalf("first Put(%q): %v", tokenKey, err)
	}
	got1, err := followerCache.Get(context.Background(), tokenKey)
	if err != nil || !bytes.Equal(got1, cert1) {
		t.Fatalf("follower Get(%q) #1: bytes=%d err=%v", tokenKey, len(got1), err)
	}
	if err := leaderCache.Put(exchangeCtx, tokenKey, cert2); err != nil {
		t.Fatalf("second same-second Put(%q): %v", tokenKey, err)
	}
	got2, err := followerCache.Get(context.Background(), tokenKey)
	if err != nil || !bytes.Equal(got2, cert2) {
		t.Fatalf("follower Get(%q) after same-second overwrite returned stale or missing cert: match_cert1=%v err=%v",
			tokenKey, bytes.Equal(got2, cert1), err)
	}

	// 2. Same-second Put -> Delete -> Put (e.g. ECDSA order cleanup then +rsa order) must
	// neither fail with ErrCertificateRevoked nor leave stale local copies on followers.
	if err := leaderCache.Delete(context.Background(), tokenKey); err != nil {
		t.Fatalf("Delete(%q): %v", tokenKey, err)
	}
	if _, err := followerCache.Get(context.Background(), tokenKey); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("follower Get(%q) after Delete: err=%v, want autocert.ErrCacheMiss", tokenKey, err)
	}
	if err := leaderCache.Put(exchangeCtx, tokenKey, cert3); err != nil {
		t.Fatalf("Put(%q) after Delete: %v", tokenKey, err)
	}
	got3, err := followerCache.Get(context.Background(), tokenKey)
	if err != nil || !bytes.Equal(got3, cert3) {
		t.Fatalf("follower Get(%q) after Delete+Put: match_cert2=%v err=%v", tokenKey, bytes.Equal(got3, cert2), err)
	}
	if err := leaderCache.Delete(context.Background(), tokenKey); err != nil {
		t.Fatalf("final Delete(%q): %v", tokenKey, err)
	}

	// 3. Unauthenticated HTTP-01 cache misses must not allocate local .sora-lock-* files.
	probeCtx, probeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer probeCancel()
	if _, err := followerCache.Get(probeCtx, httpKey); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("Get(%q): err=%v, want autocert.ErrCacheMiss", httpKey, err)
	}
	entries, err := os.ReadDir(followerDir)
	if err != nil {
		t.Fatalf("ReadDir(followerDir): %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("challenge operations polluted follower fallback dir: %v", names)
	}

	stub.mu.Lock()
	remaining := len(stub.objects)
	stub.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("expected 0 remaining S3 objects after challenge cleanup, got %d", remaining)
	}
}

func TestSameSecondCertificateReplacementInSameGeneration(t *testing.T) {
	const domain = "mail.example.com"
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	cert1 := certCacheEntry(t, domain, 201, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	cert2 := certCacheEntry(t, domain, 202, now.Add(-time.Hour), now.Add(90*24*time.Hour))

	if olderCertificate(cert2, cert1) {
		t.Fatalf("olderCertificate(cert2, cert1) = true for identical NotBefore/NotAfter")
	}
	if olderCertificate(cert1, cert2) {
		t.Fatalf("olderCertificate(cert1, cert2) = true for identical NotBefore/NotAfter")
	}

	_, endpoint := newStubS3(t)
	s3Cache := newStubS3Cache(t, endpoint)
	if err := s3Cache.Put(ctx, domain, cert1); err != nil {
		t.Fatalf("S3Cache.Put cert1: %v", err)
	}
	if err := s3Cache.Put(ctx, domain, cert2); err != nil {
		t.Fatalf("S3Cache.Put cert2: %v", err)
	}
	gotS3, err := s3Cache.Get(ctx, domain)
	if err != nil || !bytes.Equal(gotS3, cert2) {
		t.Fatalf("S3Cache dropped same-second replacement cert2: match_cert1=%v err=%v", bytes.Equal(gotS3, cert1), err)
	}

	localCache := &localCertificateCache{dir: t.TempDir()}
	gen := publicationGeneration{Value: "gen-1", Known: true}
	if err := localCache.putSnapshot(ctx, domain, cert1, gen); err != nil {
		t.Fatalf("local putSnapshot cert1: %v", err)
	}
	if err := localCache.putSnapshot(ctx, domain, cert2, gen); err != nil {
		t.Fatalf("local putSnapshot cert2: %v", err)
	}
	gotLocal, gotGen, err := localCache.snapshot(ctx, domain)
	if err != nil || gotGen != gen || !bytes.Equal(gotLocal, cert2) {
		t.Fatalf("localCertificateCache dropped same-second replacement cert2: match_cert1=%v gen=%+v err=%v",
			bytes.Equal(gotLocal, cert1), gotGen, err)
	}
}

func TestReadLocalRegularRefusesSymlinksInsideCacheDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "secret"), []byte("do-not-follow"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("secret", filepath.Join(dir, "mail.example.com")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing-target", filepath.Join(dir, "dangling.example.com")); err != nil {
		t.Fatal(err)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	for _, name := range []string{"mail.example.com", "dangling.example.com"} {
		t.Run(name, func(t *testing.T) {
			data, err := readLocalRegular(root, name)
			if err == nil {
				t.Fatalf("readLocalRegular(%q) followed symlink and returned %q", name, data)
			}
			if os.IsNotExist(err) || errors.Is(err, autocert.ErrCacheMiss) {
				t.Fatalf("readLocalRegular(%q) reported symlink as missing: %v", name, err)
			}

			c := &localCertificateCache{dir: dir}
			got, err := c.Get(context.Background(), name)
			if err == nil {
				t.Fatalf("localCertificateCache.Get(%q) followed symlink and returned %q", name, got)
			}
			if os.IsNotExist(err) || errors.Is(err, autocert.ErrCacheMiss) {
				t.Fatalf("localCertificateCache.Get(%q) reported symlink as cache miss: %v", name, err)
			}
		})
	}

	// A dangling symlink at the lock path must fail immediately rather than spinning.
	lockDir := t.TempDir()
	lockName := localPrivatePrefix + "lock-" + localDataFingerprint([]byte("locked.example.com"))
	lockFullPath := filepath.Join(lockDir, lockName)
	if err := os.Symlink("missing-lock-target", lockFullPath); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- WithLocalCertificateEntry(context.Background(), filepath.Join(lockDir, "locked.example.com"), func(*os.Root, string) error {
			return nil
		})
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("WithLocalCertificateEntry with symlinked lock succeeded, want immediate refusal")
		}
	case <-time.After(200 * time.Millisecond):
		_ = os.Remove(lockFullPath)
		<-done
		t.Fatalf("WithLocalCertificateEntry spun on dangling symlink lock instead of failing immediately")
	}
}

func TestReadLocalRegularClearsNonblockBeforeRead(t *testing.T) {
	dir := t.TempDir()
	const name = "mail.example.com"
	want := []byte("blocking-read-payload")
	if err := os.WriteFile(filepath.Join(dir, name), want, 0o600); err != nil {
		t.Fatal(err)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	origReadAll := readLocalRegularAll
	t.Cleanup(func() { readLocalRegularAll = origReadAll })

	called := false
	readLocalRegularAll = func(f *os.File) ([]byte, error) {
		called = true
		conn, err := f.SyscallConn()
		if err != nil {
			t.Fatalf("SyscallConn: %v", err)
		}
		var flags int
		var fcntlErr error
		if err := conn.Control(func(fd uintptr) {
			flags, fcntlErr = unix.FcntlInt(fd, unix.F_GETFL, 0)
		}); err != nil {
			t.Fatalf("Control: %v", err)
		}
		if fcntlErr != nil {
			t.Fatalf("FcntlInt(F_GETFL): %v", fcntlErr)
		}
		if flags&unix.O_NONBLOCK != 0 {
			t.Fatalf("regular file left in non-blocking mode during read: flags=0x%x", flags)
		}
		return origReadAll(f)
	}

	got, err := readLocalRegular(root, name)
	if err != nil {
		t.Fatalf("readLocalRegular: %v", err)
	}
	if !called {
		t.Fatal("readLocalRegularAll hook was not invoked")
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("readLocalRegular bytes=%q, want %q", got, want)
	}
}

func TestReadLocalSnapshotPropagatesNonENOENTProvenanceErrors(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	c := &localCertificateCache{dir: dir}
	const name = "mail.example.com"
	payload := []byte("fenced-cert-payload")
	gen := publicationGeneration{Value: "gen-authoritative", Known: true}

	if err := c.putSnapshot(ctx, name, payload, gen); err != nil {
		t.Fatalf("putSnapshot: %v", err)
	}
	metaPath := filepath.Join(dir, localMetadataName(name))

	// Baseline: missing provenance file (ENOENT) remains Known: false for legacy files.
	if err := os.Remove(metaPath); err != nil {
		t.Fatal(err)
	}
	got, gotGen, err := c.snapshot(ctx, name)
	if err != nil || !bytes.Equal(got, payload) || gotGen.Known {
		t.Fatalf("missing provenance should return Known=false without error: got=%q gen=%+v err=%v", got, gotGen, err)
	}

	cases := []struct {
		name  string
		setup func(t *testing.T)
	}{
		{
			name: "directory provenance entry",
			setup: func(t *testing.T) {
				if err := os.Mkdir(metaPath, 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlink provenance entry to valid file",
			setup: func(t *testing.T) {
				other := filepath.Join(dir, "other-meta")
				if err := os.WriteFile(other, []byte("invalid-json"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("other-meta", metaPath); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "dangling symlink provenance entry",
			setup: func(t *testing.T) {
				if err := os.Symlink("does-not-exist", metaPath); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "FIFO provenance entry",
			setup: func(t *testing.T) {
				if err := unix.Mkfifo(metaPath, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "unreadable provenance file",
			setup: func(t *testing.T) {
				if os.Geteuid() == 0 {
					t.Skip("root bypasses 0000 DAC read check")
				}
				if err := os.WriteFile(metaPath, []byte(`{"version":1}`), 0o000); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(metaPath, 0o600) })
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_ = os.RemoveAll(metaPath)
			tc.setup(t)

			data, g, err := c.snapshot(ctx, name)
			if err == nil {
				t.Fatalf("snapshot(%q) with %s succeeded with gen=%+v (bytes=%d), want error",
					name, tc.name, g, len(data))
			}
			if errors.Is(err, autocert.ErrCacheMiss) || os.IsNotExist(err) {
				t.Fatalf("snapshot(%q) with %s returned miss/ENOENT: %v", name, tc.name, err)
			}
			if strings.Contains(tc.name, "FIFO") && errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("snapshot(%q) blocked on FIFO provenance entry: %v", name, err)
			}
		})
	}
}
