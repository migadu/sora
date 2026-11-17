//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/migadu/sora/tlsmanager"
	"golang.org/x/crypto/acme/autocert"
)

func legacyDeletionMarkerS3Key(certKey string) string {
	return "autocert/deleted-" + strings.TrimPrefix(certKey, "autocert/cert-")
}

// TestTLSUnprovenLegacySharedCertificateLifecycle verifies that a pre-#936 raw
// certificate object in S3 alongside a legacy autocert/deleted-<hash> marker:
//   - is NOT reported as a valid active certificate by tls list,
//   - is refused by tls cache (never written to cacheDir or overwriting an existing file),
//   - is refused by tls clean instead of writing a bricked unproven tombstone, and
//   - CAN be deleted via tls delete (--domain and --key) to establish a fresh explicit
//     deletion barrier that unblocks subsequent operations and server issuance.
func TestTLSUnprovenLegacySharedCertificateLifecycle(t *testing.T) {
	t.Run("list_and_cache_reject_unproven_legacy_certificate", func(t *testing.T) {
		ctx := context.Background()
		stub, endpoint := newTLSStubS3(t)
		cfg := tlsTestConfig(endpoint)
		cfg.TLS.LetsEncrypt.Domains = []string{"mail.example.com", "other.example.com"}

		mailKey := tlsmanager.S3ObjectKey("mail.example.com")
		rawLegacyCert := validAutocertEntry(t, "mail.example.com")
		stub.put("certs", mailKey, rawLegacyCert)
		stub.put("certs", legacyDeletionMarkerS3Key(mailKey), []byte(time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)))

		validOther := validAutocertEntry(t, "other.example.com")
		putServerEntry(t, cfg, "other.example.com", validOther)

		s3cache, err := tlsmanager.OpenS3Cache(cfg.TLS.LetsEncrypt.S3)
		if err != nil {
			t.Fatalf("OpenS3Cache: %v", err)
		}
		if _, err := s3cache.Get(ctx, "mail.example.com"); err == nil || errors.Is(err, autocert.ErrCacheMiss) {
			t.Fatalf("server S3Cache.Get accepted unproven legacy shared certificate: %v", err)
		}

		// tls list --json must not report the unproven certificate as a valid ECDSA entry.
		listDir := t.TempDir()
		out := captureStdout(t, func() error {
			return listTLSCertificates(ctx, cfg, listDir, false, true)
		})
		type listedCert struct {
			Domain   string  `json:"domain"`
			CertType string  `json:"certType"`
			S3Key    string  `json:"s3Key"`
			Expiry   *string `json:"expiry"`
		}
		var listed []listedCert
		if err := json.Unmarshal([]byte(out), &listed); err != nil {
			t.Fatalf("tls list --json invalid JSON: %v\n%s", err, out)
		}
		byKey := make(map[string]listedCert, len(listed))
		for _, c := range listed {
			byKey[c.S3Key] = c
		}
		gotMail, ok := byKey[mailKey]
		if !ok {
			t.Fatalf("expected %s in tls list output, got %v", mailKey, listed)
		}
		if gotMail.CertType != "Invalid" || gotMail.Expiry != nil {
			t.Errorf("unproven legacy cert listed as %+v, want CertType=Invalid and nil Expiry", gotMail)
		}
		otherKey := tlsmanager.S3ObjectKey("other.example.com")
		if gotOther := byKey[otherKey]; gotOther.CertType != "ECDSA" || gotOther.Expiry == nil {
			t.Errorf("valid other.example.com listed as %+v, want ECDSA with expiry", gotOther)
		}

		// tls cache must refuse to sync the unproven certificate into cacheDir while still caching other.example.com.
		cacheDir := t.TempDir()
		cacheErr := cacheTLSCertificates(ctx, cfg, cacheDir, "", false)
		if cacheErr == nil {
			t.Fatal("cacheTLSCertificates succeeded and accepted unproven legacy shared certificate")
		}
		if !strings.Contains(cacheErr.Error(), mailKey) {
			t.Errorf("cacheTLSCertificates error %q does not name %s", cacheErr, mailKey)
		}
		if got, want := localNames(t, cacheDir), []string{"other.example.com"}; !slices.Equal(got, want) {
			t.Errorf("local cache after tls cache = %v, want %v", got, want)
		}

		// tls cache --force must preserve an existing valid local file rather than overwriting with unproven S3 cert.
		existingLocal := validAutocertEntry(t, "mail.example.com")
		localMail := filepath.Join(cacheDir, "mail.example.com")
		if err := os.WriteFile(localMail, existingLocal, 0600); err != nil {
			t.Fatal(err)
		}
		if err := cacheTLSCertificates(ctx, cfg, cacheDir, "mail.example.com", true); err == nil {
			t.Fatal("cacheTLSCertificates --force --domain succeeded for unproven legacy certificate")
		}
		afterForce, err := os.ReadFile(localMail)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(afterForce, existingLocal) {
			t.Error("cacheTLSCertificates --force overwrote existing local copy with unproven certificate")
		}
	})

	for _, deleteMode := range []string{"domain", "exact-key", "prefix-key"} {
		t.Run("clean_refuses_and_delete_remediates_"+deleteMode, func(t *testing.T) {
			ctx := context.Background()
			stub, endpoint := newTLSStubS3(t)
			cfg := tlsTestConfig(endpoint)
			cacheDir := t.TempDir()

			mailKey := tlsmanager.S3ObjectKey("mail.example.com")
			expiredLegacy := tlsCleanAutocertEntry(t, "mail.example.com", false, time.Now().Add(-24*time.Hour))
			stub.put("certs", mailKey, expiredLegacy)
			stub.put("certs", legacyDeletionMarkerS3Key(mailKey), []byte(time.Now().Add(-2*time.Hour).UTC().Format(time.RFC3339Nano)))

			putExpiredEntries(t, cfg, cacheDir, "other.example.com")

			// tls clean must report the ambiguous legacy deletion marker rather than silently
			// repairing provenance or writing a bricked unproven tombstone, while still cleaning other.example.com.
			if err := cleanTLSCertificates(ctx, cfg, cacheDir, false, true); err == nil {
				t.Fatal("cleanTLSCertificates succeeded despite unproven legacy shared certificate")
			}
			if slices.Contains(stub.activeKeys(), "/certs/"+tlsmanager.S3ObjectKey("other.example.com")) {
				t.Error("cleanTLSCertificates failed to clean unrelated expired domain other.example.com")
			}

			// tls delete is the documented remediation to establish a fresh explicit deletion barrier.
			var delErr error
			switch deleteMode {
			case "domain":
				delErr = deleteTLSCertificate(ctx, cfg, cacheDir, "mail.example.com", "", false)
			case "exact-key":
				delErr = deleteTLSCertificate(ctx, cfg, cacheDir, "", mailKey, false)
			case "prefix-key":
				delErr = deleteTLSCertificate(ctx, cfg, cacheDir, "", mailKey[:28]+"...", false)
			}
			if delErr != nil {
				t.Fatalf("deleteTLSCertificate (%s) failed to remediate unproven entry: %v", deleteMode, delErr)
			}

			// After explicit deletion, all admin commands and server publication succeed cleanly.
			if err := listTLSCertificates(ctx, cfg, cacheDir, false, true); err != nil {
				t.Fatalf("listTLSCertificates after remediation delete: %v", err)
			}
			if err := cacheTLSCertificates(ctx, cfg, cacheDir, "", false); err != nil {
				t.Fatalf("cacheTLSCertificates after remediation delete: %v", err)
			}
			if err := cleanTLSCertificates(ctx, cfg, cacheDir, false, true); err != nil {
				t.Fatalf("cleanTLSCertificates after remediation delete: %v", err)
			}
			s3cache, err := tlsmanager.OpenS3Cache(cfg.TLS.LetsEncrypt.S3)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s3cache.Get(ctx, "mail.example.com"); !errors.Is(err, autocert.ErrCacheMiss) {
				t.Fatalf("S3Cache.Get after remediation delete = %v, want ErrCacheMiss", err)
			}
			replacement := validAutocertEntry(t, "mail.example.com")
			if err := s3cache.Put(ctx, "mail.example.com", replacement); err != nil {
				t.Fatalf("S3Cache.Put replacement after remediation delete failed: %v", err)
			}
		})
	}
}

// TestTLSExpireAndDecodeClearUnprovenOnTombstones verifies that ExpireObject and
// QueueExpiredVersion never persist "unproven": true onto an absent tombstone, and that
// DecodeCertificateCacheData + admin commands recover cleanly even if a pre-fix binary
// already wrote {"absent": true, "unproven": true} into S3.
func TestTLSExpireAndDecodeClearUnprovenOnTombstones(t *testing.T) {
	t.Run("expire_object_and_queue_expired_version_clear_unproven", func(t *testing.T) {
		ctx := context.Background()
		stub, endpoint := newVersionedTLSStubS3(t)
		cfg := tlsTestConfig(endpoint)
		s3cache, err := tlsmanager.OpenS3Cache(cfg.TLS.LetsEncrypt.S3)
		if err != nil {
			t.Fatal(err)
		}

		const name = "mail.example.com"
		certKey := tlsmanager.S3ObjectKey(name)
		path := "/certs/" + certKey
		expired := tlsCleanAutocertEntry(t, name, false, time.Now().Add(-time.Hour))
		stub.put("certs", certKey, expired)
		stub.put("certs", legacyDeletionMarkerS3Key(certKey), []byte(time.Now().Add(-2*time.Hour).UTC().Format(time.RFC3339Nano)))

		stub.mu.Lock()
		etag := tlsStubETag(stub.objects[path])
		version := stub.versions[path][len(stub.versions[path])-1].id
		stub.mu.Unlock()

		expiredOK, err := s3cache.ExpireObject(ctx, certKey, etag, time.Now(), version)
		if err != nil || !expiredOK {
			t.Fatalf("ExpireObject = (%v, %v), want (true, nil)", expiredOK, err)
		}

		stub.mu.Lock()
		raw := append([]byte(nil), stub.objects[path]...)
		stub.mu.Unlock()
		_, absent, decodeErr := tlsmanager.DecodeCertificateCacheData(raw)
		if decodeErr != nil || !absent {
			t.Fatalf("DecodeCertificateCacheData after ExpireObject = (absent=%v, err=%v), want (true, nil)", absent, decodeErr)
		}
		if _, err := s3cache.Get(ctx, name); !errors.Is(err, autocert.ErrCacheMiss) {
			t.Fatalf("S3Cache.Get after ExpireObject = %v, want ErrCacheMiss (unproven persisted on absent tombstone)", err)
		}

		if err := s3cache.QueueExpiredVersion(ctx, certKey, "v99", time.Now().Add(-time.Hour)); err != nil {
			t.Fatalf("QueueExpiredVersion: %v", err)
		}
		stub.mu.Lock()
		rawAfterQueue := append([]byte(nil), stub.objects[path]...)
		stub.mu.Unlock()
		_, absent, decodeErr = tlsmanager.DecodeCertificateCacheData(rawAfterQueue)
		if decodeErr != nil || !absent {
			t.Fatalf("DecodeCertificateCacheData after QueueExpiredVersion = (absent=%v, err=%v), want (true, nil)", absent, decodeErr)
		}
		if _, err := s3cache.Get(ctx, name); !errors.Is(err, autocert.ErrCacheMiss) {
			t.Fatalf("S3Cache.Get after QueueExpiredVersion = %v, want ErrCacheMiss", err)
		}
	})

	t.Run("already_persisted_unproven_absent_tombstone_unbricks_all_commands", func(t *testing.T) {
		ctx := context.Background()
		stub, endpoint := newTLSStubS3(t)
		cfg := tlsTestConfig(endpoint)
		cacheDir := t.TempDir()

		const name = "mail.example.com"
		certKey := tlsmanager.S3ObjectKey(name)
		stateJSON := []byte(`{"version":1,"generation":"legacy-deleted:2026-01-01T00:00:00Z","unproven":true,"absent":true,"deleted_at":"2026-01-01T00:00:00Z"}`)
		bricked := append([]byte("\n"), pem.EncodeToMemory(&pem.Block{Type: "SORA CERTIFICATE STATE", Bytes: stateJSON})...)
		stub.put("certs", certKey, bricked)

		if _, absent, err := tlsmanager.DecodeCertificateCacheData(bricked); err != nil || !absent {
			t.Fatalf("DecodeCertificateCacheData on bricked absent tombstone = (absent=%v, err=%v), want (true, nil)", absent, err)
		}
		if err := listTLSCertificates(ctx, cfg, cacheDir, false, true); err != nil {
			t.Fatalf("listTLSCertificates failed on bricked absent tombstone: %v", err)
		}
		if err := cacheTLSCertificates(ctx, cfg, cacheDir, "", false); err != nil {
			t.Fatalf("cacheTLSCertificates failed on bricked absent tombstone: %v", err)
		}
		if err := cleanTLSCertificates(ctx, cfg, cacheDir, false, true); err != nil {
			t.Fatalf("cleanTLSCertificates failed on bricked absent tombstone: %v", err)
		}
		if err := deleteTLSCertificate(ctx, cfg, cacheDir, name, "", false); err != nil {
			t.Fatalf("deleteTLSCertificate failed to clear bricked absent tombstone: %v", err)
		}

		s3cache, err := tlsmanager.OpenS3Cache(cfg.TLS.LetsEncrypt.S3)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s3cache.Get(ctx, name); !errors.Is(err, autocert.ErrCacheMiss) {
			t.Fatalf("S3Cache.Get after deleting bricked tombstone = %v, want ErrCacheMiss", err)
		}
	})
}

// TestTLSCleanPendingHistoryDoesNotSkipActiveCertificate verifies that when an S3
// certificate object carries pending_expired historical versions from an earlier interrupted
// purge, tls clean still inspects the current active payload:
//   - if the active renewal has also expired, tls clean expires the active object, removes
//     the expired local copy, and purges historical versions;
//   - if the active payload is corrupt, tls clean fails rather than silently skipping it.
func TestTLSCleanPendingHistoryDoesNotSkipActiveCertificate(t *testing.T) {
	t.Run("active_renewal_also_expired", func(t *testing.T) {
		const name = "mail.example.com"
		ctx := context.Background()
		stub, endpoint := newVersionedTLSStubS3(t)
		cfg := tlsTestConfig(endpoint)
		cacheDir := t.TempDir()
		path := "/certs/" + tlsmanager.S3ObjectKey(name)

		// Step 1: Seed expired v1 and fail version deletes so PendingExpired retains v1.
		expiredV1 := tlsCleanAutocertEntry(t, name, false, time.Now().Add(-24*time.Hour))
		putServerEntry(t, cfg, name, expiredV1)
		stub.failDeletes(http.StatusForbidden)
		if err := cleanTLSCertificates(ctx, cfg, t.TempDir(), false, true); err == nil {
			t.Fatal("expected historical purge failure")
		}

		// Step 2: Publish short-lived renewal v2 through S3Cache (preserving PendingExpired)
		// and write it to cacheDir, then wait past its 1s-granular X.509 NotAfter.
		s3cache, err := tlsmanager.OpenS3Cache(cfg.TLS.LetsEncrypt.S3)
		if err != nil {
			t.Fatal(err)
		}
		expiryV2 := time.Now().Truncate(time.Second).Add(2 * time.Second)
		shortRenewal := tlsCleanAutocertEntry(t, name, false, expiryV2)
		if err := s3cache.Put(ctx, name, shortRenewal); err != nil {
			t.Fatalf("Put short-lived renewal: %v", err)
		}
		if err := os.WriteFile(filepath.Join(cacheDir, name), shortRenewal, 0600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Until(expiryV2) + 50*time.Millisecond)

		// Step 3: Re-enable deletes and run tls clean. Both historical v1, active expired v2,
		// and the local expired v2 copy must be cleaned.
		stub.failDeletes(0)
		if err := cleanTLSCertificates(ctx, cfg, cacheDir, false, true); err != nil {
			t.Fatalf("cleanTLSCertificates: %v", err)
		}

		stub.mu.Lock()
		raw := append([]byte(nil), stub.objects[path]...)
		versions := append([]tlsStubVersion(nil), stub.versions[path]...)
		stub.mu.Unlock()

		_, absent, decodeErr := tlsmanager.DecodeCertificateCacheData(raw)
		pending, _, pendingErr := tlsmanager.PendingCertificateCleanup(raw)
		if decodeErr != nil || pendingErr != nil || !absent || pending {
			t.Fatalf("active expired renewal remained in S3: absent=%v pending=%v err=%v/%v", absent, pending, decodeErr, pendingErr)
		}
		for _, v := range versions {
			if bytes.Contains(v.data, []byte("PRIVATE KEY")) {
				t.Fatalf("expired historical version %s still holds private key material", v.id)
			}
		}
		if got := localNames(t, cacheDir); len(got) != 0 {
			t.Errorf("local cache after clean = %v, want empty (expired v2 was not removed)", got)
		}
	})

	t.Run("active_payload_corrupt_with_pending_history", func(t *testing.T) {
		const name = "mail.example.com"
		ctx := context.Background()
		stub, endpoint := newVersionedTLSStubS3(t)
		cfg := tlsTestConfig(endpoint)

		expiredV1 := tlsCleanAutocertEntry(t, name, false, time.Now().Add(-24*time.Hour))
		putServerEntry(t, cfg, name, expiredV1)
		stub.failDeletes(http.StatusForbidden)
		if err := cleanTLSCertificates(ctx, cfg, t.TempDir(), false, true); err == nil {
			t.Fatal("expected historical purge failure")
		}

		s3cache, err := tlsmanager.OpenS3Cache(cfg.TLS.LetsEncrypt.S3)
		if err != nil {
			t.Fatal(err)
		}
		if err := s3cache.Put(ctx, name, []byte("corrupt non-certificate payload")); err != nil {
			t.Fatalf("Put corrupt payload: %v", err)
		}
		stub.failDeletes(0)

		if err := cleanTLSCertificates(ctx, cfg, t.TempDir(), true, false); err == nil {
			t.Error("cleanTLSCertificates --dry-run succeeded despite corrupt active S3 payload behind pending history")
		}
		if err := cleanTLSCertificates(ctx, cfg, t.TempDir(), false, true); err == nil {
			t.Error("cleanTLSCertificates succeeded despite corrupt active S3 payload behind pending history")
		}
	})
}

// TestTLSCleanLocalCacheRejectsSymlinkAndFIFO verifies that expiredLocalCopy does not
// follow symlinks inside or outside cacheDir (nor create lock files during --dry-run)
// and does not block indefinitely on a FIFO named pipe.
func TestTLSCleanLocalCacheRejectsSymlinkAndFIFO(t *testing.T) {
	t.Run("symlink_outside_and_inside_cache_dir", func(t *testing.T) {
		for _, targetKind := range []string{"outside", "inside"} {
			t.Run(targetKind, func(t *testing.T) {
				ctx := context.Background()
				stub, endpoint := newTLSStubS3(t)
				cfg := tlsTestConfig(endpoint)
				cacheDir := t.TempDir()
				outsideDir := t.TempDir()

				expired := time.Now().Add(-24 * time.Hour)
				expiredA := tlsCleanAutocertEntry(t, "a.example.com", false, expired)
				putServerEntry(t, cfg, "a.example.com", expiredA)
				putExpiredEntries(t, cfg, cacheDir, "mail.example.com")

				var targetPath string
				if targetKind == "outside" {
					targetPath = filepath.Join(outsideDir, "outside-cert.pem")
					if err := os.WriteFile(targetPath, expiredA, 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(targetPath, filepath.Join(cacheDir, "a.example.com")); err != nil {
						t.Fatal(err)
					}
				} else {
					targetPath = filepath.Join(cacheDir, "target-cert.pem")
					if err := os.WriteFile(targetPath, expiredA, 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink("target-cert.pem", filepath.Join(cacheDir, "a.example.com")); err != nil {
						t.Fatal(err)
					}
				}

				// --dry-run must reject the symlink and must not create .sora-lock-* files.
				if err := cleanTLSCertificates(ctx, cfg, cacheDir, true, false); err == nil {
					t.Fatalf("cleanTLSCertificates --dry-run followed %s symlink without error", targetKind)
				}
				entries, err := os.ReadDir(cacheDir)
				if err != nil {
					t.Fatal(err)
				}
				for _, e := range entries {
					if strings.HasPrefix(e.Name(), ".sora-lock-") {
						t.Errorf("--dry-run created lock file %s in cacheDir", e.Name())
					}
				}

				// Real clean rejects the symlink, keeps it and its target intact, and cleans the rest.
				if err := cleanTLSCertificates(ctx, cfg, cacheDir, false, true); err == nil {
					t.Fatalf("cleanTLSCertificates accepted %s symlink without error", targetKind)
				}
				if got := stub.activeKeys(); len(got) != 0 {
					t.Errorf("S3 active keys after clean = %v, want none", got)
				}
				if _, err := os.Lstat(filepath.Join(cacheDir, "a.example.com")); err != nil {
					t.Errorf("symlink was removed: %v", err)
				}
				if _, err := os.Stat(targetPath); err != nil {
					t.Errorf("symlink target %s was removed: %v", targetPath, err)
				}
				if _, err := os.Stat(filepath.Join(cacheDir, "mail.example.com")); !os.IsNotExist(err) {
					t.Errorf("valid expired local entry mail.example.com was not cleaned: %v", err)
				}
			})
		}
	})

	t.Run("fifo_does_not_hang", func(t *testing.T) {
		ctx := context.Background()
		stub, endpoint := newTLSStubS3(t)
		cfg := tlsTestConfig(endpoint)
		cacheDir := t.TempDir()

		expired := time.Now().Add(-24 * time.Hour)
		putServerEntry(t, cfg, "a.example.com", tlsCleanAutocertEntry(t, "a.example.com", false, expired))
		putExpiredEntries(t, cfg, cacheDir, "mail.example.com")

		fifoPath := filepath.Join(cacheDir, "a.example.com")
		if err := syscall.Mkfifo(fifoPath, 0600); err != nil {
			t.Fatalf("Mkfifo: %v", err)
		}

		runBounded := func(dryRun bool) error {
			done := make(chan error, 1)
			go func() {
				done <- cleanTLSCertificates(ctx, cfg, cacheDir, dryRun, !dryRun)
			}()
			select {
			case err := <-done:
				return err
			case <-time.After(250 * time.Millisecond):
				// Unblock any stuck O_RDONLY open on the FIFO so the test binary does not leak a goroutine.
				if w, openErr := os.OpenFile(fifoPath, os.O_WRONLY, 0); openErr == nil {
					_ = w.Close()
				}
				<-done
				t.Fatalf("cleanTLSCertificates (dryRun=%v) hung opening FIFO %s", dryRun, fifoPath)
				return nil
			}
		}

		if err := runBounded(true); err == nil {
			t.Fatal("cleanTLSCertificates --dry-run succeeded on FIFO cache entry")
		}
		if err := runBounded(false); err == nil {
			t.Fatal("cleanTLSCertificates succeeded on FIFO cache entry")
		}
		if got := stub.activeKeys(); len(got) != 0 {
			t.Errorf("S3 active keys after clean = %v, want none", got)
		}
		if info, err := os.Lstat(fifoPath); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
			t.Errorf("FIFO entry changed or removed: info=%v err=%v", info, err)
		}
		if got, want := localNames(t, cacheDir), []string{"a.example.com"}; !slices.Equal(got, want) {
			t.Errorf("local cache after clean = %v, want %v", got, want)
		}
	})
}

// TestTLSListAndDeleteSkipAndRefuseACMEAccountKeys verifies that autocert's ACME account
// keys ("acme_account+key" and legacy "acme_account.key") are skipped by tls list and
// refused by tls delete --key (both exact and prefix matches).
func TestTLSListAndDeleteSkipAndRefuseACMEAccountKeys(t *testing.T) {
	ctx := context.Background()
	_, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	cacheDir := t.TempDir()

	accountPEM := tlsCleanECPrivateKeyPEM(t)
	putServerEntry(t, cfg, "acme_account+key", accountPEM)
	putServerEntry(t, cfg, "acme_account.key", accountPEM)
	putServerCertificates(t, cfg, "mail.example.com")

	out := captureStdout(t, func() error {
		return listTLSCertificates(ctx, cfg, cacheDir, false, true)
	})
	var listed []struct {
		Domain string `json:"domain"`
		S3Key  string `json:"s3Key"`
	}
	if err := json.Unmarshal([]byte(out), &listed); err != nil {
		t.Fatalf("tls list --json invalid JSON: %v\n%s", err, out)
	}
	if len(listed) != 1 || listed[0].S3Key != tlsmanager.S3ObjectKey("mail.example.com") {
		t.Errorf("tls list included ACME account keys: got %+v, want only mail.example.com", listed)
	}

	for _, tc := range []struct {
		name   string
		keyArg string
	}{
		{"exact_plus_key", tlsmanager.S3ObjectKey("acme_account+key")},
		{"hash_plus_key", strings.TrimPrefix(tlsmanager.S3ObjectKey("acme_account+key"), "autocert/cert-")},
		{"exact_dot_key", tlsmanager.S3ObjectKey("acme_account.key")},
		{"prefix_plus_key", tlsmanager.S3ObjectKey("acme_account+key")[:28] + "..."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ep := newTLSStubS3(t)
			subCfg := tlsTestConfig(ep)
			putServerEntry(t, subCfg, "acme_account+key", accountPEM)
			putServerEntry(t, subCfg, "acme_account.key", accountPEM)
			putServerCertificates(t, subCfg, "mail.example.com")

			if err := deleteTLSCertificate(ctx, subCfg, t.TempDir(), "", tc.keyArg, false); err == nil {
				t.Errorf("deleteTLSCertificate(--key %q) succeeded and deleted an ACME account key", tc.keyArg)
			}

			s3cache, err := tlsmanager.OpenS3Cache(subCfg.TLS.LetsEncrypt.S3)
			if err != nil {
				t.Fatal(err)
			}
			for _, accountName := range []string{"acme_account+key", "acme_account.key"} {
				got, err := s3cache.Get(ctx, accountName)
				if err != nil || !bytes.Equal(got, accountPEM) {
					t.Errorf("ACME account key %q after refused delete: bytes=%d err=%v", accountName, len(got), err)
				}
			}
		})
	}
}
