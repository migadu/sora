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
	"sync/atomic"
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
// when clean's conditional PUT reaches the bucket, so after every read clean makes to decide.
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
		if r.Method == http.MethodPut && r.Header.Get("If-Match") != "" {
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
	stored, _, decodeErr := tlsmanager.DecodeCertificateCacheData(stored)
	if decodeErr != nil || !bytes.Equal(stored, renewal) {
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

// An unversioned object, or a null version exposed by a version delete, can be
// replaced after clean's last read. The DELETE must match that read's ETag.
func TestTLSCleanConditionalDeleteKeepsConcurrentRenewal(t *testing.T) {
	for _, nullVersion := range []bool{false, true} {
		t.Run(map[bool]string{false: "unversioned", true: "pre-versioning null"}[nullVersion], func(t *testing.T) {
			stub, endpoint := newTLSStubS3(t)
			path := "/certs/" + tlsmanager.S3ObjectKey("mail.example.com")
			expired := tlsCleanAutocertEntry(t, "mail.example.com", false, time.Now().Add(-time.Hour))
			renewal := tlsCleanAutocertEntry(t, "mail.example.com", false, time.Now().Add(60*24*time.Hour))
			if nullVersion {
				stub.mu.Lock()
				stub.versions = map[string][]tlsStubVersion{path: {{id: "null", data: expired}}}
				stub.objects[path] = expired
				stub.mu.Unlock()
			}
			putServerEntry(t, tlsTestConfig(endpoint), "mail.example.com", expired)
			var renew sync.Once
			var conditional atomic.Int32
			node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPut && r.URL.Query().Get("versionId") == "" {
					if r.Header.Get("If-Match") != "" {
						conditional.Add(1)
					}
					renew.Do(func() { stub.put("certs", tlsmanager.S3ObjectKey("mail.example.com"), renewal) })
				}
				stub.ServeHTTP(w, r)
			}))
			t.Cleanup(node.Close)
			if err := cleanTLSCertificates(context.Background(), tlsTestConfig(node.URL), t.TempDir(), false, true); err != nil {
				t.Fatalf("cleanTLSCertificates: %v", err)
			}
			stub.mu.Lock()
			stored := stub.objects[path]
			stub.mu.Unlock()
			stored, _, decodeErr := tlsmanager.DecodeCertificateCacheData(stored)
			if decodeErr != nil || !bytes.Equal(stored, renewal) {
				t.Error("clean removed the renewal stored after its last read")
			}
			if conditional.Load() < 1 {
				t.Errorf("conditional PUTs with an inspected opaque ETag = %d, want at least 1", conditional.Load())
			}
		})
	}
}

func TestTLSCleanWithoutVersionFailsSafelyWithoutConditionalDelete(t *testing.T) {
	for _, nullVersion := range []bool{false, true} {
		for _, missingETag := range []bool{false, true} {
			name := map[bool]string{false: "unversioned", true: "pre-versioning null"}[nullVersion] + "/" + map[bool]string{false: "unsupported condition", true: "missing ETag"}[missingETag]
			t.Run(name, func(t *testing.T) {
				stub, endpoint := newTLSStubS3(t)
				path := "/certs/" + tlsmanager.S3ObjectKey("mail.example.com")
				expired := tlsCleanAutocertEntry(t, "mail.example.com", false, time.Now().Add(-time.Hour))
				if nullVersion {
					stub.mu.Lock()
					stub.versions = map[string][]tlsStubVersion{path: {{id: "null", data: expired}}}
					stub.objects[path] = expired
					stub.mu.Unlock()
				}
				putServerEntry(t, tlsTestConfig(endpoint), "mail.example.com", expired)
				var unconditional, conditional atomic.Int32
				node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodPut && r.URL.Query().Get("versionId") == "" {
						if r.Header.Get("If-Match") == "" {
							unconditional.Add(1)
						} else {
							conditional.Add(1)
							w.WriteHeader(http.StatusNotImplemented)
							return
						}
					}
					if missingETag && r.Method == http.MethodGet {
						rec := httptest.NewRecorder()
						stub.ServeHTTP(rec, r)
						rec.Header().Del("ETag")
						for key, values := range rec.Header() {
							w.Header()[key] = values
						}
						w.WriteHeader(rec.Code)
						w.Write(rec.Body.Bytes())
						return
					}
					stub.ServeHTTP(w, r)
				}))
				t.Cleanup(node.Close)
				if err := cleanTLSCertificates(context.Background(), tlsTestConfig(node.URL), t.TempDir(), false, true); err == nil {
					t.Error("clean reported success without a safe conditional clear")
				}
				if unconditional.Load() != 0 {
					t.Errorf("sent %d unconditional PUTs", unconditional.Load())
				}
				if missingETag && conditional.Load() != 0 {
					t.Errorf("sent %d conditional PUTs without an inspected ETag", conditional.Load())
				}
				stub.mu.Lock()
				stored := stub.objects[path]
				stub.mu.Unlock()
				if !bytes.Equal(stored, expired) {
					t.Error("clean removed the object without safe delete support")
				}
			})
		}
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

	if got := stub.activeKeys(); !slices.Equal(got, valid) {
		t.Errorf("S3 objects after clean = %v, want only the valid domain's %v", got, valid)
	}
}

// TestTLSCleanAfterVersioningWasTurnedOn: the bucket got versioning after the name was
// first stored, as the clean notes advise for a bucket without it, so the oldest version
// is the "null" one from before. Deleting the expired version clean read brings that
// one back. It has expired too, and has no version of its own to name, so clean deletes
// the name the way it does on a bucket without versions, and reports no failure.
func TestTLSCleanAfterVersioningWasTurnedOn(t *testing.T) {
	stub, endpoint := newVersionedTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	path := "/certs/" + tlsmanager.S3ObjectKey("mail.example.com")
	beforeVersioning := tlsCleanAutocertEntry(t, "mail.example.com", false, time.Now().Add(-120*24*time.Hour))
	stub.mu.Lock()
	stub.objects[path] = beforeVersioning
	stub.versions[path] = []tlsStubVersion{{id: "null", data: beforeVersioning}}
	stub.mu.Unlock()
	putServerEntry(t, cfg, "mail.example.com", tlsCleanAutocertEntry(t, "mail.example.com", false, time.Now().Add(-24*time.Hour)))

	if err := cleanTLSCertificates(context.Background(), cfg, t.TempDir(), false, true); err != nil {
		t.Fatalf("cleanTLSCertificates: %v", err)
	}
	if got := stub.activeKeys(); len(got) != 0 {
		t.Errorf("S3 objects after clean = %v, want none", got)
	}
}
