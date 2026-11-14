package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/tlsmanager"
)

// tlsStubS3 is a minimal path-style S3 endpoint for the tls commands: HEAD on the
// bucket succeeds, HEAD and GET on an object answer 404 when it is absent, PUT
// stores, DELETE removes. A non-zero deleteStatus makes every DELETE fail with it.
type tlsStubS3 struct {
	mu           sync.Mutex
	objects      map[string][]byte
	deleteStatus int
}

func newTLSStubS3(t *testing.T) (*tlsStubS3, string) {
	t.Helper()
	s := &tlsStubS3{objects: make(map[string][]byte)}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	return s, srv.URL
}

func (s *tlsStubS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := r.URL.Path
	isBucket := !strings.Contains(strings.Trim(path, "/"), "/")
	data, found := s.objects[path]

	switch r.Method {
	case http.MethodHead:
		if isBucket || found {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	case http.MethodGet:
		if !found {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>`)
			return
		}
		w.Write(data)
	case http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.objects[path] = body
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		if s.deleteStatus != 0 {
			w.WriteHeader(s.deleteStatus)
			io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>InternalError</Code><Message>stub failure</Message></Error>`)
			return
		}
		delete(s.objects, path)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// keys returns the stored object paths, sorted.
func (s *tlsStubS3) keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Sorted(maps.Keys(s.objects))
}

func (s *tlsStubS3) failDeletes(status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteStatus = status
}

func tlsTestConfig(endpoint string) AdminConfig {
	return AdminConfig{TLS: config.TLSConfig{LetsEncrypt: &config.TLSLetsEncryptConfig{
		Domains: []string{"mail.example.com"},
		S3: config.TLSLetsEncryptS3Config{
			Bucket:     "certs",
			Endpoint:   endpoint,
			DisableTLS: true,
			AccessKey:  "test",
			SecretKey:  "test",
		},
	}}}
}

// putServerCertificates stores the autocert cache entries through the server's own S3
// cache, so the bucket holds exactly the keys a running server writes.
func putServerCertificates(t *testing.T, cfg AdminConfig, names ...string) {
	t.Helper()
	cache, err := tlsmanager.NewS3Cache(cfg.TLS.LetsEncrypt.S3)
	if err != nil {
		t.Fatalf("NewS3Cache: %v", err)
	}
	for _, name := range names {
		if err := cache.Put(context.Background(), name, []byte("certificate for "+name)); err != nil {
			t.Fatalf("Put %s: %v", name, err)
		}
	}
}

func writeLocalCertificates(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("certificate for "+name), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func localNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// TestTLSDeleteDomainRemovesServerKeys deletes a domain's certificates and checks that
// exactly the objects the server's S3 cache wrote for it are gone, along with both
// files of the local fallback cache (an autocert.DirCache named by the cache key).
func TestTLSDeleteDomainRemovesServerKeys(t *testing.T) {
	tests := []struct {
		arg  string // as typed on the command line
		name string // the autocert cache name the server keys it by
	}{
		{"mail.example.com", "mail.example.com"},
		{"Mail.Example.COM", "mail.example.com"},
		{"bücher.example.com", "xn--bcher-kva.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.arg, func(t *testing.T) {
			stub, endpoint := newTLSStubS3(t)
			cfg := tlsTestConfig(endpoint)
			cacheDir := t.TempDir()

			putServerCertificates(t, cfg, "other.example.com", "other.example.com+rsa")
			unrelated := stub.keys()
			putServerCertificates(t, cfg, tt.name, tt.name+"+rsa")
			writeLocalCertificates(t, cacheDir, tt.name, tt.name+"+rsa", "other.example.com")

			if err := deleteTLSCertificate(context.Background(), cfg, cacheDir, tt.arg, "", false); err != nil {
				t.Fatalf("deleteTLSCertificate: %v", err)
			}

			if got := stub.keys(); !slices.Equal(got, unrelated) {
				t.Errorf("S3 objects after delete = %v, want only the unrelated domain's %v", got, unrelated)
			}
			if got := localNames(t, cacheDir); !slices.Equal(got, []string{"other.example.com"}) {
				t.Errorf("local cache after delete = %v, want [other.example.com]", got)
			}
		})
	}
}

func TestTLSDeleteDomainDryRunKeepsCertificates(t *testing.T) {
	stub, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	cacheDir := t.TempDir()

	putServerCertificates(t, cfg, "mail.example.com", "mail.example.com+rsa")
	before := stub.keys()
	writeLocalCertificates(t, cacheDir, "mail.example.com", "mail.example.com+rsa")

	if err := deleteTLSCertificate(context.Background(), cfg, cacheDir, "mail.example.com", "", true); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if got := stub.keys(); !slices.Equal(got, before) {
		t.Errorf("dry run changed S3: %v, want %v", got, before)
	}
	if got := localNames(t, cacheDir); len(got) != 2 {
		t.Errorf("dry run changed the local cache: %v", got)
	}
}

// TestTLSDeleteDomainFailsWhenNothingMatched: a domain with no certificate in S3 or in
// the local cache is an error, not "Deleted 2 certificate(s)".
func TestTLSDeleteDomainFailsWhenNothingMatched(t *testing.T) {
	stub, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	putServerCertificates(t, cfg, "other.example.com", "other.example.com+rsa")
	before := stub.keys()

	err := deleteTLSCertificate(context.Background(), cfg, t.TempDir(), "mail.example.com", "", false)
	if err == nil {
		t.Fatal("deleteTLSCertificate succeeded for a domain with no certificate")
	}
	if got := stub.keys(); !slices.Equal(got, before) {
		t.Errorf("S3 objects changed: %v, want %v", got, before)
	}
}

// TestTLSDeleteDomainFailsWhenS3DeleteFails: a failed S3 delete must fail the command.
func TestTLSDeleteDomainFailsWhenS3DeleteFails(t *testing.T) {
	stub, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	putServerCertificates(t, cfg, "mail.example.com", "mail.example.com+rsa")
	stub.failDeletes(http.StatusInternalServerError)

	if err := deleteTLSCertificate(context.Background(), cfg, t.TempDir(), "mail.example.com", "", false); err == nil {
		t.Fatal("deleteTLSCertificate succeeded although every S3 delete failed")
	}
}

// TestTLSDeleteKeyFailsWhenNotFound: deleting a full key that is not in the bucket is
// an error; S3 DELETE answers success for a missing key, so it cannot tell.
func TestTLSDeleteKeyFailsWhenNotFound(t *testing.T) {
	_, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	h := sha256.Sum256([]byte("absent.example.com"))
	key := "autocert/cert-" + hex.EncodeToString(h[:])

	if err := deleteTLSCertificate(context.Background(), cfg, t.TempDir(), "", key, false); err == nil {
		t.Fatalf("deleteTLSCertificate succeeded for missing key %s", key)
	}
}

// TestTLSCacheUsesServerKeys: tls cache reads the objects the server wrote and stores
// them under the names autocert's DirCache reads, whatever the case of --domain.
func TestTLSCacheUsesServerKeys(t *testing.T) {
	_, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	cacheDir := t.TempDir()
	putServerCertificates(t, cfg, "mail.example.com", "mail.example.com+rsa")

	if err := cacheTLSCertificates(context.Background(), cfg, cacheDir, "Mail.Example.COM", false); err != nil {
		t.Fatalf("cacheTLSCertificates: %v", err)
	}

	want := []string{"mail.example.com", "mail.example.com+rsa"}
	if got := localNames(t, cacheDir); !slices.Equal(got, want) {
		t.Fatalf("local cache = %v, want %v", got, want)
	}
	for _, name := range want {
		data, err := os.ReadFile(filepath.Join(cacheDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "certificate for "+name {
			t.Errorf("%s holds %q, want the S3 object", name, data)
		}
	}
}

func TestTLSAutocertNameRejectsNonDomainPaths(t *testing.T) {
	for _, domain := range []string{"", ".", "..", "...", "localhost", "../outside.example.com", "outside.example.com/file"} {
		t.Run(domain, func(t *testing.T) {
			if name, err := autocertName(domain); err == nil {
				t.Fatalf("invalid domain %q became cache file %q", domain, name)
			}
		})
	}
	if name, err := autocertName("Mail.Example.COM."); err != nil || name != "mail.example.com" {
		t.Fatalf("trailing-dot normalization = %q, %v", name, err)
	}
}

// TestTLSCacheSkipsDomainsAutocertCannotServe: autocert.HostWhitelist silently drops a
// configured domain that idna.Lookup refuses, so the server runs and serves the others.
// tls cache must do the same for the configured list instead of stopping at that entry;
// an explicit --domain of that kind is still an error.
func TestTLSCacheSkipsDomainsAutocertCannotServe(t *testing.T) {
	_, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	cfg.TLS.LetsEncrypt.Domains = []string{"*.example.com", "mail.example.com"}
	cacheDir := t.TempDir()
	putServerCertificates(t, cfg, "mail.example.com", "mail.example.com+rsa")

	if err := cacheTLSCertificates(context.Background(), cfg, cacheDir, "", false); err != nil {
		t.Fatalf("cacheTLSCertificates: %v", err)
	}
	want := []string{"mail.example.com", "mail.example.com+rsa"}
	if got := localNames(t, cacheDir); !slices.Equal(got, want) {
		t.Errorf("local cache = %v, want %v", got, want)
	}

	if err := cacheTLSCertificates(context.Background(), cfg, cacheDir, "*.example.com", false); err == nil {
		t.Error("cacheTLSCertificates succeeded for --domain *.example.com")
	}
}
