package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

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
		if isBucket {
			s.listObjects(w, path, r.URL.Query().Get("prefix"))
			return
		}
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

// listObjects answers a ListObjectsV2 request on bucketPath in one page. Called with
// s.mu held.
func (s *tlsStubS3) listObjects(w http.ResponseWriter, bucketPath, prefix string) {
	bucket := strings.Trim(bucketPath, "/")
	var contents strings.Builder
	count := 0
	for _, path := range slices.Sorted(maps.Keys(s.objects)) {
		key, inBucket := strings.CutPrefix(path, "/"+bucket+"/")
		if !inBucket || !strings.HasPrefix(key, prefix) {
			continue
		}
		count++
		fmt.Fprintf(&contents, `<Contents><Key>%s</Key><Size>%d</Size><LastModified>2026-01-01T00:00:00.000Z</LastModified><ETag>"0"</ETag></Contents>`,
			key, len(s.objects[path]))
	}
	w.Header().Set("Content-Type", "application/xml")
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>%s</Name><Prefix>%s</Prefix><KeyCount>%d</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>%s</ListBucketResult>`,
		bucket, prefix, count, contents.String())
}

// keys returns the stored object paths, sorted.
func (s *tlsStubS3) keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Sorted(maps.Keys(s.objects))
}

// certificateKeys returns the paths of the stored objects that hold certificate cache
// entries, sorted, leaving out the deletion markers tls delete leaves next to them.
func (s *tlsStubS3) certificateKeys() []string {
	return slices.DeleteFunc(s.keys(), func(path string) bool {
		return !strings.HasPrefix(path, "/certs/autocert/cert-")
	})
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

			if got := stub.certificateKeys(); !slices.Equal(got, unrelated) {
				t.Errorf("S3 certificates after delete = %v, want only the unrelated domain's %v", got, unrelated)
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

// TestTLSAutocertNameIsTheServersName: the tls commands must name a domain's cache entries
// exactly as the server loads [tls.letsencrypt] domains. sora-admin counted labels before
// the IDNA fold and the server after it, so a domain written with ideographic full stops
// was mail.example.com to the server and an invalid domain to tls delete --domain.
func TestTLSAutocertNameIsTheServersName(t *testing.T) {
	for _, domain := range []string{"Mail。Example。com", "Bücher.example.com.", "MAIL.example.com"} {
		path := filepath.Join(t.TempDir(), "config.toml")
		content := "[tls.letsencrypt]\ndomains = [\"" + domain + "\"]\n"
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		var cfg config.Config
		if err := config.LoadServerConfig(path, &cfg); err != nil {
			t.Fatalf("loading config: %v", err)
		}
		if len(cfg.TLS.LetsEncrypt.Domains) != 1 {
			t.Fatalf("server loaded %q as %q", domain, cfg.TLS.LetsEncrypt.Domains)
		}
		want := cfg.TLS.LetsEncrypt.Domains[0]
		if got, err := autocertName(domain); err != nil || got != want {
			t.Errorf("autocertName(%q) = %q, %v; the server loads it as %q", domain, got, err, want)
		}
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

// certificateEntry is an autocert cache entry - the private key PEM followed by the
// certificate PEM - for a self-signed certificate valid until notAfter.
func certificateEntry(t *testing.T, domain string, serial int64, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	return buf.Bytes()
}

// startSyncingNode starts a server's TLS manager - the part of a running node that syncs
// certificates with S3 - whose local fallback cache is dir. It never handles a handshake,
// so it never contacts an ACME server.
func startSyncingNode(t *testing.T, cfg AdminConfig, dir string) {
	t.Helper()
	le := *cfg.TLS.LetsEncrypt
	le.Email = "tls-test@example.com"
	le.StorageProvider = "s3"
	le.FallbackDir = dir
	le.SyncInterval = "20ms"
	m, err := tlsmanager.New(config.TLSConfig{Enabled: true, Provider: "letsencrypt", LetsEncrypt: &le}, nil)
	if err != nil {
		t.Fatalf("starting node: %v", err)
	}
	t.Cleanup(m.Shutdown)
}

// TestTLSDeletionSticksOnRunningNodes: a node that holds a certificate in its local
// fallback cache wrote it back to S3 at its next certificate sync after an operator
// deleted it there, and the other nodes then downloaded it again. After tls delete or
// tls clean, the node must drop its copy instead, and S3 must stay without it.
func TestTLSDeletionSticksOnRunningNodes(t *testing.T) {
	const name = "mail.example.com"
	valid := time.Now().Add(60 * 24 * time.Hour)
	expired := time.Now().Add(-24 * time.Hour)

	tests := []struct {
		desc     string
		notAfter time.Time
		run      func(ctx context.Context, cfg AdminConfig, adminDir string) error
		deleted  []string // cache entries the command deletes
		kept     []string // cache entries it leaves alone
	}{
		{
			desc:     "delete --domain",
			notAfter: valid,
			run: func(ctx context.Context, cfg AdminConfig, adminDir string) error {
				return deleteTLSCertificate(ctx, cfg, adminDir, name, "", false)
			},
			deleted: []string{name, name + "+rsa"},
		},
		{
			desc:     "delete --key",
			notAfter: valid,
			run: func(ctx context.Context, cfg AdminConfig, adminDir string) error {
				return deleteTLSCertificate(ctx, cfg, adminDir, "", tlsmanager.S3ObjectKey(name+"+rsa"), false)
			},
			deleted: []string{name + "+rsa"},
			kept:    []string{name},
		},
		{
			desc:     "clean",
			notAfter: expired,
			run: func(ctx context.Context, cfg AdminConfig, adminDir string) error {
				return cleanTLSCertificates(ctx, cfg, adminDir, false, true)
			},
			deleted: []string{name, name + "+rsa"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			ctx := context.Background()
			stub, endpoint := newTLSStubS3(t)
			cfg := tlsTestConfig(endpoint)

			// Every node holds the certificates the server stored in S3.
			s3, err := tlsmanager.NewS3Cache(cfg.TLS.LetsEncrypt.S3)
			if err != nil {
				t.Fatalf("NewS3Cache: %v", err)
			}
			adminDir, nodeDir := t.TempDir(), t.TempDir()
			for i, entry := range []string{name, name + "+rsa"} {
				data := certificateEntry(t, name, int64(i+1), tt.notAfter)
				if err := s3.Put(ctx, entry, data); err != nil {
					t.Fatalf("Put %s: %v", entry, err)
				}
				for _, dir := range []string{adminDir, nodeDir} {
					if err := os.WriteFile(filepath.Join(dir, entry), data, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}

			startSyncingNode(t, cfg, nodeDir)
			time.Sleep(100 * time.Millisecond) // the node is running and in sync

			if err := tt.run(ctx, cfg, adminDir); err != nil {
				t.Fatalf("%s: %v", tt.desc, err)
			}

			// Give the node's sync worker a few rounds after the deletion.
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) && slices.ContainsFunc(tt.deleted, func(entry string) bool {
				_, err := os.Stat(filepath.Join(nodeDir, entry))
				return err == nil
			}) {
				time.Sleep(20 * time.Millisecond)
			}
			time.Sleep(100 * time.Millisecond)

			objects := stub.keys()
			for _, entry := range tt.deleted {
				if slices.Contains(objects, "/certs/"+tlsmanager.S3ObjectKey(entry)) {
					t.Errorf("%s is back in S3: the running node wrote its local copy back", entry)
				}
				if _, err := os.Stat(filepath.Join(nodeDir, entry)); !os.IsNotExist(err) {
					t.Errorf("%s: the running node kept its local copy (stat err = %v)", entry, err)
				}
			}
			for _, entry := range tt.kept {
				if !slices.Contains(objects, "/certs/"+tlsmanager.S3ObjectKey(entry)) {
					t.Errorf("%s is gone from S3, but the command did not delete it", entry)
				}
				if _, err := os.Stat(filepath.Join(nodeDir, entry)); err != nil {
					t.Errorf("%s: the running node lost its local copy: %v", entry, err)
				}
			}
		})
	}
}

// TestTLSCleanKeepsANodesValidReplacement: tls clean deletes expired certificates only.
// A node that renewed a certificate while S3 refused its writes holds the valid
// replacement locally while S3 still holds the expired one. After the clean, the node
// must write its replacement to S3, not drop it as a certificate the clean deleted.
func TestTLSCleanKeepsANodesValidReplacement(t *testing.T) {
	const name = "mail.example.com"
	ctx := context.Background()
	_, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)

	s3, err := tlsmanager.NewS3Cache(cfg.TLS.LetsEncrypt.S3)
	if err != nil {
		t.Fatalf("NewS3Cache: %v", err)
	}
	if err := s3.Put(ctx, name, certificateEntry(t, name, 1, time.Now().Add(-24*time.Hour))); err != nil {
		t.Fatalf("Put: %v", err)
	}
	nodeDir := t.TempDir()
	replacement := certificateEntry(t, name, 2, time.Now().Add(60*24*time.Hour))
	if err := os.WriteFile(filepath.Join(nodeDir, name), replacement, 0600); err != nil {
		t.Fatal(err)
	}

	if err := cleanTLSCertificates(ctx, cfg, t.TempDir(), false, true); err != nil {
		t.Fatalf("clean: %v", err)
	}

	startSyncingNode(t, cfg, nodeDir)
	deadline := time.Now().Add(3 * time.Second)
	for {
		got, err := s3.Get(ctx, name)
		if err == nil && bytes.Equal(got, replacement) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("S3 does not hold the node's valid replacement after the clean (err = %v)", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(filepath.Join(nodeDir, name)); err != nil {
		t.Errorf("the node lost its valid replacement: %v", err)
	}
}
