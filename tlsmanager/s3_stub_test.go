package tlsmanager

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/migadu/sora/config"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// mockCache is a simple in-memory cache for testing
type mockCache struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMockCache() *mockCache {
	return &mockCache{
		data: make(map[string][]byte),
	}
}

func (m *mockCache) Get(ctx context.Context, name string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, exists := m.data[name]
	if !exists {
		return nil, autocert.ErrCacheMiss
	}
	return data, nil
}

func (m *mockCache) Put(ctx context.Context, name string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.data[name] = data
	return nil
}

func (m *mockCache) Delete(ctx context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.data, name)
	return nil
}

// stubS3 is a minimal S3-compatible endpoint for tests: HEAD on the bucket succeeds,
// GET returns a stored object or a NoSuchKey 404, PUT stores, DELETE removes.
// Setting getStatus makes every GET fail with that status, simulating an S3 outage.
type stubS3 struct {
	mu        sync.Mutex
	objects   map[string][]byte
	getStatus int
}

func newStubS3(t *testing.T) (*stubS3, string) {
	t.Helper()

	s := &stubS3{objects: make(map[string][]byte)}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	return s, srv.URL
}

func (s *stubS3) failGets(status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.getStatus = status
}

func (s *stubS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	getStatus := s.getStatus
	data, found := s.objects[r.URL.Path]
	s.mu.Unlock()

	switch r.Method {
	case http.MethodHead:
		w.WriteHeader(http.StatusOK)
	case http.MethodGet:
		switch {
		case getStatus != 0:
			http.Error(w, "s3 backend failure", getStatus)
		case !found:
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>`)
		default:
			w.Write(data)
		}
	case http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.objects[r.URL.Path] = body
		s.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		s.mu.Lock()
		delete(s.objects, r.URL.Path)
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// newStubACME returns a local ACME directory URL and a counter of requests made to it.
// Tests that build an autocert manager MUST point it here so a regression cannot reach
// the real Let's Encrypt service.
func newStubACME(t *testing.T) (*atomic.Int64, string) {
	t.Helper()

	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "no ACME requests expected in tests", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return &hits, srv.URL + "/directory"
}

// newTestLetsEncryptManager builds a Let's Encrypt manager against the stub S3 endpoint,
// with ACME pointed at a local stub, and returns the manager plus the ACME request counter.
func newTestLetsEncryptManager(t *testing.T, s3Endpoint string, opts ...func(*config.TLSLetsEncryptConfig)) (*Manager, *atomic.Int64) {
	t.Helper()
	return newTestClusterManager(t, s3Endpoint, nil, opts...)
}

// newTestClusterManager is newTestLetsEncryptManager for a node that is part of a cluster.
func newTestClusterManager(t *testing.T, s3Endpoint string, clusterMgr clusterCoordinator, opts ...func(*config.TLSLetsEncryptConfig)) (*Manager, *atomic.Int64) {
	t.Helper()

	leCfg := &config.TLSLetsEncryptConfig{
		Email:           "tls-test@example.com",
		Domains:         []string{"mail.example.com"},
		StorageProvider: "s3",
		SyncInterval:    "0",
		S3: config.TLSLetsEncryptS3Config{
			Bucket:     "certs",
			Endpoint:   s3Endpoint,
			DisableTLS: true,
			AccessKey:  "test",
			SecretKey:  "test",
		},
	}
	for _, opt := range opts {
		opt(leCfg)
	}

	m, err := newManager(config.TLSConfig{
		Enabled:     true,
		Provider:    "letsencrypt",
		LetsEncrypt: leCfg,
	}, clusterMgr)
	if err != nil {
		t.Fatalf("newManager: %v", err)
	}
	t.Cleanup(m.Shutdown)

	// Redirect the directory only: the rest of the ACME client is what production builds.
	acmeHits, directoryURL := newStubACME(t)
	if m.autocertMgr.Client == nil {
		m.autocertMgr.Client = &acme.Client{}
	}
	m.autocertMgr.Client.DirectoryURL = directoryURL

	return m, acmeHits
}
