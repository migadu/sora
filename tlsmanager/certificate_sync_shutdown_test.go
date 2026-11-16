package tlsmanager

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"golang.org/x/crypto/acme/autocert"
)

func TestCertificateSyncShutdownCancelsAndJoinsGatedRead(t *testing.T) {
	const name = "mail.example.com"
	entered, finished, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var requestOnce, releaseOnce sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/certs/"+S3ObjectKey(name) {
			requestOnce.Do(func() {
				close(entered)
				select {
				case <-r.Context().Done():
				case <-release:
				}
				close(finished)
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := newStubS3Cache(t, srv.URL)
	cache, err := NewFallbackCache(c, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{config: config.TLSConfig{LetsEncrypt: &config.TLSLetsEncryptConfig{Domains: []string{name}}}, autocertMgr: &autocert.Manager{Cache: cache}, stopCertSync: make(chan struct{})}
	m.startCertificateSyncWorker(time.Millisecond)
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		if m.certSyncCancel != nil {
			m.certSyncCancel()
		}
		m.Shutdown()
		m.certSyncWG.Wait()
	})
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("periodic read never reached HTTP barrier")
	}
	done := make(chan struct{})
	go func() { m.Shutdown(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown failed to cancel/join periodic read")
	}
	// The request itself also must be canceled, rather than leaving the server's
	// response to finish and mutate local state after Shutdown has returned.
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("shutdown returned with the periodic HTTP read still live")
	}
	if err := WithLocalCertificateEntry(context.Background(), localEntryPath(cache.(*FallbackCache).fallbackDir, name), func(_ *os.Root, _ string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	m.Shutdown() // repeated shutdown is safe and still joined
}
