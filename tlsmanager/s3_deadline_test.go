package tlsmanager

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newStalledS3 is an S3 endpoint that accepts the bucket check and then never answers a
// request, as an endpoint behind a black-holed route does.
func newStalledS3(t *testing.T) string {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		select {
		case <-r.Context().Done():
		case <-time.After(12 * time.Second):
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// TestS3CacheGetIsBounded: the TLS handshake path reaches S3 through this client, and
// autocert allows it five minutes. A stalled endpoint must not hold a handshake
// goroutine for anything close to that - every listener would stop accepting new TLS
// connections while valid certificates sit in autocert's memory.
func TestS3CacheGetIsBounded(t *testing.T) {
	cache := newStubS3Cache(t, newStalledS3(t))

	done := make(chan error, 1)
	go func() {
		_, err := cache.Get(context.Background(), "mail.example.com")
		done <- err
	}()

	// Comfortably above the bound S3Cache places on a single operation.
	const patience = 8 * time.Second

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Get against a stalled S3 endpoint: err = nil, want a deadline error")
		}
	case <-time.After(patience):
		t.Fatalf("S3Cache.Get did not return within %s: a stalled S3 endpoint blocks the handshake path", patience)
	}
}
