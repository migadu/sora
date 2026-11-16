package userapiproxy

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/resilient"
)

// lockedBuffer is a bytes.Buffer for the concurrent writes of two loggers.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// The proxy's lookup cache holds routes and checks no passwords (the backend checks
// the login), so lookup_cache.positive_revalidation_window means nothing to it and
// the config warns when a table sets it there (#1418). Building the proxy must not
// read the key either: a value that does not parse drew a "Failed to parse ...
// using default" warning for a key the same startup calls unused, and the startup
// line reported a window that nothing applies.
func TestUserAPIProxy_LookupCacheIgnoresPositiveRevalidationWindow(t *testing.T) {
	logs := &lockedBuffer{}
	capture := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	// The config warns through slog.Default, the server logs through the logger package.
	prevDefault := slog.Default()
	slog.SetDefault(capture)
	t.Cleanup(func() { slog.SetDefault(prevDefault) })
	prevLogger := logger.Swap(capture)
	t.Cleanup(func() { logger.Swap(prevLogger) })

	s, err := New(context.Background(), &resilient.ResilientDatabase{}, ServerOptions{
		Name:        t.Name(),
		Addr:        "127.0.0.1:0",
		RemoteAddrs: []string{"127.0.0.1:1"},
		JWTSecret:   strings.Repeat("x", 32),
		LookupCache: &config.LookupCacheConfig{Enabled: true, PositiveRevalidationWindow: "bogus"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.cancel() })
	if s.lookupCache == nil {
		t.Fatal("the lookup_cache table did not enable the route cache")
	}
	t.Cleanup(func() { _ = s.lookupCache.Stop(context.Background()) })

	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "positive_revalidation_window") {
			t.Errorf("logged a key the proxy does not read: %s", line)
		}
	}
}
