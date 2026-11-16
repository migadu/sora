package userapi

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/resilient"
)

type lockedLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// take returns what was logged since the last call.
func (b *lockedLogBuffer) take() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.buf.String()
	b.buf.Reset()
	return s
}

// allowed_hosts matches IP addresses and CIDRs only: a host name is never resolved and
// matches no client. Such an entry is reported when a list is installed, at startup and
// when a reload replaces it, as on the Admin API (#307, #460).
func TestAllowedHosts_WarnsAboutEntriesThatMatchNoClient(t *testing.T) {
	logs := &lockedLogBuffer{}
	prev := logger.Swap(slog.New(slog.NewTextHandler(logs, nil)))
	t.Cleanup(func() { logger.Swap(prev) })

	const warning = "not an IP address or CIDR"
	s, err := New(&resilient.ResilientDatabase{}, ServerOptions{
		Name:         "user-hosts-warning",
		JWTSecret:    reloadSecretA,
		AllowedHosts: []string{"admin.example.com", "10.0.1.0/24"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := logs.take()
	if !strings.Contains(got, warning) || !strings.Contains(got, "admin.example.com") || !strings.Contains(got, "user-hosts-warning") {
		t.Errorf("startup: no warning naming the host-name entry; log:\n%s", got)
	}
	if strings.Contains(got, "10.0.1.0/24") {
		t.Errorf("startup: the CIDR entry was reported; log:\n%s", got)
	}

	if err := s.ReloadConfig(config.ServerConfig{Name: "user-hosts-warning", AllowedHosts: []string{"10.0.1.0/24", "ops.example.org"}}); err != nil {
		t.Fatal(err)
	}
	if got := logs.take(); !strings.Contains(got, warning) || !strings.Contains(got, "ops.example.org") || strings.Contains(got, "admin.example.com") {
		t.Errorf("reload: want a warning naming only the new list's host-name entry; log:\n%s", got)
	}

	// Once per list: a reload that leaves the list as it is says nothing again.
	if err := s.ReloadConfig(config.ServerConfig{Name: "user-hosts-warning", AllowedHosts: []string{"10.0.1.0/24", "ops.example.org"}}); err != nil {
		t.Fatal(err)
	}
	if got := logs.take(); strings.Contains(got, warning) {
		t.Errorf("unchanged reload repeated the warning; log:\n%s", got)
	}
}
