package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/migadu/sora/config"
)

type syncLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func captureReloadLogs(t *testing.T) *syncLogBuffer {
	t.Helper()
	buf := &syncLogBuffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return buf
}

func writeReloadConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The running config as start-up left it: the values every consumer copied.
func startupConfig() config.Config {
	cfg := config.NewDefaultConfig()
	cfg.SharedMailboxes = config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: "Shared/", DefaultRights: "lrswipkxtea"}
	cfg.Metadata = config.MetadataConfig{MaxEntrySize: 65536, MaxEntriesPerMailbox: 100, MaxEntriesPerServer: 1000, MaxTotalSize: 1 << 20}
	cfg.Servers.TrustedNetworks = []string{"127.0.0.0/8", "10.0.0.0/8"}
	cfg.Cleanup.GracePeriod = "14d"
	cfg.Cleanup.WakeInterval = "1h"
	cfg.Cleanup.MaxAgeRestriction = ""
	return cfg
}

const changedGlobalSettings = `
[shared_mailboxes]
enabled = false
namespace_prefix = "#shared/"
default_rights = "lr"

[metadata]
max_entry_size = 1024
max_entries_per_mailbox = 5
max_entries_per_server = 10
max_total_size = 4096

[servers]
trusted_networks = ["127.0.0.0/8"]

[cleanup]
grace_period = "1d"
wake_interval = "5m"
max_age_restriction = "30d"
`

// None of these four reaches its consumers on a reload: IMAP copied the metadata limits
// and every server the trusted networks at start-up, and the cleaner was configured once.
// shared_mailboxes did reach IMAP, through the shared *config.Config, but unsynchronized
// (see TestGlobalReloadDoesNotWriteTheSharedConfig). A reload must leave them as they are
// and say that they need a restart, not log them as reloaded.
func TestGlobalReloadLeavesRestartOnlySettingsInPlace(t *testing.T) {
	logs := captureReloadLogs(t)
	cfg := startupConfig()
	want := startupConfig()

	handleConfigReload(writeReloadConfig(t, changedGlobalSettings), &cfg, nil)

	if cfg.SharedMailboxes != want.SharedMailboxes {
		t.Errorf("shared_mailboxes = %+v after the reload, want the start-up %+v", cfg.SharedMailboxes, want.SharedMailboxes)
	}
	if cfg.Metadata != want.Metadata {
		t.Errorf("metadata = %+v after the reload, want the start-up %+v", cfg.Metadata, want.Metadata)
	}
	if !slices.Equal(cfg.Servers.TrustedNetworks, want.Servers.TrustedNetworks) {
		t.Errorf("trusted_networks = %v after the reload, want the start-up %v", cfg.Servers.TrustedNetworks, want.Servers.TrustedNetworks)
	}
	if cfg.Cleanup != want.Cleanup {
		t.Errorf("cleanup = %+v after the reload, want the start-up %+v", cfg.Cleanup, want.Cleanup)
	}

	out := logs.String()
	if strings.Contains(out, "Config reloaded") {
		t.Errorf("a setting that is not applied was logged as reloaded:\n%s", out)
	}
	for _, section := range []string{"[shared_mailboxes]", "[metadata]", "trusted_networks", "[cleanup]"} {
		if !hasLineWith(out, section, "requires restart") {
			t.Errorf("no restart notice for %s:\n%s", section, out)
		}
	}
}

// A reload that does not change trusted_networks must not report it at all.
func TestGlobalReloadReportsTrustedNetworksOnlyWhenChanged(t *testing.T) {
	logs := captureReloadLogs(t)
	cfg := startupConfig()

	handleConfigReload(writeReloadConfig(t, `
[servers]
trusted_networks = ["127.0.0.0/8", "10.0.0.0/8"]
`), &cfg, nil)

	if out := logs.String(); strings.Contains(out, "trusted_networks") {
		t.Errorf("unchanged trusted_networks reported:\n%s", out)
	}
}

// IMAP sessions read the shared *config.Config with no lock (NAMESPACE, LIST, SELECT,
// CREATE, NOTIFY read SharedMailboxes; the DB layer reads DefaultRights through the
// context). A reload must not write it while they do. Fails under -race on a writer.
func TestGlobalReloadDoesNotWriteTheSharedConfig(t *testing.T) {
	captureReloadLogs(t)
	cfg := startupConfig()
	toggled := writeReloadConfig(t, changedGlobalSettings)
	original := writeReloadConfig(t, `
[shared_mailboxes]
enabled = true
namespace_prefix = "Shared/"
default_rights = "lrswipkxtea"
`)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // what an IMAP session reads
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if cfg.SharedMailboxes.Enabled {
				_ = strings.TrimSuffix(cfg.SharedMailboxes.NamespacePrefix, "/")
			}
			_ = cfg.SharedMailboxes.DefaultRights
		}
	}()
	for i := 0; i < 50; i++ {
		path := toggled
		if i%2 == 1 {
			path = original
		}
		handleConfigReload(path, &cfg, nil)
	}
	close(stop)
	wg.Wait()
}

func hasLineWith(logs string, parts ...string) bool {
	for _, line := range strings.Split(logs, "\n") {
		found := true
		for _, p := range parts {
			found = found && strings.Contains(line, p)
		}
		if found {
			return true
		}
	}
	return false
}
