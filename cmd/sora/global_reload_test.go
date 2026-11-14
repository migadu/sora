package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

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

// reloadedFrom is the config a SIGHUP reads from content.
func reloadedFrom(t *testing.T, content string) *config.Config {
	t.Helper()
	cfg, err := readConfigFile(writeReloadConfig(t, content))
	if err != nil {
		t.Fatal(err)
	}
	return &cfg
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

	handleConfigReload(&cfg, reloadedFrom(t, changedGlobalSettings))

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
	for _, section := range []string{"shared_mailboxes.enabled", "metadata.max_entry_size", "servers.trusted_networks", "cleanup.grace_period"} {
		if !hasLineWith(out, section, "require restart") {
			t.Errorf("no restart notice for %s:\n%s", section, out)
		}
	}
}

// A reload that does not change trusted_networks must not report it at all.
func TestGlobalReloadReportsTrustedNetworksOnlyWhenChanged(t *testing.T) {
	logs := captureReloadLogs(t)
	cfg := startupConfig()

	handleConfigReload(&cfg, reloadedFrom(t, `
[servers]
trusted_networks = ["127.0.0.0/8", "10.0.0.0/8"]
`))

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
	toggled := reloadedFrom(t, changedGlobalSettings)
	original := reloadedFrom(t, `
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
		next := toggled
		if i%2 == 1 {
			next = original
		}
		handleConfigReload(&cfg, next)
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

// proxyNodeConfig is a proxy node: no [database] (so start-up runs it without one),
// named pools and a relay.
const proxyNodeConfig = `
bcrypt_cost = 12

[relay]
type = "smtp"
smtp_host = "smtp.example.com:587"

[[pool]]
name = "sora1"
backends = ["10.0.0.1:143", "10.0.0.2:143"]
default = true

[[server]]
type = "imap_proxy"
name = "imap-proxy"
addr = ":1993"
`

// reportsRestart reports whether a restart notice in logs names key as a whole field.
func reportsRestart(logs, key string) bool {
	field := regexp.MustCompile(`[\[ ]` + regexp.QuoteMeta(key) + `[\] ]`)
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, "require restart") && field.MatchString(line) {
			return true
		}
	}
	return false
}

// Every global setting is compared (#282). A reload used to compare logging.level,
// [cleanup], [shared_mailboxes], [sieve], [backend_maintenance], [metadata] and
// trusted_networks only, so an operator who changed [[pool]] members or the relay host
// and sent SIGHUP saw a clean reload while the old values stayed in use.
func TestGlobalReloadReportsEverySection(t *testing.T) {
	logs := captureReloadLogs(t)
	started := loadStartupDatabaseConfig(t, proxyNodeConfig)

	handleConfigReload(&started, reloadedFrom(t, `
bcrypt_cost = 13

[logging]
output = "/var/log/sora/sora.log"
format = "json"

[database.write]
hosts = ["db.example.com"]

[s3]
endpoint = "s3.example.com"

[tls]
cert_file = "/etc/sora/cert.pem"

[cluster]
peers = ["10.0.0.9:7946"]

[relay]
type = "smtp"
smtp_host = "smtp2.example.com:587"

[spam_training]
endpoint = "https://spam.example.com"

[uploader]
batch_size = 5

[local_cache]
capacity = "2gb"

[auth_cache]
enabled = true

[timeout_scheduler]
shard_count = 7

[[pool]]
name = "sora1"
backends = ["10.0.0.3:143"]
default = true

[[server]]
type = "imap_proxy"
name = "imap-proxy"
addr = ":1993"
`))

	out := logs.String()
	for _, key := range []string{
		"bcrypt_cost", "logging.output", "logging.format", "database.write.hosts", "s3.endpoint",
		"tls.cert_file", "cluster.peers", "relay.smtp_host", "spam_training.endpoint",
		"uploader.batch_size", "local_cache.capacity", "auth_cache.enabled",
		"timeout_scheduler.shard_count", "pool",
	} {
		if !reportsRestart(out, key) {
			t.Errorf("no restart notice naming %s:\n%s", key, out)
		}
	}
	// Secrets and the like are named, never logged.
	if strings.Contains(out, "smtp2.example.com") {
		t.Errorf("the restart notice logs values:\n%s", out)
	}
}

// A reload of the file the node started with reports nothing, on a node without
// [database] too: start-up unsets the endpoints the file leaves out, and a reload that
// did not would see them as added. [admin_cli] is sora-admin's, which reads the file on
// every run; sora never reads it, so a change to it is not one sora needs a restart for.
func TestGlobalReloadOfTheStartupFileReportsNothing(t *testing.T) {
	logs := captureReloadLogs(t)
	started := loadStartupDatabaseConfig(t, proxyNodeConfig)

	handleConfigReload(&started, reloadedFrom(t, proxyNodeConfig))
	handleConfigReload(&started, reloadedFrom(t, proxyNodeConfig+`
[admin_cli]
addr = "https://admin.example.com:8080"
api_key = "changed"
`))

	if out := logs.String(); strings.Contains(out, "restart") {
		t.Errorf("a reload that changed nothing sora uses reported a restart:\n%s", out)
	}
}

// Every global setting a reload does not report is a real key.
func TestReloadableGlobalSettingsAreRealKeys(t *testing.T) {
	keys := config.GlobalConfigKeys()
	for _, setting := range reloadableGlobalSettings {
		if !slices.Contains(keys, setting) {
			t.Errorf("%q is not a global setting", setting)
		}
	}
	for _, key := range keys {
		if strings.HasPrefix(key, "admin_cli.") && !slices.Contains(reloadableGlobalSettings, key) {
			t.Errorf("%s is sora-admin's, but a change to it would be reported as needing a sora restart", key)
		}
	}
}

// One read of the file per SIGHUP, shared by the global report and the per-server
// reload (#282). They used to read it once each, so the two halves could act on two
// versions of the file. The config is a FIFO that yields the content once: a second
// read blocks.
func TestConfigReloadReadsTheFileOnce(t *testing.T) {
	logs := captureReloadLogs(t)
	deps, reloaders := runningDeps(t, config.ServerConfig{Type: "http_user_api", Name: "user-api", Addr: ":8081"})

	fifo := filepath.Join(t.TempDir(), "config.toml")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("no FIFO here: %v", err)
	}
	go func() {
		f, err := os.OpenFile(fifo, os.O_WRONLY, 0)
		if err != nil {
			return
		}
		_, _ = f.WriteString(`
[relay]
type = "smtp"
smtp_host = "smtp.example.com:587"

[[server]]
type = "http_user_api"
name = "user-api"
addr = ":8081"
allowed_origins = ["https://webmail.example.com"]
`)
		f.Close()
	}()

	done := make(chan struct{})
	go func() {
		deps.reloadConfig(fifo)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		// Unblock the second read so the goroutine can finish.
		if f, err := os.OpenFile(fifo, os.O_WRONLY, 0); err == nil {
			f.Close()
		}
		<-done
		t.Fatal("the reload read the config file more than once")
	}

	if got := reloaders["user-api"].reloaded; len(got) != 1 || !slices.Equal(got[0].AllowedOrigins, []string{"https://webmail.example.com"}) {
		t.Errorf("ReloadConfig got %+v, want the server block of the one read", got)
	}
	if out := logs.String(); !reportsRestart(out, "relay.smtp_host") {
		t.Errorf("the global report did not see the relay of the one read:\n%s", out)
	}
}
