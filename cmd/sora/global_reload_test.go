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

// The relay handler is built at start-up, so a reload only reports a changed [relay] as
// needing a restart. A [relay] that start-up refuses (an unsupported type, #277, or no
// usable smtp_host or http_url, #532) is an error, as an invalid trusted_networks is:
// the restart the reload asks for would not start. The http_url is quoted masked, since
// the reload writes the error to the server log.
func TestGlobalReloadReportsAnInvalidRelay(t *testing.T) {
	tests := []struct {
		name    string
		relay   string
		wantErr string // part of the error-level report, "" for none
	}{
		{name: "valid smtp", relay: "type = \"smtp\"\nsmtp_host = \"smtp2.example.com:587\"", wantErr: ""},
		{name: "valid http", relay: "type = \"http\"\nhttp_url = \"https://api.example.com/deliver\"", wantErr: ""},
		{name: "unsupported type", relay: "type = \"lmtp\"\nsmtp_host = \"smtp2.example.com:24\"", wantErr: "unsupported [relay] type"},
		{name: "smtp without smtp_host", relay: "type = \"smtp\"", wantErr: "requires smtp_host as host:port"},
		{name: "smtp_host without port", relay: "type = \"smtp\"\nsmtp_host = \"smtp2.example.com\"", wantErr: "must be host:port"},
		{name: "http without http_url", relay: "type = \"http\"", wantErr: "requires http_url"},
		{name: "http_url other scheme", relay: "type = \"http\"\nhttp_url = \"ftp://api.example.com/deliver?key=fixture-relay-secret\"", wantErr: "must be an absolute http:// or https:// URL"},
		{name: "http_url without scheme hides query", relay: "type = \"http\"\nhttp_url = \"api.example.com/deliver?key=fixture-relay-secret\"", wantErr: "must be an absolute http:// or https:// URL"},
		{name: "smtp URL hides userinfo", relay: "type = \"smtp\"\nsmtp_host = \"smtp://user:fixture-relay-secret@smtp.example.com:587\"", wantErr: "must be host:port"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureReloadLogs(t)
			cfg := startupConfig()

			handleConfigReload(&cfg, reloadedFrom(t, "[relay]\n"+tt.relay+"\n"+metricsServerTOML))

			if cfg.Relay.IsConfigured() {
				t.Errorf("relay = %+v after the reload, want the start-up one (none)", cfg.Relay)
			}
			out := logs.String()
			if tt.wantErr == "" {
				if strings.Contains(out, "level=ERROR") {
					t.Errorf("a valid [relay] was reported as an error:\n%s", out)
				}
				return
			}
			if !hasLineWith(out, "level=ERROR", "[relay]", tt.wantErr) {
				t.Errorf("no error-level report naming %q:\n%s", tt.wantErr, out)
			}
			if strings.Contains(out, "fixture-relay-secret") {
				t.Errorf("the report quotes http_url unmasked:\n%s", out)
			}
		})
	}
}

// The relay worker also takes [relay.queue] at start-up. A worker_interval of zero or
// less, or a negative failed_retention, is refused by start-up (#643), so a reload
// reports it as an error, as it does an invalid [relay]: the restart it asks for would
// not start.
func TestGlobalReloadReportsAnInvalidRelayQueue(t *testing.T) {
	const relay = "[relay]\ntype = \"smtp\"\nsmtp_host = \"smtp2.example.com:587\"\n\n[relay.queue]\n"
	tests := []struct {
		name    string
		queue   string
		wantErr string // part of the error-level report, "" for none
	}{
		{name: "valid", queue: "worker_interval = \"30s\"\nfailed_retention = \"0\"", wantErr: ""},
		{name: "worker_interval 0", queue: "worker_interval = \"0\"", wantErr: "worker_interval must be positive"},
		{name: "worker_interval negative", queue: "worker_interval = \"-1m\"", wantErr: "worker_interval must be positive"},
		{name: "failed_retention negative", queue: "failed_retention = \"-1h\"", wantErr: "failed_retention must not be negative"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureReloadLogs(t)
			cfg := startupConfig()

			handleConfigReload(&cfg, reloadedFrom(t, relay+tt.queue+"\n"+metricsServerTOML))

			out := logs.String()
			if tt.wantErr == "" {
				if strings.Contains(out, "level=ERROR") {
					t.Errorf("a valid [relay.queue] was reported as an error:\n%s", out)
				}
				return
			}
			if !hasLineWith(out, "level=ERROR", "[relay.queue]", tt.wantErr) {
				t.Errorf("no error-level report naming %q:\n%s", tt.wantErr, out)
			}
		})
	}
}

// metricsServerTOML is a server that needs neither the database nor S3, so a file with
// it and the sections under test is one start-up takes.
const metricsServerTOML = "\n[[server]]\ntype = \"metrics\"\nname = \"metrics\"\naddr = \"127.0.0.1:9090\"\npath = \"/metrics\"\n"

// A reload applies no global section, but it reports a new file that start-up would
// refuse as an error, one for each problem Config.Validate finds: the restart the
// reload asks for would not start (#1106). The reload used to check trusted_networks,
// [relay] and [relay.queue] only, so a broken [cluster] or [[pool]] came to light when
// the next restart failed.
func TestGlobalReloadReportsWhatStartupRefuses(t *testing.T) {
	const imapBackend = storageTOML + "\n[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \"127.0.0.1:143\"\n"
	const imapProxy = "\n[[server]]\ntype = \"imap_proxy\"\nname = \"imap-proxy\"\naddr = \"127.0.0.1:1143\"\n"
	type problem struct{ section, err string }
	tests := []struct {
		name    string
		content string
		want    []problem // none for a file start-up takes
	}{
		{name: "valid mail backend", content: imapBackend},
		{name: "valid proxy with pools", content: "[[pool]]\nname = \"sora1\"\nbackends = [\"10.0.0.1:143\"]\ndefault = true\n" + storageTOML + imapProxy},
		{
			name: "cluster secret_key of 16 bytes",
			content: "[cluster]\nenabled = true\naddr = \"10.0.0.1:7946\"\nsecret_key = \"MDEyMzQ1Njc4OWFiY2RlZg==\"\n" +
				metricsServerTOML,
			want: []problem{{"[cluster]", "cluster secret_key must be 32 bytes (got 16 bytes)"}},
		},
		{
			name: "pool declared twice",
			content: "[[pool]]\nname = \"sora1\"\nbackends = [\"10.0.0.1:143\"]\ndefault = true\n" +
				"\n[[pool]]\nname = \"sora1\"\nbackends = [\"10.0.0.2:143\"]\n" + storageTOML + imapProxy,
			want: []problem{{"[[pool]]", "declared more than once"}},
		},
		{
			name:    "proxy without remote_addrs or [[pool]] blocks",
			content: storageTOML + imapProxy,
			want:    []problem{{"server 'imap-proxy'", "remote_addrs is required unless the file declares [[pool]] blocks"}},
		},
		{
			name:    "proxy_protocol without trusted_networks",
			content: "[servers]\ntrusted_networks = []\n" + imapBackend + "proxy_protocol = true\n",
			want:    []problem{{"trusted_networks", "proxy_protocol is enabled on server(s) imap but [servers] trusted_networks is empty"}},
		},
		{
			name:    "shared_mailboxes namespace_prefix without delimiter",
			content: "[shared_mailboxes]\nenabled = true\nnamespace_prefix = \"Shared\"\n" + imapBackend,
			want:    []problem{{"[shared_mailboxes]", "must be a mailbox name followed by the hierarchy delimiter"}},
		},
		{
			name:    "uploader concurrency 0 on a mail backend",
			content: "[uploader]\nconcurrency = 0\n" + imapBackend,
			want:    []problem{{"[uploader]", "concurrency must be positive, got 0"}},
		},
		{
			name:    "cleanup grace_period negative on a mail backend",
			content: "[cleanup]\ngrace_period = \"-14d\"\n" + imapBackend,
			want:    []problem{{"[cleanup]", "grace_period must not be negative"}},
		},
		{
			name:    "mail backend without database and S3",
			content: "\n[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \"127.0.0.1:143\"\n",
			want:    []problem{{"[database]", "needs the database"}, {"[s3]", "bucket is required"}},
		},
		{
			name:    "s3 encryption_key not hex",
			content: storageTOML + "encrypt = true\nencryption_key = \"not-hex\"\n" + "\n[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \"127.0.0.1:143\"\n",
			want:    []problem{{"[s3]", "encryption_key must be 64 hex characters"}},
		},
		{
			name:    "tls letsencrypt without email",
			content: "[tls]\nenabled = true\nprovider = \"letsencrypt\"\n\n[tls.letsencrypt]\ndomains = [\"mail.example.com\"]\n" + metricsServerTOML,
			want:    []problem{{"[tls]", "letsencrypt.email is required"}},
		},
		{
			name:    "no servers",
			content: "[relay]\ntype = \"smtp\"\nsmtp_host = \"smtp.example.com:587\"\n",
			want:    []problem{{"servers", "no servers configured"}},
		},
		{
			name: "server names and addresses used twice",
			content: imapBackend + "\n[[server]]\ntype = \"pop3\"\nname = \"imap\"\naddr = \"127.0.0.1:110\"\n" +
				"\n[[server]]\ntype = \"lmtp\"\nname = \"lmtp\"\naddr = \"127.0.0.1:143\"\n",
			want: []problem{
				{"server configuration", "duplicate server name 'imap' found"},
				{"server configuration", "duplicate server address '127.0.0.1:143' found"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureReloadLogs(t)
			cfg := startupConfig()

			handleConfigReload(&cfg, reloadedFrom(t, tt.content))

			out := logs.String()
			if len(tt.want) == 0 {
				if strings.Contains(out, "level=ERROR") {
					t.Errorf("a file start-up takes was reported as an error:\n%s", out)
				}
				return
			}
			for _, p := range tt.want {
				msg := "Config reload: " + p.section + " is invalid and the server will not start with this config"
				if !hasLineWith(out, "level=ERROR", msg, p.err) {
					t.Errorf("no error-level report %q naming %q:\n%s", msg, p.err, out)
				}
			}
		})
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

// proxyNodeConfig is a proxy node: no [database] (so start-up runs it without one, with
// a remote lookup for every user), named pools and a relay.
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

[server.remote_lookup]
enabled = true
url = "https://lookup.example.com/lookup?email=$email"
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
