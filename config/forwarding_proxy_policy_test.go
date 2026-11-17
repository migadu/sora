package config

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestForwardingSkipPolicyDecodesAsExplicitOptIn(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enabled_%t", enabled), func(t *testing.T) {
			line := ""
			if enabled {
				line = "remote_skip_forwarding_with_proxy_protocol = true\n"
			}
			cfg, err := loadPoolsConfig(t, `[[pool]]
name="primary"
backends=["127.0.0.1:143"]
default=true
`+line+`
[[server]]
type="imap_proxy"
name="policy"
addr=":1143"
`+line+`
[server.remote_lookup]
enabled=true
url="http://127.0.0.1/lookup?email=$email"
`+line)
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.DynamicServers) != 1 || len(cfg.Pools) != 1 {
				t.Fatalf("unexpected config: %+v", cfg)
			}
			s := cfg.DynamicServers[0]
			if s.RemoteSkipForwardingWithProxyProtocol != enabled || s.RemoteLookup == nil || s.RemoteLookup.RemoteSkipForwardingWithProxyProtocol != enabled || cfg.Pools[0].RemoteSkipForwardingWithProxyProtocol != enabled {
				t.Fatalf("server, lookup and pool must independently default tofalse and retain explicittrue: server=%+v lookup=%+v pool=%+v", s, s.RemoteLookup, cfg.Pools[0])
			}
		})
	}
}

func TestForwardingSkipPolicyWarnings(t *testing.T) {
	// Include [database.write] and a managesieve server so proxy configs without local
	// database lookups do not trigger the unrelated backend-maintenance database warning.
	const base = `[database.write]
hosts = ["db.example.com"]

[[server]]
type = "managesieve"
name = "sieve"
addr = "127.0.0.1:4190"
`

	tests := []struct {
		name      string
		toml      string
		wantSub   []string // substrings that must all appear in the single warning; nil = want 0 warnings
	}{
		{
			name: "server imap_proxy alongside [[pool]] is never consulted",
			toml: `[[pool]]
name = "primary"
backends = ["10.0.0.1:143"]
default = true
remote_use_proxy_protocol = true
remote_use_id_command = true

[[server]]
type = "imap_proxy"
name = "imap-proxy"
addr = "127.0.0.1:1143"
remote_use_proxy_protocol = true
remote_use_id_command = true
remote_skip_forwarding_with_proxy_protocol = true
`,
			wantSub: []string{"Server imap-proxy (type: imap_proxy)", "'remote_skip_forwarding_with_proxy_protocol'", "[[pool]]"},
		},
		{
			name: "server pop3_proxy alongside [[pool]] emits single pool warning even without prerequisites",
			toml: `[[pool]]
name = "primary"
backends = ["10.0.0.1:110"]
default = true
remote_use_proxy_protocol = true
remote_use_xclient = true

[[server]]
type = "pop3_proxy"
name = "pop3-proxy"
addr = "127.0.0.1:1110"
remote_skip_forwarding_with_proxy_protocol = true
`,
			wantSub: []string{"Server pop3-proxy (type: pop3_proxy)", "'remote_skip_forwarding_with_proxy_protocol'", "[[pool]]"},
		},
		{
			name: "server imap_proxy without remote_use_proxy_protocol",
			toml: `[[server]]
type = "imap_proxy"
name = "imap-proxy"
addr = "127.0.0.1:1143"
remote_addrs = ["10.0.0.1:143"]
remote_use_id_command = true
remote_skip_forwarding_with_proxy_protocol = true
`,
			wantSub: []string{"Server imap-proxy (type: imap_proxy)", "'remote_skip_forwarding_with_proxy_protocol'", "'remote_use_proxy_protocol'"},
		},
		{
			name: "server imap_proxy without remote_use_id_command",
			toml: `[[server]]
type = "imap_proxy"
name = "imap-proxy"
addr = "127.0.0.1:1143"
remote_addrs = ["10.0.0.1:143"]
remote_use_proxy_protocol = true
remote_skip_forwarding_with_proxy_protocol = true
`,
			wantSub: []string{"Server imap-proxy (type: imap_proxy)", "'remote_skip_forwarding_with_proxy_protocol'", "'remote_use_id_command'"},
		},
		{
			name: "server pop3_proxy without remote_use_proxy_protocol",
			toml: `[[server]]
type = "pop3_proxy"
name = "pop3-proxy"
addr = "127.0.0.1:1110"
remote_addrs = ["10.0.0.1:110"]
remote_use_xclient = true
remote_skip_forwarding_with_proxy_protocol = true
`,
			wantSub: []string{"Server pop3-proxy (type: pop3_proxy)", "'remote_skip_forwarding_with_proxy_protocol'", "'remote_use_proxy_protocol'"},
		},
		{
			name: "server pop3_proxy without remote_use_xclient",
			toml: `[[server]]
type = "pop3_proxy"
name = "pop3-proxy"
addr = "127.0.0.1:1110"
remote_addrs = ["10.0.0.1:110"]
remote_use_proxy_protocol = true
remote_skip_forwarding_with_proxy_protocol = true
`,
			wantSub: []string{"Server pop3-proxy (type: pop3_proxy)", "'remote_skip_forwarding_with_proxy_protocol'", "'remote_use_xclient'"},
		},
		{
			name: "remote_lookup imap_proxy without remote_use_proxy_protocol",
			toml: `[[server]]
type = "imap_proxy"
name = "imap-proxy"
addr = "127.0.0.1:1143"
remote_addrs = ["10.0.0.1:143"]
[server.remote_lookup]
enabled = true
url = "http://127.0.0.1/lookup?email=$email"
remote_use_id_command = true
remote_skip_forwarding_with_proxy_protocol = true
`,
			wantSub: []string{"Server imap-proxy (type: imap_proxy)", "'remote_lookup.remote_skip_forwarding_with_proxy_protocol'", "'remote_lookup.remote_use_proxy_protocol'"},
		},
		{
			name: "remote_lookup imap_proxy without remote_use_id_command",
			toml: `[[server]]
type = "imap_proxy"
name = "imap-proxy"
addr = "127.0.0.1:1143"
remote_addrs = ["10.0.0.1:143"]
[server.remote_lookup]
enabled = true
url = "http://127.0.0.1/lookup?email=$email"
remote_use_proxy_protocol = true
remote_skip_forwarding_with_proxy_protocol = true
`,
			wantSub: []string{"Server imap-proxy (type: imap_proxy)", "'remote_lookup.remote_skip_forwarding_with_proxy_protocol'", "'remote_lookup.remote_use_id_command'"},
		},
		{
			name: "remote_lookup pop3_proxy without remote_use_proxy_protocol",
			toml: `[[server]]
type = "pop3_proxy"
name = "pop3-proxy"
addr = "127.0.0.1:1110"
remote_addrs = ["10.0.0.1:110"]
[server.remote_lookup]
enabled = true
url = "http://127.0.0.1/lookup?email=$email"
remote_use_xclient = true
remote_skip_forwarding_with_proxy_protocol = true
`,
			wantSub: []string{"Server pop3-proxy (type: pop3_proxy)", "'remote_lookup.remote_skip_forwarding_with_proxy_protocol'", "'remote_lookup.remote_use_proxy_protocol'"},
		},
		{
			name: "remote_lookup pop3_proxy without remote_use_xclient",
			toml: `[[server]]
type = "pop3_proxy"
name = "pop3-proxy"
addr = "127.0.0.1:1110"
remote_addrs = ["10.0.0.1:110"]
[server.remote_lookup]
enabled = true
url = "http://127.0.0.1/lookup?email=$email"
remote_use_proxy_protocol = true
remote_skip_forwarding_with_proxy_protocol = true
`,
			wantSub: []string{"Server pop3-proxy (type: pop3_proxy)", "'remote_lookup.remote_skip_forwarding_with_proxy_protocol'", "'remote_lookup.remote_use_xclient'"},
		},
		{
			name: "pool without remote_use_proxy_protocol",
			toml: `[[pool]]
name = "primary"
backends = ["10.0.0.1:143"]
default = true
remote_use_id_command = true
remote_skip_forwarding_with_proxy_protocol = true

[[server]]
type = "imap_proxy"
name = "imap-proxy"
addr = "127.0.0.1:1143"
`,
			wantSub: []string{`[[pool]] "primary"`, "'remote_skip_forwarding_with_proxy_protocol'", "'remote_use_proxy_protocol'"},
		},
		{
			name: "pool without remote_use_id_command or remote_use_xclient",
			toml: `[[pool]]
name = "primary"
backends = ["10.0.0.1:143"]
default = true
remote_use_proxy_protocol = true
remote_skip_forwarding_with_proxy_protocol = true

[[server]]
type = "imap_proxy"
name = "imap-proxy"
addr = "127.0.0.1:1143"
`,
			wantSub: []string{`[[pool]] "primary"`, "'remote_skip_forwarding_with_proxy_protocol'", "'remote_use_id_command'", "'remote_use_xclient'"},
		},
		{
			name: "valid server imap_proxy and pop3_proxy without pools",
			toml: `[[server]]
type = "imap_proxy"
name = "imap-proxy"
addr = "127.0.0.1:1143"
remote_addrs = ["10.0.0.1:143"]
remote_use_proxy_protocol = true
remote_use_id_command = true
remote_skip_forwarding_with_proxy_protocol = true

[[server]]
type = "pop3_proxy"
name = "pop3-proxy"
addr = "127.0.0.1:1110"
remote_addrs = ["10.0.0.1:110"]
remote_use_proxy_protocol = true
remote_use_xclient = true
remote_skip_forwarding_with_proxy_protocol = true
`,
		},
		{
			name: "valid shared pool and remote_lookup pins",
			toml: `[[pool]]
name = "imap-only"
backends = ["10.0.0.1"]
default = true
remote_use_proxy_protocol = true
remote_use_id_command = true
remote_skip_forwarding_with_proxy_protocol = true

[[pool]]
name = "pop3-only"
backends = ["10.0.0.2"]
remote_use_proxy_protocol = true
remote_use_xclient = true
remote_skip_forwarding_with_proxy_protocol = true

[[server]]
type = "imap_proxy"
name = "imap-proxy"
addr = "127.0.0.1:1143"
remote_port = 143
[server.remote_lookup]
enabled = true
url = "http://127.0.0.1/lookup?email=$email"
remote_use_proxy_protocol = true
remote_use_id_command = true
remote_skip_forwarding_with_proxy_protocol = true

[[server]]
type = "pop3_proxy"
name = "pop3-proxy"
addr = "127.0.0.1:1110"
remote_port = 110
[server.remote_lookup]
enabled = true
url = "http://127.0.0.1/lookup?email=$email"
remote_use_proxy_protocol = true
remote_use_xclient = true
remote_skip_forwarding_with_proxy_protocol = true
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(base+"\n"+tt.toml), 0o600); err != nil {
				t.Fatal(err)
			}
			var cfg Config
			if err := LoadServerConfig(path, &cfg); err != nil {
				t.Fatalf("LoadServerConfig: %v", err)
			}
			if problems := cfg.Validate(); len(problems) != 0 {
				t.Fatalf("Validate() returned hard errors (inert skip policy must warn, not fail validation): %v", problems)
			}

			// Collect warnings both via Config.Warnings() (sora-admin config validate)
			// and via GetAllServers() -> WarnUnusedConfigOptions (cmd/sora startup).
			collected := cfg.Warnings()
			var startup []string
			for _, srv := range cfg.GetAllServers() {
				srv.WarnUnusedConfigOptions(func(format string, args ...any) {
					startup = append(startup, strings.TrimPrefix(fmt.Sprintf(format, args...), "WARNING: "))
				})
			}

			if !slices.Equal(collected, startup) {
				t.Fatalf("Config.Warnings() and startup WarnUnusedConfigOptions diverged:\nWarnings(): %q\nstartup:    %q", collected, startup)
			}

			if len(tt.wantSub) == 0 {
				if len(collected) != 0 {
					t.Fatalf("unexpected warnings on valid forwarding skip policy: %q", collected)
				}
				return
			}
			if len(collected) != 1 {
				t.Fatalf("got %d warnings %q, want 1 warning containing %q", len(collected), collected, tt.wantSub)
			}
			for _, sub := range tt.wantSub {
				if !strings.Contains(collected[0], sub) {
					t.Errorf("warning %q does not contain %q", collected[0], sub)
				}
			}
		})
	}
}
