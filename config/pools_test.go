package config

import (
	"os"
	"strings"
	"testing"
)

// loadPoolsConfig writes a TOML snippet to a temp file and runs it through the real loader,
// so the [[pool]] decoding is exercised the way sora does it, not by decoding a struct by hand.
func loadPoolsConfig(t *testing.T, content string) (Config, error) {
	t.Helper()
	tmp, err := os.CreateTemp(t.TempDir(), "pools-*.toml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmp.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	var cfg Config
	err = LoadConfigFromFile(tmp.Name(), &cfg)
	return cfg, err
}

const poolsBase = `
[[pool]]
name = "sora0"
backends = ["10.0.0.1", "10.0.0.2"]
default = true
remote_use_proxy_protocol = true
remote_use_id_command = true

[[pool]]
name = "dovecot1"
backends = ["10.0.2.1:143"]
remote_tls = true
remote_tls_verify = false
`

func TestPoolsConfig_LoadsBlocksAndDefaults(t *testing.T) {
	cfg, err := loadPoolsConfig(t, poolsBase+`
[[server]]
type = "imap_proxy"
name = "imap-proxy"
addr = ":1143"
remote_port = 143
`)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := cfg.ValidatePools(); err != nil {
		t.Fatalf("ValidatePools: %v", err)
	}
	if !cfg.HasPools() || len(cfg.Pools) != 2 {
		t.Fatalf("expected 2 pools, got %d", len(cfg.Pools))
	}
	sora0, dovecot1 := cfg.Pools[0], cfg.Pools[1]
	if sora0.Name != "sora0" || len(sora0.Backends) != 2 || !sora0.Default {
		t.Errorf("sora0 decoded wrong: %+v", sora0)
	}
	if !sora0.RemoteUseProxyProtocol || !sora0.RemoteUseIDCommand || sora0.RemoteTLS {
		t.Errorf("sora0 settings decoded wrong: %+v", sora0)
	}
	if !sora0.GetRemoteTLSVerify() {
		t.Errorf("remote_tls_verify must default to true when unset")
	}
	if dovecot1.Name != "dovecot1" || dovecot1.Default || !dovecot1.RemoteTLS || dovecot1.GetRemoteTLSVerify() {
		t.Errorf("dovecot1 decoded wrong: %+v", dovecot1)
	}
	if d := cfg.DefaultPool(); d == nil || d.Name != "sora0" {
		t.Errorf("DefaultPool = %v, want sora0", d)
	}
}

func TestPoolsConfig_NoPoolsIsLegacy(t *testing.T) {
	cfg, err := loadPoolsConfig(t, `
[[server]]
type = "imap_proxy"
name = "imap-proxy"
addr = ":1143"
remote_addrs = ["backend1:143"]
`)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.HasPools() || cfg.DefaultPool() != nil {
		t.Fatalf("no [[pool]] blocks must mean no pools")
	}
	if err := cfg.ValidatePools(); err != nil {
		t.Fatalf("legacy remote_addrs config must validate: %v", err)
	}
}

func TestPoolsConfig_Validation(t *testing.T) {
	cases := []struct {
		name string
		toml string
		want string // substring of the validation error; "" = must pass
	}{
		{
			name: "duplicate pool name",
			toml: poolsBase + `
[[pool]]
name = "sora0"
backends = ["10.0.9.1"]
`,
			want: "declared more than once",
		},
		{
			name: "missing name",
			toml: `
[[pool]]
backends = ["10.0.0.1"]
`,
			want: "name is required",
		},
		{
			name: "whitespace in name",
			toml: `
[[pool]]
name = "sora 0"
backends = ["10.0.0.1"]
`,
			want: "whitespace",
		},
		{
			name: "no backends",
			toml: `
[[pool]]
name = "empty"
backends = []
`,
			want: "at least one host",
		},
		{
			name: "same host in two pools",
			toml: poolsBase + `
[[pool]]
name = "sora1"
backends = ["10.0.0.2"]
`,
			want: `already belongs to pool "sora0"`,
		},
		{
			name: "same host differs only by case",
			toml: `
[[pool]]
name = "a"
backends = ["Backend1.internal"]
[[pool]]
name = "b"
backends = ["backend1.internal"]
`,
			want: "already belongs to pool",
		},
		{
			name: "two defaults",
			toml: poolsBase + `
[[pool]]
name = "sora1"
backends = ["10.0.1.1"]
default = true
`,
			want: "only one pool may be default",
		},
		{
			name: "proxy keeps remote_addrs next to pools",
			toml: poolsBase + `
[[server]]
type = "pop3_proxy"
name = "pop3-proxy"
addr = ":1110"
remote_addrs = ["backend1:110"]
`,
			want: "remote_addrs cannot be combined",
		},
		{
			name: "non-proxy server with remote_addrs is not the pools' business",
			toml: poolsBase + `
[[server]]
type = "imap"
name = "imap"
addr = ":143"
remote_addrs = ["stray:143"]
`,
			want: "",
		},
		{
			name: "lookup_local_users without a default pool",
			toml: `
[[pool]]
name = "sora0"
backends = ["10.0.0.1"]

[[server]]
type = "imap_proxy"
name = "imap-proxy"
addr = ":1143"
[server.remote_lookup]
enabled = true
url = "https://lookup.example.com/?email=$email"
lookup_local_users = true
`,
			want: "lookup_local_users = true needs a pool with default = true",
		},
		{
			name: "lookup_local_users with a default pool",
			toml: poolsBase + `
[[server]]
type = "imap_proxy"
name = "imap-proxy"
addr = ":1143"
[server.remote_lookup]
enabled = true
url = "https://lookup.example.com/?email=$email"
lookup_local_users = true
`,
			want: "",
		},
		{
			name: "no default pool and no local users is fine",
			toml: `
[[pool]]
name = "sora0"
backends = ["10.0.0.1"]
[[pool]]
name = "sora1"
backends = ["10.0.1.1"]

[[server]]
type = "lmtp_proxy"
name = "lmtp-proxy"
addr = ":24"
`,
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := loadPoolsConfig(t, tc.toml)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			err = cfg.ValidatePools()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("expected valid, got: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got: %v", tc.want, err)
			}
		})
	}
}
