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

// twoPoolsNoDefault is two pools, neither of them the default.
const twoPoolsNoDefault = `
[[pool]]
name = "sora0"
backends = ["10.0.0.1"]
[[pool]]
name = "sora1"
backends = ["10.0.1.1"]
`

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
remote_port = 143
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
remote_port = 143
[server.remote_lookup]
enabled = true
url = "https://lookup.example.com/?email=$email"
lookup_local_users = true
`,
			want: "",
		},
		{
			name: "no default pool and no local users is fine",
			toml: twoPoolsNoDefault + `
[[server]]
type = "lmtp_proxy"
name = "lmtp-proxy"
addr = ":24"
remote_port = 24
[server.remote_lookup]
enabled = true
url = "https://lookup.example.com/?email=$email"
`,
			want: "",
		},
		{
			// Without a remote lookup no user ever comes with a pool name: every login
			// would be refused.
			name: "no default pool and no remote lookup",
			toml: twoPoolsNoDefault + `
[[server]]
type = "lmtp_proxy"
name = "lmtp-proxy"
addr = ":24"
remote_port = 24
`,
			want: "without remote_lookup every user comes with no pool name",
		},
		{
			name: "disabled remote lookup counts as none",
			toml: twoPoolsNoDefault + `
[[server]]
type = "imap_proxy"
name = "imap-proxy"
addr = ":1143"
remote_port = 143
[server.remote_lookup]
enabled = false
url = "https://lookup.example.com/?email=$email"
`,
			want: "without remote_lookup every user comes with no pool name",
		},
		{
			// A bare host would be dialed without a port: every connection fails.
			name: "port-less backend and no remote_port",
			toml: poolsBase + `
[[server]]
type = "pop3_proxy"
name = "pop3-proxy"
addr = ":1110"
`,
			want: `server "pop3-proxy": remote_port is required`,
		},
		{
			name: "every backend has a port, no remote_port needed",
			toml: `
[[pool]]
name = "sora0"
backends = ["10.0.0.1:143", "[2001:db8::1]:143"]
default = true

[[server]]
type = "imap_proxy"
name = "imap-proxy"
addr = ":1143"
`,
			want: "",
		},
		{
			name: "same host in two pools, once with a port",
			toml: `
[[pool]]
name = "a"
backends = ["b1"]
[[pool]]
name = "b"
backends = ["B1:143"]
`,
			want: `already belongs to pool "a"`,
		},
		{
			// One pool per protocol on one machine: explicit, different ports.
			name: "same host in two pools on different explicit ports",
			toml: `
[[pool]]
name = "a"
backends = ["b1:143"]
default = true
[[pool]]
name = "b"
backends = ["b1:110"]
`,
			want: "",
		},
		{
			name: "same host and port in two pools",
			toml: `
[[pool]]
name = "a"
backends = ["10.0.0.1:143"]
[[pool]]
name = "b"
backends = ["10.0.0.1:0143"]
`,
			want: `already belongs to pool "a"`,
		},
		{
			// A port-less backend is that host on every proxy's remote_port.
			name: "port-less backend clashes with the same host on any port",
			toml: `
[[pool]]
name = "a"
backends = ["b1:110"]
[[pool]]
name = "b"
backends = ["b1"]
`,
			want: `already belongs to pool "a"`,
		},
		{
			name: "same IPv6 host in two spellings",
			toml: `
[[pool]]
name = "a"
backends = ["[2001:db8:0::1]:143"]
[[pool]]
name = "b"
backends = ["2001:db8::1"]
`,
			want: `already belongs to pool "a"`,
		},
		{
			name: "host listed twice in one pool",
			toml: `
[[pool]]
name = "a"
backends = ["10.0.0.1:143", "10.0.0.1"]
`,
			want: "listed more than once",
		},
		{
			name: "STARTTLS without TLS",
			toml: `
[[pool]]
name = "a"
backends = ["10.0.0.1"]
remote_tls_use_starttls = true
`,
			want: "remote_tls_use_starttls = true needs remote_tls = true",
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

// A pool's backends can be verified against a CA of its own (private-CA or self-signed
// backends), declared in the pool block like every other backend-leg setting. It only means
// something with remote_tls.
func TestPoolsConfig_CAFile(t *testing.T) {
	cfg, err := loadPoolsConfig(t, `
[[pool]]
name = "private"
backends = ["10.0.0.1"]
default = true
remote_tls = true
remote_tls_ca_file = "/etc/sora/private-ca.pem"

[[pool]]
name = "public"
backends = ["10.0.1.1"]
remote_tls = true
`)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := cfg.Pools[0].RemoteTLSCAFile; got != "/etc/sora/private-ca.pem" {
		t.Errorf("private pool CA file = %q", got)
	}
	if got := cfg.Pools[1].RemoteTLSCAFile; got != "" {
		t.Errorf("public pool CA file = %q, want none", got)
	}
	if err := cfg.ValidatePools(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	cfg, err = loadPoolsConfig(t, `
[[pool]]
name = "plain"
backends = ["10.0.0.1"]
default = true
remote_tls_ca_file = "/etc/sora/private-ca.pem"
`)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := cfg.ValidatePools(); err == nil || !strings.Contains(err.Error(), "remote_tls_ca_file needs remote_tls = true") {
		t.Fatalf("CA file without TLS: err = %v", err)
	}
}
