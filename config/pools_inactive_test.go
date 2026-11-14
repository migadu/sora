package config

import "testing"

func TestPoolsConfig_IgnoresInactiveProxyStanzas(t *testing.T) {
	for _, tc := range []struct{ name, inactive string }{
		{"legacy_backends", `remote_addrs = ["retired.example:110"]`},
		{"missing_remote_port", ``},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := loadPoolsConfig(t, `
[[pool]]
name = "active"
backends = ["127.0.0.1"]
default = true
[[server]]
type = "imap_proxy"
name = "active-imap"
addr = ":1143"
remote_port = 143
[[server]]
enabled = false
type = "pop3_proxy"
name = "retired-pop3"
addr = ":1110"
`+tc.inactive)
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.GetAllServers(); len(got) != 1 || got[0].Name != "active-imap" {
				t.Fatalf("startup enabled servers = %+v", got)
			}
			if err := cfg.ValidatePools(); err != nil {
				t.Fatalf("inactive proxy prevents active pool startup: %v", err)
			}
		})
	}
}

func TestPoolsConfig_InactiveProxyDoesNotRequireDefault(t *testing.T) {
	cfg, err := loadPoolsConfig(t, twoPoolsNoDefault+`
[[server]]
type = "imap_proxy"
name = "active-imap"
addr = ":1143"
remote_port = 143
[server.remote_lookup]
enabled = true
url = "https://lookup.example.com/?email=$email"
lookup_local_users = false
[[server]]
enabled = false
type = "pop3_proxy"
name = "retired-pop3"
addr = ":1110"
remote_port = 110
`)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.ValidatePools(); err != nil {
		t.Fatalf("inactive proxy requires an otherwise unnecessary default: %v", err)
	}
}
