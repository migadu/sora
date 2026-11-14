package config

import (
	"strings"
	"testing"
)

// An invalid [server.remote_lookup] remote_port was never rejected: the proxy dropped an
// unparsable or wrongly typed value with a Debug log and dialed a fallback port, and used
// a negative or out-of-range number as given. Validate (startup, SIGHUP reload and
// sora-admin config validate) now refuses it, as it does the block's own remote_port.
func TestServerConfigValidateRemoteLookupPort(t *testing.T) {
	for _, tc := range []struct {
		name    string
		port    string // TOML value; "" leaves the key out
		enabled bool
		wantErr bool
	}{
		{"absent", "", true, false},
		{"integer", "1993", true, false},
		{"string", `"1993"`, true, false},
		{"empty string", `""`, true, false},
		{"zero is unset", "0", true, false},
		{"highest port", "65535", true, false},
		{"unparsable string", `"1993x"`, true, true},
		{"negative", "-1", true, true},
		{"negative string", `"-1"`, true, true},
		{"out of range", "70000", true, true},
		{"integer would wrap on 32-bit", "4294969299", true, true},
		{"out of range string", `"70000"`, true, true},
		{"float", "1993.5", true, true},
		{"bool", "true", true, true},
		// A disabled lookup is never initialized, so its remote_port is never used.
		{"disabled lookup", `"1993x"`, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			block := `
[[server]]
type = "imap_proxy"
name = "imap-proxy"
addr = ":1143"
remote_addrs = ["backend1.example.com:143"]

[server.remote_lookup]
enabled = ` + map[bool]string{true: "true", false: "false"}[tc.enabled] + `
url = "http://127.0.0.1:8080/lookup?email=$email"
`
			if tc.port != "" {
				block += "remote_port = " + tc.port + "\n"
			}
			cfg, err := loadPoolsConfig(t, block)
			if err != nil {
				t.Fatal(err)
			}
			errs := validateServers(&cfg)
			if !tc.wantErr {
				if len(errs) != 0 {
					t.Fatalf("validation errors = %v, want none", errs)
				}
				return
			}
			if len(errs) != 1 {
				t.Fatalf("validation errors = %v, want one for remote_lookup.remote_port = %s", errs, tc.port)
			}
			if msg := errs[0].Error(); !strings.Contains(msg, "remote_lookup.remote_port") || !strings.Contains(msg, `"imap-proxy"`) {
				t.Errorf("error = %q, want it to name the server and remote_lookup.remote_port", msg)
			}
		})
	}
}

// A proxy's own remote_port was parsed only when the proxy started, so sora-admin config
// validate passed a value sora then refused to start with, and a SIGHUP reload applied
// the block without a word. Validate refuses it on every proxy type. Other servers never
// read remote_port or remote_lookup, so an unused value there is not an error.
func TestServerConfigValidateProxyRemotePort(t *testing.T) {
	load := func(t *testing.T, typ, extra string) []error {
		t.Helper()
		cfg, err := loadPoolsConfig(t, `
[[server]]
type = "`+typ+`"
name = "srv"
addr = ":1143"
`+extra)
		if err != nil {
			t.Fatal(err)
		}
		return validateServers(&cfg)
	}

	for _, typ := range []string{"imap_proxy", "pop3_proxy", "managesieve_proxy", "lmtp_proxy", "user_api_proxy"} {
		for _, port := range []string{"", "143", `"143"`, `""`, "0", "65535"} {
			t.Run(typ+" valid "+port, func(t *testing.T) {
				extra := ""
				if port != "" {
					extra = "remote_port = " + port + "\n"
				}
				if errs := load(t, typ, extra); len(errs) != 0 {
					t.Fatalf("validation errors = %v, want none", errs)
				}
			})
		}
		for _, port := range []string{`"143x"`, "-1", `"-1"`, "70000", "1.5", "true"} {
			t.Run(typ+" invalid "+port, func(t *testing.T) {
				errs := load(t, typ, "remote_port = "+port+"\n")
				if len(errs) != 1 {
					t.Fatalf("validation errors = %v, want one for remote_port = %s", errs, port)
				}
				if msg := errs[0].Error(); !strings.Contains(msg, "invalid remote_port") || !strings.Contains(msg, `"srv"`) {
					t.Errorf("error = %q, want it to name the server and remote_port", msg)
				}
			})
		}
	}

	t.Run("unused on a backend", func(t *testing.T) {
		errs := load(t, "imap", `remote_port = "143x"

[server.remote_lookup]
enabled = true
url = "http://127.0.0.1:8080/lookup?email=$email"
remote_port = "1993x"
`)
		if len(errs) != 0 {
			t.Fatalf("validation errors = %v, want none: an imap server reads neither remote_port", errs)
		}
	})
}
