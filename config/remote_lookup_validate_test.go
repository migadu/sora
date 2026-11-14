package config

import (
	"strings"
	"testing"
)

// Every proxy refused an enabled [server.remote_lookup] whose URL or durations it cannot
// use, but only when it was built, so sora-admin config validate printed "[OK]" for a
// block the proxy then refused to start with (#853). Validate (startup, SIGHUP reload
// and sora-admin config validate) now runs the same checks.
func TestServerConfigValidateRemoteLookup(t *testing.T) {
	const url = "url = \"https://lookup.example.com/lookup?email=$email\"\n"
	tests := []struct {
		name    string
		typ     string // "" runs the case on every proxy type
		enabled bool
		lookup  string // the [server.remote_lookup] keys after enabled
		wantErr string // substring of the error, "" for a valid block
	}{
		{name: "https with placeholders in path and query", enabled: true,
			lookup: "url = \"https://lookup.example.com/lookup/$email?ip=$ip\"\n"},
		{name: "plaintext to loopback", enabled: true,
			lookup: "url = \"http://127.0.0.1:8080/lookup?email=$email\"\n"},
		{name: "durations", enabled: true,
			lookup: url + "timeout = \"3s\"\n" +
				"[server.remote_lookup.circuit_breaker]\ntimeout = \"1m\"\ninterval = \"1d\"\n" +
				"[server.remote_lookup.transport]\nidle_conn_timeout = \"90s\"\ndial_timeout = \"10s\"\n" +
				"tls_handshake_timeout = \"10s\"\nexpect_continue_timeout = \"1s\"\nkeep_alive = \"30s\"\n"},
		{name: "url missing", enabled: true,
			wantErr: "remote_lookup.url is required"},
		{name: "url unparsable", enabled: true,
			lookup:  "url = \"https://lookup.example.com:99x/lookup\"\n",
			wantErr: "invalid remote_lookup.url"},
		{name: "url without host", enabled: true,
			lookup:  "url = \"https:///lookup?email=$email\"\n",
			wantErr: "invalid remote_lookup.url: no host"},
		{name: "url scheme", enabled: true,
			lookup:  "url = \"ftp://lookup.example.com/lookup\"\n",
			wantErr: "invalid remote_lookup.url: scheme must be http or https"},
		{name: "$email in host", enabled: true,
			lookup:  "url = \"https://$email.lookup.example.com/lookup\"\n",
			wantErr: `$email is allowed only in the path and query, not in the host "$email.lookup.example.com"`},
		{name: "$ip in host", enabled: true,
			lookup:  "url = \"https://$ip.lookup.example.com/lookup?email=$email\"\n",
			wantErr: "$ip is allowed only in the path and query"},
		{name: "plaintext to a remote host", enabled: true,
			lookup:  "url = \"http://lookup.example.com/lookup?email=$email\"\n",
			wantErr: "remote_lookup.url must use https:// for non-loopback hosts"},
		{name: "timeout without unit", enabled: true,
			lookup:  url + "timeout = \"5\"\n",
			wantErr: "invalid remote_lookup.timeout"},
		{name: "circuit_breaker.timeout", typ: "imap_proxy", enabled: true,
			lookup:  url + "[server.remote_lookup.circuit_breaker]\ntimeout = \"30\"\n",
			wantErr: "invalid remote_lookup.circuit_breaker.timeout"},
		{name: "circuit_breaker.interval", typ: "imap_proxy", enabled: true,
			lookup:  url + "[server.remote_lookup.circuit_breaker]\ninterval = \"never\"\n",
			wantErr: "invalid remote_lookup.circuit_breaker.interval"},
		{name: "transport.idle_conn_timeout", typ: "imap_proxy", enabled: true,
			lookup:  url + "[server.remote_lookup.transport]\nidle_conn_timeout = \"90\"\n",
			wantErr: "invalid remote_lookup.transport.idle_conn_timeout"},
		{name: "transport.dial_timeout", typ: "imap_proxy", enabled: true,
			lookup:  url + "[server.remote_lookup.transport]\ndial_timeout = \"10\"\n",
			wantErr: "invalid remote_lookup.transport.dial_timeout"},
		{name: "transport.tls_handshake_timeout", typ: "imap_proxy", enabled: true,
			lookup:  url + "[server.remote_lookup.transport]\ntls_handshake_timeout = \"10\"\n",
			wantErr: "invalid remote_lookup.transport.tls_handshake_timeout"},
		{name: "transport.expect_continue_timeout", typ: "imap_proxy", enabled: true,
			lookup:  url + "[server.remote_lookup.transport]\nexpect_continue_timeout = \"1\"\n",
			wantErr: "invalid remote_lookup.transport.expect_continue_timeout"},
		{name: "transport.keep_alive", typ: "imap_proxy", enabled: true,
			lookup:  url + "[server.remote_lookup.transport]\nkeep_alive = \"30\"\n",
			wantErr: "invalid remote_lookup.transport.keep_alive"},
		// A disabled lookup is never initialized, and a backend never reads one.
		{name: "disabled lookup",
			lookup: "url = \"https://$email.lookup.example.com/lookup\"\ntimeout = \"5\"\n"},
		{name: "unused on a backend", typ: "imap", enabled: true,
			lookup: "url = \"https://$email.lookup.example.com/lookup\"\ntimeout = \"5\"\n"},
	}
	proxies := []string{"imap_proxy", "pop3_proxy", "managesieve_proxy", "lmtp_proxy", "user_api_proxy"}
	for _, tt := range tests {
		types := proxies
		if tt.typ != "" {
			types = []string{tt.typ}
		}
		for _, typ := range types {
			t.Run(typ+" "+tt.name, func(t *testing.T) {
				cfg, err := loadPoolsConfig(t, `
[[server]]
type = "`+typ+`"
name = "srv"
addr = ":1143"

[server.remote_lookup]
enabled = `+map[bool]string{true: "true", false: "false"}[tt.enabled]+"\n"+tt.lookup)
				if err != nil {
					t.Fatal(err)
				}
				errs := validateServers(&cfg)
				if tt.wantErr == "" {
					if len(errs) != 0 {
						t.Fatalf("validation errors = %v, want none", errs)
					}
					return
				}
				if len(errs) != 1 {
					t.Fatalf("validation errors = %v, want one saying %q", errs, tt.wantErr)
				}
				if msg := errs[0].Error(); !strings.Contains(msg, tt.wantErr) || !strings.Contains(msg, `"srv"`) {
					t.Errorf("error = %q, want it to name the server and say %q", msg, tt.wantErr)
				}
			})
		}
	}
}
