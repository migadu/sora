package config

import (
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func decodeClientFiltersServer(t *testing.T, serverType, filters string) ServerConfig {
	t.Helper()
	var cfg Config
	if _, err := toml.Decode(`
[[server]]
type = "`+serverType+`"
name = "imap"
addr = ":143"

[[server.client_filters]]
client_name = "^ExampleMail$"
disable_caps = ["CONDSTORE"]

[[server.client_filters]]
`+filters+`
disable_caps = ["IDLE"]
reason = "example"
`, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg.DynamicServers[0]
}

// The IMAP server compiles each client_filters pattern when it starts and skips a
// filter with one that does not compile, so the capability the filter was meant to
// hide stayed advertised, and the skip was logged at DEBUG only. Such a pattern is
// refused at startup, SIGHUP reload and sora-admin config validate, naming the
// entry, the key and the pattern (#959).
func TestClientFiltersInvalidPatternRejected(t *testing.T) {
	for _, tt := range []struct{ filters, key, pattern string }{
		{`client_name = "Mail("`, "client_name", "Mail("},
		{`client_name = "^Mail$"` + "\nclient_version = \"[1-\"", "client_version", "[1-"},
		{`ja4_fingerprints = ["^t13d1516h2_", "t13d**"]`, "ja4_fingerprints", "t13d**"},
	} {
		s := decodeClientFiltersServer(t, "imap", tt.filters)
		err := s.Validate()
		if err == nil {
			t.Errorf("%s = %q accepted", tt.key, tt.pattern)
			continue
		}
		for _, want := range []string{`server "imap"`, "client_filters #2", tt.key, `"` + tt.pattern + `"`} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s = %q: error %q does not contain %q", tt.key, tt.pattern, err, want)
			}
		}
	}
}

// Valid patterns stay valid, and only IMAP backends read client_filters.
func TestClientFiltersPatternAccepted(t *testing.T) {
	for _, tt := range []struct{ serverType, filters string }{
		{"imap", `client_name = "com\\.apple\\.email\\.maild"` + "\nclient_version = \"16\\\\..*\""},
		{"imap", `ja4_fingerprints = ["^t13d411100_6be44479b708_.*", "^t13d2014ip_a09f3c656075_"]`},
		{"imap", `client_name = ""`},
		{"pop3", `client_name = "Mail("`},
		{"imap_proxy", `ja4_fingerprints = ["t13d**"]`},
	} {
		s := decodeClientFiltersServer(t, tt.serverType, tt.filters)
		if err := s.Validate(); err != nil {
			t.Errorf("%s: %s rejected: %v", tt.serverType, tt.filters, err)
		}
	}
}
