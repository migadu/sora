package config

import (
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func decodeMasterSASLServer(t *testing.T, serverType, networks string) ServerConfig {
	t.Helper()
	var cfg Config
	if _, err := toml.Decode(`
[[server]]
type = "`+serverType+`"
name = "`+serverType+`"
addr = ":1000"
master_sasl_username = "master"
master_sasl_password = "secret"
master_sasl_allowed_networks = `+networks+`
`, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg.DynamicServers[0]
}

// The imap, pop3 and managesieve servers build their master SASL gate from
// master_sasl_allowed_networks and refuse to start on an entry that is not an IP address
// or CIDR. Validate, which `sora-admin config validate`, start-up and a SIGHUP reload
// run, refuses the same entry, naming the server, the key and the entry (#1675).
func TestMasterSASLAllowedNetworksInvalidEntryRejected(t *testing.T) {
	for _, serverType := range []string{"imap", "pop3", "managesieve"} {
		for _, entry := range []string{"proxy.example.com", "10.0.0.5/33", "192.0.2.256", "2001:db8::/129", ""} {
			s := decodeMasterSASLServer(t, serverType, `["192.0.2.10", "`+entry+`"]`)
			err := s.Validate()
			if err == nil {
				t.Errorf("%s: master_sasl_allowed_networks entry %q accepted", serverType, entry)
				continue
			}
			for _, want := range []string{`server "` + serverType + `"`, "invalid master_sasl_allowed_networks", "'" + entry + "'"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("%s: master_sasl_allowed_networks entry %q: error %q does not say %q", serverType, entry, err, want)
				}
			}
		}
	}
}

// IPv4 and IPv6 addresses and CIDRs, and the empty list (master SASL from any source),
// stay valid.
func TestMasterSASLAllowedNetworksValidAccepted(t *testing.T) {
	for _, serverType := range []string{"imap", "pop3", "managesieve"} {
		for _, list := range []string{
			`[]`,
			`["192.0.2.10"]`,
			`["192.0.2.0/24", "10.0.0.5/32", "2001:db8::1", "2001:db8::/32", "::ffff:192.0.2.5"]`,
		} {
			s := decodeMasterSASLServer(t, serverType, list)
			if err := s.Validate(); err != nil {
				t.Errorf("%s: master_sasl_allowed_networks = %s rejected: %v", serverType, list, err)
			}
		}
	}
}

// A type that does not read master_sasl_allowed_networks starts with any value there,
// and is told the key does not apply to it; Validate does not refuse it either.
func TestMasterSASLAllowedNetworksIgnoredByOtherTypes(t *testing.T) {
	s := decodeMasterSASLServer(t, "lmtp", `["proxy.example.com"]`)
	if err := s.Validate(); err != nil {
		t.Errorf("lmtp, which does not read master_sasl_allowed_networks, refused: %v", err)
	}
}
