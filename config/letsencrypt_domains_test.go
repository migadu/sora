package config

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/crypto/acme/autocert"
)

func loadLetsEncryptConfig(t *testing.T, section string) *TLSLetsEncryptConfig {
	t.Helper()
	cfg := loadLetsEncryptFullConfig(t, section)
	return cfg.TLS.LetsEncrypt
}

func loadLetsEncryptFullConfig(t *testing.T, section string) Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	content := "[tls]\nenabled = true\nprovider = \"letsencrypt\"\n\n[tls.letsencrypt]\nemail = \"admin@example.com\"\n" + section
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	cfg := NewDefaultConfig()
	if err := LoadConfigFromFile(path, &cfg); err != nil {
		t.Fatalf("loading config: %v", err)
	}
	if cfg.TLS.LetsEncrypt == nil {
		t.Fatal("[tls.letsencrypt] not loaded")
	}
	return cfg
}

// TestLetsEncryptDomainsLoadAsAutocertNames: autocert keeps a certificate under the
// server name folded by idna.Lookup.ToASCII (lowercase, A-label) without a trailing dot.
// The certificate sync and the startup pre-warm look certificates up under the
// configured names, so a name loaded as written ("Mail.Example.com") made the sync copy
// the leader's renewal into a local file autocert never reads.
func TestLetsEncryptDomainsLoadAsAutocertNames(t *testing.T) {
	le := loadLetsEncryptConfig(t, `domains = ["Mail.Example.com", "imap.example.org.", "bücher.example.com", "MAIL.example.com", "*.example.net", "localhost"]
default_domain = "IMAP.Example.org."
`)

	want := []string{"mail.example.com", "imap.example.org", "xn--bcher-kva.example.com"}
	if !slices.Equal(le.Domains, want) {
		t.Errorf("domains = %q, want %q", le.Domains, want)
	}
	if le.DefaultDomain != "imap.example.org" {
		t.Errorf("default_domain = %q, want %q", le.DefaultDomain, "imap.example.org")
	}
}

// TestLetsEncryptUnservableDefaultDomainIsDropped: a default_domain autocert cannot serve
// is ignored, so a client without SNI gets the first domain's certificate as when
// default_domain is not set.
func TestLetsEncryptUnservableDefaultDomainIsDropped(t *testing.T) {
	le := loadLetsEncryptConfig(t, `domains = ["mail.example.com"]
default_domain = "*.example.com"
`)

	if le.DefaultDomain != "" {
		t.Errorf("default_domain = %q, want it dropped", le.DefaultDomain)
	}
}

func TestLetsEncryptServerDefaultDomainUsesNormalizedWhitelist(t *testing.T) {
	for _, tc := range []struct{ configured, want string }{
		{"MAIL.Example.com.", "mail.example.com"},
		{"bücher.example.com.", "xn--bcher-kva.example.com"},
		{"*.example.com", ""},
	} {
		t.Run(tc.configured, func(t *testing.T) {
			cfg := loadLetsEncryptFullConfig(t, `domains = ["Mail.Example.com.", "bücher.example.com"]
[[server]]
type = "imap"
name = "imap"
addr = ":993"
tls = true
tls_default_domain = "`+tc.configured+`"
`)
			name := cfg.DynamicServers[0].TLSDefaultDomain
			if name != tc.want {
				t.Fatalf("tls_default_domain = %q, want %q", name, tc.want)
			}
			if name == "" {
				name = cfg.TLS.LetsEncrypt.Domains[0]
			}
			// The SNI-less wrapper supplies this name to the manager's whitelist
			// before autocert can normalize it itself.
			policy := autocert.HostWhitelist(cfg.TLS.LetsEncrypt.Domains...)
			if err := policy(context.Background(), name); err != nil {
				t.Fatalf("configured SNI-less name was refused by the whitelist: %v", err)
			}
		})
	}
}
