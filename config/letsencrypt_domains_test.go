package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func loadLetsEncryptConfig(t *testing.T, section string) *TLSLetsEncryptConfig {
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
	return cfg.TLS.LetsEncrypt
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
