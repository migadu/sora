package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loadRelayConfig loads a config file holding a [relay] block of type smtp with
// the given extra keys, the way the server loads its configuration.
func loadRelayConfig(t *testing.T, smtpHost, extra string) RelayConfig {
	t.Helper()
	path := filepath.Join(t.TempDir(), "relay.toml")
	content := "[relay]\ntype = \"smtp\"\nsmtp_host = \"" + smtpHost + "\"\n" + extra + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := NewDefaultConfig()
	if err := LoadConfigFromFile(path, &cfg); err != nil {
		t.Fatalf("LoadConfigFromFile: %v", err)
	}
	return cfg.Relay
}

// TestRelaySMTPTLSDefaults pins the relay transport defaults: a [relay] block that
// leaves smtp_tls and smtp_tls_verify out uses TLS and verifies the relay's
// certificate, and only an explicit false turns either off.
func TestRelaySMTPTLSDefaults(t *testing.T) {
	tests := []struct {
		name       string
		extra      string
		wantTLS    bool
		wantVerify bool
	}{
		{name: "both keys absent", extra: "", wantTLS: true, wantVerify: true},
		{name: "only smtp_tls set", extra: "smtp_tls = true", wantTLS: true, wantVerify: true},
		{name: "only starttls set", extra: "smtp_use_starttls = true", wantTLS: true, wantVerify: true},
		{name: "explicit plaintext", extra: "smtp_tls = false", wantTLS: false, wantVerify: true},
		{name: "explicit no verification", extra: "smtp_tls_verify = false", wantTLS: true, wantVerify: false},
		{name: "both explicit true", extra: "smtp_tls = true\nsmtp_tls_verify = true", wantTLS: true, wantVerify: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			relay := loadRelayConfig(t, "smtp.example.com:587", tt.extra)
			if got := relay.GetSMTPTLS(); got != tt.wantTLS {
				t.Errorf("GetSMTPTLS() = %v, want %v", got, tt.wantTLS)
			}
			if got := relay.GetSMTPTLSVerify(); got != tt.wantVerify {
				t.Errorf("GetSMTPTLSVerify() = %v, want %v", got, tt.wantVerify)
			}
		})
	}
}

// TestRelaySMTPTransportWarning checks that startup can warn about a relay
// connection that is plaintext or does not verify the relay's certificate, unless
// the relay is on loopback.
func TestRelaySMTPTransportWarning(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		extra    string
		wantWarn string // substring of the warning, "" for no warning
	}{
		{name: "defaults", host: "smtp.example.com:587", wantWarn: ""},
		{name: "plaintext to remote host", host: "smtp.example.com:25", extra: "smtp_tls = false", wantWarn: "plaintext"},
		{name: "plaintext to remote IP", host: "192.0.2.10:25", extra: "smtp_tls = false", wantWarn: "plaintext"},
		{name: "unverified to remote host", host: "smtp.example.com:465", extra: "smtp_tls_verify = false", wantWarn: "not verified"},
		{name: "plaintext to 127.0.0.1", host: "127.0.0.1:25", extra: "smtp_tls = false", wantWarn: ""},
		{name: "plaintext to ::1", host: "[::1]:25", extra: "smtp_tls = false", wantWarn: ""},
		{name: "plaintext to localhost", host: "localhost:25", extra: "smtp_tls = false", wantWarn: ""},
		{name: "unverified to localhost", host: "localhost:465", extra: "smtp_tls_verify = false", wantWarn: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			relay := loadRelayConfig(t, tt.host, tt.extra)
			got := relay.SMTPTransportWarning()
			if tt.wantWarn == "" {
				if got != "" {
					t.Errorf("SMTPTransportWarning() = %q, want none", got)
				}
				return
			}
			if !strings.Contains(got, tt.wantWarn) {
				t.Errorf("SMTPTransportWarning() = %q, want it to mention %q", got, tt.wantWarn)
			}
		})
	}

	// An HTTP relay has no SMTP transport to warn about.
	httpRelay := RelayConfig{Type: "http", HTTPURL: "https://api.example.com/v1/mail/deliver"}
	if got := httpRelay.SMTPTransportWarning(); got != "" {
		t.Errorf("http relay: SMTPTransportWarning() = %q, want none", got)
	}
}
