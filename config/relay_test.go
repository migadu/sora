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
	return loadRelayBlock(t, "type = \"smtp\"\nsmtp_host = \""+smtpHost+"\"\n"+extra)
}

// loadRelayBlock loads a config file whose [relay] block holds keys.
func loadRelayBlock(t *testing.T, keys string) RelayConfig {
	t.Helper()
	path := filepath.Join(t.TempDir(), "relay.toml")
	content := "[relay]\n" + keys + "\n"
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

// TestRelayTransportWarning checks that startup can warn about a relay connection
// that is plaintext or does not verify the relay's certificate, unless the relay is
// on loopback. This holds for both relay types: an http:// URL sends the relayed
// mail and the auth_token in plaintext just as smtp_tls = false does.
func TestRelayTransportWarning(t *testing.T) {
	smtp := func(host, extra string) string {
		return "type = \"smtp\"\nsmtp_host = \"" + host + "\"\n" + extra
	}
	http := func(url string) string {
		return "type = \"http\"\nhttp_url = \"" + url + "\"\nauth_token = \"secret\""
	}
	tests := []struct {
		name     string
		block    string
		wantWarn string // substring of the warning, "" for no warning
	}{
		{name: "smtp defaults", block: smtp("smtp.example.com:587", ""), wantWarn: ""},
		{name: "smtp plaintext to remote host", block: smtp("smtp.example.com:25", "smtp_tls = false"), wantWarn: "plaintext"},
		{name: "smtp plaintext to remote IP", block: smtp("192.0.2.10:25", "smtp_tls = false"), wantWarn: "plaintext"},
		{name: "smtp unverified to remote host", block: smtp("smtp.example.com:465", "smtp_tls_verify = false"), wantWarn: "not verified"},
		{name: "smtp plaintext to 127.0.0.1", block: smtp("127.0.0.1:25", "smtp_tls = false"), wantWarn: ""},
		{name: "smtp plaintext to ::1", block: smtp("[::1]:25", "smtp_tls = false"), wantWarn: ""},
		{name: "smtp plaintext to localhost", block: smtp("localhost:25", "smtp_tls = false"), wantWarn: ""},
		{name: "smtp unverified to localhost", block: smtp("localhost:465", "smtp_tls_verify = false"), wantWarn: ""},
		{name: "http over https", block: http("https://api.example.com/v1/mail/deliver"), wantWarn: ""},
		{name: "http plaintext to remote host", block: http("http://api.example.com/v1/mail/deliver"), wantWarn: "plaintext"},
		{name: "http plaintext to remote IP", block: http("http://192.0.2.10:8080/deliver"), wantWarn: "plaintext"},
		{name: "http plaintext upper-case scheme", block: http("HTTP://api.example.com/deliver"), wantWarn: "plaintext"},
		{name: "http plaintext to localhost", block: http("http://localhost:8080/deliver"), wantWarn: ""},
		{name: "http plaintext to 127.0.0.1", block: http("http://127.0.0.1/deliver"), wantWarn: ""},
		{name: "http plaintext to ::1", block: http("http://[::1]:8080/deliver"), wantWarn: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			relay := loadRelayBlock(t, tt.block)
			got := relay.TransportWarning()
			if tt.wantWarn == "" {
				if got != "" {
					t.Errorf("TransportWarning() = %q, want none", got)
				}
				return
			}
			if !strings.Contains(got, tt.wantWarn) {
				t.Errorf("TransportWarning() = %q, want it to mention %q", got, tt.wantWarn)
			}
		})
	}
}

// TestRelayValidateType: [relay] type is "smtp" or "http", exactly, or the section is
// absent. Anything else used to create the relay queue with no worker to drain it, so
// every Sieve redirect and vacation reply was accepted into pending/ and never sent (#277).
func TestRelayValidateType(t *testing.T) {
	tests := []struct {
		name    string
		block   string
		wantErr string // substring of the error, "" for a valid section
	}{
		{name: "no relay", block: "", wantErr: ""},
		{name: "smtp", block: "type = \"smtp\"\nsmtp_host = \"smtp.example.com:587\"", wantErr: ""},
		{name: "http", block: "type = \"http\"\nhttp_url = \"https://api.example.com/deliver\"", wantErr: ""},
		{name: "smtp with surrounding spaces", block: "type = \" smtp \"\nsmtp_host = \"smtp.example.com:587\"", wantErr: ""},
		{name: "upper-case SMTP", block: "type = \"SMTP\"\nsmtp_host = \"smtp.example.com:587\"", wantErr: `unsupported [relay] type "SMTP"`},
		{name: "mixed-case Http", block: "type = \"Http\"\nhttp_url = \"https://api.example.com/deliver\"", wantErr: `unsupported [relay] type "Http"`},
		{name: "lmtp", block: "type = \"lmtp\"\nsmtp_host = \"smtp.example.com:24\"", wantErr: `unsupported [relay] type "lmtp"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			relay := loadRelayBlock(t, tt.block)
			err := relay.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate() = %v, want an error containing %q", err, tt.wantErr)
			}
		})
	}
}
