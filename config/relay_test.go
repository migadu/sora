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
//
// The type's destination is checked too: an "smtp" relay needs an smtp_host it can dial
// and an "http" relay an http_url it can post to. The SMTP handler dials smtp_host as
// given, with no default port, and the HTTP handler posts to http_url as given; with
// either missing or unusable every Sieve redirect and vacation reply was accepted into
// the queue, failed each attempt as a temporary error and went to failed/ (#532).
func TestRelayValidateType(t *testing.T) {
	smtp := func(host string) string { return "type = \"smtp\"\nsmtp_host = \"" + host + "\"" }
	http := func(url string) string { return "type = \"http\"\nhttp_url = \"" + url + "\"" }
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

		{name: "smtp IPv4:port", block: smtp("192.0.2.10:25"), wantErr: ""},
		{name: "smtp [IPv6]:port", block: smtp("[2001:db8::10]:465"), wantErr: ""},
		{name: "smtp service name as port", block: smtp("smtp.example.com:smtp"), wantErr: ""},
		{name: "smtp_host missing", block: "type = \"smtp\"", wantErr: `[relay] type "smtp" requires smtp_host as host:port`},
		{name: "smtp_host blank", block: smtp("   "), wantErr: `[relay] type "smtp" requires smtp_host as host:port`},
		{name: "smtp_host without port", block: smtp("smtp.example.com"), wantErr: `[relay] smtp_host "smtp.example.com" must be host:port`},
		{name: "smtp bare IPv6 without port", block: smtp("2001:db8::10"), wantErr: `[relay] smtp_host "2001:db8::10" must be host:port`},
		{name: "smtp_host as URL", block: smtp("smtp://smtp.example.com:587"), wantErr: `[relay] smtp_host "smtp://smtp.example.com:587" must be host:port`},
		{name: "smtp_host without host", block: smtp(":587"), wantErr: `[relay] smtp_host ":587" has no host`},
		{name: "smtp_host empty port", block: smtp("smtp.example.com:"), wantErr: `[relay] smtp_host "smtp.example.com:" has no valid port`},
		{name: "smtp_host port 0", block: smtp("smtp.example.com:0"), wantErr: `[relay] smtp_host "smtp.example.com:0" has no valid port`},
		{name: "smtp_host port out of range", block: smtp("smtp.example.com:65536"), wantErr: `[relay] smtp_host "smtp.example.com:65536" has no valid port`},
		{name: "smtp_host unknown service", block: smtp("smtp.example.com:no-such-service"), wantErr: `[relay] smtp_host "smtp.example.com:no-such-service" has no valid port`},

		{name: "http url with port", block: http("http://127.0.0.1:8080/deliver"), wantErr: ""},
		{name: "upper-case scheme", block: http("HTTPS://api.example.com/deliver"), wantErr: ""},
		{name: "http_url missing", block: "type = \"http\"", wantErr: `[relay] type "http" requires http_url`},
		{name: "http_url without scheme", block: http("api.example.com/deliver"), wantErr: `[relay] http_url "api.example.com/deliver" must be an absolute http:// or https:// URL with a host`},
		{name: "http_url other scheme", block: http("ftp://api.example.com/deliver"), wantErr: `[relay] http_url "ftp://api.example.com/deliver" must be an absolute http:// or https:// URL with a host`},
		{name: "http_url without host", block: http("https:///deliver"), wantErr: `[relay] http_url "https:///deliver" must be an absolute http:// or https:// URL with a host`},
		{name: "http_url port without host", block: http("https://:8443/deliver"), wantErr: `[relay] http_url "https://:8443/deliver" must be an absolute http:// or https:// URL with a host`},
		{name: "http_url port out of range", block: http("https://api.example.com:65536/deliver"), wantErr: `[relay] http_url "https://api.example.com:65536/deliver" has no valid port`},
		{name: "http_url unparsable", block: http("https://api.example.com:80a/deliver"), wantErr: `[relay] http_url "https://api.example.com:80a/deliver" is not a valid URL`},
		// The error quotes http_url the way the config dump shows it: a query value may
		// be the relay's API key.
		{name: "http_url query value masked", block: http("ftp://api.example.com/deliver?key=relay-secret"), wantErr: `[relay] http_url "ftp://api.example.com/deliver?key=` + SecretMask + `"`},
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

func TestRelayValidateMalformedEndpointsHideCredentials(t *testing.T) {
	for _, relay := range []RelayConfig{
		{Type: "http", HTTPURL: "relay.example/send?api_key=private-relay-token"},
		{Type: "http", HTTPURL: "user:private-relay-token@relay.example/send"},
		{Type: "smtp", SMTPHost: "smtp://user:private-relay-token@smtp.example:587"},
		{Type: "smtp", SMTPHost: "user:private-relay-token@smtp.example:587"},
		// The parser's reason quotes the part of the password before the "/" as a
		// port: `invalid port ":private" after host` (#806).
		{Type: "http", HTTPURL: "https://user:private/relay-token@relay.example/send"},
	} {
		err := relay.Validate()
		if err == nil {
			t.Fatalf("invalid relay endpoint was accepted: %#v", relay)
		}
		if strings.Contains(err.Error(), "private") {
			t.Errorf("validation exposed endpoint credentials: %v", err)
		}
	}
	for _, host := range []string{"smtp bad.example:587", "user@smtp.example:587", "smtp.example/path:587"} {
		if err := (&RelayConfig{Type: "smtp", SMTPHost: host}).Validate(); err == nil {
			t.Errorf("non-dialable SMTP host %q accepted", host)
		}
	}
}

// TestRelayQueueValidate: a [relay.queue] worker_interval of zero or less parsed and
// reached time.NewTicker in the relay worker's goroutine, which panics on a non-positive
// interval and took the server down at start-up (#643). A negative failed_retention would
// have the cleanup delete every failed message, the only copy of a Sieve redirect without
// :copy, on its first pass. Both are refused by the checks that run at start-up and in
// `sora-admin config validate`; failed_retention = "0" keeps failed messages until they
// are deleted or requeued. A value that does not parse is left to start-up, as before.
func TestRelayQueueValidate(t *testing.T) {
	const relay = "[relay]\ntype = \"smtp\"\nsmtp_host = \"smtp.example.com:587\"\n"
	const imap = "\n[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \"127.0.0.1:143\"\n"
	tests := []struct {
		name    string
		content string
		wantErr string // substring of the [relay.queue] problem, "" for none
	}{
		{name: "defaults", content: relay},
		{name: "worker_interval 30s", content: relay + "[relay.queue]\nworker_interval = \"30s\"\n"},
		{name: "worker_interval unparsable", content: relay + "[relay.queue]\nworker_interval = \"soon\"\n"},
		{name: "worker_interval 0", content: relay + "[relay.queue]\nworker_interval = \"0\"\n", wantErr: `worker_interval must be positive, got "0"`},
		{name: "worker_interval 0s", content: relay + "[relay.queue]\nworker_interval = \"0s\"\n", wantErr: `worker_interval must be positive, got "0s"`},
		{name: "worker_interval -1m", content: relay + "[relay.queue]\nworker_interval = \"-1m\"\n", wantErr: `worker_interval must be positive, got "-1m"`},
		{name: "failed_retention 0", content: relay + "[relay.queue]\nfailed_retention = \"0\"\n"},
		{name: "failed_retention 7d", content: relay + "[relay.queue]\nfailed_retention = \"7d\"\n"},
		{name: "failed_retention -1h", content: relay + "[relay.queue]\nfailed_retention = \"-1h\"\n", wantErr: `failed_retention must not be negative, got "-1h"`},
		{name: "no relay, queue not checked", content: "[relay.queue]\nworker_interval = \"0\"\nfailed_retention = \"-1h\"\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tt.content+imap), 0o600); err != nil {
				t.Fatal(err)
			}
			var cfg Config
			if err := LoadServerConfig(path, &cfg); err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, p := range cfg.Validate() {
				got = append(got, p.Section+": "+p.Err.Error())
			}
			if tt.wantErr == "" {
				if len(got) != 0 {
					t.Errorf("Validate() = %q, want no problems", got)
				}
				return
			}
			if len(got) != 1 || !strings.HasPrefix(got[0], "[relay.queue]: ") || !strings.Contains(got[0], tt.wantErr) {
				t.Errorf("Validate() = %q, want one [relay.queue] problem containing %q", got, tt.wantErr)
			}
		})
	}
}
