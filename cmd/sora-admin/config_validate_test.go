package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const configValidateHelperEnv = "SORA_ADMIN_CONFIG_VALIDATE_HELPER_PATH"

// TestConfigValidateCommandHelper is not a test: it is `sora-admin config validate`,
// run by the TestConfigValidate* tests in a process of its own because the command
// exits.
func TestConfigValidateCommandHelper(t *testing.T) {
	path := os.Getenv(configValidateHelperEnv)
	if path == "" {
		t.Skip("helper process for the config validate tests")
	}
	os.Args = []string{"sora-admin", "--config", path, "config", "validate"}
	handleConfigValidate(context.Background())
}

// TestConfigValidateRejectsUnsupportedRelayType: `sora-admin config validate` fails a
// [relay] type the server refuses to start with (#277), and a relay type without a
// usable smtp_host or http_url (#532).
func TestConfigValidateRejectsUnsupportedRelayType(t *testing.T) {
	tests := []struct {
		name    string
		relay   string
		wantErr string // substring of the failure, "" for a valid file
	}{
		{name: "smtp", relay: "[relay]\ntype = \"smtp\"\nsmtp_host = \"smtp.example.com:587\"\n", wantErr: ""},
		{name: "upper-case SMTP", relay: "[relay]\ntype = \"SMTP\"\nsmtp_host = \"smtp.example.com:587\"\n", wantErr: `unsupported [relay] type "SMTP"`},
		{name: "smtp without smtp_host", relay: "[relay]\ntype = \"smtp\"\n", wantErr: `[relay] type "smtp" requires smtp_host as host:port`},
		{name: "smtp_host without port", relay: "[relay]\ntype = \"smtp\"\nsmtp_host = \"smtp.example.com\"\n", wantErr: `[relay] smtp_host "smtp.example.com" must be host:port`},
		{name: "http without http_url", relay: "[relay]\ntype = \"http\"\n", wantErr: `[relay] type "http" requires http_url`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			content := tt.relay + "\n[[server]]\ntype = \"lmtp\"\nname = \"lmtp\"\naddr = \"127.0.0.1:0\"\n"
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestConfigValidateCommandHelper$")
			cmd.Env = append(os.Environ(), configValidateHelperEnv+"="+path)
			out, err := cmd.CombinedOutput()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("config validate failed a valid file: %v\n%s", err, out)
				}
				return
			}
			if err == nil {
				t.Fatalf("config validate passed the file; want it failed with %q", tt.wantErr)
			}
			if !strings.Contains(string(out), tt.wantErr) {
				t.Errorf("config validate failed, but the output does not say %q:\n%s", tt.wantErr, out)
			}
		})
	}
}

// TestConfigValidateRejectsIncompleteServerBlock: `sora-admin config validate` fails
// the configuration from #278, a [[server]] block without type, name or addr, which it
// used to pass while the server skipped the block without a word. enabled = false
// keeps a block in the file without starting or validating it.
func TestConfigValidateRejectsIncompleteServerBlock(t *testing.T) {
	tests := []struct {
		name    string
		block   string
		wantErr string // substring of the failure, "" for a valid file
	}{
		{name: "addr forgotten", block: "type = \"pop3\"\nname = \"pop3\"\n", wantErr: "server address is required"},
		{name: "name forgotten", block: "type = \"pop3\"\naddr = \"127.0.0.1:1110\"\n", wantErr: "server name is required"},
		{name: "type forgotten", block: "name = \"pop3\"\naddr = \"127.0.0.1:1110\"\n", wantErr: "server type is required"},
		{name: "enabled = false", block: "enabled = false\ntype = \"pop3\"\nname = \"pop3\"\naddr = \"\"\n", wantErr: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			content := "[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \"127.0.0.1:1143\"\n\n[[server]]\n" + tt.block
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestConfigValidateCommandHelper$")
			cmd.Env = append(os.Environ(), configValidateHelperEnv+"="+path)
			out, err := cmd.CombinedOutput()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("config validate failed a valid file: %v\n%s", err, out)
				}
				return
			}
			if err == nil {
				t.Fatalf("config validate passed the file; want it failed with %q", tt.wantErr)
			}
			if !strings.Contains(string(out), tt.wantErr) {
				t.Errorf("config validate failed, but the output does not say %q:\n%s", tt.wantErr, out)
			}
		})
	}
}

// TestConfigValidateRefusesWhatStartupRefuses covers the shared startup checks
// added for #516. The CLI printed "[OK] Configuration is valid!" for checks it did not run: [[pool]] blocks,
// PROXY protocol without trusted_networks, [uploader] and [shared_mailboxes], and it
// only warned about a file without servers. A file with several problems reports each.
func TestConfigValidateRefusesWhatStartupRefuses(t *testing.T) {
	const imapBackend = "\n[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \"127.0.0.1:143\"\n"
	const imapProxy = "\n[[server]]\ntype = \"imap_proxy\"\nname = \"imap-proxy\"\naddr = \"127.0.0.1:1143\"\n"
	const proxyProtocolImap = "\n[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \"127.0.0.1:143\"\nproxy_protocol = true\n"
	const remoteLookup = "remote_addrs = [\"192.0.2.10:143\"]\n\n[server.remote_lookup]\nenabled = true\n"
	tests := []struct {
		name    string
		content string
		wantErr []string // substrings of the failure, none for a valid file
	}{
		{
			name:    "PROXY protocol without trusted_networks",
			content: "[servers]\ntrusted_networks = []\n" + proxyProtocolImap,
			wantErr: []string{"proxy_protocol is enabled on server(s) imap but [servers] trusted_networks is empty"},
		},
		{
			name:    "PROXY protocol with trusted_networks",
			content: "[servers]\ntrusted_networks = [\"192.0.2.10\"]\n" + proxyProtocolImap,
		},
		{
			name: "pool declared twice",
			content: "[[pool]]\nname = \"sora1\"\nbackends = [\"192.0.2.10:143\"]\ndefault = true\n\n" +
				"[[pool]]\nname = \"sora1\"\nbackends = [\"192.0.2.11:143\"]\n" + imapProxy,
			wantErr: []string{`[[pool]] "sora1": declared more than once`},
		},
		{
			// The proxies refused these [server.remote_lookup] settings only when they
			// were built (#853).
			name:    "remote_lookup with $email in the URL host",
			content: imapProxy + remoteLookup + "url = \"https://$email.lookup.example.com/lookup\"\n",
			wantErr: []string{`$email is allowed only in the path and query, not in the host "$email.lookup.example.com"`},
		},
		{
			name:    "remote_lookup plaintext to a remote host",
			content: imapProxy + remoteLookup + "url = \"http://lookup.example.com/lookup?email=$email\"\n",
			wantErr: []string{"remote_lookup.url must use https:// for non-loopback hosts"},
		},
		{
			name:    "remote_lookup timeout without a unit",
			content: imapProxy + remoteLookup + "url = \"https://lookup.example.com/lookup?email=$email\"\ntimeout = \"5\"\n",
			wantErr: []string{"invalid remote_lookup.timeout"},
		},
		{
			name:    "remote_lookup the proxies start with",
			content: imapProxy + remoteLookup + "url = \"https://lookup.example.com/lookup?email=$email\"\ntimeout = \"5s\"\n",
		},
		{
			name:    "uploader concurrency 0 on a mail backend",
			content: "[uploader]\nconcurrency = 0\n" + imapBackend,
			wantErr: []string{"[uploader] concurrency must be positive, got 0"},
		},
		{
			// A node without a mail backend runs no upload worker; the server starts it.
			name:    "uploader concurrency 0 on a proxy",
			content: "[uploader]\nconcurrency = 0\n" + imapProxy + "remote_addrs = [\"192.0.2.10:143\"]\n",
		},
		{
			// A negative cleanup_grace_period makes the orphan sweep remove staged
			// bodies of deliveries that have not committed yet (#922).
			name:    "uploader cleanup_grace_period negative on a mail backend",
			content: "[uploader]\ncleanup_grace_period = \"-1h\"\n" + imapBackend,
			wantErr: []string{`[uploader] cleanup_grace_period must be positive, got "-1h"`},
		},
		{
			// The server exits at start-up on a cleanup_grace_period it cannot parse.
			name:    "uploader cleanup_grace_period unparseable on a mail backend",
			content: "[uploader]\ncleanup_grace_period = \"soon\"\n" + imapBackend,
			wantErr: []string{`[uploader] cleanup_grace_period`},
		},
		{
			name:    "cleanup fts_retention negative on a mail backend",
			content: "[cleanup]\nfts_retention = \"-24h\"\n" + imapBackend,
			wantErr: []string{"fts_retention must not be negative"},
		},
		{
			// A negative grace_period hard-deletes expunged mail at the next cleaner cycle.
			name:    "cleanup grace_period negative on a mail backend",
			content: "[cleanup]\ngrace_period = \"-14d\"\n" + imapBackend,
			wantErr: []string{`grace_period must not be negative, got "-14d"`},
		},
		{
			name:    "shared namespace_prefix without delimiter",
			content: "[shared_mailboxes]\nenabled = true\nnamespace_prefix = \"Shared\"\n" + imapBackend,
			wantErr: []string{`namespace_prefix "Shared"`},
		},
		{
			name:    "no servers",
			content: "[logging]\nlevel = \"info\"\n",
			wantErr: []string{"no servers configured"},
		},
		{
			name: "every problem reported",
			content: "[servers]\ntrusted_networks = []\n\n[uploader]\nconcurrency = 0\n\n" +
				"[relay]\ntype = \"SMTP\"\nsmtp_host = \"smtp.example.com:587\"\n" + proxyProtocolImap,
			wantErr: []string{
				"proxy_protocol is enabled on server(s) imap",
				"[uploader] concurrency must be positive, got 0",
				`unsupported [relay] type "SMTP"`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestConfigValidateCommandHelper$")
			cmd.Env = append(os.Environ(), configValidateHelperEnv+"="+path)
			out, err := cmd.CombinedOutput()
			if len(tt.wantErr) == 0 {
				if err != nil {
					t.Fatalf("config validate failed a file the server starts with: %v\n%s", err, out)
				}
				return
			}
			if err == nil {
				t.Fatalf("config validate passed the file; want it failed with %q:\n%s", tt.wantErr, out)
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(string(out), want) {
					t.Errorf("config validate failed, but the output does not say %q:\n%s", want, out)
				}
			}
		})
	}
}
