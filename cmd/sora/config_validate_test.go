package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// storageTOML gives a file the [database] and [s3] settings a mail backend, or a proxy
// that authenticates against the database, starts with.
const storageTOML = "[database.write]\nhosts = [\"db.example.com\"]\n\n[s3]\nendpoint = \"s3.example.com\"\nbucket = \"mail\"\n\n"

// TestStartupChecksTheWholeFile: start-up refuses an invalid file before it starts
// anything, with every problem the file has, and the checks are those `sora-admin config
// validate` runs (#516). [uploader] and [cleanup] were checked only once the database,
// S3 and the cache were up, and start-up stopped at the first problem. A node without a
// mail backend runs no upload worker or cleaner, so their sections are not checked there.
// The [relay.queue] durations, [cluster] addr and secret_key, and the [database] and
// [s3] the servers need were also checked only in service setup (#921).
func TestStartupChecksTheWholeFile(t *testing.T) {
	const imapBackend = "\n[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \"127.0.0.1:143\"\n"
	const imapProxy = "\n[[server]]\ntype = \"imap_proxy\"\nname = \"imap-proxy\"\naddr = \"127.0.0.1:1143\"\nremote_addrs = [\"192.0.2.10:143\"]\n"
	const metrics = "\n[[server]]\ntype = \"metrics\"\nname = \"metrics\"\naddr = \"127.0.0.1:9090\"\npath = \"/metrics\"\n"
	tests := []struct {
		name    string
		content string
		wantErr []string // substrings of the refusal, none when start-up goes on
	}{
		{
			name:    "uploader concurrency 0 on a mail backend",
			content: "[uploader]\nconcurrency = 0\n" + imapBackend,
			wantErr: []string{"invalid configuration - [uploader]: [uploader] concurrency must be positive, got 0"},
		},
		{
			name:    "cleanup fts_retention negative on a mail backend",
			content: "[cleanup]\nfts_retention = \"-24h\"\n" + imapBackend,
			wantErr: []string{"invalid configuration - [cleanup]: fts_retention must not be negative"},
		},
		{
			// A negative grace_period hard-deletes expunged mail at the next cleaner cycle (#667).
			name:    "cleanup grace_period negative on a mail backend",
			content: "[cleanup]\ngrace_period = \"-14d\"\n" + imapBackend,
			wantErr: []string{`invalid configuration - [cleanup]: grace_period must not be negative, got "-14d"`},
		},
		{
			name:    "cleanup instance_liveness_threshold 0 on a mail backend",
			content: "[cleanup]\ninstance_liveness_threshold = \"0\"\n" + imapBackend,
			wantErr: []string{`invalid configuration - [cleanup]: instance_liveness_threshold must be positive, got "0"`},
		},
		{
			name:    "uploader concurrency 0 on a proxy",
			content: storageTOML + "[uploader]\nconcurrency = 0\n" + imapProxy,
		},
		{
			name:    "cleanup grace_period negative on a proxy",
			content: storageTOML + "[cleanup]\ngrace_period = \"-14d\"\n" + imapProxy,
		},
		{
			name: "relay.queue circuit_breaker_timeout unparsable",
			content: "[relay]\ntype = \"smtp\"\nsmtp_host = \"smtp.example.com:587\"\n\n[relay.queue]\npath = \"/tmp/relay\"\ncircuit_breaker_timeout = \"soon\"\n" +
				metrics,
			wantErr: []string{`invalid configuration - [relay.queue]: invalid circuit_breaker_timeout "soon"`},
		},
		{
			name:    "cluster addr 0.0.0.0",
			content: "[cluster]\nenabled = true\naddr = \"0.0.0.0:7946\"\nsecret_key = \"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=\"\n" + metrics,
			wantErr: []string{"invalid configuration - [cluster]: cluster addr '0.0.0.0' must be a specific IP address reachable from other nodes"},
		},
		{
			name:    "mail backend without database and S3",
			content: imapBackend,
			wantErr: []string{
				`invalid configuration - [database]: server "imap" (imap) needs the database`,
				"invalid configuration - [s3]: bucket is required",
			},
		},
		{
			name:    "mail backend with database and S3",
			content: storageTOML + imapBackend,
		},
		{
			// The database connection needs a write host: with [database.read] alone,
			// start-up connected the replica and then stopped with "no healthy database
			// pools available".
			name:    "managesieve with a read endpoint only",
			content: "[database.read]\nhosts = [\"db.example.com\"]\n\n[[server]]\ntype = \"managesieve\"\nname = \"sieve\"\naddr = \"127.0.0.1:4190\"\n",
			wantErr: []string{`invalid configuration - [database]: server "sieve" (managesieve) needs the database, but it is not configured in [database.write]`},
		},
		{
			name:    "cluster port out of range",
			content: "[cluster]\nenabled = true\naddr = \"10.10.10.40:70000\"\nsecret_key = \"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=\"\n" + metrics,
			wantErr: []string{"invalid configuration - [cluster]: cluster port 70000 is not a valid port"},
		},
		{
			name: "every problem reported",
			content: "[servers]\ntrusted_networks = []\n\n[relay]\ntype = \"SMTP\"\nsmtp_host = \"smtp.example.com:587\"\n" +
				"\n[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \"127.0.0.1:143\"\nproxy_protocol = true\n" +
				"\n[[server]]\ntype = \"pop3\"\nname = \"imap\"\naddr = \"127.0.0.1:110\"\n",
			wantErr: []string{
				`invalid configuration - [relay]: unsupported [relay] type "SMTP"`,
				"invalid configuration - trusted_networks: proxy_protocol is enabled on server(s) imap",
				"invalid configuration - server configuration: duplicate server name 'imap' found",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestLoadAndValidateConfigHelper$")
			cmd.Env = append(os.Environ(), loadConfigHelperEnv+"="+path)
			out, err := cmd.CombinedOutput()
			if len(tt.wantErr) == 0 {
				if err != nil {
					t.Fatalf("start-up refused a valid configuration: %v\n%s", err, out)
				}
				return
			}
			if err == nil {
				t.Fatalf("start-up went on; want it refused with %q:\n%s", tt.wantErr, out)
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(string(out), want) {
					t.Errorf("start-up refused, but the output does not say %q:\n%s", want, out)
				}
			}
		})
	}
}
