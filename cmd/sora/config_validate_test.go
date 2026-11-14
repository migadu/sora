package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestStartupChecksTheWholeFile: start-up refuses an invalid file before it starts
// anything, with every problem the file has, and the checks are those `sora-admin config
// validate` runs (#516). [uploader] and [cleanup] were checked only once the database,
// S3 and the cache were up, and start-up stopped at the first problem. A node without a
// mail backend runs no upload worker or cleaner, so their sections are not checked there.
func TestStartupChecksTheWholeFile(t *testing.T) {
	const imapBackend = "\n[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \"127.0.0.1:143\"\n"
	const imapProxy = "\n[[server]]\ntype = \"imap_proxy\"\nname = \"imap-proxy\"\naddr = \"127.0.0.1:1143\"\nremote_addrs = [\"192.0.2.10:143\"]\n"
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
			content: "[uploader]\nconcurrency = 0\n" + imapProxy,
		},
		{
			name:    "cleanup grace_period negative on a proxy",
			content: "[cleanup]\ngrace_period = \"-14d\"\n" + imapProxy,
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
