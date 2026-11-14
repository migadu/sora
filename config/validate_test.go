package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestConfigValidate: Validate returns every problem of a file that stops sora at
// start-up, each with the section it is about, and nothing for a file it starts with
// (#516). sora and `sora-admin config validate` both run it.
func TestConfigValidate(t *testing.T) {
	const imapBackend = "\n[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \"127.0.0.1:143\"\n"
	const imapProxy = "\n[[server]]\ntype = \"imap_proxy\"\nname = \"imap-proxy\"\naddr = \"127.0.0.1:1143\"\nremote_addrs = [\"192.0.2.10:143\"]\n"
	type problem struct{ section, err string } // err: a substring of the problem's error
	tests := []struct {
		name    string
		content string
		want    []problem
	}{
		{name: "mail backend", content: imapBackend},
		{name: "proxy", content: imapProxy},
		{name: "server block", content: "\n[[server]]\ntype = \"imap\"\nname = \"imap\"\n",
			want: []problem{{"server 'imap'", "server address is required"}}},
		{name: "disabled server block is not checked", content: imapBackend + "\n[[server]]\nenabled = false\ntype = \"pop3\"\n"},
		{name: "pool", content: "[[pool]]\nname = \"sora1\"\nbackends = [\"192.0.2.10:143\"]\n\n[[pool]]\nname = \"sora1\"\nbackends = [\"192.0.2.11:143\"]\n" +
			"\n[[server]]\ntype = \"imap_proxy\"\nname = \"imap-proxy\"\naddr = \"127.0.0.1:1143\"\n",
			want: []problem{{"[[pool]]", `"sora1": declared more than once`}}},
		{name: "relay", content: "[relay]\ntype = \"lmtp\"\n" + imapBackend,
			want: []problem{{"[relay]", `unsupported [relay] type "lmtp"`}}},
		{name: "malformed trusted_networks", content: "[servers]\ntrusted_networks = [\"mx.example.com\"]\n" + imapBackend,
			want: []problem{{"trusted_networks", "mx.example.com"}}},
		{name: "shared_mailboxes", content: "[shared_mailboxes]\nenabled = true\nnamespace_prefix = \"Shared\"\n" + imapBackend,
			want: []problem{{"[shared_mailboxes]", `namespace_prefix "Shared"`}}},
		{name: "PROXY protocol without trusted_networks", content: imapBackend + "proxy_protocol = true\n",
			want: []problem{{"trusted_networks", "proxy_protocol is enabled on server(s) imap"}}},
		{name: "PROXY protocol with trusted_networks", content: "[servers]\ntrusted_networks = [\"192.0.2.10\"]\n" + imapBackend + "proxy_protocol = true\n"},
		{name: "duplicate name and address", content: imapBackend + imapBackend,
			want: []problem{
				{"server configuration", "duplicate server name 'imap'"},
				{"server configuration", "duplicate server address '127.0.0.1:143'"},
			}},
		{name: "blocks without addr are not duplicates", content: "\n[[server]]\ntype = \"imap\"\nname = \"a\"\n\n[[server]]\ntype = \"pop3\"\nname = \"b\"\n",
			want: []problem{{"server 'a'", "server address is required"}, {"server 'b'", "server address is required"}}},
		{name: "no servers", content: "[logging]\nlevel = \"info\"\n",
			want: []problem{{"servers", "no servers configured"}}},
		{name: "uploader on a mail backend", content: "[uploader]\nmax_attempts = 0\n" + imapBackend,
			want: []problem{{"[uploader]", "max_attempts must be positive, got 0"}}},
		{name: "cleanup on a mail backend", content: "[cleanup]\nfts_retention = \"-1h\"\n" + imapBackend,
			want: []problem{{"[cleanup]", "fts_retention must not be negative"}}},
		{name: "uploader and cleanup on a proxy are not checked", content: "[uploader]\nconcurrency = 0\n\n[cleanup]\nfts_retention = \"-1h\"\n" + imapProxy},
		{name: "every problem, in order", content: "[servers]\ntrusted_networks = []\n\n[relay]\ntype = \"SMTP\"\n\n[uploader]\nbatch_size = 0\n" +
			imapBackend + "proxy_protocol = true\n" + imapBackend,
			want: []problem{
				{"[relay]", `unsupported [relay] type "SMTP"`},
				{"trusted_networks", "proxy_protocol is enabled on server(s) imap but"},
				{"server configuration", "duplicate server name 'imap'"},
				{"server configuration", "duplicate server address '127.0.0.1:143'"},
				{"[uploader]", "batch_size must be positive, got 0"},
			}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			var cfg Config
			if err := LoadServerConfig(path, &cfg); err != nil {
				t.Fatal(err)
			}
			got := cfg.Validate()
			if len(got) != len(tt.want) {
				t.Fatalf("Validate() = %v, want %d problem(s) %v", got, len(tt.want), tt.want)
			}
			for i, w := range tt.want {
				if got[i].Section != w.section || !strings.Contains(got[i].Err.Error(), w.err) {
					t.Errorf("problem %d = %s: %v, want %s: ...%s...", i, got[i].Section, got[i].Err, w.section, w.err)
				}
			}
		})
	}
}
