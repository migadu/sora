package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// storageTOML gives a file the [database] and [s3] settings a node with a mail backend
// or a proxy that authenticates against the database starts with.
const storageTOML = "[database.write]\nhosts = [\"db.example.com\"]\n\n[s3]\nendpoint = \"s3.example.com\"\nbucket = \"mail\"\n\n"

// validClusterKey is base64 of 32 bytes, as `openssl rand -base64 32` writes one.
const validClusterKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

// TestConfigValidate covers the checks shared by sora before service setup and
// `sora-admin config validate` (#516), including each problem's section. Every file has
// [database] and [s3]; TestConfigValidateDatabaseAndS3 covers files without them.
func TestConfigValidate(t *testing.T) {
	const imapBackend = "\n[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \"127.0.0.1:143\"\n"
	const imapProxy = "\n[[server]]\ntype = \"imap_proxy\"\nname = \"imap-proxy\"\naddr = \"127.0.0.1:1143\"\nremote_addrs = [\"192.0.2.10:143\"]\n"
	const cluster = "[cluster]\nenabled = true\n"
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
		{name: "cleanup grace_period on a mail backend", content: "[cleanup]\ngrace_period = \"-14d\"\n" + imapBackend,
			want: []problem{{"[cleanup]", `grace_period must not be negative, got "-14d"`}}},
		{name: "cleanup max_age_restriction on a mail backend", content: "[cleanup]\nmax_age_restriction = \"-90d\"\n" + imapBackend,
			want: []problem{{"[cleanup]", `max_age_restriction must not be negative, got "-90d"`}}},
		{name: "cleanup health_status_retention on a mail backend", content: "[cleanup]\nhealth_status_retention = \"-30d\"\n" + imapBackend,
			want: []problem{{"[cleanup]", `health_status_retention must not be negative, got "-30d"`}}},
		{name: "cleanup instance_liveness_threshold on a mail backend", content: "[cleanup]\ninstance_liveness_threshold = \"0\"\n" + imapBackend,
			want: []problem{{"[cleanup]", `instance_liveness_threshold must be positive, got "0"`}}},
		{name: "uploader and cleanup on a proxy are not checked", content: "[uploader]\nconcurrency = 0\n\n[cleanup]\nfts_retention = \"-1h\"\n" + imapProxy},
		// cluster.New refused these only once the database and S3 were up (#921).
		{name: "cluster", content: cluster + "addr = \"10.10.10.40:7946\"\nsecret_key = \"" + validClusterKey + "\"\n" + imapBackend},
		{name: "cluster IPv6 addr and port", content: cluster + "addr = \"2001:db8::40\"\nport = 7946\nsecret_key = \"" + validClusterKey + "\"\n" + imapBackend},
		{name: "cluster on loopback", content: cluster + "addr = \"127.0.0.1:7946\"\nsecret_key = \"" + validClusterKey + "\"\n" + imapBackend},
		{name: "cluster addr 0.0.0.0", content: cluster + "addr = \"0.0.0.0:7946\"\nsecret_key = \"" + validClusterKey + "\"\n" + imapBackend,
			want: []problem{{"[cluster]", "cluster addr '0.0.0.0' must be a specific IP address reachable from other nodes"}}},
		{name: "cluster addr ::", content: cluster + "addr = \"[::]:7946\"\nsecret_key = \"" + validClusterKey + "\"\n" + imapBackend,
			want: []problem{{"[cluster]", "cluster addr '::' must be a specific IP address"}}},
		{name: "cluster addr localhost", content: cluster + "addr = \"localhost:7946\"\nsecret_key = \"" + validClusterKey + "\"\n" + imapBackend,
			want: []problem{{"[cluster]", "cluster addr 'localhost' must be a specific IP address"}}},
		{name: "cluster addr host name", content: cluster + "addr = \"gossip.example.com:7946\"\nsecret_key = \"" + validClusterKey + "\"\n" + imapBackend,
			want: []problem{{"[cluster]", "cluster addr 'gossip.example.com' must be a specific IP address"}}},
		{name: "cluster without addr", content: cluster + "secret_key = \"" + validClusterKey + "\"\n" + imapBackend,
			want: []problem{{"[cluster]", "cluster addr '' must be a specific IP address"}}},
		{name: "cluster without secret_key", content: cluster + "addr = \"10.10.10.40:7946\"\n" + imapBackend,
			want: []problem{{"[cluster]", "cluster secret_key is required when cluster mode is enabled"}}},
		{name: "cluster secret_key not base64", content: cluster + "addr = \"10.10.10.40:7946\"\nsecret_key = \"not base64!\"\n" + imapBackend,
			want: []problem{{"[cluster]", "failed to decode cluster secret_key"}}},
		{name: "cluster secret_key of 16 bytes", content: cluster + "addr = \"10.10.10.40:7946\"\nsecret_key = \"MDEyMzQ1Njc4OWFiY2RlZg==\"\n" + imapBackend,
			want: []problem{{"[cluster]", "cluster secret_key must be 32 bytes (got 16 bytes)"}}},
		{name: "cluster disabled is not checked", content: "[cluster]\nenabled = false\naddr = \"0.0.0.0:7946\"\n" + imapBackend},
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
			got := validateFile(t, storageTOML+tt.content)
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

// TestConfigValidateDatabaseAndS3: a node that runs a server needing the database, or
// one that stores or serves message bodies, is refused without [database] or [s3]. The
// server refused these only in service setup, after it had opened what came before, and
// `sora-admin config validate` passed them (#921).
func TestConfigValidateDatabaseAndS3(t *testing.T) {
	const db = "[database.write]\nhosts = [\"db.example.com\"]\n\n"
	const s3 = "[s3]\nendpoint = \"s3.example.com\"\nbucket = \"mail\"\n\n"
	const imapBackend = "\n[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \"127.0.0.1:143\"\n"
	const managesieve = "\n[[server]]\ntype = \"managesieve\"\nname = \"sieve\"\naddr = \"127.0.0.1:4190\"\n"
	const userAPI = "\n[[server]]\ntype = \"http_user_api\"\nname = \"user-api\"\naddr = \"127.0.0.1:8081\"\njwt_secret = \"secret\"\n"
	const imapProxy = "\n[[server]]\ntype = \"imap_proxy\"\nname = \"imap-proxy\"\naddr = \"127.0.0.1:1143\"\nremote_addrs = [\"192.0.2.10:143\"]\n"
	const remoteLookup = "\n[server.remote_lookup]\nenabled = true\nurl = \"https://lookup.example.com/lookup?email=$email\"\n"
	const metrics = "\n[[server]]\ntype = \"metrics\"\nname = \"metrics\"\naddr = \"127.0.0.1:9090\"\n"
	type problem struct{ section, err string } // err: a substring of the problem's error
	tests := []struct {
		name    string
		content string
		want    []problem
	}{
		{name: "mail backend", content: db + s3 + imapBackend},
		{name: "mail backend with a read endpoint only", content: "[database.read]\nhosts = [\"db.example.com\"]\n\n" + s3 + imapBackend},
		{name: "mail backend without a database", content: s3 + imapBackend,
			want: []problem{{"[database]", `server "imap" (imap) needs the database, but it is not configured in [database.write] or [database.read]`}}},
		{name: "database endpoint without hosts", content: "[database.write]\nhosts = []\n\n" + s3 + imapBackend,
			want: []problem{{"[database]", `server "imap" (imap) needs the database`}}},
		{name: "mail backend without S3", content: db + imapBackend,
			want: []problem{{"[s3]", "bucket is required"}}},
		{name: "mail backend without S3 endpoint", content: db + "[s3]\nbucket = \"mail\"\n" + imapBackend,
			want: []problem{{"[s3]", "endpoint is required"}}},
		{name: "mail backend with an S3 timeout without a unit", content: db + s3 + "timeout = \"30\"\n" + imapBackend,
			want: []problem{{"[s3]", `invalid timeout "30"`}}},
		{name: "mail backend without database and S3", content: imapBackend,
			want: []problem{{"[database]", `server "imap" (imap) needs the database`}, {"[s3]", "bucket is required"}}},
		{name: "managesieve needs the database, not S3", content: managesieve,
			want: []problem{{"[database]", `server "sieve" (managesieve) needs the database`}}},
		{name: "managesieve", content: db + managesieve},
		{name: "User API without S3 serves no bodies", content: db + userAPI},
		{name: "User API with part of [s3]", content: db + "[s3]\nbucket = \"mail\"\n" + userAPI,
			want: []problem{{"[s3]", "endpoint is required"}}},
		{name: "User API with [s3]", content: db + s3 + userAPI},
		{name: "proxy that authenticates against the database", content: imapProxy,
			want: []problem{{"[database]", `server "imap-proxy" (imap_proxy) needs the database`}}},
		{name: "proxy with a remote lookup for every user", content: "[s3]\ntimeout = \"soon\"\n" + imapProxy + remoteLookup},
		{name: "proxy with a remote lookup and local users", content: imapProxy + remoteLookup + "lookup_local_users = true\n",
			want: []problem{{"[database]", `server "imap-proxy" (imap_proxy) needs the database`}}},
		{name: "metrics only", content: metrics},
		{name: "disabled mail backend", content: metrics + "\n[[server]]\nenabled = false\ntype = \"imap\"\nname = \"imap\"\naddr = \"127.0.0.1:143\"\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateFile(t, tt.content)
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

// validateFile loads content as the server loads its file and returns what Validate finds.
func validateFile(t *testing.T, content string) []Problem {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err := LoadServerConfig(path, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg.Validate()
}
