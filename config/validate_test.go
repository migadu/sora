package config

import (
	"os"
	"path/filepath"
	"slices"
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
		// memberlist cannot bind these either, and start-up stopped there only once the
		// database and S3 were up. Port 0 binds a free port, which memberlist advertises.
		{name: "cluster dynamic port", content: cluster + "addr = \"10.10.10.40:0\"\nsecret_key = \"" + validClusterKey + "\"\n" + imapBackend},
		{name: "cluster port in addr out of range", content: cluster + "addr = \"10.10.10.40:70000\"\nsecret_key = \"" + validClusterKey + "\"\n" + imapBackend,
			want: []problem{{"[cluster]", "cluster port 70000 is not a valid port"}}},
		{name: "cluster negative port in addr", content: cluster + "addr = \"10.10.10.40:-1\"\nsecret_key = \"" + validClusterKey + "\"\n" + imapBackend,
			want: []problem{{"[cluster]", "cluster port -1 is not a valid port"}}},
		{name: "cluster port field out of range", content: cluster + "addr = \"10.10.10.40\"\nport = 70000\nsecret_key = \"" + validClusterKey + "\"\n" + imapBackend,
			want: []problem{{"[cluster]", "cluster port 70000 is not a valid port"}}},
		// A negative port key bound the default 7946 instead of being refused.
		{name: "cluster negative port field", content: cluster + "addr = \"10.10.10.40\"\nport = -1\nsecret_key = \"" + validClusterKey + "\"\n" + imapBackend,
			want: []problem{{"[cluster]", "cluster port -1 is not a valid port"}}},

		{name: "cluster port overflow", content: cluster + "addr = \"10.10.10.40:999999999999999999999999999999\"\nsecret_key = \"" + validClusterKey + "\"\n" + imapBackend, want: []problem{{"[cluster]", `cluster port "999999999999999999999999999999" is not a valid port`}}},
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
// `sora-admin config validate` passed them (#921); it passed [database.read] hosts without
// [database.write] ones too (#1266).
func TestConfigValidateDatabaseAndS3(t *testing.T) {
	const db = "[database.write]\nhosts = [\"db.example.com\"]\n\n"
	const readOnly = "[database.read]\nhosts = [\"replica.example.com\"]\n\n"
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
		// Start-up opens write pools only from [database.write] and stops with "no healthy
		// database pools available" without one, after trying every replica (#1266).
		{name: "mail backend with a read endpoint only", content: readOnly + s3 + imapBackend,
			want: []problem{{"[database.write]", `server "imap" (imap) needs the database, but [database.write] has no hosts`}}},
		{name: "managesieve with a read endpoint only", content: readOnly + managesieve,
			want: []problem{{"[database.write]", `server "sieve" (managesieve) needs the database, but [database.write] has no hosts`}}},
		{name: "read endpoint and a write endpoint without hosts", content: "[database.write]\nhosts = []\n\n" + readOnly + managesieve,
			want: []problem{{"[database.write]", `server "sieve" (managesieve) needs the database, but [database.write] has no hosts`}}},
		{name: "proxy that authenticates against a read endpoint only", content: readOnly + imapProxy,
			want: []problem{{"[database.write]", `server "imap-proxy" (imap_proxy) needs the database, but [database.write] has no hosts`}}},
		{name: "write and read endpoints", content: db + readOnly + managesieve},
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

// TestConfigValidateWhatServiceSetupRefuses: these settings are known to be wrong from
// the file alone, but the server found them only while it set up the service that reads
// them, after it had opened what came before, and `sora-admin config validate` passed
// them: [uploader] max_staging_size (#1092), [s3] encryption_key and a lone access_key or
// secret_key (#1095), the [database] durations (#1104) and [tls] (#1105). Each is checked
// only where start-up reads it. [timeout_scheduler] shard_count is read on every node, by
// the scheduler set up once logging is (#1325).
func TestConfigValidateWhatServiceSetupRefuses(t *testing.T) {
	const db = "[database.write]\nhosts = [\"db.example.com\"]\n"
	const s3 = "[s3]\nendpoint = \"s3.example.com\"\nbucket = \"mail\"\n"
	const imapBackend = "\n[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \"127.0.0.1:143\"\n"
	const managesieve = "\n[[server]]\ntype = \"managesieve\"\nname = \"sieve\"\naddr = \"127.0.0.1:4190\"\n"
	const imapProxy = "\n[[server]]\ntype = \"imap_proxy\"\nname = \"imap-proxy\"\naddr = \"127.0.0.1:1143\"\nremote_addrs = [\"192.0.2.10:143\"]\n" +
		"\n[server.remote_lookup]\nenabled = true\nurl = \"https://lookup.example.com/lookup?email=$email\"\n"
	const metrics = "\n[[server]]\ntype = \"metrics\"\nname = \"metrics\"\naddr = \"127.0.0.1:9090\"\n"
	const encryptionKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" // 32 bytes
	const tls = "[tls]\nenabled = true\nprovider = \"letsencrypt\"\n\n[tls.letsencrypt]\nemail = \"postmaster@example.com\"\ndomains = [\"mail.example.com\"]\nstorage_provider = \"s3\"\n"
	type problem struct{ section, err string } // err: a substring of the problem's error
	tests := []struct {
		name    string
		content string
		want    []problem
	}{
		// #1092: start-up exits on a max_staging_size it cannot parse.
		{name: "uploader max_staging_size", content: "[uploader]\nmax_staging_size = \"100gb\"\n" + db + s3 + imapBackend},
		{name: "uploader max_staging_size unparsable", content: "[uploader]\nmax_staging_size = \"100 gigs\"\n" + db + s3 + imapBackend,
			want: []problem{{"[uploader]", "[uploader] max_staging_size: invalid size format: '100 gigs'"}}},
		{name: "uploader max_staging_size on a proxy is not checked", content: "[uploader]\nmax_staging_size = \"100 gigs\"\n" + imapProxy},

		// #1095: storage set-up refuses these with encrypt = true, or with one key alone.
		{name: "s3 encrypt", content: db + s3 + "encrypt = true\nencryption_key = \"" + encryptionKey + "\"\n" + imapBackend},
		{name: "s3 encrypt without encryption_key", content: db + s3 + "encrypt = true\n" + imapBackend,
			want: []problem{{"[s3]", "encryption_key is required when encrypt = true"}}},
		{name: "s3 encryption_key not hex", content: db + s3 + "encrypt = true\nencryption_key = \"not-hex\"\n" + imapBackend,
			want: []problem{{"[s3]", "encryption_key must be 64 hex characters"}}},
		{name: "s3 encryption_key of 16 bytes", content: db + s3 + "encrypt = true\nencryption_key = \"" + encryptionKey[:32] + "\"\n" + imapBackend,
			want: []problem{{"[s3]", "encryption_key must be 32 bytes (64 hex characters), got 16 bytes"}}},
		{name: "s3 encryption_key without encrypt is not used", content: db + s3 + "encryption_key = \"not-hex\"\n" + imapBackend},
		{name: "s3 access_key without secret_key", content: db + s3 + "access_key = \"AKIAEXAMPLE\"\n" + imapBackend,
			want: []problem{{"[s3]", "access_key and secret_key must be set together"}}},
		{name: "s3 secret_key without access_key", content: db + s3 + "secret_key = \"example-secret\"\n" + imapBackend,
			want: []problem{{"[s3]", "access_key and secret_key must be set together"}}},
		{name: "s3 access_key and secret_key", content: db + s3 + "access_key = \"AKIAEXAMPLE\"\nsecret_key = \"example-secret\"\n" + imapBackend},
		{name: "s3 on a proxy is not checked", content: s3 + "encrypt = true\naccess_key = \"AKIAEXAMPLE\"\n" + imapProxy},

		// #1104: a write host whose pool settings do not parse is marked failed, and
		// start-up stops with "no healthy database pools available"; a read replica is
		// retried for good.
		{name: "database durations", content: "[database]\nmigration_timeout = \"5m\"\n\n" + db + "max_conn_lifetime = \"1h\"\nmax_conn_idle_time = \"30m\"\n" + managesieve},
		{name: "database migration_timeout unparsable", content: "[database]\nmigration_timeout = \"soon\"\n\n" + db + managesieve,
			want: []problem{{"[database]", `invalid migration_timeout "soon"`}}},
		{name: "database.write max_conn_lifetime unparsable", content: db + "max_conn_lifetime = \"an hour\"\n" + managesieve,
			want: []problem{{"[database.write]", `invalid max_conn_lifetime "an hour"`}}},
		{name: "database.read max_conn_idle_time unparsable", content: db + "\n[database.read]\nhosts = [\"replica.example.com\"]\nmax_conn_idle_time = \"idle\"\n" + managesieve,
			want: []problem{{"[database.read]", `invalid max_conn_idle_time "idle"`}}},
		{name: "database.read without hosts is not checked", content: db + "\n[database.read]\nhosts = []\nmax_conn_idle_time = \"idle\"\n" + managesieve},
		{name: "database on a node that queries none is not checked", content: "[database]\nmigration_timeout = \"soon\"\n\n" + db + "max_conn_lifetime = \"an hour\"\n" + metrics},
		// So is a host whose connection string cannot be built from the endpoint's port.
		{name: "database ports", content: db + "port = 5433\n\n[database.read]\nhosts = [\"replica.example.com\"]\nport = \"5434\"\n" + managesieve},
		{name: "database.write port out of range", content: db + "port = 70000\n" + managesieve,
			want: []problem{{"[database.write]", "port number 70000 is out of the valid range (1-65535)"}}},
		{name: "database.read port not a number", content: db + "\n[database.read]\nhosts = [\"replica.example.com\"]\nport = \"x\"\n" + managesieve,
			want: []problem{{"[database.read]", `invalid string for port: "x"`}}},
		{name: "database port unused when every host names one", content: "[database.write]\nhosts = [\"db.example.com:5433\"]\nport = \"x\"\n" + managesieve},
		{name: "database.write host port not a number", content: "[database.write]\nhosts = [\"db.example.com:5433\", \"db2.example.com:abc\"]\n" + managesieve,
			want: []problem{{"[database.write]", `invalid port "abc" in host "db2.example.com:abc"`}}},

		// #1105: the TLS manager refused these last, after every other service was up.
		{name: "tls letsencrypt", content: tls + "renew_before = \"720h\"\nsync_interval = \"0\"\n" + metrics},
		{name: "tls file", content: "[tls]\nenabled = true\nprovider = \"file\"\ncert_file = \"/etc/sora/cert.pem\"\nkey_file = \"/etc/sora/key.pem\"\n" + metrics},
		{name: "tls provider unknown", content: "[tls]\nenabled = true\nprovider = \"acme\"\n" + metrics,
			want: []problem{{"[tls]", "unknown TLS provider: acme (must be 'file' or 'letsencrypt')"}}},
		{name: "tls file without key_file", content: "[tls]\nenabled = true\nprovider = \"file\"\ncert_file = \"/etc/sora/cert.pem\"\n" + metrics,
			want: []problem{{"[tls]", "cert_file and key_file are required for provider='file'"}}},
		{name: "tls letsencrypt without its table", content: "[tls]\nenabled = true\nprovider = \"letsencrypt\"\n" + metrics,
			want: []problem{{"[tls]", "letsencrypt configuration is required for provider='letsencrypt'"}}},
		{name: "tls letsencrypt without email", content: "[tls]\nenabled = true\nprovider = \"letsencrypt\"\n\n[tls.letsencrypt]\ndomains = [\"mail.example.com\"]\nstorage_provider = \"s3\"\n" + metrics,
			want: []problem{{"[tls]", "letsencrypt.email is required"}}},
		{name: "tls letsencrypt without domains", content: "[tls]\nenabled = true\nprovider = \"letsencrypt\"\n\n[tls.letsencrypt]\nemail = \"postmaster@example.com\"\nstorage_provider = \"s3\"\n" + metrics,
			want: []problem{{"[tls]", "letsencrypt.domains is required and must not be empty"}}},
		{name: "tls letsencrypt without storage_provider", content: "[tls]\nenabled = true\nprovider = \"letsencrypt\"\n\n[tls.letsencrypt]\nemail = \"postmaster@example.com\"\ndomains = [\"mail.example.com\"]\n" + metrics,
			want: []problem{{"[tls]", "only storage_provider='s3' is currently supported for Let's Encrypt"}}},
		{name: "tls letsencrypt renew_before unparsable", content: tls + "renew_before = \"a month\"\n" + metrics,
			want: []problem{{"[tls]", `invalid renew_before duration "a month"`}}},
		{name: "tls letsencrypt sync_interval unparsable", content: tls + "sync_interval = \"often\"\n" + metrics,
			want: []problem{{"[tls]", `invalid sync_interval duration "often"`}}},
		// The certificate store's client and its encryption settings are refused from the
		// file as well, before the store is reached.
		{name: "tls letsencrypt s3", content: tls + "\n[tls.letsencrypt.s3]\nbucket = \"certs\"\naccess_key = \"AKIAEXAMPLE\"\nsecret_key = \"example-secret\"\nserver_side_encryption = \"aws:kms\"\nserver_side_encryption_kms_key_id = \"example-key\"\n" + metrics},
		{name: "tls letsencrypt s3 without server-side encryption", content: tls + "\n[tls.letsencrypt.s3]\nbucket = \"certs\"\nserver_side_encryption = \"\"\n" + metrics},
		{name: "tls letsencrypt s3 access_key without secret_key", content: tls + "\n[tls.letsencrypt.s3]\nbucket = \"certs\"\naccess_key = \"AKIAEXAMPLE\"\n" + metrics,
			want: []problem{{"[tls]", "letsencrypt.s3: access_key and secret_key must be set together"}}},
		{name: "tls letsencrypt s3 server_side_encryption unsupported", content: tls + "\n[tls.letsencrypt.s3]\nbucket = \"certs\"\nserver_side_encryption = \"rot13\"\n" + metrics,
			want: []problem{{"[tls]", `letsencrypt.s3: unsupported server-side encryption "rot13"`}}},
		{name: "tls letsencrypt s3 aws:kms without key id", content: tls + "\n[tls.letsencrypt.s3]\nbucket = \"certs\"\nserver_side_encryption = \"aws:kms\"\n" + metrics,
			want: []problem{{"[tls]", `letsencrypt.s3: server-side encryption "aws:kms" requires a KMS key id`}}},
		{name: "tls letsencrypt s3 key id without aws:kms", content: tls + "\n[tls.letsencrypt.s3]\nbucket = \"certs\"\nserver_side_encryption_kms_key_id = \"example-key\"\n" + metrics,
			want: []problem{{"[tls]", `letsencrypt.s3: a KMS key id is only used by server-side encryption "aws:kms", not "AES256"`}}},
		{name: "tls disabled is not checked", content: "[tls]\nenabled = false\nprovider = \"acme\"\n" + metrics},

		// #1325: start-up exits on a shard_count below -1, after it has set up logging.
		{name: "timeout_scheduler shard_count", content: "[timeout_scheduler]\nshard_count = -1\n" + metrics},
		{name: "timeout_scheduler shard_count below -1", content: "[timeout_scheduler]\nshard_count = -2\n" + metrics,
			want: []problem{{"[timeout_scheduler]", "shard_count must be >= -1, got -2"}}},
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

// TestConfigValidateProxyNeedsBackends: every proxy refuses to be built without backends,
// in its remote_addrs or in the file's [[pool]] blocks, so Validate refuses such a file
// too, naming the server. It passed both start-up's configuration check and `sora-admin
// config validate` (#1038).
func TestConfigValidateProxyNeedsBackends(t *testing.T) {
	const pool = "[[pool]]\nname = \"sora1\"\nbackends = [\"192.0.2.10\"]\ndefault = true\n"
	const want = "remote_addrs is required unless the file declares [[pool]] blocks"
	var proxies int
	for _, typ := range ServerTypes {
		if !strings.HasSuffix(typ, "_proxy") {
			continue
		}
		proxies++
		server := "\n[[server]]\ntype = \"" + typ + "\"\nname = \"proxy\"\naddr = \"127.0.0.1:1143\"\nremote_port = 143\n"
		t.Run(typ, func(t *testing.T) {
			got := validateFile(t, storageTOML+server)
			if len(got) != 1 || got[0].Section != "server 'proxy'" || !strings.Contains(got[0].Err.Error(), want) {
				t.Errorf("without backends: Validate() = %v, want server 'proxy': ...%s...", got, want)
			}
			if got := validateFile(t, storageTOML+server+"remote_addrs = [\"192.0.2.10\"]\n"); len(got) != 0 {
				t.Errorf("with remote_addrs: Validate() = %v, want no problems", got)
			}
			if got := validateFile(t, storageTOML+pool+server); len(got) != 0 {
				t.Errorf("with [[pool]] blocks: Validate() = %v, want no problems", got)
			}
		})
	}
	if proxies != 5 {
		t.Errorf("checked %d proxy types, want the 5 proxies", proxies)
	}
}

// TestConfigValidateProxyRefusesEmptyRemoteAddr: an empty remote_addrs entry passed
// Validate, and the proxy was built with "" as a backend and routed users to it. Validate
// refuses it as ValidatePools refuses an empty [[pool]] backend, naming the entry (#1147).
// A port alone (":143") has an empty host too: the proxy dials it, and an empty host
// dials this node itself.
func TestConfigValidateProxyRefusesEmptyRemoteAddr(t *testing.T) {
	tests := []struct {
		remoteAddrs string
		want        string // "" for a valid list
	}{
		{`[""]`, `server "proxy": remote_addrs #1: empty backend address`},
		{`[" "]`, `server "proxy": remote_addrs #1: empty backend address`},
		{`["192.0.2.10:143", "\t"]`, `server "proxy": remote_addrs #2: empty backend address`},
		{`[":143"]`, `server "proxy": remote_addrs #1: empty backend address`},
		{`["192.0.2.10:143", "[]:143"]`, `server "proxy": remote_addrs #2: empty backend address`},
		{`["192.0.2.10:143", "backend.example.com"]`, ""},
		{`["[2001:db8::1]:143", "2001:db8::2"]`, ""},
	}
	var proxies int
	for _, typ := range ServerTypes {
		if !strings.HasSuffix(typ, "_proxy") {
			continue
		}
		proxies++
		for _, tt := range tests {
			t.Run(typ+" "+tt.remoteAddrs, func(t *testing.T) {
				got := validateFile(t, storageTOML+"\n[[server]]\ntype = \""+typ+"\"\nname = \"proxy\"\naddr = \"127.0.0.1:1143\"\nremote_port = 143\nremote_addrs = "+tt.remoteAddrs+"\n")
				if tt.want == "" {
					if len(got) != 0 {
						t.Errorf("Validate() = %v, want no problems", got)
					}
					return
				}
				if len(got) != 1 || got[0].Section != "server 'proxy'" || !strings.Contains(got[0].Err.Error(), tt.want) {
					t.Errorf("Validate() = %v, want server 'proxy': %s", got, tt.want)
				}
			})
		}
	}
	if proxies != 5 {
		t.Errorf("checked %d proxy types, want the 5 proxies", proxies)
	}

	// The [[pool]] check refuses the same entries.
	for _, backend := range []string{`""`, `" "`, `":143"`, `"[]:143"`} {
		t.Run("pool "+backend, func(t *testing.T) {
			got := validateFile(t, storageTOML+"\n[[server]]\ntype = \"imap_proxy\"\nname = \"proxy\"\naddr = \"127.0.0.1:1143\"\nremote_port = 143\n"+
				"\n[[pool]]\nname = \"sora0\"\ndefault = true\nbackends = ["+backend+"]\n")
			if len(got) != 1 || got[0].Section != "[[pool]]" || !strings.Contains(got[0].Err.Error(), `[[pool]] "sora0": empty backend address`) {
				t.Errorf("Validate() = %v, want [[pool]]: empty backend address", got)
			}
		})
	}
}

// TestConfigValidateProxyRefusesWhitespaceInRemoteAddr: the loader trims the ends of every
// string, so " 192.0.2.11:143" reaches the proxy as "192.0.2.11:143"; whitespace inside a
// remote_addrs entry ("192.0.2.10 :143") passed Validate and the proxy dialed the entry as
// written, a name that never resolves. No host or IP contains whitespace, so Validate
// refuses the entry, naming it, as it refuses an empty one (#1322).
func TestConfigValidateProxyRefusesWhitespaceInRemoteAddr(t *testing.T) {
	tests := []struct {
		remoteAddrs string
		want        string // "" for a valid list
	}{
		{`["192.0.2.10 :143"]`, `server "proxy": remote_addrs #1: backend address "192.0.2.10 :143" contains whitespace`},
		{`["192.0.2.10:143", "backend .example.com"]`, `server "proxy": remote_addrs #2: backend address "backend .example.com" contains whitespace`},
		{`["backend.example.com\t:143"]`, `server "proxy": remote_addrs #1: backend address "backend.example.com\t:143" contains whitespace`},
		{`["backend\u00a0.example.com"]`, `server "proxy": remote_addrs #1: backend address "backend\u00a0.example.com" contains whitespace`},
		// The ends are trimmed when the file is loaded (TestLoadServerConfigTrimsBackendAddresses).
		{`[" 192.0.2.10:143", "[2001:db8::1]:143 ", "\tbackend.example.com"]`, ""},
	}
	var proxies int
	for _, typ := range ServerTypes {
		if !strings.HasSuffix(typ, "_proxy") {
			continue
		}
		proxies++
		for _, tt := range tests {
			t.Run(typ+" "+tt.remoteAddrs, func(t *testing.T) {
				got := validateFile(t, storageTOML+"\n[[server]]\ntype = \""+typ+"\"\nname = \"proxy\"\naddr = \"127.0.0.1:1143\"\nremote_port = 143\nremote_addrs = "+tt.remoteAddrs+"\n")
				if tt.want == "" {
					if len(got) != 0 {
						t.Errorf("Validate() = %v, want no problems", got)
					}
					return
				}
				if len(got) != 1 || got[0].Section != "server 'proxy'" || !strings.Contains(got[0].Err.Error(), tt.want) {
					t.Errorf("Validate() = %v, want server 'proxy': %s", got, tt.want)
				}
			})
		}
	}
	if proxies != 5 {
		t.Errorf("checked %d proxy types, want the 5 proxies", proxies)
	}
}

// TestLoadServerConfigTrimsBackendAddresses: a remote_addrs entry or a [[pool]] backend
// written with a leading or trailing space reaches Validate and the proxies trimmed, from
// the loader that startup, SIGHUP reload and `sora-admin config validate` share (#1322).
func TestLoadServerConfigTrimsBackendAddresses(t *testing.T) {
	load := func(t *testing.T, content string) Config {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.toml")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		var cfg Config
		if err := LoadServerConfig(path, &cfg); err != nil {
			t.Fatal(err)
		}
		return cfg
	}

	cfg := load(t, storageTOML+"[[server]]\ntype = \"imap_proxy\"\nname = \"imap-proxy\"\naddr = \"127.0.0.1:11143\"\nremote_addrs = [\"192.0.2.10:143\", \" 192.0.2.11:143\", \"192.0.2.12:143\\t\"]\nremote_port = 143\n")
	if got, want := cfg.DynamicServers[0].RemoteAddrs, []string{"192.0.2.10:143", "192.0.2.11:143", "192.0.2.12:143"}; !slices.Equal(got, want) {
		t.Errorf("remote_addrs = %q, want %q", got, want)
	}
	if got := cfg.Validate(); len(got) != 0 {
		t.Errorf("remote_addrs: Validate() = %v, want no problems", got)
	}

	cfg = load(t, storageTOML+"[[pool]]\nname = \"sora0\"\ndefault = true\nbackends = [\"192.0.2.10\", \"192.0.2.11 \", \" 192.0.2.12:143\"]\n\n[[server]]\ntype = \"imap_proxy\"\nname = \"imap-proxy\"\naddr = \"127.0.0.1:11143\"\nremote_port = 143\n")
	if got, want := cfg.Pools[0].Backends, []string{"192.0.2.10", "192.0.2.11", "192.0.2.12:143"}; !slices.Equal(got, want) {
		t.Errorf("[[pool]] backends = %q, want %q", got, want)
	}
	if got := cfg.Validate(); len(got) != 0 {
		t.Errorf("[[pool]]: Validate() = %v, want no problems", got)
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
