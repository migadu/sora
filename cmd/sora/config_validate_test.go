package main

import (
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
// [s3] the servers need were also checked only in service setup (#921), and so were
// [uploader] max_staging_size, the [s3] keys, the [database] durations and [tls] (#1092,
// #1095, #1104, #1105). [timeout_scheduler] shard_count was refused only once logging
// was set up (#1325). The refusal is written to the [logging] output, where it went to
// stderr only (#1762).
func TestStartupChecksTheWholeFile(t *testing.T) {
	const imapBackend = "\n[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \"127.0.0.1:143\"\n"
	const imapProxy = "\n[[server]]\ntype = \"imap_proxy\"\nname = \"imap-proxy\"\naddr = \"127.0.0.1:1143\"\nremote_addrs = [\"192.0.2.10:143\"]\n"
	const metrics = "\n[[server]]\ntype = \"metrics\"\nname = \"metrics\"\naddr = \"127.0.0.1:9090\"\npath = \"/metrics\"\n"
	tests := []struct {
		name    string
		content string
		wantErr []string // substrings of the logged problems ("<section>: <reason>"), none when start-up goes on
	}{
		{
			name:    "uploader concurrency 0 on a mail backend",
			content: "[uploader]\nconcurrency = 0\n" + imapBackend,
			wantErr: []string{"[uploader]: [uploader] concurrency must be positive, got 0"},
		},
		{
			name:    "cleanup fts_retention negative on a mail backend",
			content: "[cleanup]\nfts_retention = \"-24h\"\n" + imapBackend,
			wantErr: []string{"[cleanup]: fts_retention must not be negative"},
		},
		{
			// A negative grace_period hard-deletes expunged mail at the next cleaner cycle (#667).
			name:    "cleanup grace_period negative on a mail backend",
			content: "[cleanup]\ngrace_period = \"-14d\"\n" + imapBackend,
			wantErr: []string{`[cleanup]: grace_period must not be negative, got "-14d"`},
		},
		{
			name:    "cleanup instance_liveness_threshold 0 on a mail backend",
			content: "[cleanup]\ninstance_liveness_threshold = \"0\"\n" + imapBackend,
			wantErr: []string{`[cleanup]: instance_liveness_threshold must be positive, got "0"`},
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
			wantErr: []string{`[relay.queue]: invalid circuit_breaker_timeout "soon"`},
		},
		{
			name:    "cluster addr 0.0.0.0",
			content: "[cluster]\nenabled = true\naddr = \"0.0.0.0:7946\"\nsecret_key = \"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=\"\n" + metrics,
			wantErr: []string{"[cluster]: cluster addr '0.0.0.0' must be a specific IP address reachable from other nodes"},
		},
		{
			name:    "mail backend without database and S3",
			content: imapBackend,
			wantErr: []string{
				`[database]: server "imap" (imap) needs the database`,
				"[s3]: bucket is required",
			},
		},
		{
			// Start-up set up S3 and tried every replica before it stopped with "no
			// healthy database pools available" (#1266).
			name:    "mail backend with only [database.read] hosts",
			content: "[database.read]\nhosts = [\"replica.example.com\"]\n\n[s3]\nendpoint = \"s3.example.com\"\nbucket = \"mail\"\n" + imapBackend,
			wantErr: []string{`[database.write]: server "imap" (imap) needs the database, but [database.write] has no hosts`},
		},
		{
			// Every proxy refused this file only as it was built (#1038).
			name: "proxy without remote_addrs or [[pool]] blocks",
			content: "\n[[server]]\ntype = \"imap_proxy\"\nname = \"imap-proxy\"\naddr = \"127.0.0.1:1143\"\n" +
				"\n[server.remote_lookup]\nenabled = true\nurl = \"https://lookup.example.com/lookup?email=$email\"\n",
			wantErr: []string{"server 'imap-proxy': remote_addrs is required unless the file declares [[pool]] blocks"},
		},
		{
			// The proxy was built with "" as a backend and routed users to it (#1147).
			name: "proxy with an empty remote_addrs entry",
			content: "\n[[server]]\ntype = \"imap_proxy\"\nname = \"imap-proxy\"\naddr = \"127.0.0.1:1143\"\nremote_addrs = [\"\"]\nremote_port = 143\n" +
				"\n[server.remote_lookup]\nenabled = true\nurl = \"https://lookup.example.com/lookup?email=$email\"\n",
			wantErr: []string{`server 'imap-proxy': server "imap-proxy": remote_addrs #1: empty backend address`},
		},
		{
			name:    "mail backend with database and S3",
			content: storageTOML + imapBackend,
		},
		{
			// Start-up exited on this as it started the upload worker (#1092).
			name:    "uploader max_staging_size unparsable on a mail backend",
			content: storageTOML + "[uploader]\nmax_staging_size = \"100 gigs\"\n" + imapBackend,
			wantErr: []string{"[uploader]: [uploader] max_staging_size: invalid size format: '100 gigs'"},
		},
		{
			// Storage set-up refused these (#1095).
			name:    "s3 encryption_key not hex",
			content: storageTOML + "encrypt = true\nencryption_key = \"not-hex\"\n" + imapBackend,
			wantErr: []string{"[s3]: encryption_key must be 64 hex characters"},
		},
		{
			name:    "s3 secret_key without access_key",
			content: storageTOML + "secret_key = \"example-secret\"\n" + imapBackend,
			wantErr: []string{"[s3]: access_key and secret_key must be set together"},
		},
		{
			// Start-up marked the write host failed and stopped with "no healthy database
			// pools available"; a read replica was retried for good (#1104).
			name: "database durations unparsable",
			content: "[database]\nmigration_timeout = \"soon\"\n\n[database.write]\nhosts = [\"db.example.com\"]\nmax_conn_lifetime = \"an hour\"\n" +
				"\n[database.read]\nhosts = [\"replica.example.com\"]\nmax_conn_idle_time = \"idle\"\n" +
				"\n[[server]]\ntype = \"managesieve\"\nname = \"managesieve\"\naddr = \"127.0.0.1:4190\"\n",
			wantErr: []string{
				`[database]: invalid migration_timeout "soon"`,
				`[database.write]: invalid max_conn_lifetime "an hour"`,
				`[database.read]: invalid max_conn_idle_time "idle"`,
			},
		},
		{
			// The TLS manager refused this after every other service was up (#1105).
			name:    "tls letsencrypt without email",
			content: "[tls]\nenabled = true\nprovider = \"letsencrypt\"\n\n[tls.letsencrypt]\ndomains = [\"mail.example.com\"]\n" + metrics,
			wantErr: []string{"[tls]: letsencrypt.email is required"},
		},
		{
			name:    "cluster port out of range",
			content: "[cluster]\nenabled = true\naddr = \"10.10.10.40:70000\"\nsecret_key = \"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=\"\n" + metrics,
			wantErr: []string{"[cluster]: cluster port 70000 is not a valid port"},
		},

		{name: "cluster port overflow", content: "[cluster]\nenabled = true\naddr = \"10.10.10.40:999999999999999999999999999999\"\nsecret_key = \"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=\"\n" + metrics, wantErr: []string{`[cluster]: cluster port "999999999999999999999999999999" is not a valid port`}},
		{
			name:    "timeout_scheduler shard_count below -1",
			content: "[timeout_scheduler]\nshard_count = -2\n" + metrics,
			wantErr: []string{"[timeout_scheduler]: shard_count must be >= -1, got -2"},
		},
		{
			name: "every problem reported",
			content: "[servers]\ntrusted_networks = []\n\n[relay]\ntype = \"SMTP\"\nsmtp_host = \"smtp.example.com:587\"\n" +
				"\n[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \"127.0.0.1:143\"\nproxy_protocol = true\n" +
				"\n[[server]]\ntype = \"pop3\"\nname = \"imap\"\naddr = \"127.0.0.1:110\"\n",
			wantErr: []string{
				`[relay]: unsupported [relay] type "SMTP"`,
				"trusted_networks: proxy_protocol is enabled on server(s) imap",
				"server configuration: duplicate server name 'imap' found",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			refused, problems, out := checkStartupConfig(t, tt.content)
			if len(tt.wantErr) == 0 {
				if refused {
					t.Fatalf("start-up refused a valid configuration:\n%s%s", problems, out)
				}
				return
			}
			if !refused {
				t.Fatalf("start-up went on; want it refused with %q:\n%s", tt.wantErr, out)
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(problems, want) {
					t.Errorf("start-up refused, but the log does not say %q:\nlog:\n%s\noutput:\n%s", want, problems, out)
				}
			}
		})
	}
}
