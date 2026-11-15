package main

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const configValidateHelperEnv = "SORA_ADMIN_CONFIG_VALIDATE_HELPER_PATH"

// storageTOML gives a file the [database] and [s3] settings a mail backend, or a proxy
// that authenticates against the database, starts with.
const storageTOML = "[database.write]\nhosts = [\"db.example.com\"]\n\n[s3]\nendpoint = \"s3.example.com\"\nbucket = \"mail\"\n\n"

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
			content := storageTOML + tt.relay + "\n[[server]]\ntype = \"lmtp\"\nname = \"lmtp\"\naddr = \"127.0.0.1:0\"\n"
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
			content := storageTOML + "[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \"127.0.0.1:1143\"\n\n[[server]]\n" + tt.block
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
// Nor did it check what start-up checked only as it set up services (#921): the
// [relay.queue] durations, [cluster] addr and secret_key, and the [database] and [s3]
// a node's servers need; nor [uploader] max_staging_size, the [s3] keys, the [database]
// durations and [tls] (#1092, #1095, #1104, #1105).
func TestConfigValidateRefusesWhatStartupRefuses(t *testing.T) {
	const imapBackend = "\n[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \"127.0.0.1:143\"\n"
	const imapProxy = "\n[[server]]\ntype = \"imap_proxy\"\nname = \"imap-proxy\"\naddr = \"127.0.0.1:1143\"\n"
	const proxyProtocolImap = "\n[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \"127.0.0.1:143\"\nproxy_protocol = true\n"
	const remoteLookup = "remote_addrs = [\"192.0.2.10:143\"]\n\n[server.remote_lookup]\nenabled = true\n"
	const metrics = "\n[[server]]\ntype = \"metrics\"\nname = \"metrics\"\naddr = \"127.0.0.1:9090\"\npath = \"/metrics\"\n"
	const userAPI = "\n[[server]]\ntype = \"http_user_api\"\nname = \"user-api\"\naddr = \"127.0.0.1:8081\"\njwt_secret = \"secret\"\n"
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
			content: storageTOML + "[servers]\ntrusted_networks = [\"192.0.2.10\"]\n" + proxyProtocolImap,
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
			// The issue's file: every proxy refuses to be built without backends (#1038).
			name:    "proxy without remote_addrs or [[pool]] blocks",
			content: imapProxy + "\n[server.remote_lookup]\nenabled = true\nurl = \"https://lookup.example.com/lookup?email=$email\"\n",
			wantErr: []string{"[FAIL] server 'imap-proxy':\n   remote_addrs is required unless the file declares [[pool]] blocks"},
		},
		{
			// The issue's file: the proxy was built with "" as a backend (#1147).
			name: "proxy with an empty remote_addrs entry",
			content: imapProxy + "remote_addrs = [\"\"]\nremote_port = 143\n" +
				"\n[server.remote_lookup]\nenabled = true\nurl = \"https://lookup.example.com/lookup?email=$email\"\n",
			wantErr: []string{"[FAIL] server 'imap-proxy':\n   server \"imap-proxy\": remote_addrs #1: empty backend address"},
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
			content: storageTOML + "[uploader]\nconcurrency = 0\n" + imapProxy + "remote_addrs = [\"192.0.2.10:143\"]\n",
		},
		{
			// The issue's file: the relay worker runs on any node with [relay].
			name: "relay.queue circuit_breaker_timeout unparsable",
			content: "[relay]\ntype = \"smtp\"\nsmtp_host = \"smtp.example.com:587\"\n\n[relay.queue]\npath = \"/tmp/relay\"\ncircuit_breaker_timeout = \"soon\"\n" +
				metrics,
			wantErr: []string{`invalid circuit_breaker_timeout "soon"`},
		},
		{
			name:    "relay.queue cleanup_interval unparsable",
			content: "[relay]\ntype = \"smtp\"\nsmtp_host = \"smtp.example.com:587\"\n\n[relay.queue]\ncleanup_interval = \"hourly\"\n" + metrics,
			wantErr: []string{`invalid cleanup_interval "hourly"`},
		},
		{
			name:    "cluster addr 0.0.0.0",
			content: "[cluster]\nenabled = true\naddr = \"0.0.0.0:7946\"\n" + metrics,
			wantErr: []string{"cluster addr '0.0.0.0' must be a specific IP address reachable from other nodes"},
		},
		{
			name:    "cluster secret_key of 16 bytes",
			content: "[cluster]\nenabled = true\naddr = \"10.10.10.40:7946\"\nsecret_key = \"MDEyMzQ1Njc4OWFiY2RlZg==\"\n" + metrics,
			wantErr: []string{"cluster secret_key must be 32 bytes (got 16 bytes)"},
		},
		{
			name:    "cluster",
			content: "[cluster]\nenabled = true\naddr = \"10.10.10.40:7946\"\nsecret_key = \"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=\"\n" + metrics,
		},
		{
			// memberlist cannot bind it: "bind: invalid argument".
			name:    "cluster port out of range",
			content: "[cluster]\nenabled = true\naddr = \"10.10.10.40\"\nport = 70000\nsecret_key = \"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=\"\n" + metrics,
			wantErr: []string{"cluster port 70000 is not a valid port"},
		},

		{name: "cluster port overflow", content: "[cluster]\nenabled = true\naddr = \"[2001:db8::40]:999999999999999999999999999999\"\nsecret_key = \"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=\"\n" + metrics, wantErr: []string{`cluster port "999999999999999999999999999999" is not a valid port`}},
		{
			name:    "mail backend without database and S3",
			content: imapBackend,
			wantErr: []string{`server "imap" (imap) needs the database`, "bucket is required"},
		},
		{
			// Start-up opens no write pool and stops with "no healthy database pools
			// available" (#1266).
			name:    "managesieve with only [database.read] hosts",
			content: "[database.read]\nhosts = [\"replica.example.com\"]\n\n[[server]]\ntype = \"managesieve\"\nname = \"managesieve\"\naddr = \"127.0.0.1:4190\"\n",
			wantErr: []string{"[FAIL] [database.write]:\n   server \"managesieve\" (managesieve) needs the database, but [database.write] has no hosts"},
		},
		{
			name:    "mail backend with an S3 timeout without a unit",
			content: storageTOML + "timeout = \"30\"\n" + imapBackend,
			wantErr: []string{`invalid timeout "30"`},
		},
		{
			name:    "User API with part of [s3]",
			content: "[database.write]\nhosts = [\"db.example.com\"]\n\n[s3]\nbucket = \"mail\"\n" + userAPI,
			wantErr: []string{"endpoint is required"},
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
			// The file of #1092: the server exits on it as it starts the upload worker.
			name:    "uploader max_staging_size unparsable on a mail backend",
			content: storageTOML + "[uploader]\nmax_staging_size = \"100 gigs\"\n" + imapBackend,
			wantErr: []string{"[uploader] max_staging_size: invalid size format: '100 gigs'"},
		},
		{
			// The files of #1095: storage set-up refused them.
			name:    "s3 encryption_key not hex",
			content: storageTOML + "encrypt = true\nencryption_key = \"not-hex\"\n" + imapBackend,
			wantErr: []string{"[FAIL] [s3]:\n   encryption_key must be 64 hex characters"},
		},
		{
			name:    "s3 access_key without secret_key",
			content: storageTOML + "access_key = \"AKIAEXAMPLE\"\n" + imapBackend,
			wantErr: []string{"[FAIL] [s3]:\n   access_key and secret_key must be set together"},
		},
		{
			// The files of #1104: start-up stopped with "no healthy database pools
			// available", which does not name the key.
			name: "database.write max_conn_lifetime unparsable",
			content: "[database.write]\nhosts = [\"localhost\"]\nuser = \"postgres\"\nname = \"sora_mail_db\"\nmax_conn_lifetime = \"an hour\"\n" +
				"\n[[server]]\ntype = \"managesieve\"\nname = \"managesieve\"\naddr = \"127.0.0.1:4190\"\n",
			wantErr: []string{"[FAIL] [database.write]:\n   invalid max_conn_lifetime \"an hour\""},
		},
		{
			name: "database migration_timeout unparsable",
			content: "[database]\nmigration_timeout = \"soon\"\n\n[database.write]\nhosts = [\"localhost\"]\n" +
				"\n[[server]]\ntype = \"managesieve\"\nname = \"managesieve\"\naddr = \"127.0.0.1:4190\"\n",
			wantErr: []string{"[FAIL] [database]:\n   invalid migration_timeout \"soon\""},
		},
		{
			// The files of #1105: the TLS manager refused them after every other service.
			name:    "tls letsencrypt without email",
			content: "[tls]\nenabled = true\nprovider = \"letsencrypt\"\n\n[tls.letsencrypt]\ndomains = [\"mail.example.com\"]\n" + metrics,
			wantErr: []string{"[FAIL] [tls]:\n   letsencrypt.email is required"},
		},
		{
			name:    "tls provider unknown",
			content: "[tls]\nenabled = true\nprovider = \"acme\"\n" + metrics,
			wantErr: []string{"[FAIL] [tls]:\n   unknown TLS provider: acme (must be 'file' or 'letsencrypt')"},
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

// validateSections returns the sections Config.Validate reports problems under, read
// from its source: the string literals it passes to add. A label that names neither a
// table ("[s3]") nor a key ("trusted_networks"), such as "servers", is about the
// [[server]] blocks.
func validateSections(t *testing.T) []string {
	t.Helper()
	path := filepath.Join("..", "..", "config", "config.go")
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	var sections []string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Validate" || fn.Recv == nil || len(fn.Recv.List) != 1 {
			continue
		}
		star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		if recv, ok := star.X.(*ast.Ident); !ok || recv.Name != "Config" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			if fun, ok := call.Fun.(*ast.Ident); !ok || fun.Name != "add" {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			section, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(section, "[") && (strings.Contains(section, " ") || !strings.Contains(section, "_")) {
				section = "[[server]]"
			}
			if !seen[section] {
				seen[section] = true
				sections = append(sections, section)
			}
			return true
		})
	}
	return sections
}

// TestConfigValidateHelpNamesWhatItChecks (#1425): `config validate --help` names every
// section the command checks (Config.Validate, read from its source, so a check added
// there cannot be left out of the help), and does not say the database and S3 settings
// are left to service start: the command refuses them (TestConfigValidateRefusesWhatStartupRefuses).
func TestConfigValidateHelpNamesWhatItChecks(t *testing.T) {
	sections := validateSections(t)
	for _, want := range []string{"[[server]]", "[database]", "[s3]", "[tls]"} {
		if !strings.Contains(strings.Join(sections, " "), want) {
			t.Fatalf("read %q from Config.Validate, which lacks %s: is the parse still right?", sections, want)
		}
	}
	help := captureStdout(t, func() error {
		printConfigValidateUsage()
		return nil
	})
	for _, section := range sections {
		if !strings.Contains(help, section) {
			t.Errorf("the help does not name %s, which config validate checks", section)
		}
	}
	flat := strings.Join(strings.Fields(help), " ")
	for _, stale := range []string{"does not check required database/S3 settings", "S3 timeout"} {
		if strings.Contains(flat, stale) {
			t.Errorf("the help says %q, but config validate checks the database and S3 settings and the S3 timeout:\n%s", stale, help)
		}
	}
	for _, left := range []string{"connectivity", "disk"} {
		if !strings.Contains(flat, left) {
			t.Errorf("the help does not say %s is left to service start:\n%s", left, help)
		}
	}
}

// TestConfigValidateHelpStartChecksNoS3 (#1425): what the help says service start checks
// must not include S3 or a remote lookup. Start-up builds the S3 client
// (storage.New) and the remote lookup client (NewHTTPRemoteLookupClient) without a
// request to either; only the health monitor reaches them, after start. An operator told
// otherwise takes a clean start as proof that a mistyped S3 endpoint works.
func TestConfigValidateHelpStartChecksNoS3(t *testing.T) {
	help := captureStdout(t, func() error {
		printConfigValidateUsage()
		return nil
	})
	var found bool
	for _, paragraph := range strings.Split(help, "\n\n") {
		flat := strings.Join(strings.Fields(paragraph), " ")
		for _, sentence := range strings.Split(flat, ". ") {
			if !strings.Contains(strings.ToLower(sentence), "services start") {
				continue
			}
			found = true
			for _, unchecked := range []string{"S3", "remote lookup"} {
				if strings.Contains(sentence, unchecked) {
					t.Errorf("the help says service start checks %s, which start-up does not reach: %q", unchecked, sentence)
				}
			}
		}
	}
	if !found {
		t.Errorf("the help does not say what service start checks:\n%s", help)
	}
}

// TestConfigValidateReportsStartupWarnings (#1557): `sora-admin config validate` prints
// the warnings start-up logs about the file: a key the server type does not read
// (ServerConfig.WarnUnusedConfigOptions) and an imap or pop3 session_memory_limit below
// an lmtp max_message_size (Config.SessionMemoryShortfalls). It used to print only
// "[OK] Configuration is valid!". Warnings do not fail the file.
func TestConfigValidateReportsStartupWarnings(t *testing.T) {
	const lmtp = "\n[[server]]\ntype = \"lmtp\"\nname = \"lmtp\"\naddr = \"127.0.0.1:24\"\nmax_message_size = \"50mb\"\n"
	tests := []struct {
		name     string
		content  string
		wantWarn []string // substrings of the [WARN] lines, none for a file without warnings
	}{
		{
			// The issue's file.
			name:     "debug on pop3",
			content:  storageTOML + "[[server]]\ntype = \"pop3\"\nname = \"pop3\"\naddr = \"127.0.0.1:110\"\ndebug = true\n",
			wantWarn: []string{"[WARN] Server pop3 (type: pop3) has 'debug' configured, but only "},
		},
		{
			name: "lookup_cache key on a proxy that does not read it",
			content: storageTOML + "[[server]]\ntype = \"lmtp_proxy\"\nname = \"lmtp-proxy\"\naddr = \"127.0.0.1:2424\"\n" +
				"remote_addrs = [\"192.0.2.10:24\"]\n\n[server.lookup_cache]\npositive_revalidation_window = \"1m\"\n",
			wantWarn: []string{"[WARN] Server lmtp-proxy (type: lmtp_proxy) has 'lookup_cache.positive_revalidation_window' configured, but only "},
		},
		{
			name: "imap session_memory_limit below the lmtp max_message_size",
			content: storageTOML + "[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \"127.0.0.1:143\"\n\n[server.limits]\nsession_memory_limit = \"10mb\"\n" +
				lmtp,
			wantWarn: []string{"[WARN] Server imap (type: imap) has session_memory_limit 10485760 bytes, below max_message_size 52428800 bytes of lmtp server lmtp"},
		},
		{
			name:    "no warnings",
			content: storageTOML + "[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \"127.0.0.1:143\"\n" + lmtp,
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
			if err != nil {
				t.Fatalf("config validate failed a valid file (warnings must not fail it): %v\n%s", err, out)
			}
			if !strings.Contains(string(out), "[OK] Configuration is valid!") {
				t.Errorf("config validate did not report the file valid:\n%s", out)
			}
			for _, want := range tt.wantWarn {
				if !strings.Contains(string(out), want) {
					t.Errorf("config validate output does not warn %q:\n%s", want, out)
				}
			}
			if len(tt.wantWarn) == 0 && strings.Contains(string(out), "[WARN]") {
				t.Errorf("config validate warned about a file without warnings:\n%s", out)
			}
		})
	}
}

// TestConfigValidateReportsFileOnlyStartupWarnings (#1605): `sora-admin config validate`
// prints the other warnings start-up logs about the file alone: enable_affinity and
// per-user proxy limits without [cluster], a User API without [s3], an Admin API
// without an upload worker, a proxy without a database (backend maintenance), the
// [relay] transport, and every value start-up cannot parse and replaces with its
// default. It used to print "[OK] Configuration is valid!" and none of them. Each file
// must still pass, and a file that does not cause a warning at start-up must not get
// one here either.
func TestConfigValidateReportsFileOnlyStartupWarnings(t *testing.T) {
	const (
		imap        = "[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \"127.0.0.1:143\"\n\n"
		imapProxy   = "[[server]]\ntype = \"imap_proxy\"\nname = \"imap-proxy\"\naddr = \"127.0.0.1:1143\"\nremote_addrs = [\"192.0.2.10:143\"]\n"
		cluster     = "[cluster]\nenabled = true\naddr = \"192.0.2.1:7946\"\nnode_id = \"node-1\"\nsecret_key = \"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\"\n\n"
		dbOnly      = "[database.write]\nhosts = [\"db.example.com\"]\n\n"
		adminAPI    = "[[server]]\ntype = \"http_admin_api\"\nname = \"admin-api\"\naddr = \"127.0.0.1:8080\"\napi_key = \"key\"\n\n"
		userAPI     = "[[server]]\ntype = \"http_user_api\"\nname = \"user-api\"\naddr = \"127.0.0.1:8081\"\njwt_secret = \"secret\"\n\n"
		userAPIPrxy = "[[server]]\ntype = \"user_api_proxy\"\nname = \"user-api-proxy\"\naddr = \"127.0.0.1:8082\"\nremote_addrs = [\"192.0.2.10:8081\"]\n"
	)
	tests := []struct {
		name     string
		content  string
		wantWarn []string // prefixes of [WARN] lines; none for a file start-up does not warn about
	}{
		{
			// The issue's file.
			name: "affinity, per-user limits and a search window on a node without [cluster]",
			content: storageTOML + imapProxy + "enable_affinity = true\nmax_connections_per_user = 5\n\n" +
				imap + "[server.limits]\nsearch_rate_limit_window = \"bogus\"\n",
			wantWarn: []string{
				"[WARN] Server imap-proxy (type: imap_proxy) has 'enable_affinity' configured, but it has no effect without [cluster] and [cluster.affinity] enabled",
				"[WARN] Server imap-proxy (type: imap_proxy) has 'max_connections_per_user' configured, but per-user connection limits are not applied without [cluster]",
				"[WARN] Server imap (type: imap) has an invalid 'limits.search_rate_limit_window', start-up uses the default",
			},
		},
		{
			name:     "enable_affinity with [cluster.affinity] disabled",
			content:  storageTOML + cluster + "[cluster.affinity]\nenabled = false\n\n" + imapProxy + "enable_affinity = true\n",
			wantWarn: []string{"[WARN] Server imap-proxy (type: imap_proxy) has 'enable_affinity' configured, but it has no effect without [cluster] and [cluster.affinity] enabled"},
		},
		{
			name: "per-user limits on pop3 and managesieve proxies without [cluster]",
			content: storageTOML +
				"[[server]]\ntype = \"pop3_proxy\"\nname = \"pop3-proxy\"\naddr = \"127.0.0.1:1110\"\nremote_addrs = [\"192.0.2.10:110\"]\nmax_connections_per_user_per_ip = 2\n\n" +
				"[[server]]\ntype = \"managesieve_proxy\"\nname = \"sieve-proxy\"\naddr = \"127.0.0.1:4190\"\nremote_addrs = [\"192.0.2.10:4190\"]\nmax_connections_per_user = 3\n",
			wantWarn: []string{
				"[WARN] Server pop3-proxy (type: pop3_proxy) has 'max_connections_per_user_per_ip' configured, but per-user connection limits are not applied without [cluster]",
				"[WARN] Server sieve-proxy (type: managesieve_proxy) has 'max_connections_per_user' configured, but per-user connection limits are not applied without [cluster]",
			},
		},
		{
			name:     "User API without [s3]",
			content:  dbOnly + userAPI,
			wantWarn: []string{"[WARN] User API: no [s3] configured on this node; message bodies (/user/messages/{id}/body and /raw) cannot be served"},
		},
		{
			name:     "Admin API on a node without a mail backend",
			content:  dbOnly + adminAPI,
			wantWarn: []string{"[WARN] Server admin-api (type: http_admin_api): no upload worker on this node (no imap, pop3 or lmtp server), POST /admin/mail/deliver will answer 503"},
		},
		{
			name:     "proxy on a node without a database",
			content:  userAPIPrxy + "jwt_secret = \"secret\"\n",
			wantWarn: []string{"[WARN] Backend maintenance is not honored on this node: proxies read the maintenance list from the database"},
		},
		{
			name:     "relay in plaintext to a non-loopback host",
			content:  storageTOML + "[relay]\ntype = \"smtp\"\nsmtp_host = \"relay.example.com:25\"\nsmtp_tls = false\n\n" + imap,
			wantWarn: []string{"[WARN] [relay] smtp_tls = false: mail is relayed in plaintext to a non-loopback host"},
		},
		{
			name:     "relay without certificate verification",
			content:  storageTOML + "[relay]\ntype = \"smtp\"\nsmtp_host = \"relay.example.com:465\"\nsmtp_tls_verify = false\n\n" + imap,
			wantWarn: []string{"[WARN] [relay] smtp_tls_verify = false: the relay's TLS certificate is not verified"},
		},
		{
			name: "[[server]] values start-up replaces with the default",
			content: storageTOML +
				imap + "[server.limits]\nsession_memory_limit = \"100 megabytes\"\npreview_s3_max_size = \"5 megabytes\"\n" +
				"[server.timeouts.imap_command_timeouts]\nsearch = \"1 min\"\n\n" +
				"[[server]]\ntype = \"pop3\"\nname = \"pop3\"\naddr = \"127.0.0.1:110\"\n[server.limits]\nsession_memory_limit = \"1 gigabyte\"\n" +
				"[server.timeouts.pop3_command_timeouts]\nretr = \"1 min\"\n\n" +
				"[[server]]\ntype = \"managesieve\"\nname = \"sieve\"\naddr = \"127.0.0.1:4190\"\n" +
				"[server.timeouts.managesieve_command_timeouts]\nputscript = \"10 sec\"\n\n" +
				"[[server]]\ntype = \"lmtp\"\nname = \"lmtp\"\naddr = \"127.0.0.1:24\"\n[server.limits]\nredirect_rate_window = \"1 h\"\n" +
				"[server.timeouts.lmtp_command_timeouts]\ndata = \"1 min\"\n\n" +
				adminAPI + "[server.limits]\nredirect_rate_window = \"1 h\"\n\n" +
				imapProxy + "remote_dns_refresh = \"-1m\"\n\n" +
				userAPIPrxy + "jwt_secret = \"secret\"\nremote_dns_refresh = \"5 min\"\n",
			wantWarn: []string{
				"[WARN] Server imap (type: imap) has an invalid 'limits.session_memory_limit', start-up uses the default",
				"[WARN] Server imap (type: imap) has an invalid 'limits.preview_s3_max_size', start-up uses the default",
				"[WARN] Server imap (type: imap) has an invalid 'timeouts.imap_command_timeouts', start-up uses the default",
				"[WARN] Server pop3 (type: pop3) has an invalid 'limits.session_memory_limit', start-up uses the default",
				"[WARN] Server pop3 (type: pop3) has an invalid 'timeouts.pop3_command_timeouts', start-up uses the default",
				"[WARN] Server sieve (type: managesieve) has an invalid 'timeouts.managesieve_command_timeouts', start-up uses the default",
				"[WARN] Server lmtp (type: lmtp) has an invalid 'limits.redirect_rate_window', start-up uses the default",
				"[WARN] Server lmtp (type: lmtp) has an invalid 'timeouts.lmtp_command_timeouts', start-up uses the default",
				"[WARN] Server admin-api (type: http_admin_api) has an invalid 'limits.redirect_rate_window', start-up uses the default",
				"[WARN] Server imap-proxy (type: imap_proxy) has an invalid 'remote_dns_refresh', start-up uses the default",
				"[WARN] Server user-api-proxy (type: user_api_proxy) has an invalid 'remote_dns_refresh', start-up uses the default",
			},
		},
		{
			name: "section values start-up replaces with the default",
			content: storageTOML + cluster + "[cluster.affinity]\nttl = \"a day\"\ncleanup_interval = \"hourly\"\n\n" +
				"[backend_maintenance]\npoll_interval = \"0s\"\nrefuse_after = \"30 sec\"\n\n" +
				"[relay]\ntype = \"smtp\"\nsmtp_host = \"127.0.0.1:25\"\n\n[relay.queue]\nretry_backoff = [\"1m\", \"5 min\"]\nworker_interval = \"1 min\"\n\n" +
				imap + imapProxy,
			wantWarn: []string{
				"[WARN] [cluster.affinity] has an invalid 'ttl', start-up uses the default",
				"[WARN] [cluster.affinity] has an invalid 'cleanup_interval', start-up uses the default",
				"[WARN] [backend_maintenance] has an invalid 'poll_interval', start-up uses the default",
				"[WARN] [backend_maintenance] has an invalid 'refuse_after', start-up uses the default",
				"[WARN] [relay.queue] has an invalid 'retry_backoff', start-up uses the default",
				"[WARN] [relay.queue] has an invalid 'worker_interval', start-up uses the default",
			},
		},
		{
			// [cluster] and [cluster.affinity] serve enable_affinity and the per-user
			// limits; [s3] the User API's bodies; the imap server an upload worker for the
			// Admin API and a database for the proxies; a relay on loopback or with a
			// verified certificate is not exposed.
			name: "every part the warnings ask for",
			content: storageTOML + cluster + imap + imapProxy + "enable_affinity = true\nmax_connections_per_user = 5\nmax_connections_per_user_per_ip = 2\n\n" +
				"[relay]\ntype = \"smtp\"\nsmtp_host = \"relay.example.com:465\"\n\n" +
				adminAPI + userAPI + userAPIPrxy + "jwt_secret = \"secret\"\n",
		},
		{
			name:    "plaintext relay on loopback",
			content: storageTOML + "[relay]\ntype = \"smtp\"\nsmtp_host = \"127.0.0.1:25\"\nsmtp_tls = false\n\n" + imap,
		},
		{
			// Start-up reads [cluster.affinity] only with [cluster], [backend_maintenance]
			// poll_interval only with a proxy, and [relay.queue] only with [relay]. It leaves
			// out an Admin API without api_key, and so parses nothing of its.
			name: "values start-up does not read",
			content: storageTOML + "[cluster.affinity]\nttl = \"a day\"\n\n[backend_maintenance]\npoll_interval = \"5 sec\"\n\n" +
				"[relay.queue]\nworker_interval = \"1 min\"\n\n" + imap +
				"[[server]]\ntype = \"http_admin_api\"\nname = \"admin-api\"\naddr = \"127.0.0.1:8080\"\n[server.limits]\nredirect_rate_window = \"1 h\"\n",
		},
		{
			// Nor does it start a User API proxy without jwt_secret.
			name:    "User API proxy without jwt_secret",
			content: storageTOML + imap + userAPIPrxy + "remote_dns_refresh = \"5 min\"\n",
		},
		{
			// Without a mail backend start-up runs no upload worker and so no backend
			// maintenance report, which is what reads refuse_after.
			name:    "refuse_after on a proxy-only node",
			content: storageTOML + "[backend_maintenance]\nrefuse_after = \"30 sec\"\n\n" + imapProxy,
		},
		{
			// The [[server]] values the config getters and the servers' constructors
			// replace with the default, each on a server type that reads it.
			name: "[[server]] values the servers replace with the default",
			content: storageTOML + "[servers]\ntrusted_networks = [\"192.0.2.0/24\"]\n\n" +
				"[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \"127.0.0.1:143\"\nappend_limit = \"lots\"\nauth_idle_timeout = \"soon\"\n" +
				"proxy_protocol = true\nproxy_protocol_timeout = \"0s\"\n" +
				"[server.timeouts]\ncommand_timeout = \"soon\"\nabsolute_session_timeout = \"a day\"\n" +
				"[server.lookup_cache]\npositive_ttl = \"a while\"\npositive_revalidation_window = \"a moment\"\n\n" +
				"[[server]]\ntype = \"managesieve\"\nname = \"sieve\"\naddr = \"127.0.0.1:4190\"\nmax_script_size = \"lots\"\n\n" +
				"[[server]]\ntype = \"lmtp\"\nname = \"lmtp\"\naddr = \"127.0.0.1:24\"\nmax_message_size = \"lots\"\n\n" +
				imapProxy + "connect_timeout = \"soon\"\n\n" +
				userAPI + "token_duration = \"a while\"\n",
			wantWarn: []string{
				"[WARN] Server imap (type: imap) has an invalid 'append_limit', start-up uses the default",
				"[WARN] Server imap (type: imap) has an invalid 'auth_idle_timeout', start-up uses the default",
				"[WARN] Server imap (type: imap) has an invalid 'proxy_protocol_timeout', start-up uses the default",
				"[WARN] Server imap (type: imap) has an invalid 'timeouts.command_timeout', start-up uses the default",
				"[WARN] Server imap (type: imap) has an invalid 'timeouts.absolute_session_timeout', start-up uses the default",
				"[WARN] Server imap (type: imap) has an invalid 'lookup_cache.positive_ttl', start-up uses the default",
				"[WARN] Server imap (type: imap) has an invalid 'lookup_cache.positive_revalidation_window', start-up uses the default",
				"[WARN] Server sieve (type: managesieve) has an invalid 'max_script_size', start-up uses the default",
				"[WARN] Server lmtp (type: lmtp) has an invalid 'max_message_size', start-up uses the default",
				"[WARN] Server imap-proxy (type: imap_proxy) has an invalid 'connect_timeout', start-up uses the default",
				"[WARN] Server user-api (type: http_user_api) has an invalid 'token_duration', start-up uses the default",
			},
		},
		{
			// GetMaxMessageSize caps max_message_size at the largest message Sora can store.
			name: "max_message_size above the largest message Sora stores",
			content: storageTOML + "[[server]]\ntype = \"lmtp\"\nname = \"lmtp\"\naddr = \"127.0.0.1:24\"\nmax_message_size = \"4gb\"\n\n" +
				adminAPI + "max_message_size = \"4gb\"\n",
			wantWarn: []string{
				"[WARN] Server lmtp (type: lmtp) has max_message_size 4294967296 bytes, above the largest message Sora can store: start-up uses 2147483647",
				"[WARN] Server admin-api (type: http_admin_api) has max_message_size 4294967296 bytes, above the largest message Sora can store: start-up uses 2147483647",
			},
		},
		{
			// The section values a mail backend's workers, its IMAP server, the auth cache,
			// the database connection and spam training replace with the default (spam
			// training is left out instead).
			name: "section values a mail backend replaces with the default",
			content: "[database]\nlock_timeout = \"soon\"\nquery_timeout = \"soon\"\nsearch_timeout = \"soon\"\nwrite_timeout = \"soon\"\n\n" +
				"[database.write]\nhosts = [\"db.example.com\"]\nquery_timeout = \"soon\"\n\n" +
				"[s3]\nendpoint = \"s3.example.com\"\nbucket = \"mail\"\n\n" +
				"[local_cache]\ncapacity = \"huge\"\nmax_object_size = \"huge\"\npurge_interval = \"often\"\norphan_cleanup_age = \"old\"\n" +
				"metrics_interval = \"often\"\nmetrics_retention = \"long\"\nwarmup_timeout = \"0s\"\nwarmup_interval = \"daily\"\n\n" +
				"[cleanup]\ngrace_period = \"two weeks\"\nwake_interval = \"hourly\"\nmax_age_restriction = \"a year\"\nfts_retention = \"forever\"\n" +
				"health_status_retention = \"a month\"\ninstance_liveness_threshold = \"a week\"\npurge_poll_interval = \"often\"\n\n" +
				"[uploader]\nretry_interval = \"soon\"\n\n" +
				"[auth_cache]\nenabled = true\nmax_age = \"a day\"\npurge_unused = \"a week\"\ncleanup_interval = \"hourly\"\n\n" +
				"[spam_training]\nenabled = true\nendpoint = \"https://spam.example.com/train\"\ntimeout = \"soon\"\nmax_message_size = \"0\"\n\n" +
				"[spam_training.circuit_breaker]\ntimeout = \"soon\"\n\n" + imap,
			wantWarn: []string{
				"[WARN] [local_cache] has an invalid 'capacity', start-up uses the default",
				"[WARN] [local_cache] has an invalid 'max_object_size', start-up uses the default",
				"[WARN] [local_cache] has an invalid 'purge_interval', start-up uses the default",
				"[WARN] [local_cache] has an invalid 'orphan_cleanup_age', start-up uses the default",
				"[WARN] [local_cache] has an invalid 'metrics_interval', start-up uses the default",
				"[WARN] [local_cache] has an invalid 'metrics_retention', start-up uses the default",
				"[WARN] [local_cache] has an invalid 'warmup_timeout', start-up uses the default",
				"[WARN] [local_cache] has an invalid 'warmup_interval', start-up uses the default",
				"[WARN] [cleanup] has an invalid 'grace_period', start-up uses the default",
				"[WARN] [cleanup] has an invalid 'wake_interval', start-up uses the default",
				"[WARN] [cleanup] has an invalid 'max_age_restriction', start-up uses the default",
				"[WARN] [cleanup] has an invalid 'fts_retention', start-up uses the default",
				"[WARN] [cleanup] has an invalid 'health_status_retention', start-up uses the default",
				"[WARN] [cleanup] has an invalid 'instance_liveness_threshold', start-up uses the default",
				"[WARN] [cleanup] has an invalid 'purge_poll_interval', start-up uses the default",
				"[WARN] [uploader] has an invalid 'retry_interval', start-up uses the default",
				"[WARN] [auth_cache] has an invalid 'max_age', start-up uses the default",
				"[WARN] [auth_cache] has an invalid 'purge_unused', start-up uses the default",
				"[WARN] [auth_cache] has an invalid 'cleanup_interval', start-up uses the default",
				"[WARN] [database] has an invalid 'lock_timeout', start-up uses the default",
				"[WARN] [database] has an invalid 'query_timeout', every query uses the default",
				"[WARN] [database] has an invalid 'search_timeout', every query uses the default",
				"[WARN] [database] has an invalid 'write_timeout', every query uses the default",
				"[WARN] [database.write] has an invalid 'query_timeout', every read uses the [database] query_timeout",
				"[WARN] [spam_training] has an invalid 'timeout', start-up runs without spam training",
				"[WARN] [spam_training] has an invalid 'max_message_size', start-up runs without spam training",
				"[WARN] [spam_training.circuit_breaker] has an invalid 'timeout', start-up runs without spam training",
			},
		},
		{
			// Without a mail backend start-up runs no cache, cleaner or upload worker,
			// without an imap server no warmup, and it leaves out a disabled auth cache and
			// spam training.
			name: "section values a proxy-only node does not read",
			content: storageTOML + "[local_cache]\ncapacity = \"huge\"\nwarmup_timeout = \"soon\"\n\n[cleanup]\ngrace_period = \"two weeks\"\n\n" +
				"[uploader]\nretry_interval = \"soon\"\n\n[auth_cache]\nenabled = false\nmax_age = \"a day\"\n\n" +
				"[spam_training]\nenabled = false\nendpoint = \"https://spam.example.com/train\"\ntimeout = \"soon\"\n\n" + imapProxy,
		},
		{
			// Nor the [database] values on a node that connects to no database.
			name:    "[database] values on a node without a database",
			content: "[database]\nlock_timeout = \"soon\"\nwrite_timeout = \"soon\"\n\n[[server]]\ntype = \"metrics\"\nname = \"metrics\"\naddr = \"127.0.0.1:9090\"\n",
		},
		{
			// A disabled lookup cache, a proxy whose remote lookup URL names $ip (it
			// caches nothing), and proxy_protocol_timeout without proxy_protocol.
			name: "[[server]] values the servers do not read",
			content: storageTOML + imap + "proxy_protocol_timeout = \"soon\"\n[server.lookup_cache]\nenabled = false\npositive_ttl = \"a while\"\n\n" +
				imapProxy + "[server.remote_lookup]\nenabled = true\nurl = \"https://lookup.example.com/lookup?user=$email&ip=$ip\"\n" +
				"[server.lookup_cache]\npositive_ttl = \"a while\"\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := configValidateOutput(t, tt.content)
			var warnings []string
			for _, line := range strings.Split(out, "\n") {
				if strings.HasPrefix(line, "[WARN]") {
					warnings = append(warnings, line)
				}
			}
			for _, want := range tt.wantWarn {
				found := false
				for _, line := range warnings {
					if strings.HasPrefix(line, want) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("config validate output does not warn %q:\n%s", want, out)
				}
			}
			if len(warnings) != len(tt.wantWarn) {
				t.Errorf("config validate printed %d [WARN] lines, want %d:\n%s", len(warnings), len(tt.wantWarn), out)
			}
		})
	}
}

// configValidateOutput runs `sora-admin config validate` on a file with content, in a
// process of its own, and returns its output. The file must pass.
func configValidateOutput(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestConfigValidateCommandHelper$")
	cmd.Env = append(os.Environ(), configValidateHelperEnv+"="+path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("config validate failed a valid file (warnings must not fail it): %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "[OK] Configuration is valid!") {
		t.Fatalf("config validate did not report the file valid:\n%s", out)
	}
	return string(out)
}
