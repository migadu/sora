package config

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// warningsFor returns the startup warnings WarnUnusedConfigOptions logs for s.
func warningsFor(s ServerConfig) []string {
	var warnings []string
	s.WarnUnusedConfigOptions(func(format string, args ...any) {
		warnings = append(warnings, fmt.Sprintf(format, args...))
	})
	return warnings
}

// The HTTP servers count no connections per user, and only the User API proxy counts
// them per client address (#697). The metrics listener counts none at all. A block
// that sets a limit its server does not apply is told so at startup; a limit the
// server applies is not warned about.
func TestWarnUnusedConfigOptions_HTTPConnectionLimits(t *testing.T) {
	limits := []struct {
		key string
		set func(*ServerConfig)
	}{
		{"max_connections", func(s *ServerConfig) { s.MaxConnections = 100 }},
		{"max_connections_per_ip", func(s *ServerConfig) { s.MaxConnectionsPerIP = 2 }},
		{"max_connections_per_user", func(s *ServerConfig) { s.MaxConnectionsPerUser = 3 }},
		{"max_connections_per_user_per_ip", func(s *ServerConfig) { s.MaxConnectionsPerUserPerIP = 1 }},
	}
	applied := map[string][]string{
		"metrics":        nil,
		"http_admin_api": {"max_connections"},
		"http_user_api":  {"max_connections"},
		"user_api_proxy": {"max_connections", "max_connections_per_ip"},
	}
	for serverType, appliedKeys := range applied {
		for _, limit := range limits {
			t.Run(serverType+" "+limit.key, func(t *testing.T) {
				s := ServerConfig{Type: serverType, Name: "server-697"}
				limit.set(&s)
				warnings := warningsFor(s)
				if slices.Contains(appliedKeys, limit.key) {
					if len(warnings) > 0 {
						t.Errorf("%s applies '%s' but it was warned about: %v", serverType, limit.key, warnings)
					}
					return
				}
				if len(warnings) != 1 || !strings.Contains(warnings[0], "'"+limit.key+"'") || !strings.Contains(warnings[0], "server-697") {
					t.Errorf("want one warning naming '%s' on server-697, got %v", limit.key, warnings)
				}
			})
		}
	}
}

// allowed_hosts is enforced by the metrics listener and the Admin and User APIs only.
// Every other server type, the User API proxy included, serves every client whatever
// the list says, so a block that sets it is told so at startup (#708).
func TestWarnUnusedConfigOptions_AllowedHostsOnlyOnHTTPServers(t *testing.T) {
	enforcing := []string{"metrics", "http_admin_api", "http_user_api"}
	for _, serverType := range ServerTypes {
		t.Run(serverType, func(t *testing.T) {
			s := ServerConfig{Type: serverType, Name: "server-708", AllowedHosts: []string{"192.0.2.10", "10.0.0.0/8"}}
			warnings := warningsFor(s)
			if slices.Contains(enforcing, serverType) {
				if len(warnings) > 0 {
					t.Errorf("%s enforces 'allowed_hosts' but it was warned about: %v", serverType, warnings)
				}
				return
			}
			if len(warnings) != 1 || !strings.Contains(warnings[0], "'allowed_hosts'") || !strings.Contains(warnings[0], "server-708") {
				t.Errorf("want one warning naming 'allowed_hosts' on server-708, got %v", warnings)
			}
		})
	}

	// An empty list restricts nothing on any server type: nothing to warn about.
	if warnings := warningsFor(ServerConfig{Type: "user_api_proxy", Name: "server-708", AllowedHosts: []string{}}); len(warnings) > 0 {
		t.Errorf("an empty allowed_hosts was warned about: %v", warnings)
	}
}

// Keys only some server types read (#908, #1081): listen_backlog by the mail servers
// and proxies (the HTTP servers listen with the kernel's default backlog), the API
// keys, the User API's JWT and CORS keys, the metrics listener's path and collection
// settings, and the protocol, login and backend keys the start functions in
// cmd/sora/main.go pass to some servers only. Each one set on any other type is
// reported at startup, naming the key and the server; on a type that reads it,
// nothing is reported.
func TestWarnUnusedConfigOptions_KeysOnlySomeServerTypesRead(t *testing.T) {
	mailServers := []string{"imap", "lmtp", "pop3", "managesieve", "imap_proxy", "pop3_proxy", "managesieve_proxy", "lmtp_proxy"}
	userAPI := []string{"http_user_api", "user_api_proxy"}
	metricsOnly := []string{"metrics"}
	imapOnly := []string{"imap"}
	imapAndProxy := []string{"imap", "imap_proxy"}
	// The IMAP, POP3 and ManageSieve servers and proxies. The LMTP backend offers no
	// AUTH, so insecure_auth has nothing to allow there, and the HTTP User API's
	// login reads none of these keys.
	loginServers := []string{"imap", "pop3", "managesieve", "imap_proxy", "pop3_proxy", "managesieve_proxy"}
	proxies := []string{"imap_proxy", "pop3_proxy", "managesieve_proxy", "lmtp_proxy", "user_api_proxy"}
	// The LMTP backend's only timeout is timeouts.command_timeout.
	authIdle := []string{"imap", "pop3", "managesieve", "imap_proxy", "pop3_proxy", "managesieve_proxy", "lmtp_proxy"}
	// The POP3 and ManageSieve backends take debug and write nothing with it.
	debugReaders := []string{"imap", "lmtp", "imap_proxy", "pop3_proxy", "managesieve_proxy", "lmtp_proxy"}
	no, yes, n := false, true, 50
	keys := []struct {
		key    string
		set    func(*ServerConfig)
		readBy []string
	}{
		{"listen_backlog", func(s *ServerConfig) { s.ListenBacklog = 8192 }, mailServers},
		{"api_key", func(s *ServerConfig) { s.APIKey = "a-long-random-key-aaaaaaaaaaaaaaaa" }, []string{"metrics", "http_admin_api"}},
		{"read_only_api_key", func(s *ServerConfig) { s.ReadOnlyAPIKey = "a-long-random-key-bbbbbbbbbbbbbbbb" }, []string{"http_admin_api"}},
		{"jwt_secret", func(s *ServerConfig) { s.JWTSecret = "0123456789abcdef0123456789abcdef" }, userAPI},
		{"allowed_origins", func(s *ServerConfig) { s.AllowedOrigins = []string{"https://mail.example.com"} }, userAPI},
		{"token_duration", func(s *ServerConfig) { s.TokenDuration = "12h" }, []string{"http_user_api"}},
		{"token_issuer", func(s *ServerConfig) { s.TokenIssuer = "mail.example.com" }, []string{"http_user_api"}},
		{"path", func(s *ServerConfig) { s.Path = "/metrics" }, metricsOnly},
		{"enable_user_metrics", func(s *ServerConfig) { s.EnableUserMetrics = true }, metricsOnly},
		{"enable_domain_metrics", func(s *ServerConfig) { s.EnableDomainMetrics = &no }, metricsOnly},
		{"user_metrics_threshold", func(s *ServerConfig) { s.UserMetricsThreshold = &n }, metricsOnly},
		{"max_tracked_users", func(s *ServerConfig) { s.MaxTrackedUsers = &n }, metricsOnly},
		{"hash_usernames", func(s *ServerConfig) { s.HashUsernames = &no }, metricsOnly},

		// IMAP capabilities and the ID answer.
		{"client_filters", func(s *ServerConfig) {
			s.ClientFilters = []ClientCapabilityFilter{{ClientName: "^Mail$", DisableCaps: []string{"IDLE"}}}
		}, imapOnly},
		{"disabled_caps", func(s *ServerConfig) { s.DisabledCaps = []string{"IDLE"} }, imapOnly},
		{"enable_preview", func(s *ServerConfig) { s.EnablePreview = true }, imapOnly},
		{"additional_caps", func(s *ServerConfig) { s.AdditionalCaps = []string{"X-EXAMPLE"} }, imapAndProxy},
		{"id_name", func(s *ServerConfig) { s.IDName = "Example" }, imapAndProxy},
		{"id_version", func(s *ServerConfig) { s.IDVersion = "1.0" }, imapAndProxy},
		{"id_vendor", func(s *ServerConfig) { s.IDVendor = "Example Org" }, imapAndProxy},
		{"id_support_url", func(s *ServerConfig) { s.IDSupportURL = "https://example.com" }, imapAndProxy},

		// Logins. Only the backends limit the SASL master login by network.
		{"master_username", func(s *ServerConfig) { s.MasterUsername = "master" }, loginServers},
		{"master_password", func(s *ServerConfig) { s.MasterPassword = "secret" }, loginServers},
		{"master_sasl_username", func(s *ServerConfig) { s.MasterSASLUsername = "proxyuser" }, loginServers},
		{"master_sasl_password", func(s *ServerConfig) { s.MasterSASLPassword = "proxypass" }, loginServers},
		{"master_sasl_allowed_networks", func(s *ServerConfig) { s.MasterSASLAllowedNetworks = []string{"10.0.0.0/8"} }, []string{"imap", "pop3", "managesieve"}},
		{"insecure_auth", func(s *ServerConfig) { s.InsecureAuth = true }, loginServers},
		{"auth_idle_timeout", func(s *ServerConfig) { s.AuthIdleTimeout = "2m" }, authIdle},
		{"debug", func(s *ServerConfig) { s.Debug = true }, debugReaders},

		// The proxies' backend legs.
		{"remote_port", func(s *ServerConfig) { s.RemotePort = int64(143) }, proxies},
		{"connect_timeout", func(s *ServerConfig) { s.ConnectTimeout = "10s" }, proxies},
		{"remote_dns_refresh", func(s *ServerConfig) { s.RemoteDNSRefresh = "1m" }, proxies},
		{"remote_health_checks", func(s *ServerConfig) { s.RemoteHealthChecks = &yes }, proxies},
		{"enable_affinity", func(s *ServerConfig) { s.EnableAffinity = true }, proxies},
		{"remote_use_id_command", func(s *ServerConfig) { s.RemoteUseIDCommand = true }, []string{"imap_proxy"}},
		{"remote_use_xclient", func(s *ServerConfig) { s.RemoteUseXCLIENT = true }, []string{"pop3_proxy", "lmtp_proxy"}},
		{"remote_use_utf8", func(s *ServerConfig) { s.RemoteUseUTF8 = true }, []string{"pop3_proxy"}},

		// Size limits and the ManageSieve proxy's extensions.
		{"max_message_size", func(s *ServerConfig) { s.MaxMessageSize = "10mb" }, []string{"lmtp", "lmtp_proxy", "http_admin_api"}},
		{"append_limit", func(s *ServerConfig) { s.AppendLimit = "10mb" }, imapOnly},
		{"max_script_size", func(s *ServerConfig) { s.MaxScriptSize = "32kb" }, []string{"managesieve"}},
		{"supported_extensions", func(s *ServerConfig) { s.SupportedExtensions = []string{"vacation"} }, []string{"managesieve_proxy"}},
	}
	for _, k := range keys {
		for _, serverType := range ServerTypes {
			t.Run(k.key+"/"+serverType, func(t *testing.T) {
				s := ServerConfig{Type: serverType, Name: "server-908"}
				k.set(&s)
				var named []string
				for _, w := range warningsFor(s) {
					if strings.Contains(w, "'"+k.key+"'") {
						named = append(named, w)
					}
				}
				if slices.Contains(k.readBy, serverType) {
					if len(named) > 0 {
						t.Errorf("%s reads '%s' but it was warned about: %v", serverType, k.key, named)
					}
					return
				}
				if len(named) != 1 || !strings.Contains(named[0], "server-908") {
					t.Errorf("'%s' on %s (read by %v only): want one warning naming it on server-908, got %v", k.key, serverType, k.readBy, named)
				}
			})
		}
	}
}
