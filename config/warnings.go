package config

import (
	"fmt"
	"slices"
	"strings"
)

// Warnings returns the warnings start-up logs about the file alone, one line each, so
// that `sora-admin config validate` can print them before the file is deployed. Each is
// about a setting start-up accepts but that does not do on this node what it says:
//
//   - a [[server]] key the server type does not apply (ServerConfig.WarnUnusedConfigOptions);
//   - an imap or pop3 session_memory_limit below an lmtp max_message_size
//     (SessionMemoryShortfalls);
//   - a feature without the part of the node that serves it: enable_affinity without
//     [cluster] and [cluster.affinity], per-user proxy limits without [cluster], a User
//     API without [s3], an Admin API without an upload worker, and proxies without a
//     database to read backend maintenance from;
//   - a [relay] connection in plaintext or without certificate verification
//     (RelayConfig.TransportWarning);
//   - a value start-up cannot parse and replaces with its default: [server.limits]
//     search_rate_limit_window, session_memory_limit, preview_s3_max_size and
//     redirect_rate_window, the timeouts.*_command_timeouts tables, a proxy's
//     remote_dns_refresh, and [cluster.affinity], [backend_maintenance] and
//     [relay.queue] durations.
//
// Start-up logs each where the part that uses the setting starts, so a new start-up
// warning about the file belongs here as well. Warnings that depend on the host (its
// addresses, its name) are start-up's alone. Like start-up, Warnings assumes the file
// passes Validate.
func (c *Config) Warnings() []string {
	var warnings []string
	warn := func(format string, args ...any) {
		warnings = append(warnings, fmt.Sprintf(format, args...))
	}

	var proxy, userAPI bool
	servers := c.GetAllServers()
	for i := range servers {
		s := &servers[i]
		s.WarnUnusedConfigOptions(func(format string, args ...any) {
			warn("%s", strings.TrimPrefix(fmt.Sprintf(format, args...), "WARNING: "))
		})

		switch s.Type {
		case "imap_proxy", "pop3_proxy", "managesieve_proxy", "lmtp_proxy", "user_api_proxy":
			proxy = true
			// The cluster affinity manager serves enable_affinity; there is none
			// without [cluster], or with [cluster.affinity] enabled = false.
			if s.EnableAffinity && !(c.Cluster.Enabled && c.Cluster.Affinity.Enabled) {
				warn("Server %s (type: %s) has 'enable_affinity' configured, but it has no effect without [cluster] and [cluster.affinity] enabled: the proxy routes by consistent hash", s.Name, s.Type)
			}
		case "http_user_api":
			userAPI = true
		}

		switch s.Type {
		case "imap_proxy", "pop3_proxy", "managesieve_proxy":
			// Only the cluster connection tracker counts a user's connections through
			// these proxies. The LMTP and User API proxies never apply the limits, which
			// WarnUnusedConfigOptions reports.
			var limits []string
			if s.MaxConnectionsPerUser != 0 {
				limits = append(limits, "'max_connections_per_user'")
			}
			if s.MaxConnectionsPerUserPerIP != 0 {
				limits = append(limits, "'max_connections_per_user_per_ip'")
			}
			if len(limits) > 0 && !c.Cluster.Enabled {
				warn("Server %s (type: %s) has %s configured, but per-user connection limits are not applied without [cluster]: the proxy counts a user's connections only through the cluster connection tracker",
					s.Name, s.Type, strings.Join(limits, " and "))
			}
		case "http_admin_api":
			// The upload worker runs with a mail backend. Without api_key start-up does
			// not start the Admin API at all.
			if s.APIKey != "" && !c.HasMailBackend() {
				warn("Server %s (type: %s): no upload worker on this node (no imap, pop3 or lmtp server), POST /admin/mail/deliver will answer 503", s.Name, s.Type)
			}
		}

		// Start-up leaves out an Admin API without api_key and a User API or its proxy
		// without jwt_secret, and so parses none of their values.
		if (s.Type == "http_admin_api" && s.APIKey == "") || ((s.Type == "http_user_api" || s.Type == "user_api_proxy") && s.JWTSecret == "") {
			continue
		}
		for _, v := range serverValues {
			if !slices.Contains(v.types, s.Type) {
				continue
			}
			if err := v.parse(s); err != nil {
				warn("Server %s (type: %s) has an invalid '%s', start-up uses the default: %v", s.Name, s.Type, v.key, err)
			}
		}
	}

	for _, s := range c.SessionMemoryShortfalls() {
		warn("Server %s (type: %s) has session_memory_limit %d bytes, below max_message_size %d bytes of lmtp server %s: "+
			"a delivered message larger than session_memory_limit is stored, but this server can never fetch it (IMAP NO [LIMIT], POP3 -ERR [SYS/PERM]); "+
			"sora-admin imports are bounded by [admin_cli] import_message_limit instead",
			s.Server, s.Type, s.SessionMemoryLimit, s.MaxMessageSize, s.LMTPServer)
	}

	// The User API reads message bodies from S3, which a node without a mail backend
	// connects to only when [s3] has settings (NeedsS3).
	if userAPI && !c.NeedsS3() {
		warn("User API: no [s3] configured on this node; message bodies (/user/messages/{id}/body and /raw) cannot be served")
	}
	// The database connection is opened for the servers that query it (DatabaseUser).
	database := c.DatabaseUser() != nil
	if proxy && !database {
		warn("Backend maintenance is not honored on this node: proxies read the maintenance list from the database, which no server on this node connects to")
	}
	if w := c.Relay.TransportWarning(); w != "" {
		warn("%s", w)
	}

	// The section values, each parsed only on a node that runs what reads it.
	for _, v := range []struct {
		section, key string
		read         bool
		parse        func() error
	}{
		{"[cluster.affinity]", "ttl", c.Cluster.Enabled, func() error { _, err := c.Cluster.Affinity.GetTTL(); return err }},
		{"[cluster.affinity]", "cleanup_interval", c.Cluster.Enabled, func() error { _, err := c.Cluster.Affinity.GetCleanupInterval(); return err }},
		// The proxies poll the maintenance list from the database; the backend
		// maintenance report (a node with an upload worker) refuses sessions after
		// refuse_after.
		{"[backend_maintenance]", "poll_interval", proxy && database, func() error { _, err := c.Maintenance.GetPollInterval(); return err }},
		{"[backend_maintenance]", "refuse_after", c.HasMailBackend(), func() error { _, err := c.Maintenance.GetRefuseAfter(); return err }},
		{"[relay.queue]", "retry_backoff", c.Relay.IsQueueEnabled(), func() error { _, err := c.Relay.Queue.GetRetryBackoff(); return err }},
		{"[relay.queue]", "worker_interval", c.Relay.IsQueueEnabled(), func() error { _, err := c.Relay.Queue.GetWorkerInterval(); return err }},
	} {
		if !v.read {
			continue
		}
		if err := v.parse(); err != nil {
			warn("%s has an invalid '%s', start-up uses the default: %v", v.section, v.key, err)
		}
	}

	return warnings
}

// serverValues are the [[server]] values start-up parses for the server types listed and,
// when one does not parse, replaces with its default.
var serverValues = []struct {
	key   string
	types []string
	parse func(*ServerConfig) error
}{
	{"limits.search_rate_limit_window", []string{"imap"}, func(s *ServerConfig) error { _, err := s.GetSearchRateLimitWindow(); return err }},
	{"limits.session_memory_limit", []string{"imap", "pop3"}, func(s *ServerConfig) error { _, err := s.GetSessionMemoryLimit(); return err }},
	// The default is the cache's max_object_size, which does not change whether it parses.
	{"limits.preview_s3_max_size", []string{"imap"}, func(s *ServerConfig) error { _, err := s.GetPreviewS3MaxSize(0); return err }},
	{"limits.redirect_rate_window", []string{"lmtp", "http_admin_api"}, func(s *ServerConfig) error { _, err := s.GetRedirectRateWindow(); return err }},
	{"timeouts.imap_command_timeouts", []string{"imap"}, func(s *ServerConfig) error { _, err := s.GetCommandTimeoutsOverrides(); return err }},
	{"timeouts.pop3_command_timeouts", []string{"pop3"}, func(s *ServerConfig) error { _, err := s.GetPOP3CommandTimeoutsOverrides(); return err }},
	{"timeouts.managesieve_command_timeouts", []string{"managesieve"}, func(s *ServerConfig) error { _, err := s.GetManageSieveCommandTimeoutsOverrides(); return err }},
	{"timeouts.lmtp_command_timeouts", []string{"lmtp"}, func(s *ServerConfig) error { _, err := s.GetLMTPCommandTimeoutsOverrides(); return err }},
	{"remote_dns_refresh", proxyServerTypes, func(s *ServerConfig) error { _, err := s.GetRemoteDNSRefresh(); return err }},
}
