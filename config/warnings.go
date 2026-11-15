package config

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/helpers"
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
//   - a value start-up cannot parse and replaces with its default: the [[server]] values
//     in serverValues, and the [cluster.affinity], [backend_maintenance], [relay.queue],
//     [local_cache], [cleanup], [uploader], [auth_cache] and [database] values below
//     ([database] timeouts are parsed by every query, not once); a [spam_training] value
//     start-up cannot parse leaves spam training out;
//   - a max_message_size above the largest message Sora can store, which start-up caps.
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
		if slices.Contains(maxMessageSizeServerTypes, s.Type) {
			if size, err := s.configuredMaxMessageSize(); err == nil && size > consts.MaxStoredMessageSize {
				warn("Server %s (type: %s) has max_message_size %d bytes, above the largest message Sora can store: start-up uses %d",
					s.Name, s.Type, size, int64(consts.MaxStoredMessageSize))
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

	// The section values, each parsed only on a node that runs what reads it. The
	// [local_cache], [cleanup] and [uploader] getters fill in a value the file leaves
	// out, so they parse copies.
	mailBackend := c.HasMailBackend()
	imapServer := slices.ContainsFunc(servers, func(s ServerConfig) bool { return s.Type == "imap" })
	localCache, cleanup, uploader := c.LocalCache, c.Cleanup, c.Uploader
	// Reads take the query_timeout of [database.read], or of [database.write] without one.
	endpoint, endpointSection := c.Database.Read, "[database.read]"
	if endpoint == nil {
		endpoint, endpointSection = c.Database.Write, "[database.write]"
	}
	const (
		useDefault     = "start-up uses the default"
		queriesDefault = "every query uses the default"
		noSpamTraining = "start-up runs without spam training"
	)
	for _, v := range []struct {
		section, key string
		read         bool
		parse        func() error
		effect       string
	}{
		{"[cluster.affinity]", "ttl", c.Cluster.Enabled, func() error { _, err := c.Cluster.Affinity.GetTTL(); return err }, useDefault},
		{"[cluster.affinity]", "cleanup_interval", c.Cluster.Enabled, func() error { _, err := c.Cluster.Affinity.GetCleanupInterval(); return err }, useDefault},
		// The proxies poll the maintenance list from the database; the backend
		// maintenance report (a node with an upload worker) refuses sessions after
		// refuse_after.
		{"[backend_maintenance]", "poll_interval", proxy && database, func() error { _, err := c.Maintenance.GetPollInterval(); return err }, useDefault},
		{"[backend_maintenance]", "refuse_after", mailBackend, func() error { _, err := c.Maintenance.GetRefuseAfter(); return err }, useDefault},
		{"[relay.queue]", "retry_backoff", c.Relay.IsQueueEnabled(), func() error { _, err := c.Relay.Queue.GetRetryBackoff(); return err }, useDefault},
		{"[relay.queue]", "worker_interval", c.Relay.IsQueueEnabled(), func() error { _, err := c.Relay.Queue.GetWorkerInterval(); return err }, useDefault},
		// A mail backend's local cache, cleaner, purge worker and upload worker.
		{"[local_cache]", "capacity", mailBackend, func() error { _, err := localCache.GetCapacity(); return err }, useDefault},
		{"[local_cache]", "max_object_size", mailBackend, func() error { _, err := localCache.GetMaxObjectSize(); return err }, useDefault},
		{"[local_cache]", "purge_interval", mailBackend, func() error { _, err := localCache.GetPurgeInterval(); return err }, useDefault},
		{"[local_cache]", "orphan_cleanup_age", mailBackend, func() error { _, err := localCache.GetOrphanCleanupAge(); return err }, useDefault},
		{"[local_cache]", "metrics_interval", mailBackend, func() error { _, err := localCache.GetMetricsInterval(); return err }, useDefault},
		{"[local_cache]", "metrics_retention", mailBackend, func() error { _, err := localCache.GetMetricsRetention(); return err }, useDefault},
		{"[cleanup]", "grace_period", mailBackend, func() error { _, err := cleanup.GetGracePeriod(); return err }, useDefault},
		{"[cleanup]", "wake_interval", mailBackend, func() error { _, err := cleanup.GetWakeInterval(); return err }, useDefault},
		{"[cleanup]", "max_age_restriction", mailBackend, func() error { _, err := cleanup.GetMaxAgeRestriction(); return err }, useDefault},
		{"[cleanup]", "fts_retention", mailBackend, func() error { _, err := cleanup.GetFTSRetention(); return err }, useDefault},
		{"[cleanup]", "health_status_retention", mailBackend, func() error { _, err := cleanup.GetHealthStatusRetention(); return err }, useDefault},
		{"[cleanup]", "instance_liveness_threshold", mailBackend, func() error { _, err := cleanup.GetInstanceLivenessThreshold(); return err }, useDefault},
		{"[cleanup]", "purge_poll_interval", mailBackend, func() error { _, err := cleanup.GetPurgePollInterval(); return err }, useDefault},
		{"[uploader]", "retry_interval", mailBackend, func() error { _, err := uploader.GetRetryInterval(); return err }, useDefault},
		// Each IMAP server's cache warmup. A zero or negative timeout would cancel every
		// warmup before its first query.
		{"[local_cache]", "warmup_timeout", imapServer, func() error { return positiveDuration(c.LocalCache.WarmupTimeout) }, useDefault},
		{"[local_cache]", "warmup_interval", imapServer, func() error { return parsedDuration(c.LocalCache.WarmupInterval) }, useDefault},
		{"[auth_cache]", "max_age", c.AuthCache.Enabled, func() error { _, err := c.AuthCache.GetMaxAge(); return err }, useDefault},
		{"[auth_cache]", "purge_unused", c.AuthCache.Enabled, func() error { _, err := c.AuthCache.GetPurgeUnused(); return err }, useDefault},
		{"[auth_cache]", "cleanup_interval", c.AuthCache.Enabled, func() error { _, err := c.AuthCache.GetCleanupInterval(); return err }, useDefault},
		// The database connection parses lock_timeout once, and the others for each query.
		{"[database]", "lock_timeout", database, func() error { _, err := c.Database.GetLockTimeout(); return err }, useDefault},
		{"[database]", "query_timeout", database, func() error { _, err := c.Database.GetQueryTimeout(); return err }, queriesDefault},
		{"[database]", "search_timeout", database, func() error { _, err := c.Database.GetSearchTimeout(); return err }, queriesDefault},
		{"[database]", "write_timeout", database, func() error { _, err := c.Database.GetWriteTimeout(); return err }, queriesDefault},
		{endpointSection, "query_timeout", database && endpoint != nil, func() error { _, err := endpoint.GetQueryTimeout(); return err }, "every read uses the [database] query_timeout"},
		// Spam training starts without a client when one of these does not parse.
		{"[spam_training]", "timeout", c.SpamTraining.IsConfigured(), func() error { _, err := c.SpamTraining.GetTimeout(); return err }, noSpamTraining},
		{"[spam_training]", "max_message_size", c.SpamTraining.IsConfigured(), func() error {
			size, err := c.SpamTraining.GetMaxMessageSize()
			if err == nil && size <= 0 {
				err = errors.New("must be positive")
			}
			return err
		}, noSpamTraining},
		{"[spam_training.circuit_breaker]", "timeout", c.SpamTraining.IsConfigured(), func() error { _, err := c.SpamTraining.CircuitBreaker.GetTimeout(); return err }, noSpamTraining},
	} {
		if !v.read {
			continue
		}
		if err := v.parse(); err != nil {
			warn("%s has an invalid '%s', %s: %v", v.section, v.key, v.effect, err)
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
	// The values the start functions read through the *WithDefault getters, on the types
	// WarnUnusedConfigOptions says apply them.
	{"append_limit", []string{"imap"}, func(s *ServerConfig) error { _, err := s.GetAppendLimit(); return err }},
	{"max_script_size", []string{"managesieve"}, func(s *ServerConfig) error { _, err := s.GetMaxScriptSize(); return err }},
	{"max_message_size", maxMessageSizeServerTypes, func(s *ServerConfig) error { _, err := s.configuredMaxMessageSize(); return err }},
	{"connect_timeout", proxyServerTypes, func(s *ServerConfig) error { _, err := s.GetConnectTimeout(); return err }},
	{"auth_idle_timeout", []string{"imap", "pop3", "managesieve", "imap_proxy", "pop3_proxy", "managesieve_proxy", "lmtp_proxy"}, func(s *ServerConfig) error { _, err := s.GetAuthIdleTimeout(); return err }},
	{"timeouts.command_timeout", []string{"imap", "lmtp", "pop3", "managesieve", "imap_proxy", "pop3_proxy", "managesieve_proxy"}, func(s *ServerConfig) error { _, err := s.GetCommandTimeout(); return err }},
	{"timeouts.absolute_session_timeout", []string{"imap", "pop3", "managesieve", "imap_proxy", "pop3_proxy", "managesieve_proxy", "lmtp_proxy"}, func(s *ServerConfig) error { _, err := s.GetAbsoluteSessionTimeout(); return err }},
	{"token_duration", []string{"http_user_api"}, func(s *ServerConfig) error { _, err := s.GetTokenDuration(); return err }},
	// The values the servers parse as they are built. The PROXY header reader reads its
	// timeout only with proxy_protocol, and a zero or negative one would fail every header.
	{"proxy_protocol_timeout", listenerServerTypes, func(s *ServerConfig) error {
		if !s.ProxyProtocol {
			return nil
		}
		d, err := s.GetProxyProtocolTimeout()
		if err == nil && d <= 0 {
			err = errors.New("must be positive")
		}
		return err
	}},
	{"lookup_cache.positive_ttl", lookupCacheServerTypes, lookupCacheValue((*LookupCacheConfig).GetPositiveTTL)},
	{"lookup_cache.negative_ttl", lookupCacheServerTypes, lookupCacheValue((*LookupCacheConfig).GetNegativeTTL)},
	{"lookup_cache.cleanup_interval", lookupCacheServerTypes, lookupCacheValue((*LookupCacheConfig).GetCleanupInterval)},
	{"lookup_cache.positive_revalidation_window", []string{"imap", "pop3", "managesieve", "imap_proxy", "pop3_proxy", "managesieve_proxy", "http_user_api"}, lookupCacheValue((*LookupCacheConfig).GetPositiveRevalidationWindow)},
}

// maxMessageSizeServerTypes read max_message_size: LMTP, its proxy and Admin API delivery.
var maxMessageSizeServerTypes = []string{"lmtp", "lmtp_proxy", "http_admin_api"}

// lookupCacheValue is a serverValues parse of a lookup_cache duration, read only by a
// server that builds a lookup cache from its lookup_cache table: one the table enables,
// except a proxy whose remote lookup URL names the client's $ip, which caches nothing.
// Without the table a server caches with the defaults, which parse.
func lookupCacheValue(get func(*LookupCacheConfig) (time.Duration, error)) func(*ServerConfig) error {
	return func(s *ServerConfig) error {
		if s.LookupCache == nil || !s.LookupCache.Enabled {
			return nil
		}
		if slices.Contains(proxyServerTypes, s.Type) && s.RemoteLookup != nil && s.RemoteLookup.Enabled && strings.Contains(s.RemoteLookup.URL, "$ip") {
			return nil
		}
		_, err := get(s.LookupCache)
		return err
	}
}

// parsedDuration checks a duration the server parses itself, where "" is its default.
func parsedDuration(value string) error {
	if value == "" {
		return nil
	}
	_, err := helpers.ParseDuration(value)
	return err
}

// positiveDuration is parsedDuration for a duration that must also be positive.
func positiveDuration(value string) error {
	if value == "" {
		return nil
	}
	d, err := helpers.ParseDuration(value)
	if err == nil && d <= 0 {
		err = errors.New("must be positive")
	}
	return err
}
