package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/helpers"
)

// Warnings returns the file-derived startup warning classes collected here, one line each, so
// that `sora-admin config validate` can print them before the file is deployed. Each is
// about a setting start-up accepts but that does not do on this node what it says:
//
//   - a [[server]] or [[pool]] key that does not apply as configured
//     (ServerConfig.WarnUnusedConfigOptions, PoolConfig.WarnUnusedConfigOptions);
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
//   - a max_message_size above the largest message Sora can store, which start-up caps;
//   - what the servers, the cluster manager, the TLS manager and the cleaner log about
//     their settings as they start: master SASL without master_sasl_allowed_networks;
//     an imap append_limit above the largest message Sora can store or above
//     session_memory_limit, an imap command_timeout at or above go-imap's own read
//     deadline, and imap capabilities disabled_caps or client_filters cannot withdraw;
//     a User API token_duration above MaxTokenDuration; Admin and User API
//     allowed_hosts entries that match no client; tls_cert_file or tls_key_file
//     beside an enabled [tls]; [tls.letsencrypt] enable_fallback = false; a [cluster]
//     addr with a port beside the port key or on loopback, peers naming this node,
//     and no peers to join; and [cleanup] intervals below their minimum.
//
// Start-up logs each where the part that uses the setting starts, so a new start-up
// warning about the file can be added here as well. Warnings that depend on the host
// (its addresses, names, disk and DNS) remain at start-up only: plaintext
// authentication or metrics on a publicly reachable address, the instance id and
// mail host name, and a peers entry that names this node by host name. Like
// start-up, Warnings assumes the file passes Validate.
func (c *Config) Warnings() []string {
	var warnings []string
	warn := func(format string, args ...any) {
		warnings = append(warnings, fmt.Sprintf(format, args...))
	}

	var proxy, userAPI bool
	servers := c.GetAllServers()
	if len(servers) == 0 && c.HasPools() {
		for _, w := range c.poolWarnings() {
			warn("%s", strings.TrimPrefix(w, "WARNING: "))
		}
	}
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
		case "imap", "pop3", "managesieve":
			// These accept master SASL logins; a proxy presents the credentials to its
			// backends instead.
			if s.MasterSASLPassword != "" && len(s.MasterSASLAllowedNetworks) == 0 {
				warn("Server %s (type: %s) has 'master_sasl_password' configured without 'master_sasl_allowed_networks': "+
					"it accepts master SASL logins from any source that knows the secret; restrict its port to the proxy hosts or set master_sasl_allowed_networks",
					s.Name, s.Type)
			}
			if s.Type == "imap" {
				s.imapWarnings(warn)
			}
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
		switch s.Type {
		case "http_admin_api", "http_user_api":
			// The APIs log these as they install the list; the metrics endpoint's are
			// WarnUnusedConfigOptions'.
			for _, entry := range helpers.InvalidNetworkEntries(s.AllowedHosts) {
				warn("Server %s (type: %s) has 'allowed_hosts' entry %q, which is not an IP address or CIDR and matches no client", s.Name, s.Type, entry)
			}
		}
		if s.Type == "http_user_api" {
			if d, err := s.GetTokenDuration(); err == nil && d > MaxTokenDuration {
				warn("Server %s (type: %s) has token_duration %s, above the maximum %s: start-up uses %s", s.Name, s.Type, d, MaxTokenDuration, MaxTokenDuration)
			}
		}
		// Every listener with tls = true takes the global [tls] certificate when there
		// is one (server.ListenerTLS).
		if c.TLS.Enabled && s.TLS && (s.TLSCertFile != "" || s.TLSKeyFile != "") && slices.Contains(listenerServerTypes, s.Type) {
			warn("Server %s (type: %s) has 'tls_cert_file'/'tls_key_file' configured, but they are ignored: with [tls] enabled the listener uses the global [tls] certificate", s.Name, s.Type)
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
	// The TLS manager mirrors the Let's Encrypt certificates on local disk unless
	// enable_fallback = false.
	if le := c.TLS.LetsEncrypt; c.TLS.Enabled && c.TLS.Provider == "letsencrypt" && le != nil && le.EnableFallback != nil && !*le.EnableFallback {
		warn("[tls.letsencrypt] enable_fallback = false: certificates are served from S3 only, so TLS handshakes fail while S3 is unavailable")
	}
	if c.Cluster.Enabled {
		c.Cluster.warnings(warn)
	}

	// The section values, each parsed only on a node that runs what reads it. The
	// [local_cache], [cleanup] and [uploader] getters fill in a value the file leaves
	// out, so they parse copies.
	mailBackend := c.HasMailBackend()
	imapServer := slices.ContainsFunc(servers, func(s ServerConfig) bool { return s.Type == "imap" })
	localCache, cleanup, uploader := c.LocalCache, c.Cleanup, c.Uploader

	// A mail backend's cleaner and purge worker raise a shorter interval to their
	// minimum.
	if mailBackend {
		if d, err := cleanup.GetWakeInterval(); err == nil && d < MinCleanupWakeInterval {
			warn("[cleanup] wake_interval %s is below the minimum %s: start-up uses %s", d, MinCleanupWakeInterval, MinCleanupWakeInterval)
		}
		if d, err := cleanup.GetPurgePollInterval(); err == nil && d < MinPurgePollInterval {
			warn("[cleanup] purge_poll_interval %s is below the minimum %s: start-up uses %s", d, MinPurgePollInterval, MinPurgePollInterval)
		}
	}
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
		{endpointSection, "query_timeout", database && endpoint != nil, func() error { _, err := endpoint.GetQueryTimeout(); return err }, "every read uses the [database] query_timeout or its default"},
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
	{"lookup_cache.positive_revalidation_window", []string{"imap", "pop3", "managesieve", "imap_proxy", "pop3_proxy", "managesieve_proxy"}, lookupCacheRevalidationValue},
}

// maxMessageSizeServerTypes read max_message_size: LMTP, its proxy and Admin API delivery.
var maxMessageSizeServerTypes = []string{"lmtp", "lmtp_proxy", "http_admin_api"}

// The IMAP proxy parses this value before deciding whether to build its cache,
// including a disabled cache or a remote lookup keyed by client IP. Other readers
// parse it only while constructing their credential cache.
func lookupCacheRevalidationValue(s *ServerConfig) error {
	if s.Type == "imap_proxy" && s.LookupCache != nil {
		_, err := s.LookupCache.GetPositiveRevalidationWindow()
		return err
	}
	return lookupCacheValue((*LookupCacheConfig).GetPositiveRevalidationWindow)(s)
}

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

// imapWarnings are the warnings an IMAP server logs about its settings as it is built
// (server/imap New).
func (s *ServerConfig) imapWarnings(warn func(format string, args ...any)) {
	// append_limit as the server resolves it: the default when it does not parse or is
	// not positive, at most the largest message Sora can store.
	appendLimit, err := s.GetAppendLimit()
	if err != nil || appendLimit <= 0 {
		appendLimit = defaultAppendLimit
	}
	if appendLimit > consts.MaxStoredMessageSize {
		warn("Server %s (type: %s) has append_limit %d bytes, above the largest message Sora can store: start-up uses %d",
			s.Name, s.Type, appendLimit, int64(consts.MaxStoredMessageSize))
		appendLimit = consts.MaxStoredMessageSize
	}
	// APPEND reads the message into the session memory budget ("0" is none), so a
	// session advertises and enforces the budget as its APPENDLIMIT.
	sessionMemoryLimit, err := s.GetSessionMemoryLimit()
	if err != nil {
		sessionMemoryLimit = defaultSessionMemoryLimit
	}
	if sessionMemoryLimit > 0 && sessionMemoryLimit < appendLimit {
		warn("Server %s (type: %s) has append_limit %d bytes, above its session_memory_limit %d bytes, which APPEND reads the message into: "+
			"the server advertises and enforces session_memory_limit as its APPENDLIMIT", s.Name, s.Type, appendLimit, sessionMemoryLimit)
	}

	if timeout, err := s.GetCommandTimeout(); err == nil && timeout >= IMAPLibraryReadDeadline {
		warn("Server %s (type: %s) has 'timeouts.command_timeout' %s, at or above the IMAP library's %s read deadline: idle sessions are closed silently at %s instead",
			s.Name, s.Type, timeout, IMAPLibraryReadDeadline, IMAPLibraryReadDeadline)
	}

	caps := IMAPServerCaps(s.EnablePreview)
	for i, filter := range s.ClientFilters {
		for _, name := range filter.DisableCaps {
			if why := IMAPCapNotWithdrawn(caps, name, true); why != "" {
				warn("Server %s (type: %s) has %q in the disable_caps of client_filters entry %d, which cannot disable it: %s", s.Name, s.Type, name, i+1, why)
			}
		}
	}
	for _, name := range s.DisabledCaps {
		if why := IMAPCapNotWithdrawn(caps, name, false); why != "" {
			warn("Server %s (type: %s) has %q in 'disabled_caps', which cannot disable it: %s", s.Name, s.Type, name, why)
		}
	}
}

// warnings are the warnings the cluster manager (cluster.New) logs about an enabled
// [cluster]'s addr, port and peers. It drops the peers entries that name this node and
// joins the rest. An entry written as an IP address is compared with addr here; one
// written as a host name is resolved at start-up, so it counts as another node.
func (c *ClusterConfig) warnings(warn func(format string, args ...any)) {
	if _, _, err := net.SplitHostPort(c.Addr); err == nil && c.Port > 0 {
		warn("[cluster] addr %q includes a port and port = %d is also set: the port from addr is used and the port key is ignored; remove one of them", c.Addr, c.Port)
	}
	bindAddr, bindPort := c.GetBindAddr(), c.GetBindPort()
	if bindAddr == "127.0.0.1" || bindAddr == "::1" {
		warn("[cluster] addr %s is a loopback address: gossip only reaches nodes on this machine; use a network address the other nodes can reach", bindAddr)
	}

	// With port 0 the node binds a free port, which no entry can name in advance.
	var own []string
	self, err := netip.ParseAddr(bindAddr)
	selfAddrPort := netip.AddrPortFrom(self.Unmap(), uint16(bindPort))
	if err == nil && bindPort != 0 {
		for _, peer := range c.Peers {
			host, port, ok := SplitClusterPeer(peer, bindPort)
			if !ok {
				continue
			}
			if addr, err := netip.ParseAddr(host); err == nil && netip.AddrPortFrom(addr.Unmap(), port) == selfAddrPort {
				own = append(own, strconv.Quote(peer))
			}
		}
	}
	if len(own) > 0 {
		warn("[cluster] peers lists this node's own address %s (%s): it is ignored", selfAddrPort, strings.Join(own, ", "))
	}
	if len(own) == len(c.Peers) {
		warn("[cluster] has no peers to join: this node runs as a standalone single-node cluster")
	}
}
