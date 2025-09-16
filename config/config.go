package config

import (
	"fmt"
	"strconv"
	"time"

	"github.com/migadu/sora/helpers"
)

// DatabaseEndpointConfig holds configuration for a single database endpoint
type DatabaseEndpointConfig struct {
	// List of database hosts for runtime failover/load balancing
	// Examples:
	//   Single host: ["db.example.com"] - hostname with DNS-based IP redundancy
	//   Multiple hosts: ["db1", "db2", "db3"] - for connection pools, proxies, or clusters
	//   With ports: ["db1:5432", "db2:5433"] - explicit port specification
	//
	// WRITE HOSTS: Use single host unless you have:
	//   - Multi-master setup (BDR, Postgres-XL)
	//   - Multiple connection pool/proxy instances (PgBouncer, HAProxy)
	//   - Service discovery endpoints (Consul, K8s services)
	//
	// READ HOSTS: Multiple hosts are common for read replica load balancing
	Hosts           []string    `toml:"hosts"`
	Port            interface{} `toml:"port"` // Database port (default: "5432"), can be string or integer
	User            string      `toml:"user"`
	Password        string      `toml:"password"`
	Name            string      `toml:"name"`
	TLSMode         bool        `toml:"tls"`
	MaxConns        int         `toml:"max_conns"`          // Maximum number of connections in the pool
	MinConns        int         `toml:"min_conns"`          // Minimum number of connections in the pool
	MaxConnLifetime string      `toml:"max_conn_lifetime"`  // Maximum lifetime of a connection
	MaxConnIdleTime string      `toml:"max_conn_idle_time"` // Maximum idle time before a connection is closed
	QueryTimeout    string      `toml:"query_timeout"`      // Per-endpoint timeout for individual database queries (e.g., "30s")
}

// DatabaseConfig holds database configuration with separate read/write endpoints
type DatabaseConfig struct {
	LogQueries    bool                    `toml:"log_queries"`    // Global setting for query logging
	QueryTimeout  string                  `toml:"query_timeout"`  // Default timeout for all database queries (default: "30s")
	SearchTimeout string                  `toml:"search_timeout"` // Specific timeout for complex search queries (default: "60s")
	WriteTimeout  string                  `toml:"write_timeout"`  // Timeout for write operations (default: "10s")
	Write         *DatabaseEndpointConfig `toml:"write"`          // Write database configuration
	Read          *DatabaseEndpointConfig `toml:"read"`           // Read database configuration (can have multiple hosts for load balancing)
}

// GetMaxConnLifetime parses the max connection lifetime duration for an endpoint
func (e *DatabaseEndpointConfig) GetMaxConnLifetime() (time.Duration, error) {
	if e.MaxConnLifetime == "" {
		return time.Hour, nil
	}
	return helpers.ParseDuration(e.MaxConnLifetime)
}

// GetMaxConnIdleTime parses the max connection idle time duration for an endpoint
func (e *DatabaseEndpointConfig) GetMaxConnIdleTime() (time.Duration, error) {
	if e.MaxConnIdleTime == "" {
		return 30 * time.Minute, nil
	}
	return helpers.ParseDuration(e.MaxConnIdleTime)
}

// GetQueryTimeout parses the query timeout duration for an endpoint.
func (e *DatabaseEndpointConfig) GetQueryTimeout() (time.Duration, error) {
	if e.QueryTimeout == "" {
		return 0, nil // Return zero duration if not set, caller handles default.
	}
	return helpers.ParseDuration(e.QueryTimeout)
}

// GetQueryTimeout parses the general query timeout duration.
func (d *DatabaseConfig) GetQueryTimeout() (time.Duration, error) {
	if d.QueryTimeout == "" {
		return 30 * time.Second, nil // Default 30 second timeout for general queries
	}
	return helpers.ParseDuration(d.QueryTimeout)
}

// GetSearchTimeout parses the search timeout duration
func (d *DatabaseConfig) GetSearchTimeout() (time.Duration, error) {
	if d.SearchTimeout == "" {
		return 60 * time.Second, nil // Default 60 second timeout for complex search operations
	}
	return helpers.ParseDuration(d.SearchTimeout)
}

// GetWriteTimeout parses the write timeout duration
func (d *DatabaseConfig) GetWriteTimeout() (time.Duration, error) {
	if d.WriteTimeout == "" {
		return 10 * time.Second, nil // Default 10 second timeout for write operations
	}
	return helpers.ParseDuration(d.WriteTimeout)
}

// S3Config holds S3 configuration.
type S3Config struct {
	Endpoint      string `toml:"endpoint"`
	DisableTLS    bool   `toml:"disable_tls"`
	AccessKey     string `toml:"access_key"`
	SecretKey     string `toml:"secret_key"`
	Bucket        string `toml:"bucket"`
	Trace         bool   `toml:"trace"`
	Encrypt       bool   `toml:"encrypt"`
	EncryptionKey string `toml:"encryption_key"`
}

// CleanupConfig holds cleaner worker configuration.
type CleanupConfig struct {
	GracePeriod           string `toml:"grace_period"`
	WakeInterval          string `toml:"wake_interval"`
	MaxAgeRestriction     string `toml:"max_age_restriction"`
	FTSRetention          string `toml:"fts_retention"`
	AuthAttemptsRetention string `toml:"auth_attempts_retention"`
	HealthStatusRetention string `toml:"health_status_retention"`
}

// GetGracePeriod parses the grace period duration
func (c *CleanupConfig) GetGracePeriod() (time.Duration, error) {
	if c.GracePeriod == "" {
		c.GracePeriod = "14d"
	}
	return helpers.ParseDuration(c.GracePeriod)
}

// GetWakeInterval parses the wake interval duration
func (c *CleanupConfig) GetWakeInterval() (time.Duration, error) {
	if c.WakeInterval == "" {
		c.WakeInterval = "1h"
	}
	return helpers.ParseDuration(c.WakeInterval)
}

// GetMaxAgeRestriction parses the max age restriction duration
func (c *CleanupConfig) GetMaxAgeRestriction() (time.Duration, error) {
	if c.MaxAgeRestriction == "" {
		return 0, nil // 0 means no restriction
	}
	return helpers.ParseDuration(c.MaxAgeRestriction)
}

// GetFTSRetention parses the FTS retention duration
func (c *CleanupConfig) GetFTSRetention() (time.Duration, error) {
	if c.FTSRetention == "" {
		return 730 * 24 * time.Hour, nil // 2 years default
	}
	return helpers.ParseDuration(c.FTSRetention)
}

// GetAuthAttemptsRetention parses the auth attempts retention duration
func (c *CleanupConfig) GetAuthAttemptsRetention() (time.Duration, error) {
	if c.AuthAttemptsRetention == "" {
		return 7 * 24 * time.Hour, nil // 7 days default
	}
	return helpers.ParseDuration(c.AuthAttemptsRetention)
}

// GetHealthStatusRetention parses the health status retention duration
func (c *CleanupConfig) GetHealthStatusRetention() (time.Duration, error) {
	if c.HealthStatusRetention == "" {
		return 30 * 24 * time.Hour, nil // 30 days default
	}
	return helpers.ParseDuration(c.HealthStatusRetention)
}

// LocalCacheConfig holds local disk cache configuration.
type LocalCacheConfig struct {
	Capacity           string   `toml:"capacity"`
	MaxObjectSize      string   `toml:"max_object_size"`
	Path               string   `toml:"path"`
	MetricsInterval    string   `toml:"metrics_interval"`
	MetricsRetention   string   `toml:"metrics_retention"`
	PurgeInterval      string   `toml:"purge_interval"`
	OrphanCleanupAge   string   `toml:"orphan_cleanup_age"`
	EnableWarmup       bool     `toml:"enable_warmup"`
	WarmupMessageCount int      `toml:"warmup_message_count"`
	WarmupMailboxes    []string `toml:"warmup_mailboxes"`
	WarmupAsync        bool     `toml:"warmup_async"`
	WarmupTimeout      string   `toml:"warmup_timeout"`
}

// GetCapacity parses the cache capacity size
func (c *LocalCacheConfig) GetCapacity() (int64, error) {
	if c.Capacity == "" {
		c.Capacity = "1gb"
	}
	return helpers.ParseSize(c.Capacity)
}

// GetMaxObjectSize parses the max object size
func (c *LocalCacheConfig) GetMaxObjectSize() (int64, error) {
	if c.MaxObjectSize == "" {
		c.MaxObjectSize = "5mb"
	}
	return helpers.ParseSize(c.MaxObjectSize)
}

// GetMetricsInterval parses the metrics interval duration
func (c *LocalCacheConfig) GetMetricsInterval() (time.Duration, error) {
	if c.MetricsInterval == "" {
		c.MetricsInterval = "5m"
	}
	return helpers.ParseDuration(c.MetricsInterval)
}

// GetMetricsRetention parses the metrics retention duration
func (c *LocalCacheConfig) GetMetricsRetention() (time.Duration, error) {
	if c.MetricsRetention == "" {
		c.MetricsRetention = "30d"
	}
	return helpers.ParseDuration(c.MetricsRetention)
}

// GetPurgeInterval parses the purge interval duration
func (c *LocalCacheConfig) GetPurgeInterval() (time.Duration, error) {
	if c.PurgeInterval == "" {
		c.PurgeInterval = "12h"
	}
	return helpers.ParseDuration(c.PurgeInterval)
}

// GetOrphanCleanupAge parses the orphan cleanup age duration
func (c *LocalCacheConfig) GetOrphanCleanupAge() (time.Duration, error) {
	if c.OrphanCleanupAge == "" {
		c.OrphanCleanupAge = "30d"
	}
	return helpers.ParseDuration(c.OrphanCleanupAge)
}

// UploaderConfig holds upload worker configuration.
type UploaderConfig struct {
	Path          string `toml:"path"`
	BatchSize     int    `toml:"batch_size"`
	Concurrency   int    `toml:"concurrency"`
	MaxAttempts   int    `toml:"max_attempts"`
	RetryInterval string `toml:"retry_interval"`
}

// GetRetryInterval parses the retry interval duration
func (c *UploaderConfig) GetRetryInterval() (time.Duration, error) {
	if c.RetryInterval == "" {
		c.RetryInterval = "30s"
	}
	return helpers.ParseDuration(c.RetryInterval)
}

// ProxyProtocolConfig holds PROXY protocol configuration
type ProxyProtocolConfig struct {
	Enabled        bool     `toml:"enabled"`         // Enable PROXY protocol support
	TrustedProxies []string `toml:"trusted_proxies"` // CIDR blocks of trusted proxies
	Timeout        string   `toml:"timeout"`         // Timeout for reading PROXY header
}

// AuthRateLimiterConfig holds authentication rate limiter configuration
type AuthRateLimiterConfig struct {
	Enabled                bool          `toml:"enabled"`                   // Enable/disable rate limiting
	MaxAttemptsPerIP       int           `toml:"max_attempts_per_ip"`       // Max failed attempts per IP before DB-based block
	MaxAttemptsPerUsername int           `toml:"max_attempts_per_username"` // Max failed attempts per username before DB-based block
	IPWindowDuration       time.Duration `toml:"ip_window_duration"`        // Time window for IP-based limiting
	UsernameWindowDuration time.Duration `toml:"username_window_duration"`  // Time window for username-based limiting
	CleanupInterval        time.Duration `toml:"cleanup_interval"`          // How often to clean up old DB entries

	// Enhanced Features (for EnhancedAuthRateLimiter)
	FastBlockThreshold   int           `toml:"fast_block_threshold"`   // Failed attempts before in-memory fast block
	FastBlockDuration    time.Duration `toml:"fast_block_duration"`    // How long to fast block an IP in-memory
	DelayStartThreshold  int           `toml:"delay_start_threshold"`  // Failed attempts before progressive delays start
	InitialDelay         time.Duration `toml:"initial_delay"`          // First delay duration
	MaxDelay             time.Duration `toml:"max_delay"`              // Maximum delay duration
	DelayMultiplier      float64       `toml:"delay_multiplier"`       // Delay increase factor
	CacheCleanupInterval time.Duration `toml:"cache_cleanup_interval"` // How often to clean in-memory cache
	DBSyncInterval       time.Duration `toml:"db_sync_interval"`       // How often to sync attempt batches to database
	MaxPendingBatch      int           `toml:"max_pending_batch"`      // Max records before a forced batch sync
	DBErrorThreshold     time.Duration `toml:"db_error_threshold"`     // Wait time before retrying DB after an error
}

// DefaultAuthRateLimiterConfig returns sensible defaults for authentication rate limiting
func DefaultAuthRateLimiterConfig() AuthRateLimiterConfig {
	return AuthRateLimiterConfig{
		MaxAttemptsPerIP:       10,               // 10 failed attempts per IP
		MaxAttemptsPerUsername: 5,                // 5 failed attempts per username
		IPWindowDuration:       15 * time.Minute, // 15 minute window for IP
		UsernameWindowDuration: 30 * time.Minute, // 30 minute window for username
		CleanupInterval:        5 * time.Minute,  // Clean up every 5 minutes
		Enabled:                false,            // Disabled by default

		// Enhanced Defaults
		FastBlockThreshold:   10,               // Block IP after 10 failures
		FastBlockDuration:    5 * time.Minute,  // Block for 5 minutes
		DelayStartThreshold:  2,                // Start delays after 2 failures
		InitialDelay:         2 * time.Second,  // 2 second initial delay
		MaxDelay:             30 * time.Second, // Max 30 second delay
		DelayMultiplier:      2.0,              // Double delay each time
		CacheCleanupInterval: 10 * time.Minute, // Clean in-memory cache every 10 min
		DBSyncInterval:       30 * time.Second, // Sync batches every 30 seconds
		MaxPendingBatch:      100,              // Max 100 records before force sync
		DBErrorThreshold:     1 * time.Minute,  // Wait 1 minute after DB error
	}
}

// PreLookupConfig holds configuration for database-driven user routing
type PreLookupConfig struct {
	Enabled                bool        `toml:"enabled"`
	Hosts                  []string    `toml:"hosts"`
	Port                   interface{} `toml:"port"` // Database port (default: "5432"), can be string or integer
	User                   string      `toml:"user"`
	Password               string      `toml:"password"`
	Name                   string      `toml:"name"`
	TLS                    bool        `toml:"tls"`
	MaxConns               int         `toml:"max_conns"`
	MinConns               int         `toml:"min_conns"`
	MaxConnLifetime        string      `toml:"max_conn_lifetime"`
	MaxConnIdleTime        string      `toml:"max_conn_idle_time"`
	CacheTTL               string      `toml:"cache_ttl"`
	CacheSize              int         `toml:"cache_size"`
	FallbackDefault        bool        `toml:"fallback_to_default"`
	AuthMethod             string      `toml:"auth_method"`               // "bcrypt", "plain", etc.
	Query                  string      `toml:"query"`                     // Main query (auto-detects mode based on columns returned)
	RemoteTLS              bool        `toml:"remote_tls"`                // Use TLS for backend connections from prelookup
	RemoteTLSVerify        *bool       `toml:"remote_tls_verify"`         // Verify backend TLS certificate
	RemotePort             interface{} `toml:"remote_port"`               // Default port for routed backends if not in address
	RemoteUseProxyProtocol bool        `toml:"remote_use_proxy_protocol"` // Use PROXY protocol for backend connections from prelookup
	RemoteUseIDCommand     bool        `toml:"remote_use_id_command"`     // Use IMAP ID command for forwarding from prelookup (IMAP only)
	RemoteUseXCLIENT       bool        `toml:"remote_use_xclient"`        // Use XCLIENT command for forwarding from prelookup (POP3/LMTP/ManageSieve)
}

// GetCacheTTL returns the configured cache TTL duration
func (c *PreLookupConfig) GetCacheTTL() (time.Duration, error) {
	if c.CacheTTL == "" {
		return 10 * time.Minute, nil
	}
	return helpers.ParseDuration(c.CacheTTL)
}

// GetMaxConnLifetime returns the configured max connection lifetime
func (c *PreLookupConfig) GetMaxConnLifetime() (time.Duration, error) {
	if c.MaxConnLifetime == "" {
		return time.Hour, nil
	}
	return helpers.ParseDuration(c.MaxConnLifetime)
}

// GetMaxConnIdleTime returns the configured max connection idle time
func (c *PreLookupConfig) GetMaxConnIdleTime() (time.Duration, error) {
	if c.MaxConnIdleTime == "" {
		return 30 * time.Minute, nil
	}
	return helpers.ParseDuration(c.MaxConnIdleTime)
}

// GetRemotePort parses the remote port and returns it as an int.
func (c *PreLookupConfig) GetRemotePort() (int, error) {
	if c.RemotePort == nil {
		return 0, nil // No port configured
	}
	var p int64
	var err error
	switch v := c.RemotePort.(type) {
	case string:
		if v == "" {
			return 0, nil
		}
		p, err = strconv.ParseInt(v, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid string for remote_port: %q", v)
		}
	case int:
		p = int64(v)
	case int64: // TOML parsers often use int64 for numbers
		p = v
	default:
		return 0, fmt.Errorf("invalid type for remote_port: %T", v)
	}
	port := int(p)
	if port < 0 || port > 65535 {
		return 0, fmt.Errorf("remote_port number %d is out of the valid range (1-65535)", port)
	}
	return port, nil
}

// IMAPServerConfig holds IMAP server configuration.
type IMAPServerConfig struct {
	Start               bool                  `toml:"start"`
	Addr                string                `toml:"addr"`
	AppendLimit         string                `toml:"append_limit"`
	MaxConnections      int                   `toml:"max_connections"`        // Maximum concurrent connections
	MaxConnectionsPerIP int                   `toml:"max_connections_per_ip"` // Maximum connections per IP address
	MasterUsername      string                `toml:"master_username"`
	MasterPassword      string                `toml:"master_password"`
	MasterSASLUsername  string                `toml:"master_sasl_username"`
	MasterSASLPassword  string                `toml:"master_sasl_password"`
	TLS                 bool                  `toml:"tls"`
	TLSCertFile         string                `toml:"tls_cert_file"`
	TLSKeyFile          string                `toml:"tls_key_file"`
	TLSVerify           bool                  `toml:"tls_verify"`
	ProxyProtocol       ProxyProtocolConfig   `toml:"proxy_protocol"`  // PROXY protocol configuration
	AuthRateLimit       AuthRateLimiterConfig `toml:"auth_rate_limit"` // Authentication rate limiting
}

// LMTPServerConfig holds LMTP server configuration.
type LMTPServerConfig struct {
	Start               bool                `toml:"start"`
	Addr                string              `toml:"addr"`
	MaxConnections      int                 `toml:"max_connections"`        // Maximum concurrent connections
	MaxConnectionsPerIP int                 `toml:"max_connections_per_ip"` // Maximum connections per IP address
	ExternalRelay       string              `toml:"external_relay"`
	TLS                 bool                `toml:"tls"`
	TLSUseStartTLS      bool                `toml:"tls_use_starttls"`
	TLSCertFile         string              `toml:"tls_cert_file"`
	TLSKeyFile          string              `toml:"tls_key_file"`
	TLSVerify           bool                `toml:"tls_verify"`
	ProxyProtocol       ProxyProtocolConfig `toml:"proxy_protocol"` // PROXY protocol configuration
}

// POP3ServerConfig holds POP3 server configuration.
type POP3ServerConfig struct {
	Start               bool                  `toml:"start"`
	Addr                string                `toml:"addr"`
	MaxConnections      int                   `toml:"max_connections"`        // Maximum concurrent connections
	MaxConnectionsPerIP int                   `toml:"max_connections_per_ip"` // Maximum connections per IP address
	MasterSASLUsername  string                `toml:"master_sasl_username"`
	MasterSASLPassword  string                `toml:"master_sasl_password"`
	TLS                 bool                  `toml:"tls"`
	TLSCertFile         string                `toml:"tls_cert_file"`
	TLSKeyFile          string                `toml:"tls_key_file"`
	TLSVerify           bool                  `toml:"tls_verify"`
	ProxyProtocol       ProxyProtocolConfig   `toml:"proxy_protocol"`  // PROXY protocol configuration
	AuthRateLimit       AuthRateLimiterConfig `toml:"auth_rate_limit"` // Authentication rate limiting
}

// ManageSieveServerConfig holds ManageSieve server configuration.
type ManageSieveServerConfig struct {
	Start               bool                  `toml:"start"`
	Addr                string                `toml:"addr"`
	MaxConnections      int                   `toml:"max_connections"`        // Maximum concurrent connections
	MaxConnectionsPerIP int                   `toml:"max_connections_per_ip"` // Maximum connections per IP address
	MaxScriptSize       string                `toml:"max_script_size"`
	InsecureAuth        bool                  `toml:"insecure_auth"`
	MasterSASLUsername  string                `toml:"master_sasl_username"`
	MasterSASLPassword  string                `toml:"master_sasl_password"`
	TLS                 bool                  `toml:"tls"`
	TLSUseStartTLS      bool                  `toml:"tls_use_starttls"`
	TLSCertFile         string                `toml:"tls_cert_file"`
	TLSKeyFile          string                `toml:"tls_key_file"`
	TLSVerify           bool                  `toml:"tls_verify"`
	ProxyProtocol       ProxyProtocolConfig   `toml:"proxy_protocol"`  // PROXY protocol configuration
	AuthRateLimit       AuthRateLimiterConfig `toml:"auth_rate_limit"` // Authentication rate limiting
}

// IMAPProxyServerConfig holds IMAP proxy server configuration.
type IMAPProxyServerConfig struct {
	Start                  bool                  `toml:"start"`
	Addr                   string                `toml:"addr"`
	RemoteAddrs            []string              `toml:"remote_addrs"`
	MaxConnections         int                   `toml:"max_connections"`        // Maximum concurrent connections
	MaxConnectionsPerIP    int                   `toml:"max_connections_per_ip"` // Maximum connections per IP address
	MasterSASLUsername     string                `toml:"master_sasl_username"`
	MasterSASLPassword     string                `toml:"master_sasl_password"`
	TLS                    bool                  `toml:"tls"`
	TLSCertFile            string                `toml:"tls_cert_file"`
	TLSKeyFile             string                `toml:"tls_key_file"`
	TLSVerify              bool                  `toml:"tls_verify"`
	RemoteTLS              bool                  `toml:"remote_tls"`
	RemoteTLSVerify        bool                  `toml:"remote_tls_verify"`
	RemoteUseProxyProtocol bool                  `toml:"remote_use_proxy_protocol"` // Use PROXY protocol for backend connections
	ConnectTimeout         string                `toml:"connect_timeout"`
	EnableAffinity         bool                  `toml:"enable_affinity"`
	AffinityStickiness     float64               `toml:"affinity_stickiness"` // Probability (0.0 to 1.0) of using an affinity server.
	AffinityValidity       string                `toml:"affinity_validity"`
	AuthRateLimit          AuthRateLimiterConfig `toml:"auth_rate_limit"` // Authentication rate limiting
	PreLookup              *PreLookupConfig      `toml:"prelookup"`       // Database-driven user routing
}

// POP3ProxyServerConfig holds POP3 proxy server configuration.
type POP3ProxyServerConfig struct {
	Start                  bool                  `toml:"start"`
	Addr                   string                `toml:"addr"`
	RemoteAddrs            []string              `toml:"remote_addrs"`
	MaxConnections         int                   `toml:"max_connections"`        // Maximum concurrent connections
	MaxConnectionsPerIP    int                   `toml:"max_connections_per_ip"` // Maximum connections per IP address
	MasterSASLUsername     string                `toml:"master_sasl_username"`
	MasterSASLPassword     string                `toml:"master_sasl_password"`
	TLS                    bool                  `toml:"tls"`
	TLSCertFile            string                `toml:"tls_cert_file"`
	TLSKeyFile             string                `toml:"tls_key_file"`
	TLSVerify              bool                  `toml:"tls_verify"`
	RemoteTLS              bool                  `toml:"remote_tls"`
	RemoteTLSVerify        bool                  `toml:"remote_tls_verify"`
	RemoteUseProxyProtocol bool                  `toml:"remote_use_proxy_protocol"` // Use PROXY protocol for backend connections
	ConnectTimeout         string                `toml:"connect_timeout"`
	EnableAffinity         bool                  `toml:"enable_affinity"`
	AffinityStickiness     float64               `toml:"affinity_stickiness"` // Probability (0.0 to 1.0) of using an affinity server.
	AffinityValidity       string                `toml:"affinity_validity"`
	AuthRateLimit          AuthRateLimiterConfig `toml:"auth_rate_limit"` // Authentication rate limiting
	PreLookup              *PreLookupConfig      `toml:"prelookup"`       // Database-driven user routing
}

// ManageSieveProxyServerConfig holds ManageSieve proxy server configuration.
type ManageSieveProxyServerConfig struct {
	Start                  bool                  `toml:"start"`
	Addr                   string                `toml:"addr"`
	RemoteAddrs            []string              `toml:"remote_addrs"`
	MaxConnections         int                   `toml:"max_connections"`        // Maximum concurrent connections
	MaxConnectionsPerIP    int                   `toml:"max_connections_per_ip"` // Maximum connections per IP address
	MasterSASLUsername     string                `toml:"master_sasl_username"`
	MasterSASLPassword     string                `toml:"master_sasl_password"`
	TLS                    bool                  `toml:"tls"`
	TLSCertFile            string                `toml:"tls_cert_file"`
	TLSKeyFile             string                `toml:"tls_key_file"`
	TLSVerify              bool                  `toml:"tls_verify"`
	RemoteTLS              bool                  `toml:"remote_tls"`
	RemoteTLSVerify        bool                  `toml:"remote_tls_verify"`
	RemoteUseProxyProtocol bool                  `toml:"remote_use_proxy_protocol"` // Use PROXY protocol for backend connections
	ConnectTimeout         string                `toml:"connect_timeout"`
	AuthRateLimit          AuthRateLimiterConfig `toml:"auth_rate_limit"` // Authentication rate limiting
	PreLookup              *PreLookupConfig      `toml:"prelookup"`       // Database-driven user routing
	EnableAffinity         bool                  `toml:"enable_affinity"`
	AffinityStickiness     float64               `toml:"affinity_stickiness"` // Probability (0.0 to 1.0) of using an affinity server.
	AffinityValidity       string                `toml:"affinity_validity"`
}

// LMTPProxyServerConfig holds LMTP proxy server configuration.
type LMTPProxyServerConfig struct {
	Start                  bool             `toml:"start"`
	Addr                   string           `toml:"addr"`
	RemoteAddrs            []string         `toml:"remote_addrs"`
	MaxConnections         int              `toml:"max_connections"`        // Maximum concurrent connections
	MaxConnectionsPerIP    int              `toml:"max_connections_per_ip"` // Maximum connections per IP address
	TLS                    bool             `toml:"tls"`
	TLSCertFile            string           `toml:"tls_cert_file"`
	TLSKeyFile             string           `toml:"tls_key_file"`
	TLSVerify              bool             `toml:"tls_verify"`
	RemoteTLS              bool             `toml:"remote_tls"`
	RemoteTLSVerify        bool             `toml:"remote_tls_verify"`
	RemoteUseProxyProtocol bool             `toml:"remote_use_proxy_protocol"` // Use PROXY protocol for backend connections
	ConnectTimeout         string           `toml:"connect_timeout"`
	EnableAffinity         bool             `toml:"enable_affinity"`
	AffinityStickiness     float64          `toml:"affinity_stickiness"` // Probability (0.0 to 1.0) of using an affinity server.
	AffinityValidity       string           `toml:"affinity_validity"`
	PreLookup              *PreLookupConfig `toml:"prelookup"` // Database-driven user routing
}

// ConnectionTrackingConfig holds connection tracking configuration.
type ConnectionTrackingConfig struct {
	Enabled                 bool   `toml:"enabled"`
	UpdateInterval          string `toml:"update_interval"`
	TerminationPollInterval string `toml:"termination_poll_interval"`
	BatchUpdates            bool   `toml:"batch_updates"`
	PersistToDB             bool   `toml:"persist_to_db"`
}

// RealIPConfig holds real IP extraction configuration
type RealIPConfig struct {
	Enabled        bool     `toml:"enabled"`         // Enable real IP extraction
	TrustedProxies []string `toml:"trusted_proxies"` // CIDR blocks of trusted proxies
	HeaderNames    []string `toml:"header_names"`    // Headers to check for real IP
}

// MetricsConfig holds metrics server configuration
type MetricsConfig struct {
	Enabled              bool   `toml:"enabled"`
	Addr                 string `toml:"addr"`
	Path                 string `toml:"path"`
	EnableUserMetrics    bool   `toml:"enable_user_metrics"`    // High-cardinality user metrics
	EnableDomainMetrics  bool   `toml:"enable_domain_metrics"`  // Domain-level metrics (safer)
	UserMetricsThreshold int    `toml:"user_metrics_threshold"` // Threshold for tracking users
	MaxTrackedUsers      int    `toml:"max_tracked_users"`      // Maximum users to track
	HashUsernames        bool   `toml:"hash_usernames"`         // Hash usernames for privacy
}

// HTTPAPIConfig holds HTTP API server configuration
type HTTPAPIConfig struct {
	Start        bool     `toml:"start"`
	Addr         string   `toml:"addr"`
	APIKey       string   `toml:"api_key"`
	AllowedHosts []string `toml:"allowed_hosts"` // If empty, all hosts are allowed
	TLS          bool     `toml:"tls"`
	TLSCertFile  string   `toml:"tls_cert_file"`
	TLSKeyFile   string   `toml:"tls_key_file"`
}

// ServersConfig holds all server configurations.
type ServersConfig struct {
	Debug              bool                         `toml:"debug"`
	IMAP               IMAPServerConfig             `toml:"imap"`
	LMTP               LMTPServerConfig             `toml:"lmtp"`
	POP3               POP3ServerConfig             `toml:"pop3"`
	ManageSieve        ManageSieveServerConfig      `toml:"managesieve"`
	IMAPProxy          IMAPProxyServerConfig        `toml:"imap_proxy"`
	POP3Proxy          POP3ProxyServerConfig        `toml:"pop3_proxy"`
	ManageSieveProxy   ManageSieveProxyServerConfig `toml:"managesieve_proxy"`
	LMTPProxy          LMTPProxyServerConfig        `toml:"lmtp_proxy"`
	ConnectionTracking ConnectionTrackingConfig     `toml:"connection_tracking"`
	RealIP             RealIPConfig                 `toml:"real_ip"`
	Metrics            MetricsConfig                `toml:"metrics"`
	HTTPAPI            HTTPAPIConfig                `toml:"http_api"`
}

// Config holds all configuration for the application.
type Config struct {
	LogOutput  string           `toml:"log_output"`
	Database   DatabaseConfig   `toml:"database"`
	S3         S3Config         `toml:"s3"`
	LocalCache LocalCacheConfig `toml:"local_cache"`
	Cleanup    CleanupConfig    `toml:"cleanup"`
	Servers    ServersConfig    `toml:"servers"`
	Uploader   UploaderConfig   `toml:"uploader"`
}

// NewDefaultConfig creates a Config struct with default values.
func NewDefaultConfig() Config {
	return Config{
		LogOutput: "syslog",
		Database: DatabaseConfig{
			QueryTimeout:  "30s",
			SearchTimeout: "1m",
			WriteTimeout:  "15s",
			LogQueries:    false,
			Write: &DatabaseEndpointConfig{
				Hosts:           []string{"localhost"},
				Port:            "5432",
				User:            "postgres",
				Password:        "",
				Name:            "sora_mail_db",
				TLSMode:         false,
				MaxConns:        100,
				MinConns:        10,
				MaxConnLifetime: "1h",
				MaxConnIdleTime: "30m",
				QueryTimeout:    "30s",
			},
			Read: &DatabaseEndpointConfig{
				Hosts:           []string{"localhost"},
				Port:            "5432",
				User:            "postgres",
				Password:        "",
				Name:            "sora_mail_db",
				TLSMode:         false,
				MaxConns:        100,
				MinConns:        10,
				MaxConnLifetime: "1h",
				MaxConnIdleTime: "30m",
				QueryTimeout:    "30s",
			},
		},
		S3: S3Config{
			Endpoint:      "",
			AccessKey:     "",
			SecretKey:     "",
			Bucket:        "",
			Encrypt:       false,
			EncryptionKey: "",
		},
		Cleanup: CleanupConfig{
			GracePeriod:           "14d",
			WakeInterval:          "1h",
			FTSRetention:          "730d", // 2 years default
			AuthAttemptsRetention: "7d",
			HealthStatusRetention: "30d",
		},
		LocalCache: LocalCacheConfig{
			Capacity:           "1gb",
			MaxObjectSize:      "5mb",
			Path:               "/tmp/sora/cache",
			MetricsInterval:    "5m",
			MetricsRetention:   "30d",
			PurgeInterval:      "12h",
			OrphanCleanupAge:   "30d",
			EnableWarmup:       true,
			WarmupMessageCount: 50,
			WarmupMailboxes:    []string{"INBOX"},
			WarmupAsync:        true,
		},
		Servers: ServersConfig{
			Debug: false,
			IMAP: IMAPServerConfig{
				Start:               true,
				Addr:                ":143",
				AppendLimit:         "25mb",
				MaxConnections:      1000,
				MaxConnectionsPerIP: 10,
				MasterUsername:      "",
				MasterPassword:      "",
				TLS:                 false,
				TLSCertFile:         "",
				TLSKeyFile:          "",
				TLSVerify:           true,
			},
			LMTP: LMTPServerConfig{
				Start:               true,
				Addr:                ":24",
				MaxConnections:      500,
				MaxConnectionsPerIP: 5,
				ExternalRelay:       "",
				TLS:                 false,
				TLSUseStartTLS:      false,
				TLSCertFile:         "",
				TLSKeyFile:          "",
				TLSVerify:           true,
			},
			POP3: POP3ServerConfig{
				Start:               true,
				Addr:                ":110",
				MaxConnections:      500,
				MaxConnectionsPerIP: 5,
				MasterSASLUsername:  "",
				MasterSASLPassword:  "",
				TLS:                 false,
				TLSCertFile:         "",
				TLSKeyFile:          "",
				TLSVerify:           true,
			},
			ManageSieve: ManageSieveServerConfig{
				Start:               true,
				Addr:                ":4190",
				MaxConnections:      200,
				MaxConnectionsPerIP: 3,
				MaxScriptSize:       "16kb",
				InsecureAuth:        false,
				MasterSASLUsername:  "",
				MasterSASLPassword:  "",
				TLS:                 false,
				TLSUseStartTLS:      false,
				TLSCertFile:         "",
				TLSKeyFile:          "",
				TLSVerify:           true,
			},
			IMAPProxy: IMAPProxyServerConfig{
				Start:                  false,
				Addr:                   ":1143",
				MaxConnections:         2000,
				MaxConnectionsPerIP:    50,
				MasterSASLUsername:     "",
				MasterSASLPassword:     "",
				TLS:                    false,
				RemoteTLS:              false,
				RemoteTLSVerify:        true,
				RemoteUseProxyProtocol: true, // Default to true for backward compatibility
				EnableAffinity:         true,
				AffinityStickiness:     0.9,
				AffinityValidity:       "24h",
			},
			POP3Proxy: POP3ProxyServerConfig{
				Start:                  false,
				Addr:                   ":1110",
				MaxConnections:         1000,
				MaxConnectionsPerIP:    20,
				MasterSASLUsername:     "",
				MasterSASLPassword:     "",
				TLS:                    false,
				RemoteTLS:              false,
				RemoteTLSVerify:        true,
				RemoteUseProxyProtocol: true, // Default to true for backward compatibility
				EnableAffinity:         true,
				AffinityStickiness:     0.9,
				AffinityValidity:       "24h",
				AuthRateLimit:          DefaultAuthRateLimiterConfig(),
			},
			ManageSieveProxy: ManageSieveProxyServerConfig{
				Start:                  false,
				Addr:                   ":14190",
				MaxConnections:         500,
				MaxConnectionsPerIP:    10,
				MasterSASLUsername:     "",
				MasterSASLPassword:     "",
				TLS:                    false,
				RemoteTLS:              false,
				RemoteTLSVerify:        true,
				RemoteUseProxyProtocol: true, // Default to true for backward compatibility
				AuthRateLimit:          DefaultAuthRateLimiterConfig(),
				EnableAffinity:         true,
				AffinityStickiness:     0.9,
				AffinityValidity:       "24h",
			},
			LMTPProxy: LMTPProxyServerConfig{
				Start:                  false,
				Addr:                   ":124",
				MaxConnections:         1000,
				MaxConnectionsPerIP:    0, // Disable per-IP limits for proxy scenarios
				TLS:                    false,
				RemoteTLS:              false,
				RemoteTLSVerify:        true,
				RemoteUseProxyProtocol: true, // Default to true for backward compatibility
				EnableAffinity:         true,
				AffinityStickiness:     0.9,
				AffinityValidity:       "24h",
			},
			ConnectionTracking: ConnectionTrackingConfig{
				Enabled:                 true,
				UpdateInterval:          "15s",
				TerminationPollInterval: "30s",
				BatchUpdates:            true,
				PersistToDB:             true,
			},
			RealIP: RealIPConfig{
				Enabled: false,
				TrustedProxies: []string{
					"127.0.0.0/8",    // localhost
					"10.0.0.0/8",     // RFC1918 private
					"172.16.0.0/12",  // RFC1918 private
					"192.168.0.0/16", // RFC1918 private
					"fc00::/7",       // IPv6 unique local
					"::1/128",        // IPv6 localhost
				},
				HeaderNames: []string{
					"X-Forwarded-For",
					"X-Real-IP",
					"CF-Connecting-IP",
					"True-Client-IP",
					"X-Forwarded",
					"Forwarded-For",
					"Forwarded",
				},
			},
			Metrics: MetricsConfig{
				Enabled:              true,
				Addr:                 ":9090",
				Path:                 "/metrics",
				EnableUserMetrics:    false,
				EnableDomainMetrics:  true,
				UserMetricsThreshold: 1000,
				MaxTrackedUsers:      1000,
				HashUsernames:        true,
			},
			HTTPAPI: HTTPAPIConfig{
				Start:        false,
				Addr:         ":8080",
				APIKey:       "",
				AllowedHosts: []string{},
				TLS:          false,
				TLSCertFile:  "",
				TLSKeyFile:   "",
			},
		},
		Uploader: UploaderConfig{
			Path:          "/tmp/sora/uploads",
			BatchSize:     10,
			Concurrency:   20,
			MaxAttempts:   5,
			RetryInterval: "30s",
		},
	}
}

// GetAppendLimit parses and returns the IMAP append limit
func (c *IMAPServerConfig) GetAppendLimit() (int64, error) {
	if c.AppendLimit == "" {
		c.AppendLimit = "25mb"
	}
	return helpers.ParseSize(c.AppendLimit)
}

// GetMaxScriptSize parses and returns the ManageSieve max script size
func (c *ManageSieveServerConfig) GetMaxScriptSize() (int64, error) {
	if c.MaxScriptSize == "" {
		c.MaxScriptSize = "16kb"
	}
	return helpers.ParseSize(c.MaxScriptSize)
}

// GetAppendLimit gets the append limit from IMAP server config
func (c *ServersConfig) GetAppendLimit() (int64, error) {
	return c.IMAP.GetAppendLimit()
}

// GetConnectTimeout parses the connect timeout duration for IMAP proxy
func (c *IMAPProxyServerConfig) GetConnectTimeout() (time.Duration, error) {
	if c.ConnectTimeout == "" {
		return 30 * time.Second, nil
	}
	return helpers.ParseDuration(c.ConnectTimeout)
}

// GetConnectTimeout parses the connect timeout duration for POP3 proxy
func (c *POP3ProxyServerConfig) GetConnectTimeout() (time.Duration, error) {
	if c.ConnectTimeout == "" {
		return 30 * time.Second, nil
	}
	return helpers.ParseDuration(c.ConnectTimeout)
}

// GetAffinityValidity parses the affinity validity duration for POP3 proxy
func (c *POP3ProxyServerConfig) GetAffinityValidity() (time.Duration, error) {
	if c.AffinityValidity == "" {
		return 24 * time.Hour, nil
	}
	return helpers.ParseDuration(c.AffinityValidity)
}

// GetConnectTimeout parses the connect timeout duration for ManageSieve proxy
func (c *ManageSieveProxyServerConfig) GetConnectTimeout() (time.Duration, error) {
	if c.ConnectTimeout == "" {
		return 30 * time.Second, nil
	}
	return helpers.ParseDuration(c.ConnectTimeout)
}

// GetAffinityValidity parses the affinity validity duration for ManageSieve proxy
func (c *ManageSieveProxyServerConfig) GetAffinityValidity() (time.Duration, error) {
	if c.AffinityValidity == "" {
		return 24 * time.Hour, nil
	}
	return helpers.ParseDuration(c.AffinityValidity)
}

// GetUpdateInterval parses the update interval duration for connection tracking
func (c *ConnectionTrackingConfig) GetUpdateInterval() (time.Duration, error) {
	if c.UpdateInterval == "" {
		return 15 * time.Second, nil
	}
	return helpers.ParseDuration(c.UpdateInterval)
}

// GetTerminationPollInterval parses the termination poll interval duration for connection tracking
func (c *ConnectionTrackingConfig) GetTerminationPollInterval() (time.Duration, error) {
	if c.TerminationPollInterval == "" {
		return 30 * time.Second, nil
	}
	return helpers.ParseDuration(c.TerminationPollInterval)
}

// GetConnectTimeout parses the connect timeout duration for LMTP proxy
func (c *LMTPProxyServerConfig) GetConnectTimeout() (time.Duration, error) {
	if c.ConnectTimeout == "" {
		return 30 * time.Second, nil
	}
	return helpers.ParseDuration(c.ConnectTimeout)
}

// GetAffinityValidity parses the affinity validity duration for LMTP proxy
func (c *LMTPProxyServerConfig) GetAffinityValidity() (time.Duration, error) {
	if c.AffinityValidity == "" {
		return 24 * time.Hour, nil
	}
	return helpers.ParseDuration(c.AffinityValidity)
}

// GetAffinityValidity parses the affinity validity duration for IMAP proxy
func (c *IMAPProxyServerConfig) GetAffinityValidity() (time.Duration, error) {
	if c.AffinityValidity == "" {
		return 24 * time.Hour, nil
	}
	return helpers.ParseDuration(c.AffinityValidity)
}
