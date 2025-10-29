package config

import (
	"fmt"
	"log"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/migadu/sora/helpers"
)

// ClientCapabilityFilter defines capability filtering rules for specific clients
type ClientCapabilityFilter struct {
	ClientName      string   `toml:"client_name"`      // Client name pattern (regex)
	ClientVersion   string   `toml:"client_version"`   // Client version pattern (regex)
	JA4Fingerprints []string `toml:"ja4_fingerprints"` // JA4 TLS fingerprint patterns (regex). Can be a single string or array. Useful when a client has multiple fingerprints across versions/platforms. Format: "t13d1516h2_8daaf6152771_e5627efa2ab1"
	DisableCaps     []string `toml:"disable_caps"`     // List of capabilities to disable
	Reason          string   `toml:"reason"`           // Human-readable reason for the filter
}

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
	Debug            bool                    `toml:"debug"`             // Enable SQL query logging
	QueryTimeout     string                  `toml:"query_timeout"`     // Default timeout for all database queries (default: "30s")
	SearchTimeout    string                  `toml:"search_timeout"`    // Specific timeout for complex search queries (default: "60s")
	WriteTimeout     string                  `toml:"write_timeout"`     // Timeout for write operations (default: "10s")
	MigrationTimeout string                  `toml:"migration_timeout"` // Timeout for auto-migrations at startup (default: "2m")
	Write            *DatabaseEndpointConfig `toml:"write"`             // Write database configuration
	Read             *DatabaseEndpointConfig `toml:"read"`              // Read database configuration (can have multiple hosts for load balancing)
	PoolTypeOverride string                  `toml:"-"`                 // Internal: Override pool type in logs (not in config file)
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

// GetDebug returns the debug flag
func (d *DatabaseConfig) GetDebug() bool {
	return d.Debug
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

// GetMigrationTimeout parses the migration timeout duration
func (d *DatabaseConfig) GetMigrationTimeout() (time.Duration, error) {
	if d.MigrationTimeout == "" {
		return 2 * time.Minute, nil // Default 2 minute timeout for auto-migrations
	}
	return helpers.ParseDuration(d.MigrationTimeout)
}

// S3Config holds S3 configuration.
type S3Config struct {
	Endpoint      string `toml:"endpoint"`
	DisableTLS    bool   `toml:"disable_tls"`
	AccessKey     string `toml:"access_key"`
	SecretKey     string `toml:"secret_key"`
	Bucket        string `toml:"bucket"`
	Debug         bool   `toml:"debug"` // Enable detailed S3 request/response tracing
	Encrypt       bool   `toml:"encrypt"`
	EncryptionKey string `toml:"encryption_key"`
}

// GetDebug returns the debug flag
func (s *S3Config) GetDebug() bool {
	return s.Debug
}

// ClusterRateLimitSyncConfig holds configuration for cluster-wide auth rate limiting
type ClusterRateLimitSyncConfig struct {
	Enabled           bool `toml:"enabled"`             // Enable cluster-wide rate limiting (default: true if cluster enabled)
	SyncBlocks        bool `toml:"sync_blocks"`         // Sync IP blocks across cluster (default: true)
	SyncFailureCounts bool `toml:"sync_failure_counts"` // Sync progressive delay failure counts (default: true)
}

// ClusterAffinityConfig holds configuration for cluster-wide server affinity
type ClusterAffinityConfig struct {
	Enabled         bool   `toml:"enabled"`          // Enable cluster-wide affinity (default: false)
	TTL             string `toml:"ttl"`              // How long affinity persists (default: "24h")
	CleanupInterval string `toml:"cleanup_interval"` // How often to clean up expired affinities (default: "1h")
}

// ClusterConfig holds cluster coordination configuration using gossip protocol
type ClusterConfig struct {
	Enabled           bool                       `toml:"enabled"`              // Enable cluster mode
	Addr              string                     `toml:"addr"`                 // Gossip listen address (must be specific IP:port, NOT 0.0.0.0 or localhost)
	Port              int                        `toml:"port"`                 // Gossip port (used if not specified in addr)
	NodeID            string                     `toml:"node_id"`              // Unique node ID (defaults to hostname)
	Peers             []string                   `toml:"peers"`                // Initial seed nodes
	SecretKey         string                     `toml:"secret_key"`           // Cluster encryption key (base64-encoded 32-byte key)
	MaxEventQueueSize int                        `toml:"max_event_queue_size"` // Maximum events per protocol queue (default: 50000)
	RateLimitSync     ClusterRateLimitSyncConfig `toml:"rate_limit_sync"`      // Auth rate limiting sync configuration
	Affinity          ClusterAffinityConfig      `toml:"affinity"`             // Server affinity configuration
}

// GetBindAddr returns the bind address by parsing the addr field
func (c *ClusterConfig) GetBindAddr() string {
	if c.Addr == "" {
		return ""
	}
	// Parse addr to extract just the IP (not port)
	if strings.Contains(c.Addr, ":") {
		parts := strings.Split(c.Addr, ":")
		return parts[0]
	}
	return c.Addr
}

// GetBindPort returns the bind port from addr or the port field
func (c *ClusterConfig) GetBindPort() int {
	// If addr contains a port, use that
	if c.Addr != "" && strings.Contains(c.Addr, ":") {
		parts := strings.Split(c.Addr, ":")
		if len(parts) == 2 {
			if port, err := strconv.Atoi(parts[1]); err == nil {
				return port
			}
		}
	}

	// Otherwise use explicit port field
	if c.Port > 0 {
		return c.Port
	}

	// Default to 7946
	return 7946
}

// GetMaxEventQueueSize returns the maximum event queue size with a default of 50000
func (c *ClusterConfig) GetMaxEventQueueSize() int {
	if c.MaxEventQueueSize > 0 {
		return c.MaxEventQueueSize
	}
	return 50000 // Default: sufficient for busy servers
}

// TLSLetsEncryptS3Config holds S3-specific configuration for Let's Encrypt certificate storage
type TLSLetsEncryptS3Config struct {
	Bucket          string `toml:"bucket"`            // S3 bucket for certificate storage
	Endpoint        string `toml:"endpoint"`          // S3-compatible storage endpoint (default: "s3.amazonaws.com")
	DisableTLS      bool   `toml:"disable_tls"`       // Disable TLS for S3 endpoint (useful for local MinIO setups)
	Debug           bool   `toml:"debug"`             // Enable detailed S3 request/response tracing
	AccessKeyID     string `toml:"access_key_id"`     // AWS credentials (optional, uses default chain)
	SecretAccessKey string `toml:"secret_access_key"` // AWS credentials (optional)
}

// TLSLetsEncryptConfig holds Let's Encrypt automatic certificate management configuration
type TLSLetsEncryptConfig struct {
	Email           string                 `toml:"email"`            // Email for Let's Encrypt notifications
	Domains         []string               `toml:"domains"`          // Domains for certificate (supports multiple)
	DefaultDomain   string                 `toml:"default_domain"`   // Default domain to use when client doesn't provide SNI (optional, defaults to first domain in list)
	StorageProvider string                 `toml:"storage_provider"` // Certificate storage backend (currently only "s3")
	S3              TLSLetsEncryptS3Config `toml:"s3"`               // S3 storage configuration
	RenewBefore     string                 `toml:"renew_before"`     // Renew certificates this duration before expiry (e.g., "720h" = 30 days). Default: 30 days
	EnableFallback  bool                   `toml:"enable_fallback"`  // Enable local filesystem fallback when S3 is unavailable (default: true)
	FallbackDir     string                 `toml:"fallback_dir"`     // Local directory for certificate fallback when S3 is unavailable (default: "/var/lib/sora/certs")
	SyncInterval    string                 `toml:"sync_interval"`    // Interval to check S3 for certificate updates (e.g., "5m"). Default: 5m. Set to "0" to disable periodic sync.
}

// TLSConfig holds TLS/SSL configuration
type TLSConfig struct {
	Enabled     bool                  `toml:"enabled"`     // Enable HTTPS/TLS
	Provider    string                `toml:"provider"`    // TLS provider: "file" or "letsencrypt"
	CertFile    string                `toml:"cert_file"`   // Certificate file (for provider="file")
	KeyFile     string                `toml:"key_file"`    // Private key file (for provider="file")
	LetsEncrypt *TLSLetsEncryptConfig `toml:"letsencrypt"` // Let's Encrypt configuration
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
	WarmupInterval     string   `toml:"warmup_interval"`
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
	Mode           string   `toml:"mode,omitempty"`  // "required" (default) or "optional"
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

// AuthCacheConfig holds configuration for authentication result caching
type AuthCacheConfig struct {
	Enabled         bool   `toml:"enabled"`          // Enable in-memory caching of authentication results
	PositiveTTL     string `toml:"positive_ttl"`     // TTL for successful auth (default: "30s")
	NegativeTTL     string `toml:"negative_ttl"`     // TTL for failed auth (default: "5m")
	MaxSize         int    `toml:"max_size"`         // Maximum number of cached entries (default: 10000)
	CleanupInterval string `toml:"cleanup_interval"` // How often to clean expired entries (default: "5m")
}

// DefaultAuthCacheConfig returns sensible defaults for authentication caching
func DefaultAuthCacheConfig() AuthCacheConfig {
	return AuthCacheConfig{
		Enabled:         false,
		PositiveTTL:     "30s",
		NegativeTTL:     "5m",
		MaxSize:         10000,
		CleanupInterval: "5m",
	}
}

// PreLookupConfig holds configuration for HTTP-based user routing
// PreLookupCacheConfig holds caching configuration for prelookup
type PreLookupCacheConfig struct {
	Enabled         bool   `toml:"enabled"`          // Enable in-memory caching of lookup results
	PositiveTTL     string `toml:"positive_ttl"`     // TTL for successful lookups (default: "5m")
	NegativeTTL     string `toml:"negative_ttl"`     // TTL for failed lookups (default: "1m")
	MaxSize         int    `toml:"max_size"`         // Maximum number of cached entries (default: 10000)
	CleanupInterval string `toml:"cleanup_interval"` // How often to clean expired entries (default: "1m")
}

type PreLookupConfig struct {
	Enabled   bool   `toml:"enabled"`
	URL       string `toml:"url"`        // HTTP endpoint URL for lookups (e.g., "http://localhost:8080/lookup")
	Timeout   string `toml:"timeout"`    // HTTP request timeout (default: "5s")
	AuthToken string `toml:"auth_token"` // Bearer token for HTTP authentication (optional)

	// Backend connection settings
	FallbackDefault        bool        `toml:"fallback_to_default"`       // Fallback to default routing if lookup fails
	RemoteTLS              bool        `toml:"remote_tls"`                // Use TLS for backend connections
	RemoteTLSUseStartTLS   bool        `toml:"remote_tls_use_starttls"`   // Use STARTTLS for backend connections (LMTP/ManageSieve only)
	RemoteTLSVerify        *bool       `toml:"remote_tls_verify"`         // Verify backend TLS certificate
	RemotePort             interface{} `toml:"remote_port"`               // Default port for routed backends if not in address
	RemoteUseProxyProtocol bool        `toml:"remote_use_proxy_protocol"` // Use PROXY protocol for backend connections
	RemoteUseIDCommand     bool        `toml:"remote_use_id_command"`     // Use IMAP ID command (IMAP only)
	RemoteUseXCLIENT       bool        `toml:"remote_use_xclient"`        // Use XCLIENT command (POP3/LMTP)

	// Cache configuration
	Cache *PreLookupCacheConfig `toml:"cache"` // Caching configuration

	// Circuit breaker configuration
	CircuitBreaker *PreLookupCircuitBreakerConfig `toml:"circuit_breaker"` // Circuit breaker configuration

	// HTTP transport configuration
	Transport *PreLookupTransportConfig `toml:"transport"` // HTTP transport connection pooling settings
}

// PreLookupCircuitBreakerConfig holds circuit breaker configuration for prelookup
type PreLookupCircuitBreakerConfig struct {
	MaxRequests  int     `toml:"max_requests"`  // Maximum concurrent requests in half-open state (default: 3)
	Interval     string  `toml:"interval"`      // Time before resetting failure counts in closed state (default: "0s" - never reset)
	Timeout      string  `toml:"timeout"`       // Time before transitioning from open to half-open (default: "30s")
	FailureRatio float64 `toml:"failure_ratio"` // Failure ratio threshold to open circuit (0.0-1.0, default: 0.6)
	MinRequests  int     `toml:"min_requests"`  // Minimum requests before evaluating failure ratio (default: 3)
}

// PreLookupTransportConfig holds HTTP transport configuration for prelookup connection pooling
type PreLookupTransportConfig struct {
	MaxIdleConns        int    `toml:"max_idle_conns"`          // Maximum idle connections across all hosts (default: 100)
	MaxIdleConnsPerHost int    `toml:"max_idle_conns_per_host"` // Maximum idle connections per host (default: 100)
	MaxConnsPerHost     int    `toml:"max_conns_per_host"`      // Maximum total connections per host, 0 = unlimited (default: 0)
	IdleConnTimeout     string `toml:"idle_conn_timeout"`       // How long idle connections stay open (default: "90s")
}

// GetTimeout returns the configured HTTP timeout duration
func (c *PreLookupConfig) GetTimeout() (time.Duration, error) {
	if c.Timeout == "" {
		return 5 * time.Second, nil
	}
	return helpers.ParseDuration(c.Timeout)
}

// GetPositiveTTL returns the positive cache TTL duration
func (c *PreLookupCacheConfig) GetPositiveTTL() (time.Duration, error) {
	if c.PositiveTTL == "" {
		return 5 * time.Minute, nil
	}
	return helpers.ParseDuration(c.PositiveTTL)
}

// GetNegativeTTL returns the negative cache TTL duration
func (c *PreLookupCacheConfig) GetNegativeTTL() (time.Duration, error) {
	if c.NegativeTTL == "" {
		return 1 * time.Minute, nil
	}
	return helpers.ParseDuration(c.NegativeTTL)
}

// GetCleanupInterval returns the cache cleanup interval
func (c *PreLookupCacheConfig) GetCleanupInterval() (time.Duration, error) {
	if c.CleanupInterval == "" {
		return 1 * time.Minute, nil
	}
	return helpers.ParseDuration(c.CleanupInterval)
}

// Circuit breaker configuration helpers

// GetMaxRequests returns the maximum concurrent requests in half-open state
func (c *PreLookupCircuitBreakerConfig) GetMaxRequests() uint32 {
	if c.MaxRequests <= 0 {
		return 3 // Default: 3 concurrent requests
	}
	return uint32(c.MaxRequests)
}

// GetInterval returns the interval before resetting failure counts in closed state
func (c *PreLookupCircuitBreakerConfig) GetInterval() (time.Duration, error) {
	if c.Interval == "" {
		return 0, nil // Default: never reset automatically
	}
	return helpers.ParseDuration(c.Interval)
}

// GetTimeout returns the timeout before transitioning from open to half-open
func (c *PreLookupCircuitBreakerConfig) GetTimeout() (time.Duration, error) {
	if c.Timeout == "" {
		return 30 * time.Second, nil // Default: 30 seconds
	}
	return helpers.ParseDuration(c.Timeout)
}

// GetFailureRatio returns the failure ratio threshold to open circuit
func (c *PreLookupCircuitBreakerConfig) GetFailureRatio() float64 {
	if c.FailureRatio <= 0 || c.FailureRatio > 1 {
		return 0.6 // Default: 60% failure rate
	}
	return c.FailureRatio
}

// GetMinRequests returns the minimum requests before evaluating failure ratio
func (c *PreLookupCircuitBreakerConfig) GetMinRequests() uint32 {
	if c.MinRequests <= 0 {
		return 3 // Default: 3 requests
	}
	return uint32(c.MinRequests)
}

// Transport configuration helpers

// GetMaxIdleConns returns the maximum idle connections across all hosts
func (c *PreLookupTransportConfig) GetMaxIdleConns() int {
	if c.MaxIdleConns <= 0 {
		return 100 // Default: 100 idle connections
	}
	return c.MaxIdleConns
}

// GetMaxIdleConnsPerHost returns the maximum idle connections per host
func (c *PreLookupTransportConfig) GetMaxIdleConnsPerHost() int {
	if c.MaxIdleConnsPerHost <= 0 {
		return 100 // Default: 100 idle connections per host
	}
	return c.MaxIdleConnsPerHost
}

// GetMaxConnsPerHost returns the maximum total connections per host (0 = unlimited)
func (c *PreLookupTransportConfig) GetMaxConnsPerHost() int {
	return c.MaxConnsPerHost // Default: 0 (unlimited)
}

// GetIdleConnTimeout returns the idle connection timeout duration
func (c *PreLookupTransportConfig) GetIdleConnTimeout() (time.Duration, error) {
	if c.IdleConnTimeout == "" {
		return 90 * time.Second, nil // Default: 90 seconds
	}
	return helpers.ParseDuration(c.IdleConnTimeout)
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

// GetRemotePort parses the remote port for IMAP proxy and returns it as an int.
func (c *IMAPProxyServerConfig) GetRemotePort() (int, error) {
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

// GetRemotePort parses the remote port for POP3 proxy and returns it as an int.
func (c *POP3ProxyServerConfig) GetRemotePort() (int, error) {
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

// GetRemotePort parses the remote port for ManageSieve proxy and returns it as an int.
func (c *ManageSieveProxyServerConfig) GetRemotePort() (int, error) {
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

// GetRemotePort parses the remote port for LMTP proxy and returns it as an int.
func (c *LMTPProxyServerConfig) GetRemotePort() (int, error) {
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
	Start                  bool                  `toml:"start"`
	Addr                   string                `toml:"addr"`
	AppendLimit            string                `toml:"append_limit"`
	MaxConnections         int                   `toml:"max_connections"`        // Maximum concurrent connections
	MaxConnectionsPerIP    int                   `toml:"max_connections_per_ip"` // Maximum connections per IP address
	MasterUsername         string                `toml:"master_username"`
	MasterPassword         string                `toml:"master_password"`
	MasterSASLUsername     string                `toml:"master_sasl_username"`
	MasterSASLPassword     string                `toml:"master_sasl_password"`
	TLS                    bool                  `toml:"tls"`
	TLSCertFile            string                `toml:"tls_cert_file"`
	TLSKeyFile             string                `toml:"tls_key_file"`
	TLSVerify              bool                  `toml:"tls_verify"`
	DisabledCaps           []string              `toml:"disabled_caps"`             // List of capabilities to disable globally for this server
	AuthRateLimit          AuthRateLimiterConfig `toml:"auth_rate_limit"`           // Authentication rate limiting
	SearchRateLimitPerMin  int                   `toml:"search_rate_limit_per_min"` // Search rate limit (searches per minute, 0=disabled)
	SearchRateLimitWindow  string                `toml:"search_rate_limit_window"`  // Search rate limit time window (default: 1m)
	CommandTimeout         string                `toml:"command_timeout"`           // Maximum idle time before disconnection (e.g., "5m", default: 5 minutes)
	AbsoluteSessionTimeout string                `toml:"absolute_session_timeout"`  // Maximum total session duration (e.g., "30m", default: 30 minutes)
	MinBytesPerMinute      int64                 `toml:"min_bytes_per_minute"`      // Minimum throughput to prevent slowloris (default: 1024 bytes/min, 0=use default)
}

// GetSearchRateLimitWindow parses the search rate limit window duration
func (i *IMAPServerConfig) GetSearchRateLimitWindow() (time.Duration, error) {
	if i.SearchRateLimitWindow == "" {
		return time.Minute, nil // Default: 1 minute
	}
	return helpers.ParseDuration(i.SearchRateLimitWindow)
}

// GetCommandTimeout parses the command timeout duration for IMAP
func (i *IMAPServerConfig) GetCommandTimeout() (time.Duration, error) {
	if i.CommandTimeout == "" {
		return 5 * time.Minute, nil // Default: 5 minutes for IMAP commands
	}
	return helpers.ParseDuration(i.CommandTimeout)
}

// GetAbsoluteSessionTimeout parses the absolute session timeout duration for IMAP
func (i *IMAPServerConfig) GetAbsoluteSessionTimeout() (time.Duration, error) {
	if i.AbsoluteSessionTimeout == "" {
		return 30 * time.Minute, nil // Default: 30 minutes for IMAP sessions
	}
	return helpers.ParseDuration(i.AbsoluteSessionTimeout)
}

// LMTPServerConfig holds LMTP server configuration.
type LMTPServerConfig struct {
	Start               bool   `toml:"start"`
	Addr                string `toml:"addr"`
	MaxConnections      int    `toml:"max_connections"`        // Maximum concurrent connections
	MaxConnectionsPerIP int    `toml:"max_connections_per_ip"` // Maximum connections per IP address
	ExternalRelay       string `toml:"external_relay"`
	TLS                 bool   `toml:"tls"`
	TLSUseStartTLS      bool   `toml:"tls_use_starttls"`
	TLSCertFile         string `toml:"tls_cert_file"`
	TLSKeyFile          string `toml:"tls_key_file"`
	TLSVerify           bool   `toml:"tls_verify"`
}

// POP3ServerConfig holds POP3 server configuration.
type POP3ServerConfig struct {
	Start                  bool                  `toml:"start"`
	Addr                   string                `toml:"addr"`
	MaxConnections         int                   `toml:"max_connections"`        // Maximum concurrent connections
	MaxConnectionsPerIP    int                   `toml:"max_connections_per_ip"` // Maximum connections per IP address
	MasterSASLUsername     string                `toml:"master_sasl_username"`
	MasterSASLPassword     string                `toml:"master_sasl_password"`
	TLS                    bool                  `toml:"tls"`
	TLSCertFile            string                `toml:"tls_cert_file"`
	TLSKeyFile             string                `toml:"tls_key_file"`
	TLSVerify              bool                  `toml:"tls_verify"`
	AuthRateLimit          AuthRateLimiterConfig `toml:"auth_rate_limit"`          // Authentication rate limiting
	CommandTimeout         string                `toml:"command_timeout"`          // Maximum idle time before disconnection (default: 2m)
	AbsoluteSessionTimeout string                `toml:"absolute_session_timeout"` // Maximum total session duration (default: 30m)
	MinBytesPerMinute      int64                 `toml:"min_bytes_per_minute"`     // Minimum throughput to prevent slowloris (default: 1024 bytes/min, 0=use default)
}

// GetCommandTimeout parses the command timeout duration for POP3
func (c *POP3ServerConfig) GetCommandTimeout() (time.Duration, error) {
	if c.CommandTimeout == "" {
		return 2 * time.Minute, nil // Default: 2 minutes for POP3 commands
	}
	return helpers.ParseDuration(c.CommandTimeout)
}

// GetAbsoluteSessionTimeout parses the absolute session timeout duration for POP3
func (c *POP3ServerConfig) GetAbsoluteSessionTimeout() (time.Duration, error) {
	if c.AbsoluteSessionTimeout == "" {
		return 30 * time.Minute, nil // Default: 30 minutes for POP3 sessions
	}
	return helpers.ParseDuration(c.AbsoluteSessionTimeout)
}

// ManageSieveServerConfig holds ManageSieve server configuration.
type ManageSieveServerConfig struct {
	Start                  bool                  `toml:"start"`
	Addr                   string                `toml:"addr"`
	MaxConnections         int                   `toml:"max_connections"`        // Maximum concurrent connections
	MaxConnectionsPerIP    int                   `toml:"max_connections_per_ip"` // Maximum connections per IP address
	MaxScriptSize          string                `toml:"max_script_size"`
	SupportedExtensions    []string              `toml:"supported_extensions"` // List of supported Sieve extensions
	InsecureAuth           bool                  `toml:"insecure_auth"`
	MasterSASLUsername     string                `toml:"master_sasl_username"`
	MasterSASLPassword     string                `toml:"master_sasl_password"`
	TLS                    bool                  `toml:"tls"`
	TLSUseStartTLS         bool                  `toml:"tls_use_starttls"`
	TLSCertFile            string                `toml:"tls_cert_file"`
	TLSKeyFile             string                `toml:"tls_key_file"`
	TLSVerify              bool                  `toml:"tls_verify"`
	AuthRateLimit          AuthRateLimiterConfig `toml:"auth_rate_limit"`          // Authentication rate limiting
	CommandTimeout         string                `toml:"command_timeout"`          // Maximum idle time before disconnection (default: 3m)
	AbsoluteSessionTimeout string                `toml:"absolute_session_timeout"` // Maximum total session duration (default: 30m)
	MinBytesPerMinute      int64                 `toml:"min_bytes_per_minute"`     // Minimum throughput to prevent slowloris (default: 1024 bytes/min, 0=use default)
}

// GetCommandTimeout parses the command timeout duration for ManageSieve
func (c *ManageSieveServerConfig) GetCommandTimeout() (time.Duration, error) {
	if c.CommandTimeout == "" {
		return 3 * time.Minute, nil // Default: 3 minutes for ManageSieve commands
	}
	return helpers.ParseDuration(c.CommandTimeout)
}

// GetAbsoluteSessionTimeout parses the absolute session timeout duration for ManageSieve
func (c *ManageSieveServerConfig) GetAbsoluteSessionTimeout() (time.Duration, error) {
	if c.AbsoluteSessionTimeout == "" {
		return 30 * time.Minute, nil // Default: 30 minutes for ManageSieve sessions
	}
	return helpers.ParseDuration(c.AbsoluteSessionTimeout)
}

// IMAPProxyServerConfig holds IMAP proxy server configuration.
type IMAPProxyServerConfig struct {
	Start                  bool                  `toml:"start"`
	Addr                   string                `toml:"addr"`
	RemoteAddrs            []string              `toml:"remote_addrs"`
	RemotePort             interface{}           `toml:"remote_port"`            // Default port for backends if not in address
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
	RemoteUseIDCommand     bool                  `toml:"remote_use_id_command"`     // Use IMAP ID command for forwarding client info
	ConnectTimeout         string                `toml:"connect_timeout"`
	SessionTimeout         string                `toml:"session_timeout"`          // Maximum session duration
	CommandTimeout         string                `toml:"command_timeout"`          // Maximum idle time (e.g., "5m")
	AbsoluteSessionTimeout string                `toml:"absolute_session_timeout"` // Maximum total session duration (e.g., "30m")
	MinBytesPerMinute      int64                 `toml:"min_bytes_per_minute"`     // Minimum throughput to prevent slowloris attacks
	EnableAffinity         bool                  `toml:"enable_affinity"`
	AuthRateLimit          AuthRateLimiterConfig `toml:"auth_rate_limit"` // Authentication rate limiting
	PreLookup              *PreLookupConfig      `toml:"prelookup"`       // Database-driven user routing
}

// POP3ProxyServerConfig holds POP3 proxy server configuration.
type POP3ProxyServerConfig struct {
	Start                  bool                  `toml:"start"`
	Addr                   string                `toml:"addr"`
	RemoteAddrs            []string              `toml:"remote_addrs"`
	RemotePort             interface{}           `toml:"remote_port"`            // Default port for backends if not in address
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
	RemoteUseXCLIENT       bool                  `toml:"remote_use_xclient"`        // Use XCLIENT command for forwarding client info
	ConnectTimeout         string                `toml:"connect_timeout"`
	SessionTimeout         string                `toml:"session_timeout"`          // Maximum session duration
	CommandTimeout         string                `toml:"command_timeout"`          // Maximum idle time (e.g., "5m")
	AbsoluteSessionTimeout string                `toml:"absolute_session_timeout"` // Maximum total session duration (e.g., "30m")
	MinBytesPerMinute      int64                 `toml:"min_bytes_per_minute"`     // Minimum throughput to prevent slowloris attacks
	EnableAffinity         bool                  `toml:"enable_affinity"`
	AuthRateLimit          AuthRateLimiterConfig `toml:"auth_rate_limit"` // Authentication rate limiting
	PreLookup              *PreLookupConfig      `toml:"prelookup"`       // Database-driven user routing
}

// ManageSieveProxyServerConfig holds ManageSieve proxy server configuration.
type ManageSieveProxyServerConfig struct {
	Start                  bool                  `toml:"start"`
	Addr                   string                `toml:"addr"`
	RemoteAddrs            []string              `toml:"remote_addrs"`
	RemotePort             interface{}           `toml:"remote_port"`            // Default port for backends if not in address
	MaxConnections         int                   `toml:"max_connections"`        // Maximum concurrent connections
	MaxConnectionsPerIP    int                   `toml:"max_connections_per_ip"` // Maximum connections per IP address
	InsecureAuth           bool                  `toml:"insecure_auth"`
	MasterSASLUsername     string                `toml:"master_sasl_username"`
	MasterSASLPassword     string                `toml:"master_sasl_password"`
	TLS                    bool                  `toml:"tls"`
	TLSUseStartTLS         bool                  `toml:"tls_use_starttls"` // Use STARTTLS on listening port
	TLSCertFile            string                `toml:"tls_cert_file"`
	TLSKeyFile             string                `toml:"tls_key_file"`
	TLSVerify              bool                  `toml:"tls_verify"`
	RemoteTLS              bool                  `toml:"remote_tls"`
	RemoteTLSUseStartTLS   bool                  `toml:"remote_tls_use_starttls"` // Use STARTTLS for backend connections
	RemoteTLSVerify        bool                  `toml:"remote_tls_verify"`
	RemoteUseProxyProtocol bool                  `toml:"remote_use_proxy_protocol"` // Use PROXY protocol for backend connections
	ConnectTimeout         string                `toml:"connect_timeout"`
	SessionTimeout         string                `toml:"session_timeout"`          // Maximum session duration
	CommandTimeout         string                `toml:"command_timeout"`          // Maximum idle time (e.g., "5m")
	AbsoluteSessionTimeout string                `toml:"absolute_session_timeout"` // Maximum total session duration (e.g., "30m")
	MinBytesPerMinute      int64                 `toml:"min_bytes_per_minute"`     // Minimum throughput to prevent slowloris attacks
	AuthRateLimit          AuthRateLimiterConfig `toml:"auth_rate_limit"`          // Authentication rate limiting
	PreLookup              *PreLookupConfig      `toml:"prelookup"`                // Database-driven user routing
	EnableAffinity         bool                  `toml:"enable_affinity"`
	AffinityStickiness     float64               `toml:"affinity_stickiness"` // Probability (0.0 to 1.0) of using an affinity server.
	AffinityValidity       string                `toml:"affinity_validity"`
}

// LMTPProxyServerConfig holds LMTP proxy server configuration.
type LMTPProxyServerConfig struct {
	Start                  bool             `toml:"start"`
	Addr                   string           `toml:"addr"`
	RemoteAddrs            []string         `toml:"remote_addrs"`
	RemotePort             interface{}      `toml:"remote_port"`            // Default port for backends if not in address
	MaxConnections         int              `toml:"max_connections"`        // Maximum concurrent connections
	MaxConnectionsPerIP    int              `toml:"max_connections_per_ip"` // Maximum connections per IP address
	TLS                    bool             `toml:"tls"`
	TLSUseStartTLS         bool             `toml:"tls_use_starttls"` // Use STARTTLS on listening port
	TLSCertFile            string           `toml:"tls_cert_file"`
	TLSKeyFile             string           `toml:"tls_key_file"`
	TLSVerify              bool             `toml:"tls_verify"`
	RemoteTLS              bool             `toml:"remote_tls"`
	RemoteTLSUseStartTLS   bool             `toml:"remote_tls_use_starttls"` // Use STARTTLS for backend connections
	RemoteTLSVerify        bool             `toml:"remote_tls_verify"`
	RemoteUseProxyProtocol bool             `toml:"remote_use_proxy_protocol"` // Use PROXY protocol for backend connections
	RemoteUseXCLIENT       bool             `toml:"remote_use_xclient"`        // Use XCLIENT command for forwarding client info
	ConnectTimeout         string           `toml:"connect_timeout"`
	SessionTimeout         string           `toml:"session_timeout"`  // Maximum session duration
	MaxMessageSize         string           `toml:"max_message_size"` // Maximum message size announced in EHLO
	EnableAffinity         bool             `toml:"enable_affinity"`
	AffinityStickiness     float64          `toml:"affinity_stickiness"` // Probability (0.0 to 1.0) of using an affinity server.
	AffinityValidity       string           `toml:"affinity_validity"`
	PreLookup              *PreLookupConfig `toml:"prelookup"` // Database-driven user routing
}

// ConnectionTrackingConfig is deprecated - connection tracking is now configured per-server
// via ServerConfig.MaxConnectionsPerUser. This type is kept for backward compatibility.
type ConnectionTrackingConfig struct {
	Enabled               bool `toml:"enabled"`                  // Ignored
	MaxConnectionsPerUser int  `toml:"max_connections_per_user"` // Ignored - use per-server config instead
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
	TLSVerify    bool     `toml:"tls_verify"` // Verify client certificates (mutual TLS)
}

// UserAPIServerConfig holds User API server configuration
type UserAPIServerConfig struct {
	Start          bool     `toml:"start"`
	Addr           string   `toml:"addr"`
	JWTSecret      string   `toml:"jwt_secret"`
	TokenDuration  string   `toml:"token_duration"`  // JWT token validity duration (default: 24h)
	TokenIssuer    string   `toml:"token_issuer"`    // JWT issuer (default: sora-mail-api)
	AllowedOrigins []string `toml:"allowed_origins"` // CORS allowed origins
	AllowedHosts   []string `toml:"allowed_hosts"`   // If empty, all hosts are allowed
	TLS            bool     `toml:"tls"`
	TLSCertFile    string   `toml:"tls_cert_file"`
	TLSKeyFile     string   `toml:"tls_key_file"`
	TLSVerify      bool     `toml:"tls_verify"` // Verify client certificates (mutual TLS)
}

// UserAPIProxyServerConfig holds User API proxy server configuration
type UserAPIProxyServerConfig struct {
	Start               bool        `toml:"start"`
	Addr                string      `toml:"addr"`
	RemoteAddrs         []string    `toml:"remote_addrs"`
	RemotePort          interface{} `toml:"remote_port"`            // Default port for backends if not in address
	JWTSecret           string      `toml:"jwt_secret"`             // JWT secret for token validation (must match backend)
	MaxConnections      int         `toml:"max_connections"`        // Maximum concurrent connections
	MaxConnectionsPerIP int         `toml:"max_connections_per_ip"` // Maximum connections per IP address
	TLS                 bool        `toml:"tls"`
	TLSCertFile         string      `toml:"tls_cert_file"`
	TLSKeyFile          string      `toml:"tls_key_file"`
	TLSVerify           bool        `toml:"tls_verify"`
	RemoteTLS           bool        `toml:"remote_tls"`
	RemoteTLSVerify     bool        `toml:"remote_tls_verify"`
	ConnectTimeout      string      `toml:"connect_timeout"`
	EnableAffinity      bool        `toml:"enable_affinity"`
}

// ServerLimitsConfig holds resource limits for a server
type ServerLimitsConfig struct {
	SearchRateLimitPerMin int    `toml:"search_rate_limit_per_min,omitempty"` // Search rate limit (searches per minute, 0=disabled)
	SearchRateLimitWindow string `toml:"search_rate_limit_window,omitempty"`  // Search rate limit time window (default: 1m)
	SessionMemoryLimit    string `toml:"session_memory_limit,omitempty"`      // Per-session memory limit (default: 100mb, 0=unlimited)
}

// ServerTimeoutsConfig holds timeout settings for a server
type ServerTimeoutsConfig struct {
	CommandTimeout         string `toml:"command_timeout,omitempty"`          // Maximum idle time before disconnection (default: protocol-specific)
	AbsoluteSessionTimeout string `toml:"absolute_session_timeout,omitempty"` // Maximum total session duration (default: 30m)
	MinBytesPerMinute      int64  `toml:"min_bytes_per_minute,omitempty"`     // Minimum throughput to prevent slowloris (default: 1024 bytes/min, 0=use default)
}

// ServerConfig represents a single server instance
type ServerConfig struct {
	Type string `toml:"type"`
	Name string `toml:"name"`
	Addr string `toml:"addr"`

	// Common server options
	TLS              bool   `toml:"tls,omitempty"`
	TLSCertFile      string `toml:"tls_cert_file,omitempty"`
	TLSKeyFile       string `toml:"tls_key_file,omitempty"`
	TLSVerify        bool   `toml:"tls_verify,omitempty"`
	TLSDefaultDomain string `toml:"tls_default_domain,omitempty"` // Default domain for SNI-less connections (overrides global default)
	Debug            bool   `toml:"debug,omitempty"`              // Enable debug logging for this server

	// PROXY protocol support (for non-proxy servers)
	ProxyProtocol        bool   `toml:"proxy_protocol,omitempty"`
	ProxyProtocolTimeout string `toml:"proxy_protocol_timeout,omitempty"`

	// Connection limits
	MaxConnections        int `toml:"max_connections,omitempty"`
	MaxConnectionsPerIP   int `toml:"max_connections_per_ip,omitempty"`
	MaxConnectionsPerUser int `toml:"max_connections_per_user,omitempty"` // Cluster-wide per-user limit (proxy only, requires cluster mode)

	// IMAP specific
	AppendLimit        string `toml:"append_limit,omitempty"`
	MasterUsername     string `toml:"master_username,omitempty"`
	MasterPassword     string `toml:"master_password,omitempty"`
	MasterSASLUsername string `toml:"master_sasl_username,omitempty"`
	MasterSASLPassword string `toml:"master_sasl_password,omitempty"`

	// LMTP specific
	ExternalRelay  string `toml:"external_relay,omitempty"`
	TLSUseStartTLS bool   `toml:"tls_use_starttls,omitempty"`
	MaxMessageSize string `toml:"max_message_size,omitempty"` // Maximum size for incoming LMTP messages

	// ManageSieve specific
	MaxScriptSize       string   `toml:"max_script_size,omitempty"`
	SupportedExtensions []string `toml:"supported_extensions,omitempty"` // List of supported Sieve extensions (additional to builtins)
	InsecureAuth        bool     `toml:"insecure_auth,omitempty"`

	// Proxy specific
	RemoteAddrs            []string    `toml:"remote_addrs,omitempty"`
	RemotePort             interface{} `toml:"remote_port,omitempty"` // Default port for backends if not in address
	RemoteTLS              bool        `toml:"remote_tls,omitempty"`
	RemoteTLSUseStartTLS   bool        `toml:"remote_tls_use_starttls,omitempty"` // Use STARTTLS for backend connections
	RemoteTLSVerify        bool        `toml:"remote_tls_verify,omitempty"`
	RemoteUseProxyProtocol bool        `toml:"remote_use_proxy_protocol,omitempty"`
	RemoteUseIDCommand     bool        `toml:"remote_use_id_command,omitempty"`
	RemoteUseXCLIENT       bool        `toml:"remote_use_xclient,omitempty"`
	ConnectTimeout         string      `toml:"connect_timeout,omitempty"`
	SessionTimeout         string      `toml:"session_timeout,omitempty"`
	EnableAffinity         bool        `toml:"enable_affinity,omitempty"`
	AffinityStickiness     float64     `toml:"affinity_stickiness,omitempty"`
	AffinityValidity       string      `toml:"affinity_validity,omitempty"`

	// HTTP API specific
	APIKey       string   `toml:"api_key,omitempty"`
	AllowedHosts []string `toml:"allowed_hosts,omitempty"`

	// Mail HTTP API specific (stateless JWT-based authentication)
	JWTSecret      string   `toml:"jwt_secret,omitempty"`      // Secret key for signing JWT tokens
	TokenDuration  string   `toml:"token_duration,omitempty"`  // Token validity duration (e.g., "24h", "7d")
	TokenIssuer    string   `toml:"token_issuer,omitempty"`    // JWT issuer field
	AllowedOrigins []string `toml:"allowed_origins,omitempty"` // CORS allowed origins for web clients

	// Metrics specific
	Path                 string `toml:"path,omitempty"`
	EnableUserMetrics    bool   `toml:"enable_user_metrics,omitempty"`
	EnableDomainMetrics  bool   `toml:"enable_domain_metrics,omitempty"`
	UserMetricsThreshold int    `toml:"user_metrics_threshold,omitempty"`
	MaxTrackedUsers      int    `toml:"max_tracked_users,omitempty"`
	HashUsernames        bool   `toml:"hash_usernames,omitempty"`

	// Auth rate limiting (embedded)
	AuthRateLimit *AuthRateLimiterConfig `toml:"auth_rate_limit,omitempty"`

	// Resource limits (embedded)
	Limits *ServerLimitsConfig `toml:"limits,omitempty"`

	// Session timeouts (embedded)
	Timeouts *ServerTimeoutsConfig `toml:"timeouts,omitempty"`

	// Pre-lookup (embedded)
	PreLookup *PreLookupConfig `toml:"prelookup,omitempty"`

	// Client capability filtering (IMAP specific)
	ClientFilters []ClientCapabilityFilter `toml:"client_filters,omitempty"`
	DisabledCaps  []string                 `toml:"disabled_caps,omitempty"` // Globally disabled capabilities (IMAP specific)
}

// ServersConfig holds all server configurations.
type ServersConfig struct {
	TrustedNetworks []string `toml:"trusted_networks"` // Global trusted networks for proxy parameter forwarding

	IMAP               IMAPServerConfig             `toml:"imap,omitempty"`
	LMTP               LMTPServerConfig             `toml:"lmtp,omitempty"`
	POP3               POP3ServerConfig             `toml:"pop3,omitempty"`
	ManageSieve        ManageSieveServerConfig      `toml:"managesieve,omitempty"`
	IMAPProxy          IMAPProxyServerConfig        `toml:"imap_proxy,omitempty"`
	POP3Proxy          POP3ProxyServerConfig        `toml:"pop3_proxy,omitempty"`
	ManageSieveProxy   ManageSieveProxyServerConfig `toml:"managesieve_proxy,omitempty"`
	LMTPProxy          LMTPProxyServerConfig        `toml:"lmtp_proxy,omitempty"`
	ConnectionTracking ConnectionTrackingConfig     `toml:"connection_tracking"`
	Metrics            MetricsConfig                `toml:"metrics"`
	HTTPAPI            HTTPAPIConfig                `toml:"http_api"`
	UserAPI            UserAPIServerConfig          `toml:"user_api,omitempty"`
	UserAPIProxy       UserAPIProxyServerConfig     `toml:"user_api_proxy,omitempty"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Output string `toml:"output"` // Log output: "stderr", "stdout", "syslog", or file path
	Format string `toml:"format"` // Log format: "json" or "console"
	Level  string `toml:"level"`  // Log level: "debug", "info", "warn", "error"
}

// MetadataConfig holds IMAP METADATA extension limits (RFC 5464).
type MetadataConfig struct {
	// MaxEntrySize is the maximum size in bytes for a single metadata entry value.
	// Default: 65536 (64KB). RFC 5464 recommends servers impose reasonable limits.
	MaxEntrySize int `toml:"max_entry_size"`

	// MaxEntriesPerMailbox is the maximum number of metadata entries per mailbox.
	// Default: 100. Prevents excessive storage usage.
	MaxEntriesPerMailbox int `toml:"max_entries_per_mailbox"`

	// MaxEntriesPerServer is the maximum number of server-level metadata entries per account.
	// Default: 50. Server metadata is stored per-account.
	MaxEntriesPerServer int `toml:"max_entries_per_server"`

	// MaxTotalSize is the maximum total size in bytes for all metadata per account.
	// Default: 1048576 (1MB). Prevents quota exhaustion.
	MaxTotalSize int `toml:"max_total_size"`
}

// SharedMailboxesConfig holds shared mailbox configuration
type SharedMailboxesConfig struct {
	Enabled               bool   `toml:"enabled"`                 // Enable shared mailbox functionality
	NamespacePrefix       string `toml:"namespace_prefix"`        // IMAP namespace prefix (e.g., "Shared/" or "#shared/")
	AllowUserCreate       bool   `toml:"allow_user_create"`       // Allow regular users to create shared mailboxes
	DefaultRights         string `toml:"default_rights"`          // Default ACL rights for shared mailbox creators
	AllowAnyoneIdentifier bool   `toml:"allow_anyone_identifier"` // Enable RFC 4314 "anyone" identifier for domain-wide sharing
}

// AdminCLIConfig holds configuration for sora-admin CLI tool
type AdminCLIConfig struct {
	Addr               string `toml:"addr"`                 // HTTP Admin API endpoint address
	APIKey             string `toml:"api_key"`              // API key for authentication
	InsecureSkipVerify *bool  `toml:"insecure_skip_verify"` // Skip TLS verification (default: true)
}

// Config holds all configuration for the application.
type Config struct {
	Logging         LoggingConfig         `toml:"logging"`
	Database        DatabaseConfig        `toml:"database"`
	S3              S3Config              `toml:"s3"`
	TLS             TLSConfig             `toml:"tls"`
	Cluster         ClusterConfig         `toml:"cluster"`
	LocalCache      LocalCacheConfig      `toml:"local_cache"`
	Cleanup         CleanupConfig         `toml:"cleanup"`
	Servers         ServersConfig         `toml:"servers"`
	Uploader        UploaderConfig        `toml:"uploader"`
	Metadata        MetadataConfig        `toml:"metadata"`
	SharedMailboxes SharedMailboxesConfig `toml:"shared_mailboxes"`
	AuthCache       AuthCacheConfig       `toml:"auth_cache"`
	Relay           RelayConfig           `toml:"relay"`
	AdminCLI        AdminCLIConfig        `toml:"admin_cli"` // Admin CLI tool configuration

	// Dynamic server instances (top-level array)
	DynamicServers []ServerConfig `toml:"server"`
}

// NewDefaultConfig creates a Config struct with default values.
func NewDefaultConfig() Config {
	return Config{
		Logging: LoggingConfig{
			Output: "stderr",  // Default to stderr
			Format: "console", // Default to console format
			Level:  "info",    // Default to info level
		},
		Database: DatabaseConfig{
			QueryTimeout:  "30s",
			SearchTimeout: "1m",
			WriteTimeout:  "15s",
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
		Metadata: MetadataConfig{
			MaxEntrySize:         65536,   // 64KB per entry
			MaxEntriesPerMailbox: 100,     // 100 entries per mailbox
			MaxEntriesPerServer:  50,      // 50 server-level entries per account
			MaxTotalSize:         1048576, // 1MB total per account
		},
		SharedMailboxes: SharedMailboxesConfig{
			Enabled:         false,         // Disabled by default
			NamespacePrefix: "Shared/",     // Default prefix
			AllowUserCreate: false,         // Admin-only by default
			DefaultRights:   "lrswipkxtea", // Full rights for creators
		},
		Servers: ServersConfig{
			TrustedNetworks: []string{"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10"},
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
				RemoteUseProxyProtocol: true,
				RemoteUseIDCommand:     false,
				EnableAffinity:         true,
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
				RemoteUseProxyProtocol: true,
				RemoteUseXCLIENT:       false,
				EnableAffinity:         true,
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
				RemoteUseProxyProtocol: true,
				AuthRateLimit:          DefaultAuthRateLimiterConfig(),
				EnableAffinity:         true,
			},
			LMTPProxy: LMTPProxyServerConfig{
				Start:                  false,
				Addr:                   ":124",
				MaxConnections:         1000,
				MaxConnectionsPerIP:    0, // Disable per-IP limits for proxy scenarios
				MaxMessageSize:         "50mb",
				TLS:                    false,
				RemoteTLS:              false,
				RemoteTLSVerify:        true,
				RemoteUseProxyProtocol: true,
				RemoteUseXCLIENT:       false,
				EnableAffinity:         true,
			},
			ConnectionTracking: ConnectionTrackingConfig{
				Enabled:               true,
				MaxConnectionsPerUser: 0, // Unlimited by default
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
				TLSVerify:    false,
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

// GetConnectTimeout parses the connect timeout duration for ManageSieve proxy
func (c *ManageSieveProxyServerConfig) GetConnectTimeout() (time.Duration, error) {
	if c.ConnectTimeout == "" {
		return 30 * time.Second, nil
	}
	return helpers.ParseDuration(c.ConnectTimeout)
}

// GetConnectTimeout parses the connect timeout duration for LMTP proxy
func (c *LMTPProxyServerConfig) GetConnectTimeout() (time.Duration, error) {
	if c.ConnectTimeout == "" {
		return 30 * time.Second, nil
	}
	return helpers.ParseDuration(c.ConnectTimeout)
}

// GetMaxMessageSize parses the max message size for LMTP proxy.
func (c *LMTPProxyServerConfig) GetMaxMessageSize() (int64, error) {
	if c.MaxMessageSize == "" {
		return 52428800, nil // Default: 50MiB
	}
	return helpers.ParseSize(c.MaxMessageSize)
}

// GetSessionTimeout parses the session timeout duration for IMAP proxy
func (c *IMAPProxyServerConfig) GetSessionTimeout() (time.Duration, error) {
	if c.SessionTimeout == "" {
		return 30 * time.Minute, nil // Default: 30 minutes for IMAP (interactive sessions)
	}
	return helpers.ParseDuration(c.SessionTimeout)
}

// GetSessionTimeout parses the session timeout duration for POP3 proxy
func (c *POP3ProxyServerConfig) GetSessionTimeout() (time.Duration, error) {
	if c.SessionTimeout == "" {
		return 10 * time.Minute, nil // Default: 10 minutes for POP3 (short sessions)
	}
	return helpers.ParseDuration(c.SessionTimeout)
}

// GetSessionTimeout parses the session timeout duration for ManageSieve proxy
func (c *ManageSieveProxyServerConfig) GetSessionTimeout() (time.Duration, error) {
	if c.SessionTimeout == "" {
		return 15 * time.Minute, nil // Default: 15 minutes for ManageSieve (script management)
	}
	return helpers.ParseDuration(c.SessionTimeout)
}

// GetSessionTimeout parses the session timeout duration for LMTP proxy
func (c *LMTPProxyServerConfig) GetSessionTimeout() (time.Duration, error) {
	if c.SessionTimeout == "" {
		return 5 * time.Minute, nil // Default: 5 minutes for LMTP (delivery sessions)
	}
	return helpers.ParseDuration(c.SessionTimeout)
}

// GetCommandTimeout parses the command timeout duration for IMAP proxy
func (c *IMAPProxyServerConfig) GetCommandTimeout() (time.Duration, error) {
	if c.CommandTimeout == "" {
		return 5 * time.Minute, nil // Default: 5 minutes idle timeout
	}
	return helpers.ParseDuration(c.CommandTimeout)
}

// GetAbsoluteSessionTimeout parses the absolute session timeout duration for IMAP proxy
func (c *IMAPProxyServerConfig) GetAbsoluteSessionTimeout() (time.Duration, error) {
	if c.AbsoluteSessionTimeout == "" {
		return 30 * time.Minute, nil // Default: 30 minutes maximum session duration
	}
	return helpers.ParseDuration(c.AbsoluteSessionTimeout)
}

// GetCommandTimeout parses the command timeout duration for POP3 proxy
func (c *POP3ProxyServerConfig) GetCommandTimeout() (time.Duration, error) {
	if c.CommandTimeout == "" {
		return 5 * time.Minute, nil // Default: 5 minutes idle timeout
	}
	return helpers.ParseDuration(c.CommandTimeout)
}

// GetAbsoluteSessionTimeout parses the absolute session timeout duration for POP3 proxy
func (c *POP3ProxyServerConfig) GetAbsoluteSessionTimeout() (time.Duration, error) {
	if c.AbsoluteSessionTimeout == "" {
		return 30 * time.Minute, nil // Default: 30 minutes maximum session duration
	}
	return helpers.ParseDuration(c.AbsoluteSessionTimeout)
}

// GetCommandTimeout parses the command timeout duration for ManageSieve proxy
func (c *ManageSieveProxyServerConfig) GetCommandTimeout() (time.Duration, error) {
	if c.CommandTimeout == "" {
		return 5 * time.Minute, nil // Default: 5 minutes idle timeout
	}
	return helpers.ParseDuration(c.CommandTimeout)
}

// GetAbsoluteSessionTimeout parses the absolute session timeout duration for ManageSieve proxy
func (c *ManageSieveProxyServerConfig) GetAbsoluteSessionTimeout() (time.Duration, error) {
	if c.AbsoluteSessionTimeout == "" {
		return 30 * time.Minute, nil // Default: 30 minutes maximum session duration
	}
	return helpers.ParseDuration(c.AbsoluteSessionTimeout)
}

// Helper methods for ServerConfig
func (s *ServerConfig) GetAppendLimit() (int64, error) {
	if s.AppendLimit == "" {
		return 25 * 1024 * 1024, nil // 25MB default
	}
	return helpers.ParseSize(s.AppendLimit)
}

func (s *ServerConfig) GetMaxScriptSize() (int64, error) {
	if s.MaxScriptSize == "" {
		return 16 * 1024, nil // 16KB default
	}
	return helpers.ParseSize(s.MaxScriptSize)
}

func (s *ServerConfig) GetMaxMessageSize() (int64, error) {
	if s.MaxMessageSize == "" {
		return 50 * 1024 * 1024, nil // 50MB default
	}
	return helpers.ParseSize(s.MaxMessageSize)
}

func (s *ServerConfig) GetConnectTimeout() (time.Duration, error) {
	if s.ConnectTimeout == "" {
		return 30 * time.Second, nil
	}
	return helpers.ParseDuration(s.ConnectTimeout)
}

func (s *ServerConfig) GetSessionTimeout() (time.Duration, error) {
	if s.SessionTimeout == "" {
		// Default timeouts based on server type
		switch s.Type {
		case "imap", "imap_proxy":
			return 30 * time.Minute, nil
		case "pop3", "pop3_proxy":
			return 10 * time.Minute, nil
		case "managesieve", "managesieve_proxy":
			return 15 * time.Minute, nil
		case "lmtp", "lmtp_proxy":
			return 5 * time.Minute, nil
		default:
			return 30 * time.Minute, nil
		}
	}
	return helpers.ParseDuration(s.SessionTimeout)
}

func (s *ServerConfig) GetProxyProtocolTimeout() (time.Duration, error) {
	if s.ProxyProtocolTimeout == "" {
		return 5 * time.Second, nil // 5 second default
	}
	return helpers.ParseDuration(s.ProxyProtocolTimeout)
}

// GetSearchRateLimitWindow parses the search rate limit window duration
func (s *ServerConfig) GetSearchRateLimitWindow() (time.Duration, error) {
	if s.Limits != nil && s.Limits.SearchRateLimitWindow != "" {
		return helpers.ParseDuration(s.Limits.SearchRateLimitWindow)
	}
	return time.Minute, nil // Default: 1 minute
}

// GetSessionMemoryLimit parses the session memory limit
func (s *ServerConfig) GetSessionMemoryLimit() (int64, error) {
	if s.Limits != nil && s.Limits.SessionMemoryLimit != "" {
		return helpers.ParseSize(s.Limits.SessionMemoryLimit)
	}
	return 100 * 1024 * 1024, nil // Default: 100MB
}

// GetCommandTimeout parses the command timeout duration with protocol-specific defaults
func (s *ServerConfig) GetCommandTimeout() (time.Duration, error) {
	if s.Timeouts != nil && s.Timeouts.CommandTimeout != "" {
		return helpers.ParseDuration(s.Timeouts.CommandTimeout)
	}
	// Protocol-specific defaults
	switch s.Type {
	case "pop3", "pop3_proxy":
		return 2 * time.Minute, nil // 2 minutes for POP3
	case "imap", "imap_proxy":
		return 5 * time.Minute, nil // 5 minutes for IMAP
	case "managesieve", "managesieve_proxy":
		return 3 * time.Minute, nil // 3 minutes for ManageSieve
	default:
		return 2 * time.Minute, nil // Default: 2 minutes
	}
}

// GetAbsoluteSessionTimeout parses the absolute session timeout duration (default: 30 minutes for all protocols)
func (s *ServerConfig) GetAbsoluteSessionTimeout() (time.Duration, error) {
	if s.Timeouts != nil && s.Timeouts.AbsoluteSessionTimeout != "" {
		return helpers.ParseDuration(s.Timeouts.AbsoluteSessionTimeout)
	}
	return 30 * time.Minute, nil // Default: 30 minutes for all protocols
}

// GetSearchRateLimitPerMin returns search rate limit per minute
func (s *ServerConfig) GetSearchRateLimitPerMin() int {
	if s.Limits != nil && s.Limits.SearchRateLimitPerMin > 0 {
		return s.Limits.SearchRateLimitPerMin
	}
	return 0
}

// GetMinBytesPerMinute returns minimum bytes per minute
func (s *ServerConfig) GetMinBytesPerMinute() int64 {
	if s.Timeouts != nil && s.Timeouts.MinBytesPerMinute > 0 {
		return s.Timeouts.MinBytesPerMinute
	}
	return 1024 // Default: 1024 bytes/min
}

func (s *ServerConfig) GetRemotePort() (int, error) {
	if s.RemotePort == nil {
		return 0, nil // No port configured
	}
	var p int64
	var err error
	switch v := s.RemotePort.(type) {
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

// Configuration defaulting methods with logging
func (s *ServerConfig) GetAppendLimitWithDefault() int64 {
	limit, err := s.GetAppendLimit()
	if err != nil {
		log.Printf("WARNING: Failed to parse append limit for server '%s': %v, using default (25MB)", s.Name, err)
		return 25 * 1024 * 1024 // 25MB default
	}
	return limit
}

func (s *ServerConfig) GetMaxScriptSizeWithDefault() int64 {
	size, err := s.GetMaxScriptSize()
	if err != nil {
		log.Printf("WARNING: Failed to parse max script size for server '%s': %v, using default (16KB)", s.Name, err)
		return 16 * 1024 // 16KB default
	}
	return size
}

func (s *ServerConfig) GetConnectTimeoutWithDefault() time.Duration {
	timeout, err := s.GetConnectTimeout()
	if err != nil {
		log.Printf("WARNING: Failed to parse connect timeout for server '%s': %v, using default (30s)", s.Name, err)
		return 30 * time.Second
	}
	return timeout
}

func (s *ServerConfig) GetSessionTimeoutWithDefault() time.Duration {
	timeout, err := s.GetSessionTimeout()
	if err != nil {
		log.Printf("WARNING: Failed to parse session timeout for server '%s': %v, using default", s.Name, err)
		// Return type-specific defaults
		switch s.Type {
		case "imap", "imap_proxy":
			return 30 * time.Minute
		case "pop3", "pop3_proxy":
			return 10 * time.Minute
		case "managesieve", "managesieve_proxy":
			return 15 * time.Minute
		case "lmtp", "lmtp_proxy":
			return 5 * time.Minute
		default:
			return 30 * time.Minute
		}
	}
	return timeout
}

func (s *ServerConfig) GetMaxMessageSizeWithDefault() int64 {
	size, err := s.GetMaxMessageSize()
	if err != nil {
		log.Printf("WARNING: Failed to parse max message size for server '%s': %v, using default (50MB)", s.Name, err)
		return 52428800 // 50MB default
	}
	return size
}

func (s *ServerConfig) GetProxyProtocolTimeoutWithDefault() string {
	if s.ProxyProtocolTimeout == "" {
		return "5s"
	}
	return s.ProxyProtocolTimeout
}

// Configuration defaulting methods for other config types
func (c *CleanupConfig) GetGracePeriodWithDefault() time.Duration {
	period, err := c.GetGracePeriod()
	if err != nil {
		log.Printf("WARNING: Failed to parse cleanup grace_period: %v, using default (14 days)", err)
		return 14 * 24 * time.Hour
	}
	return period
}

func (c *CleanupConfig) GetWakeIntervalWithDefault() time.Duration {
	interval, err := c.GetWakeInterval()
	if err != nil {
		log.Printf("WARNING: Failed to parse cleanup wake_interval: %v, using default (1 hour)", err)
		return time.Hour
	}
	return interval
}

func (c *CleanupConfig) GetMaxAgeRestrictionWithDefault() time.Duration {
	restriction, err := c.GetMaxAgeRestriction()
	if err != nil {
		log.Printf("WARNING: Failed to parse cleanup max_age_restriction: %v, using default (no restriction)", err)
		return 0
	}
	return restriction
}

func (c *CleanupConfig) GetFTSRetentionWithDefault() time.Duration {
	retention, err := c.GetFTSRetention()
	if err != nil {
		log.Printf("WARNING: Failed to parse cleanup fts_retention: %v, using default (2 years)", err)
		return 730 * 24 * time.Hour
	}
	return retention
}

func (c *CleanupConfig) GetAuthAttemptsRetentionWithDefault() time.Duration {
	retention, err := c.GetAuthAttemptsRetention()
	if err != nil {
		log.Printf("WARNING: Failed to parse cleanup auth_attempts_retention: %v, using default (7 days)", err)
		return 7 * 24 * time.Hour
	}
	return retention
}

func (c *CleanupConfig) GetHealthStatusRetentionWithDefault() time.Duration {
	retention, err := c.GetHealthStatusRetention()
	if err != nil {
		log.Printf("WARNING: Failed to parse cleanup health_status_retention: %v, using default (30 days)", err)
		return 30 * 24 * time.Hour
	}
	return retention
}

func (c *LocalCacheConfig) GetCapacityWithDefault() int64 {
	capacity, err := c.GetCapacity()
	if err != nil {
		log.Printf("WARNING: Failed to parse cache size: %v, using default (1GB)", err)
		return 1024 * 1024 * 1024 // 1GB
	}
	return capacity
}

func (c *LocalCacheConfig) GetMaxObjectSizeWithDefault() int64 {
	size, err := c.GetMaxObjectSize()
	if err != nil {
		log.Printf("WARNING: Failed to parse cache max object size: %v, using default (5MB)", err)
		return 5 * 1024 * 1024 // 5MB
	}
	return size
}

func (c *LocalCacheConfig) GetPurgeIntervalWithDefault() time.Duration {
	interval, err := c.GetPurgeInterval()
	if err != nil {
		log.Printf("WARNING: Failed to parse cache purge interval: %v, using default (12 hours)", err)
		return 12 * time.Hour
	}
	return interval
}

func (c *LocalCacheConfig) GetOrphanCleanupAgeWithDefault() time.Duration {
	age, err := c.GetOrphanCleanupAge()
	if err != nil {
		log.Printf("WARNING: Failed to parse cache orphan cleanup age: %v, using default (30 days)", err)
		return 30 * 24 * time.Hour
	}
	return age
}

func (c *LocalCacheConfig) GetMetricsIntervalWithDefault() time.Duration {
	interval, err := c.GetMetricsInterval()
	if err != nil {
		log.Printf("WARNING: Failed to parse cache metrics_interval: %v, using default (5 minutes)", err)
		return 5 * time.Minute
	}
	return interval
}

func (c *LocalCacheConfig) GetMetricsRetentionWithDefault() time.Duration {
	retention, err := c.GetMetricsRetention()
	if err != nil {
		log.Printf("WARNING: Failed to parse cache metrics_retention: %v, using default (30 days)", err)
		return 30 * 24 * time.Hour
	}
	return retention
}

func (c *UploaderConfig) GetRetryIntervalWithDefault() time.Duration {
	interval, err := c.GetRetryInterval()
	if err != nil {
		log.Printf("WARNING: Failed to parse uploader retry_interval: %v, using default (30 seconds)", err)
		return 30 * time.Second
	}
	return interval
}

// GetMaxConnectionsPerUser returns the cluster-wide connection limit per user
func (c *ConnectionTrackingConfig) GetMaxConnectionsPerUser() int {
	if c.MaxConnectionsPerUser < 0 {
		return 0 // Unlimited
	}
	return c.MaxConnectionsPerUser
}

// IsEnabled checks if a server should be started based on its configuration
func (s *ServerConfig) IsEnabled() bool {
	return s.Type != "" && s.Name != "" && s.Addr != ""
}

// ValidateServerConfig validates a server configuration
func (s *ServerConfig) Validate() error {
	if s.Type == "" {
		return fmt.Errorf("server type is required")
	}
	if s.Name == "" {
		return fmt.Errorf("server name is required")
	}
	if s.Addr == "" {
		return fmt.Errorf("server address is required")
	}

	validTypes := []string{"imap", "lmtp", "pop3", "managesieve", "imap_proxy", "pop3_proxy", "managesieve_proxy", "lmtp_proxy", "metrics", "http_admin_api", "http_user_api"}
	isValidType := false
	for _, validType := range validTypes {
		if s.Type == validType {
			isValidType = true
			break
		}
	}
	if !isValidType {
		return fmt.Errorf("invalid server type '%s', must be one of: %s", s.Type, strings.Join(validTypes, ", "))
	}

	return nil
}

// WarnUnusedConfigOptions logs warnings for config options that don't apply to this server type
func (s *ServerConfig) WarnUnusedConfigOptions(logger func(format string, args ...interface{})) {
	// Check proxy-only options on non-proxy servers
	if !strings.HasSuffix(s.Type, "_proxy") {
		if len(s.RemoteAddrs) > 0 {
			logger("WARNING: Server %s (type: %s) has 'remote_addrs' configured, but this only applies to proxy servers", s.Name, s.Type)
		}
		if s.RemoteTLS {
			logger("WARNING: Server %s (type: %s) has 'remote_tls' configured, but this only applies to proxy servers", s.Name, s.Type)
		}
		if s.RemoteTLSUseStartTLS {
			logger("WARNING: Server %s (type: %s) has 'remote_tls_use_starttls' configured, but this only applies to proxy servers", s.Name, s.Type)
		}
		if s.RemoteTLSVerify {
			logger("WARNING: Server %s (type: %s) has 'remote_tls_verify' configured, but this only applies to proxy servers", s.Name, s.Type)
		}
		if s.RemoteUseProxyProtocol {
			logger("WARNING: Server %s (type: %s) has 'remote_use_proxy_protocol' configured, but this only applies to proxy servers", s.Name, s.Type)
		}
	}

	switch s.Type {
	case "imap":
		// IMAP server
		if len(s.SupportedExtensions) > 0 {
			logger("WARNING: Server %s (type: %s) has 'supported_extensions' configured, but this only applies to ManageSieve servers", s.Name, s.Type)
		}
		if s.RemoteUseIDCommand {
			logger("WARNING: Server %s (type: %s) has 'remote_use_id_command' configured, but this only applies to IMAP proxy servers", s.Name, s.Type)
		}

	case "lmtp":
		// LMTP server
		if len(s.SupportedExtensions) > 0 {
			logger("WARNING: Server %s (type: %s) has 'supported_extensions' configured, but this only applies to ManageSieve servers", s.Name, s.Type)
		}
		if s.RemoteUseXCLIENT {
			logger("WARNING: Server %s (type: %s) has 'remote_use_xclient' configured, but this only applies to LMTP proxy servers", s.Name, s.Type)
		}

	case "pop3":
		// POP3 server
		if len(s.SupportedExtensions) > 0 {
			logger("WARNING: Server %s (type: %s) has 'supported_extensions' configured, but this only applies to ManageSieve servers", s.Name, s.Type)
		}

	case "managesieve":
		// ManageSieve server - no proxy-specific warnings needed (handled above)

	case "imap_proxy":
		// IMAP proxy
		if len(s.SupportedExtensions) > 0 {
			logger("WARNING: Server %s (type: %s) has 'supported_extensions' configured, but this only applies to ManageSieve servers/proxies", s.Name, s.Type)
		}
		if s.MaxScriptSize != "" {
			logger("WARNING: Server %s (type: %s) has 'max_script_size' configured, but this only applies to ManageSieve servers", s.Name, s.Type)
		}
		if s.RemoteUseXCLIENT {
			logger("WARNING: Server %s (type: %s) has 'remote_use_xclient' configured, but this only applies to LMTP proxy servers", s.Name, s.Type)
		}

	case "pop3_proxy":
		// POP3 proxy
		if len(s.SupportedExtensions) > 0 {
			logger("WARNING: Server %s (type: %s) has 'supported_extensions' configured, but this only applies to ManageSieve servers/proxies", s.Name, s.Type)
		}
		if s.MaxScriptSize != "" {
			logger("WARNING: Server %s (type: %s) has 'max_script_size' configured, but this only applies to ManageSieve servers", s.Name, s.Type)
		}
		if s.RemoteUseIDCommand {
			logger("WARNING: Server %s (type: %s) has 'remote_use_id_command' configured, but this only applies to IMAP proxy servers", s.Name, s.Type)
		}
		if s.RemoteUseXCLIENT {
			logger("WARNING: Server %s (type: %s) has 'remote_use_xclient' configured, but this only applies to LMTP proxy servers", s.Name, s.Type)
		}

	case "lmtp_proxy":
		// LMTP proxy
		if len(s.SupportedExtensions) > 0 {
			logger("WARNING: Server %s (type: %s) has 'supported_extensions' configured, but this only applies to ManageSieve servers/proxies", s.Name, s.Type)
		}
		if s.MaxScriptSize != "" {
			logger("WARNING: Server %s (type: %s) has 'max_script_size' configured, but this only applies to ManageSieve servers", s.Name, s.Type)
		}
		if s.RemoteUseIDCommand {
			logger("WARNING: Server %s (type: %s) has 'remote_use_id_command' configured, but this only applies to IMAP proxy servers", s.Name, s.Type)
		}

	case "managesieve_proxy":
		// ManageSieve proxy
		if s.AppendLimit != "" {
			logger("WARNING: Server %s (type: %s) has 'append_limit' configured, but this only applies to IMAP servers", s.Name, s.Type)
		}
		if s.RemoteUseIDCommand {
			logger("WARNING: Server %s (type: %s) has 'remote_use_id_command' configured, but this only applies to IMAP proxy servers", s.Name, s.Type)
		}
		if s.RemoteUseXCLIENT {
			logger("WARNING: Server %s (type: %s) has 'remote_use_xclient' configured, but this only applies to LMTP proxy servers", s.Name, s.Type)
		}

	case "metrics", "http_admin_api", "http_user_api":
		// HTTP servers - warn about protocol-specific options
		if len(s.SupportedExtensions) > 0 {
			logger("WARNING: Server %s (type: %s) has 'supported_extensions' configured, but this only applies to ManageSieve servers", s.Name, s.Type)
		}
		if s.MaxScriptSize != "" {
			logger("WARNING: Server %s (type: %s) has 'max_script_size' configured, but this only applies to ManageSieve servers", s.Name, s.Type)
		}
		if s.AppendLimit != "" {
			logger("WARNING: Server %s (type: %s) has 'append_limit' configured, but this only applies to IMAP servers", s.Name, s.Type)
		}
		if s.TLSUseStartTLS {
			logger("WARNING: Server %s (type: %s) has 'tls_use_starttls' configured, but this only applies to protocol servers (IMAP, POP3, LMTP, ManageSieve)", s.Name, s.Type)
		}
	}
}

// GetAllServers returns all configured servers from the dynamic configuration
func (c *Config) GetAllServers() []ServerConfig {
	var allServers []ServerConfig

	// Add dynamic servers
	for _, server := range c.DynamicServers {
		if server.IsEnabled() {
			allServers = append(allServers, server)
		}
	}

	return allServers
}

// LoadConfigFromFile loads configuration from a TOML file and trims whitespace from all string fields
// This function is lenient with:
//   - Duplicate keys: logs warning and uses first occurrence
//   - Unknown keys: logs warning and ignores them
//
// All other syntax errors will cause the server to fail with helpful error messages
func LoadConfigFromFile(configPath string, cfg *Config) error {
	// Read the file content first
	content, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	// Try to decode - capture metadata to check for unknown keys
	metadata, err := toml.Decode(string(content), cfg)
	if err != nil {
		// Check if this is a duplicate key error
		if strings.Contains(err.Error(), "has already been defined") {
			// Extract the duplicate key name from error message
			errMsg := err.Error()
			log.Printf("WARNING: Configuration file '%s' contains duplicate keys: %s", configPath, errMsg)
			log.Printf("WARNING: Ignoring duplicate entries. Only the first occurrence of each key will be used.")
			log.Printf("WARNING: Please fix your configuration file to remove duplicates.")

			// Parse again with a lenient approach by removing duplicate keys
			cleanedContent, parseErr := removeDuplicateKeysFromTOML(string(content))
			if parseErr != nil {
				// If we can't clean it, return a helpful error
				return enhanceConfigError(err)
			}

			// Try decoding the cleaned content
			metadata, err = toml.Decode(cleanedContent, cfg)
			if err != nil {
				return enhanceConfigError(err)
			}
		} else {
			// For other errors, provide enhanced error messages
			return enhanceConfigError(err)
		}
	}

	// Warn about unknown keys (might be typos or deprecated settings)
	if len(metadata.Undecoded()) > 0 {
		log.Printf("WARNING: Configuration file '%s' contains unknown keys that will be ignored:", configPath)
		for _, key := range metadata.Undecoded() {
			log.Printf("WARNING:   - %s", key)
		}
		log.Printf("WARNING: These keys may be typos or deprecated settings. Please review your configuration.")
	}

	// Trim whitespace from all string fields in the configuration
	trimStringFields(reflect.ValueOf(cfg).Elem())
	return nil
}

// removeDuplicateKeysFromTOML removes duplicate keys from TOML content
// This is a simple implementation that keeps the first occurrence of each key
// Supports nested tables ([table.subtable]) and array tables ([[array.table]])
// Note: Array tables reset key tracking per instance since each [[table]] is a new array element
func removeDuplicateKeysFromTOML(content string) (string, error) {
	lines := strings.Split(content, "\n")
	seenKeys := make(map[string]int) // Maps key path to line number
	var result []string
	var currentSection string
	var lastArrayTable string

	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip empty lines and comments
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			result = append(result, line)
			continue
		}

		// Track section changes - handle both regular tables and array tables
		if strings.HasPrefix(trimmed, "[[") && strings.HasSuffix(trimmed, "]]") {
			// Array table: [[table.name]]
			// Remove outer brackets to get the section name
			currentSection = strings.TrimSpace(trimmed[2 : len(trimmed)-2])

			// Reset key tracking for this array table instance
			// Each [[table]] is a new array element, so same keys are expected
			if currentSection == lastArrayTable {
				// Same array table name - clear keys for this section
				for k := range seenKeys {
					if strings.HasPrefix(k, currentSection+".") {
						delete(seenKeys, k)
					}
				}
			}
			lastArrayTable = currentSection

			result = append(result, line)
			continue
		} else if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			// Regular table: [table.name]
			// Remove brackets to get the section name
			currentSection = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			lastArrayTable = "" // Not an array table
			result = append(result, line)
			continue
		}

		// Check if this is a key = value line
		if strings.Contains(trimmed, "=") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				// Build full key path: section.key
				var fullKey string
				if currentSection != "" {
					fullKey = currentSection + "." + key
				} else {
					fullKey = key
				}

				// Check if we've seen this key before
				if prevLine, exists := seenKeys[fullKey]; exists {
					// Duplicate found - comment it out
					log.Printf("WARNING: Duplicate key '%s' found at line %d (first occurrence at line %d). Ignoring duplicate.",
						fullKey, lineNum+1, prevLine+1)
					result = append(result, "# DUPLICATE IGNORED: "+line)
					continue
				}

				// Remember this key
				seenKeys[fullKey] = lineNum
			}
		}

		result = append(result, line)
	}

	return strings.Join(result, "\n"), nil
}

// enhanceConfigError provides more helpful error messages for common TOML parsing issues
func enhanceConfigError(err error) error {
	errMsg := err.Error()

	// Check for duplicate key errors
	if strings.Contains(errMsg, "has already been defined") {
		// Extract the key name from the error message
		// Format: "toml: line X (last key "key.name"): Key 'key.name' has already been defined."
		return fmt.Errorf("%w\n\nHINT: You have a duplicate configuration key in your TOML file.\n"+
			"Please check your configuration file and remove or comment out the duplicate entry.\n"+
			"Common causes:\n"+
			"  - Same key appears twice in the same section\n"+
			"  - Copy-paste errors when creating multiple server configurations\n"+
			"  - Uncommenting a setting that already exists elsewhere", err)
	}

	// Check for common boolean typos
	if strings.Contains(errMsg, "expected value but found \"f\"") ||
		strings.Contains(errMsg, "expected value but found \"t\"") {
		return fmt.Errorf("%w\n\nHINT: Invalid boolean value in your TOML configuration file\n"+
			"Common mistakes:\n"+
			"  - Using 'f' instead of 'false'\n"+
			"  - Using 't' instead of 'true'\n"+
			"  - Using 'yes'/'no' instead of 'true'/'false'\n"+
			"  - Using '1'/'0' instead of 'true'/'false'\n\n"+
			"In TOML, boolean values must be exactly 'true' or 'false' (lowercase, unquoted)", err)
	}

	// Check for invalid TOML syntax
	if strings.Contains(errMsg, "expected") || strings.Contains(errMsg, "invalid") {
		return fmt.Errorf("%w\n\nHINT: There is a syntax error in your TOML configuration file.\n"+
			"Please check:\n"+
			"  - All strings are properly quoted\n"+
			"  - All brackets and braces are balanced\n"+
			"  - No special characters are unescaped\n"+
			"  - Section headers use [section] or [[array]] format\n"+
			"  - Boolean values are 'true' or 'false' (not 'yes'/'no', '1'/'0', 'f'/'t')", err)
	}

	// Return original error if we don't have specific guidance
	return err
}

// trimStringFields recursively trims whitespace from all string fields in a struct
func trimStringFields(v reflect.Value) {
	if !v.IsValid() || !v.CanSet() {
		return
	}

	switch v.Kind() {
	case reflect.String:
		// Trim whitespace from string fields
		v.SetString(strings.TrimSpace(v.String()))

	case reflect.Slice:
		// Handle slices of strings and slices of structs
		for i := 0; i < v.Len(); i++ {
			elem := v.Index(i)
			if elem.Kind() == reflect.String {
				elem.SetString(strings.TrimSpace(elem.String()))
			} else {
				trimStringFields(elem)
			}
		}

	case reflect.Struct:
		// Recursively process struct fields
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			if field.CanSet() {
				trimStringFields(field)
			}
		}

	case reflect.Ptr:
		// Handle pointers to structs
		if !v.IsNil() {
			trimStringFields(v.Elem())
		}

	case reflect.Interface:
		// Handle interface{} values (like the Port field which can be string or int)
		if !v.IsNil() {
			elem := v.Elem()
			if elem.Kind() == reflect.String {
				v.Set(reflect.ValueOf(strings.TrimSpace(elem.String())))
			}
		}
	}
}
