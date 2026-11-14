package config

import (
	"errors"
	"fmt"
	"log"
	"log/slog"
	"maps"
	"math"
	"net"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/migadu/sora/consts"
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
	Hosts              []string `toml:"hosts"`
	Port               any      `toml:"port"` // Database port (default: "5432"), can be string or integer
	User               string   `toml:"user"`
	Password           string   `toml:"password" secret:"true"`
	Name               string   `toml:"name"`
	TLSMode            bool     `toml:"tls"`
	MaxConnections     int      `toml:"max_connections"`      // Maximum number of connections in the pool (per host; without [database.read] a write host has a second, read pool of the same size)
	MinConnections     int      `toml:"min_connections"`      // Minimum number of connections in the pool (eagerly created on startup)
	MinIdleConnections int      `toml:"min_idle_connections"` // Minimum number of idle connections (lazily maintained, superior to min_connections)
	MaxConnLifetime    string   `toml:"max_conn_lifetime"`    // Maximum lifetime of a connection
	MaxConnIdleTime    string   `toml:"max_conn_idle_time"`   // Maximum idle time before a connection is closed
	QueryTimeout       string   `toml:"query_timeout"`        // Per-endpoint timeout for individual database queries (e.g., "30s")
}

// DatabaseConfig holds database configuration with separate read/write endpoints
type DatabaseConfig struct {
	Debug            bool                    `toml:"debug"`             // Enable SQL query logging
	QueryTimeout     string                  `toml:"query_timeout"`     // Default timeout for all database queries (default: "30s")
	SearchTimeout    string                  `toml:"search_timeout"`    // Specific timeout for complex search queries (default: "60s")
	WriteTimeout     string                  `toml:"write_timeout"`     // Timeout for write operations (default: "10s")
	LockTimeout      string                  `toml:"lock_timeout"`      // Max time a statement waits for a row lock before failing (default: "10s"; "0" disables)
	MigrationTimeout string                  `toml:"migration_timeout"` // Timeout for auto-migrations at startup (default: "2m")
	FetchChunkSize   int                     `toml:"fetch_chunk_size"`  // Number of messages to fetch per chunk for large result sets (default: 5000)
	Write            *DatabaseEndpointConfig `toml:"write"`             // Write database configuration
	Read             *DatabaseEndpointConfig `toml:"read"`              // Read database configuration (can have multiple hosts for load balancing)
	PoolTypeOverride string                  `toml:"-"`                 // Internal: Override pool type in logs (not in config file)
	// Internal (not in config file): with Read unset, serve reads from the write pool
	// instead of opening a dedicated read pool to the same host. The resilient layer sets
	// it for read replicas, and for write hosts when [database.read] is configured: those
	// serve reads only while no replica is healthy, or in sora-admin, which skips the
	// replicas, and then the reads share the one pool with the writes.
	ReadsShareWritePool bool `toml:"-"`
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

// GetLockTimeout parses the row-lock wait timeout. It is applied as a
// transaction-scoped `SET LOCAL lock_timeout` at the start of every write
// transaction (not as a connection/startup parameter, which PgBouncer rejects
// with SQLSTATE 08P01). A statement blocked waiting for a row lock — e.g. the
// per-mailbox FOR UPDATE that MOVE/EXPUNGE/STORE take for unseen_count
// maintenance — then fails fast with SQLSTATE 55P03 instead of parking on a
// connection for the full write_timeout. This bounds tail latency and frees the
// connection back to the pool, preventing the contention spiral where blocked
// writers starve the pool. Because it is SET LOCAL it is correct under every
// PgBouncer pooling mode (session, transaction, statement). "0" disables it.
func (d *DatabaseConfig) GetLockTimeout() (time.Duration, error) {
	if d.LockTimeout == "" {
		return 10 * time.Second, nil // Default: bound lock waits to 10s
	}
	return helpers.ParseDuration(d.LockTimeout)
}

// GetMigrationTimeout parses the migration timeout duration
func (d *DatabaseConfig) GetMigrationTimeout() (time.Duration, error) {
	if d.MigrationTimeout == "" {
		return 2 * time.Minute, nil // Default 2 minute timeout for auto-migrations
	}
	return helpers.ParseDuration(d.MigrationTimeout)
}

// GetFetchChunkSize returns the chunk size for large message fetches
func (d *DatabaseConfig) GetFetchChunkSize() int {
	if d.FetchChunkSize <= 0 {
		return 5000 // Default: 5k messages per chunk
	}
	return d.FetchChunkSize
}

// S3Config holds S3 configuration.
type S3Config struct {
	Endpoint      string `toml:"endpoint"`
	DisableTLS    bool   `toml:"disable_tls"`
	Region        string `toml:"region"`                   // Signing region (default: AWS_REGION or the shared AWS config, else "us-east-1")
	AccessKey     string `toml:"access_key" secret:"true"` // Without both keys the AWS default credential chain is used
	SecretKey     string `toml:"secret_key" secret:"true"`
	Bucket        string `toml:"bucket"`
	Debug         bool   `toml:"debug"`   // Enable detailed S3 request/response tracing
	Timeout       string `toml:"timeout"` // Timeout for individual S3 operations (default: 30s)
	Encrypt       bool   `toml:"encrypt"`
	EncryptionKey string `toml:"encryption_key" secret:"true"`
}

// GetDebug returns the debug flag
func (s *S3Config) GetDebug() bool {
	return s.Debug
}

// GetTimeout parses the S3 operation timeout duration
func (s *S3Config) GetTimeout() (time.Duration, error) {
	if s.Timeout == "" {
		return 30 * time.Second, nil // Default 30 second timeout for S3 operations
	}
	return helpers.ParseDuration(s.Timeout)
}

// ClusterRateLimitSyncConfig holds configuration for cluster-wide auth rate limiting
type ClusterRateLimitSyncConfig struct {
	Enabled           bool `toml:"enabled"`             // Enable cluster-wide rate limiting (default: true if cluster enabled)
	SyncBlocks        bool `toml:"sync_blocks"`         // Sync IP blocks across cluster (default: true)
	SyncFailureCounts bool `toml:"sync_failure_counts"` // Sync progressive delay failure counts (default: true)
}

// ClusterAffinityConfig holds configuration for cluster-wide server affinity
type ClusterAffinityConfig struct {
	Enabled         bool   `toml:"enabled"`          // Enable cluster-wide affinity (default: true; only read with [cluster] enabled)
	TTL             string `toml:"ttl"`              // How long affinity persists (default: "24h")
	CleanupInterval string `toml:"cleanup_interval"` // How often to clean up expired affinities (default: "1h")
	CachePath       string `toml:"cache_path"`       // SQLite path for persistent affinity (default: "" = disabled)
}

// GetTTL parses and returns the affinity TTL duration
func (c *ClusterAffinityConfig) GetTTL() (time.Duration, error) {
	if c.TTL == "" {
		return 24 * time.Hour, nil // Default: 24h
	}
	return helpers.ParseDuration(c.TTL)
}

// GetCleanupInterval parses and returns the affinity cleanup interval duration
func (c *ClusterAffinityConfig) GetCleanupInterval() (time.Duration, error) {
	if c.CleanupInterval == "" {
		return 1 * time.Hour, nil // Default: 1h
	}
	return helpers.ParseDuration(c.CleanupInterval)
}

// ClusterConfig holds cluster coordination configuration using gossip protocol
type ClusterConfig struct {
	Enabled           bool                       `toml:"enabled"`                  // Enable cluster mode
	Addr              string                     `toml:"addr"`                     // Gossip listen address (must be specific IP:port, NOT 0.0.0.0 or localhost)
	Port              int                        `toml:"port"`                     // Gossip port (used if not specified in addr)
	NodeID            string                     `toml:"node_id"`                  // Unique node ID (defaults to hostname)
	Peers             []string                   `toml:"peers"`                    // Initial seed nodes
	SecretKey         string                     `toml:"secret_key" secret:"true"` // Cluster encryption key (base64-encoded 32-byte key)
	MaxEventQueueSize int                        `toml:"max_event_queue_size"`     // Maximum events per protocol queue (default: 50000)
	RateLimitSync     ClusterRateLimitSyncConfig `toml:"rate_limit_sync"`          // Auth rate limiting sync configuration
	Affinity          ClusterAffinityConfig      `toml:"affinity"`                 // Server affinity configuration
}

// splitClusterAddr splits addr into host and port. addr is a host or IP address,
// IPv6 bare or bracketed ("2001:db8::40", "[2001:db8::40]"), with an optional
// port ("10.0.0.40:7946", "[2001:db8::40]:7946"). port is "" when addr has none.
func splitClusterAddr(addr string) (host, port string) {
	if h, p, err := net.SplitHostPort(addr); err == nil {
		return h, p
	}
	return strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]"), ""
}

// GetBindAddr returns the bind address by parsing the addr field
func (c *ClusterConfig) GetBindAddr() string {
	host, _ := splitClusterAddr(c.Addr)
	return host
}

// GetBindPort returns the bind port from addr or the port field
func (c *ClusterConfig) GetBindPort() int {
	// If addr contains a port, use that
	if _, p := splitClusterAddr(c.Addr); p != "" {
		if port, err := strconv.Atoi(p); err == nil {
			return port
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
	Bucket     string `toml:"bucket"`                   // S3 bucket for certificate storage
	Endpoint   string `toml:"endpoint"`                 // S3-compatible storage endpoint (default: "s3.amazonaws.com")
	DisableTLS bool   `toml:"disable_tls"`              // Disable TLS for S3 endpoint (useful for local MinIO setups)
	Region     string `toml:"region"`                   // Signing region (default: AWS_REGION or the shared AWS config, else "us-east-1")
	Debug      bool   `toml:"debug"`                    // Enable detailed S3 request/response tracing
	AccessKey  string `toml:"access_key" secret:"true"` // AWS credentials (optional, uses default chain)
	SecretKey  string `toml:"secret_key" secret:"true"` // AWS credentials (optional)
	// ServerSideEncryption is the encryption asked of the store on every certificate
	// write: "AES256" for the store's own key management, "aws:kms" with a key id, or
	// "" for no encryption header at all. Pointer so an absent key (keep the default,
	// AES256) is distinguishable from an explicit "" (send no header), which is what a
	// store that rejects the header needs.
	ServerSideEncryption *string `toml:"server_side_encryption"`
	// ServerSideEncryptionKMSKeyID is the key id required by "aws:kms".
	ServerSideEncryptionKMSKeyID string `toml:"server_side_encryption_kms_key_id"`
}

// TLSLetsEncryptConfig holds Let's Encrypt automatic certificate management configuration
type TLSLetsEncryptConfig struct {
	Email           string                 `toml:"email"`            // Email for Let's Encrypt notifications
	Domains         []string               `toml:"domains"`          // Domains for certificate (supports multiple)
	DefaultDomain   string                 `toml:"default_domain"`   // Default domain to use when client doesn't provide SNI (optional, defaults to first domain in list)
	StorageProvider string                 `toml:"storage_provider"` // Certificate storage backend (currently only "s3")
	S3              TLSLetsEncryptS3Config `toml:"s3"`               // S3 storage configuration
	RenewBefore     string                 `toml:"renew_before"`     // Renew certificates this duration before expiry (e.g., "720h" = 30 days). Default: 30 days
	EnableFallback  *bool                  `toml:"enable_fallback"`  // Enable local filesystem fallback when S3 is unavailable (default: true). Pointer so an absent key is distinguishable from an explicit false.
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
	FTSRetention          string `toml:"fts_retention"` // How long to keep a message's FTS vector (messages_fts_v2)
	HealthStatusRetention string `toml:"health_status_retention"`
	// InstanceLivenessThreshold is how long an uploader instance must be silent
	// (no heartbeat, no lease on its own uploads) before the cleaner treats it as
	// gone and reaps the unuploaded messages whose bodies only existed on its disk.
	InstanceLivenessThreshold string `toml:"instance_liveness_threshold"`
	// PurgePollInterval is how often the purge worker (on nodes with object storage)
	// looks for accounts marked for purging.
	PurgePollInterval string `toml:"purge_poll_interval"`
}

// GetPurgePollInterval parses the purge worker's poll interval.
func (c *CleanupConfig) GetPurgePollInterval() (time.Duration, error) {
	if c.PurgePollInterval == "" {
		return 30 * time.Second, nil
	}
	return helpers.ParseDuration(c.PurgePollInterval)
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

// GetFTSRetention parses the FTS retention duration (for vector data)
func (c *CleanupConfig) GetFTSRetention() (time.Duration, error) {
	if c.FTSRetention == "" {
		return 0, nil // 0 means keep vectors forever (default)
	}
	return helpers.ParseDuration(c.FTSRetention)
}

// GetHealthStatusRetention parses the health status retention duration
func (c *CleanupConfig) GetHealthStatusRetention() (time.Duration, error) {
	if c.HealthStatusRetention == "" {
		return 30 * 24 * time.Hour, nil // 30 days default
	}
	return helpers.ParseDuration(c.HealthStatusRetention)
}

// GetInstanceLivenessThreshold parses the instance liveness threshold.
// The default is deliberately long: a shorter value than a plausible maintenance
// window would let a node that is merely rebooting be mistaken for a decommissioned
// one, and reaping mail whose only copy is on that node's disk is unrecoverable.
func (c *CleanupConfig) GetInstanceLivenessThreshold() (time.Duration, error) {
	if c.InstanceLivenessThreshold == "" {
		return 7 * 24 * time.Hour, nil // 7 days default
	}
	return helpers.ParseDuration(c.InstanceLivenessThreshold)
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
	Path      string `toml:"path"`
	BatchSize int    `toml:"batch_size"`
	// InstanceID is the identity this node writes into pending_uploads.instance_id and
	// instance_heartbeats.instance_id — the upload lease key. Default: the OS hostname.
	// It is deliberately NOT cluster.node_id: the lease key names whoever owns the staged
	// message bodies on this node's local disk, and must survive gossip renames. Set it
	// explicitly when running multiple sora instances on one host (each needs its own),
	// or to keep the lease identity stable across a planned hostname change. WARNING:
	// changing the resolved value strands queued uploads — drain first (see
	// config.Config.InstanceID).
	InstanceID         string `toml:"instance_id"`
	Concurrency        int    `toml:"concurrency"`
	MaxAttempts        int    `toml:"max_attempts"`
	RetryInterval      string `toml:"retry_interval"`
	CleanupGracePeriod string `toml:"cleanup_grace_period"` // Minimum age of a local upload file before cleanup considers it (default: "1h"). Must exceed the longest possible DB transaction to avoid the race where a file is deleted before its pending_upload record commits.
	MaxStagingSize     string `toml:"max_staging_size"`     // Maximum size of the global upload staging queue (e.g. "100gb"). If set and exceeded, new appends are rejected.
}

// DefaultUploaderMaxAttempts is [uploader] max_attempts when the key is absent.
const DefaultUploaderMaxAttempts = 20

// Validate rejects [uploader] settings that stop or crash the upload worker:
// batch_size, concurrency and max_attempts must be positive. A zero concurrency
// blocks the worker (and its instance heartbeat) for good, a negative one panics,
// a zero batch_size leases nothing and a negative one is refused by PostgreSQL,
// and max_attempts <= 0 leases nothing and fails the cleaner's failed-upload pass.
func (c *UploaderConfig) Validate() error {
	for _, f := range []struct {
		key   string
		value int
	}{
		{"batch_size", c.BatchSize},
		{"concurrency", c.Concurrency},
		{"max_attempts", c.MaxAttempts},
	} {
		if f.value <= 0 {
			return fmt.Errorf("[uploader] %s must be positive, got %d", f.key, f.value)
		}
	}
	return nil
}

// GetRetryInterval parses the retry interval duration
func (c *UploaderConfig) GetRetryInterval() (time.Duration, error) {
	if c.RetryInterval == "" {
		c.RetryInterval = "30s"
	}
	return helpers.ParseDuration(c.RetryInterval)
}

// GetCleanupGracePeriod parses the cleanup grace period duration.
// Must be long enough that no in-flight DB transaction can still be open when
// cleanupOrphanedFiles first considers a file (default: 1h).
func (c *UploaderConfig) GetCleanupGracePeriod() (time.Duration, error) {
	if c.CleanupGracePeriod == "" {
		return time.Hour, nil // safe default: no real transaction stays open for an hour
	}
	return helpers.ParseDuration(c.CleanupGracePeriod)
}

// GetMaxStagingSize parses the maximum staging size.
func (c *UploaderConfig) GetMaxStagingSize() (int64, error) {
	if c.MaxStagingSize == "" {
		return 0, nil // 0 means no limit
	}
	return helpers.ParseSize(c.MaxStagingSize)
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
	Enabled bool `toml:"enabled"` // Enable/disable rate limiting

	// Two-tier blocking system
	// Tier 1: Fast IP+username blocking (protects shared IPs like corporate gateways)
	MaxAttemptsPerIPUsername int           `toml:"max_attempts_per_ip_username"` // Max failed attempts per IP+username combo before blocking
	IPUsernameBlockDuration  time.Duration `toml:"ip_username_block_duration"`   // How long to block specific IP+username combo
	IPUsernameWindowDuration time.Duration `toml:"ip_username_window_duration"`  // Time window for counting IP+username failures

	// Tier 2: Slow IP-only blocking (catches distributed attacks from same IP)
	MaxAttemptsPerIP int           `toml:"max_attempts_per_ip"` // Max failed attempts per IP (any username) before blocking entire IP
	IPBlockDuration  time.Duration `toml:"ip_block_duration"`   // How long to block entire IP after max_attempts_per_ip reached
	IPWindowDuration time.Duration `toml:"ip_window_duration"`  // Time window for counting IP failures

	// Username tracking (statistics only, does not block)
	MaxAttemptsPerUsername int           `toml:"max_attempts_per_username"` // Max failed attempts per username (tracking only, does not block)
	UsernameWindowDuration time.Duration `toml:"username_window_duration"`  // Time window for username-based tracking

	CleanupInterval time.Duration `toml:"cleanup_interval"` // How often to clean up old entries and update metrics

	// Progressive delay settings
	DelayStartThreshold int           `toml:"delay_start_threshold"` // Failed attempts before progressive delays start
	InitialDelay        time.Duration `toml:"initial_delay"`         // First delay duration
	MaxDelay            time.Duration `toml:"max_delay"`             // Maximum delay duration
	DelayMultiplier     float64       `toml:"delay_multiplier"`      // Delay increase factor

	// Memory safety limits (prevents unbounded growth during burst attacks)
	MaxIPUsernameEntries int `toml:"max_ip_username_entries"` // Maximum IP+username tracking entries (default: 100000)
	MaxIPEntries         int `toml:"max_ip_entries"`          // Maximum IP failure tracking entries (default: 50000)
	MaxUsernameEntries   int `toml:"max_username_entries"`    // Maximum username tracking entries (default: 50000)

	// Networks exempt from IP-based blocking (Tier 1 IP+username and Tier 2 IP-only).
	// Username statistics are still tracked even for exempt IPs.
	//
	// DECOUPLED from [servers] trusted_networks, which governs PROXY/XCLIENT source-IP
	// trust: a host allowed to forward a client IP is not automatically exempt from rate
	// limiting, and vice versa. Keep this as narrow as possible — ideally just your own
	// webmail/relay hosts that legitimately make many auth attempts from one IP.
	//
	// Resolution (security-audit M2):
	//   - key absent → falls back to trusted_networks (backward-compatible default)
	//   - exempt_networks = []           → exempt nobody (every IP is rate-limited)
	//   - exempt_networks = ["a", "b"]   → exempt only these CIDRs
	ExemptNetworks []string `toml:"exempt_networks,omitempty"`
}

// Validate rejects negative counts, durations and multipliers, and a NaN or infinite
// multiplier. Zero means "use the default" (see applyAuthRateLimitDefaults); a negative
// value has no meaning, and the limiter does not read it consistently
// (max_attempts_per_ip = -1 blocked an address at its first failure on one path and
// disabled the IP block on another). TOML accepts nan and inf, which pass a sign check
// but are no growth factor. Any finite multiplier is safe: the limiter caps the
// product at max_delay before converting it to a time.Duration.
func (c *AuthRateLimiterConfig) Validate() error {
	v := reflect.ValueOf(c).Elem()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		problem := ""
		switch {
		case f.CanInt(): // int counts and time.Duration
			if f.Int() < 0 {
				problem = "must not be negative"
			}
		case f.CanFloat():
			if x := f.Float(); math.IsNaN(x) || math.IsInf(x, 0) {
				problem = "must be a finite number"
			} else if x < 0 {
				problem = "must not be negative"
			}
		}
		if problem != "" {
			return fmt.Errorf("auth_rate_limit.%s %s, got %v", tomlKey(v.Type().Field(i)), problem, f.Interface())
		}
	}
	return nil
}

// UnmarshalTOML decodes an auth_rate_limit table field by field, with its
// durations parsed like every other duration key (see decodeTable).
func (c *AuthRateLimiterConfig) UnmarshalTOML(data any) error {
	type plain AuthRateLimiterConfig
	return decodeTable("auth_rate_limit", data, (*plain)(c))
}

// DefaultAuthRateLimiterConfig returns sensible defaults for authentication rate limiting
func DefaultAuthRateLimiterConfig() AuthRateLimiterConfig {
	return AuthRateLimiterConfig{
		Enabled: false, // Disabled by default

		// Tier 1: Fast IP+username blocking (protects shared IPs like corporate gateways)
		// Blocks specific user from specific IP only - does not affect other users on same IP
		MaxAttemptsPerIPUsername: 5,                // Block after 5 failures (allows for typos)
		IPUsernameBlockDuration:  15 * time.Minute, // Block for 15 minutes
		IPUsernameWindowDuration: 10 * time.Minute, // 10 minute sliding window

		// Tier 2: Slow IP-only blocking (catches distributed attacks from same IP)
		// Only triggers when many usernames are tried from same IP
		MaxAttemptsPerIP: 50,               // Block entire IP after 50 failures (high threshold)
		IPBlockDuration:  30 * time.Minute, // Block for 30 minutes (more severe)
		IPWindowDuration: 30 * time.Minute, // 30 minute sliding window

		// Username tracking (statistics only, does NOT block to prevent DoS)
		MaxAttemptsPerUsername: 10,               // Track username failures across all IPs
		UsernameWindowDuration: 60 * time.Minute, // 1 hour window for monitoring

		CleanupInterval: 5 * time.Minute, // Clean up expired entries every 5 minutes

		// Progressive delays (slows down attackers before blocking)
		DelayStartThreshold: 2,                // Start delays after 2 failures
		InitialDelay:        1 * time.Second,  // 1 second initial delay
		MaxDelay:            30 * time.Second, // Max 30 second delay
		DelayMultiplier:     2.0,              // Double delay each time

		// Memory safety limits (prevents OOM during burst attacks)
		MaxIPUsernameEntries: 100000, // ~25MB per protocol at capacity
		MaxIPEntries:         50000,  // ~7.5MB per protocol at capacity
		MaxUsernameEntries:   50000,  // ~7.5MB per protocol at capacity
	}
}

// LookupCacheConfig holds configuration for authentication result caching.
// A [server.lookup_cache] table is decoded on top of DefaultLookupCacheConfig
// (see UnmarshalTOML), so the keys it leaves out, enabled included, keep their defaults.
type LookupCacheConfig struct {
	Enabled                    bool   `toml:"enabled"`                      // Enable in-memory caching of authentication results (default: true; the User API and its proxy cache only with a lookup_cache table)
	PositiveTTL                string `toml:"positive_ttl"`                 // TTL for successful auth (default: "5m")
	NegativeTTL                string `toml:"negative_ttl"`                 // TTL for failed auth (default: "1m")
	MaxSize                    int    `toml:"max_size"`                     // Maximum number of cached entries (default: 50000)
	CleanupInterval            string `toml:"cleanup_interval"`             // How often to clean expired entries (default: "5m")
	PositiveRevalidationWindow string `toml:"positive_revalidation_window"` // How long to wait before revalidating positive cache with different password (default: "30s")
}

// DefaultLookupCacheConfig returns sensible defaults for authentication and routing lookup caching
func DefaultLookupCacheConfig() LookupCacheConfig {
	return LookupCacheConfig{
		Enabled:                    true,  // Enable by default for better performance
		PositiveTTL:                "5m",  // Cache successful auth for 5 minutes (avoid expensive bcrypt)
		NegativeTTL:                "1m",  // Cache failed auth for 1 minute (limit brute force impact)
		MaxSize:                    50000, // 50k entries = ~10MB memory (80% positive, 20% negative)
		CleanupInterval:            "5m",  // Clean up expired entries every 5 minutes
		PositiveRevalidationWindow: "30s", // Allow password change detection after 30 seconds
	}
}

// tomlErrorPosition matches the position prefix of a toml decode error,
// capturing the key: `toml: line 1 (last key "enabled"): `.
var tomlErrorPosition = regexp.MustCompile(`^toml: (?:line \d+ )?\(last key "([^"]*)"\): `)

// UnmarshalTOML decodes a [server.lookup_cache] table on top of
// DefaultLookupCacheConfig, so a table that only tunes, say, positive_ttl leaves
// the cache enabled with the default max_size. Decoded field by field, an omitted
// enabled would be false and turn the cache off.
func (c *LookupCacheConfig) UnmarshalTOML(data any) error {
	type plain LookupCacheConfig
	decoded := plain(DefaultLookupCacheConfig())
	if err := decodeTable("lookup_cache", data, &decoded); err != nil {
		return err
	}
	*c = LookupCacheConfig(decoded)
	return nil
}

// decodeTable decodes data, the table the toml package hands an UnmarshalTOML
// method, into v, a pointer to a struct type without one: the table is encoded
// again and decoded field by field. name is the table's key, for messages.
//
// A time.Duration field is parsed with helpers.ParseDuration, like every other
// duration key, so it takes whole days ("1d"). Left to the toml package it would
// take time.ParseDuration syntax only, and a bare integer as nanoseconds; here an
// integer has no unit, so it is an error as "900" is for the other keys.
func decodeTable(name string, data any, v any) error {
	table, ok := data.(map[string]any)
	if !ok {
		return fmt.Errorf("%s must be a table, got %T", name, data)
	}
	table = maps.Clone(table)
	typ := reflect.TypeOf(v).Elem()
	for i := range typ.NumField() {
		field := typ.Field(i)
		if field.Type != reflect.TypeOf(time.Duration(0)) {
			continue
		}
		key := tomlKey(field)
		value, ok := table[key]
		if !ok {
			continue
		}
		s, ok := value.(string)
		if !ok {
			return fmt.Errorf("%s: a duration is a string with a unit, such as \"15m\" or \"1d\", got %v", key, value)
		}
		// Parsed here, before LoadConfigFromFile trims every string, so trim it the same way.
		d, err := helpers.ParseDuration(strings.TrimSpace(s))
		if err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		table[key] = int64(d) // the toml package decodes an integer into a time.Duration as nanoseconds
	}

	var buf strings.Builder
	if err := toml.NewEncoder(&buf).Encode(table); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	md, err := toml.Decode(buf.String(), v)
	if err != nil {
		// The line in err is one of the re-encoded table, not of the file; the
		// outer decoder adds the table's own line. Keep the key and the reason.
		return errors.New(tomlErrorPosition.ReplaceAllString(err.Error(), "$1: "))
	}
	// The outer decoder counts every key of a table handled here as decoded, so
	// report unknown ones here.
	for _, key := range md.Undecoded() {
		log.Printf("WARNING: Unknown key '%s.%s' will be ignored", name, key)
	}
	return nil
}

// GetMaxSize returns max_size, or the default (50000) when it is zero or negative.
func (c *LookupCacheConfig) GetMaxSize() int {
	if c.MaxSize <= 0 {
		return DefaultLookupCacheConfig().MaxSize
	}
	return c.MaxSize
}

// The lookup_cache durations a key gets when it is absent.
const (
	defaultLookupCachePositiveTTL                = 5 * time.Minute
	defaultLookupCacheNegativeTTL                = 1 * time.Minute
	defaultLookupCacheCleanupInterval            = 5 * time.Minute
	defaultLookupCachePositiveRevalidationWindow = 30 * time.Second
)

// GetPositiveTTL parses and returns the positive TTL duration
func (c *LookupCacheConfig) GetPositiveTTL() (time.Duration, error) {
	return parseLookupCacheDuration(c.PositiveTTL, defaultLookupCachePositiveTTL)
}

// GetPositiveTTLWithDefault returns positive_ttl, or its default if the value cannot be
// parsed. server names the server whose table this is, for the warning.
func (c *LookupCacheConfig) GetPositiveTTLWithDefault(server string) time.Duration {
	return lookupCacheDurationWithDefault(server, "positive_ttl", c.PositiveTTL, defaultLookupCachePositiveTTL)
}

// GetNegativeTTL parses and returns the negative TTL duration
func (c *LookupCacheConfig) GetNegativeTTL() (time.Duration, error) {
	return parseLookupCacheDuration(c.NegativeTTL, defaultLookupCacheNegativeTTL)
}

// GetNegativeTTLWithDefault returns negative_ttl, or its default if the value cannot be
// parsed. server names the server whose table this is, for the warning.
func (c *LookupCacheConfig) GetNegativeTTLWithDefault(server string) time.Duration {
	return lookupCacheDurationWithDefault(server, "negative_ttl", c.NegativeTTL, defaultLookupCacheNegativeTTL)
}

// GetCleanupInterval parses and returns the cleanup interval duration
func (c *LookupCacheConfig) GetCleanupInterval() (time.Duration, error) {
	return parseLookupCacheDuration(c.CleanupInterval, defaultLookupCacheCleanupInterval)
}

// GetCleanupIntervalWithDefault returns cleanup_interval, or its default if the value
// cannot be parsed. server names the server whose table this is, for the warning.
func (c *LookupCacheConfig) GetCleanupIntervalWithDefault(server string) time.Duration {
	return lookupCacheDurationWithDefault(server, "cleanup_interval", c.CleanupInterval, defaultLookupCacheCleanupInterval)
}

// GetPositiveRevalidationWindow parses and returns the positive revalidation window duration
func (c *LookupCacheConfig) GetPositiveRevalidationWindow() (time.Duration, error) {
	return parseLookupCacheDuration(c.PositiveRevalidationWindow, defaultLookupCachePositiveRevalidationWindow)
}

// GetPositiveRevalidationWindowWithDefault returns positive_revalidation_window, or its
// default if the value cannot be parsed. server names the server whose table this is,
// for the warning.
func (c *LookupCacheConfig) GetPositiveRevalidationWindowWithDefault(server string) time.Duration {
	return lookupCacheDurationWithDefault(server, "positive_revalidation_window", c.PositiveRevalidationWindow, defaultLookupCachePositiveRevalidationWindow)
}

func parseLookupCacheDuration(value string, def time.Duration) (time.Duration, error) {
	if value == "" {
		return def, nil
	}
	return helpers.ParseDuration(value)
}

func lookupCacheDurationWithDefault(server, key, value string, def time.Duration) time.Duration {
	d, err := parseLookupCacheDuration(value, def)
	if err != nil {
		warnf("Failed to parse lookup_cache.%s for server '%s': %v, using default (%s)", key, server, err, def)
		return def
	}
	return d
}

// RemoteLookupConfig holds configuration for HTTP-based user routing
type RemoteLookupConfig struct {
	Enabled   bool   `toml:"enabled"`
	URL       string `toml:"url"`                      // HTTP endpoint URL for lookups (e.g., "http://localhost:8080/lookup")
	Timeout   string `toml:"timeout"`                  // HTTP request timeout (default: "5s")
	AuthToken string `toml:"auth_token" secret:"true"` // Bearer token for HTTP authentication (optional)

	// Backend connection settings
	LookupLocalUsers       bool   `toml:"lookup_local_users"`        // Check local DB when remote returns 404/3xx (for split user scenarios)
	UserNotFoundResponse   string `toml:"user_not_found_response"`   // LMTP response when user not found: "reject" (550), "tempfail" (450) - default: "reject"
	RemoteTLS              bool   `toml:"remote_tls"`                // Use TLS for backend connections
	RemoteTLSUseStartTLS   bool   `toml:"remote_tls_use_starttls"`   // Use STARTTLS for backend connections (requires remote_tls)
	RemoteTLSVerify        *bool  `toml:"remote_tls_verify"`         // Verify backend TLS certificate
	RemotePort             any    `toml:"remote_port"`               // Default port for routed backends if not in address
	RemoteUseProxyProtocol bool   `toml:"remote_use_proxy_protocol"` // Use PROXY protocol for backend connections
	RemoteUseIDCommand     bool   `toml:"remote_use_id_command"`     // Use IMAP ID command (IMAP only)
	RemoteUseXCLIENT       bool   `toml:"remote_use_xclient"`        // Use XCLIENT command (POP3/LMTP)
	RemoteUseUTF8          bool   `toml:"remote_use_utf8"`           // Lookup-routed backends support POP3 UTF8/RFC 6856 (mirror client's pre-auth UTF8 to them). Keep false for Dovecot backends. (POP3 only)

	// RestrictToPool, when true, refuses a backend address returned by the remote-lookup
	// API unless it is in the configured pool (remote_addrs); routing then falls back to
	// in-pool selection (consistent-hash/round-robin). Defends against SSRF via a
	// compromised/MITM'd lookup API. Default false (routing mode may legitimately return
	// dynamic out-of-pool backends).
	RestrictToPool bool `toml:"restrict_to_pool"`

	// Circuit breaker configuration
	CircuitBreaker *RemoteLookupCircuitBreakerConfig `toml:"circuit_breaker"` // Circuit breaker configuration

	// HTTP transport configuration
	Transport *RemoteLookupTransportConfig `toml:"transport"` // HTTP transport connection pooling settings
}

// RemoteLookupCircuitBreakerConfig holds circuit breaker configuration for remote_lookup
type RemoteLookupCircuitBreakerConfig struct {
	MaxRequests  int     `toml:"max_requests"`  // Maximum concurrent requests in half-open state (default: 3)
	Interval     string  `toml:"interval"`      // Time before resetting failure counts in closed state (default: "0s" - never reset)
	Timeout      string  `toml:"timeout"`       // Time before transitioning from open to half-open (default: "30s")
	FailureRatio float64 `toml:"failure_ratio"` // Failure ratio threshold to open circuit (0.0-1.0, default: 0.6)
	MinRequests  int     `toml:"min_requests"`  // Minimum completed requests before evaluating failure ratio (default: 3)
}

// RemoteLookupTransportConfig holds HTTP transport configuration for remote_lookup connection pooling and timeouts
type RemoteLookupTransportConfig struct {
	MaxIdleConns          int    `toml:"max_idle_conns"`          // Maximum idle connections across all hosts (default: 100)
	MaxIdleConnsPerHost   int    `toml:"max_idle_conns_per_host"` // Maximum idle connections per host (default: 100)
	MaxConnsPerHost       int    `toml:"max_conns_per_host"`      // Maximum total connections per host, 0 = unlimited (default: 0)
	IdleConnTimeout       string `toml:"idle_conn_timeout"`       // How long idle connections stay open (default: "90s")
	DialTimeout           string `toml:"dial_timeout"`            // TCP connection timeout including DNS (default: "30s")
	TLSHandshakeTimeout   string `toml:"tls_handshake_timeout"`   // TLS handshake timeout (default: "30s")
	ExpectContinueTimeout string `toml:"expect_continue_timeout"` // 100-continue timeout (default: "1s")
	KeepAlive             string `toml:"keep_alive"`              // TCP keep-alive interval (default: "30s")
}

// GetTimeout returns the configured HTTP timeout duration
func (c *RemoteLookupConfig) GetTimeout() (time.Duration, error) {
	if c.Timeout == "" {
		return 5 * time.Second, nil
	}
	return helpers.ParseDuration(c.Timeout)
}

// ShouldLookupLocalUsers returns whether to check local DB when remote returns 404/3xx
func (c *RemoteLookupConfig) ShouldLookupLocalUsers() bool {
	// If new setting is explicitly set, use it
	if c.LookupLocalUsers {
		return true
	}
	return false
}

// GetUserNotFoundResponse returns the configured response for user not found scenario
// Returns: "reject" (550) or "tempfail" (450)
// Default: "reject"
func (c *RemoteLookupConfig) GetUserNotFoundResponse() string {
	switch c.UserNotFoundResponse {
	case "reject", "tempfail":
		return c.UserNotFoundResponse
	default:
		return "reject" // Default to rejection
	}
}

// Circuit breaker configuration helpers

// GetMaxRequests returns the maximum concurrent requests in half-open state
func (c *RemoteLookupCircuitBreakerConfig) GetMaxRequests() uint32 {
	if c.MaxRequests <= 0 {
		return 3 // Default: 3 concurrent requests
	}
	return uint32(c.MaxRequests)
}

// GetInterval returns the interval before resetting failure counts in closed state
func (c *RemoteLookupCircuitBreakerConfig) GetInterval() (time.Duration, error) {
	if c.Interval == "" {
		return 0, nil // Default: never reset automatically
	}
	return helpers.ParseDuration(c.Interval)
}

// GetTimeout returns the timeout before transitioning from open to half-open
func (c *RemoteLookupCircuitBreakerConfig) GetTimeout() (time.Duration, error) {
	if c.Timeout == "" {
		return 30 * time.Second, nil // Default: 30 seconds
	}
	return helpers.ParseDuration(c.Timeout)
}

// GetFailureRatio returns the failure ratio threshold to open circuit
func (c *RemoteLookupCircuitBreakerConfig) GetFailureRatio() float64 {
	if c.FailureRatio <= 0 || c.FailureRatio > 1 {
		return 0.6 // Default: 60% failure rate
	}
	return c.FailureRatio
}

// GetMinRequests returns the minimum completed requests before evaluating failure ratio
func (c *RemoteLookupCircuitBreakerConfig) GetMinRequests() uint32 {
	if c.MinRequests <= 0 {
		return 3 // Default: 3 requests
	}
	return uint32(c.MinRequests)
}

// Transport configuration helpers

// GetMaxIdleConns returns the maximum idle connections across all hosts
func (c *RemoteLookupTransportConfig) GetMaxIdleConns() int {
	if c.MaxIdleConns <= 0 {
		return 100 // Default: 100 idle connections
	}
	return c.MaxIdleConns
}

// GetMaxIdleConnsPerHost returns the maximum idle connections per host
func (c *RemoteLookupTransportConfig) GetMaxIdleConnsPerHost() int {
	if c.MaxIdleConnsPerHost <= 0 {
		return 100 // Default: 100 idle connections per host
	}
	return c.MaxIdleConnsPerHost
}

// GetMaxConnsPerHost returns the maximum total connections per host (0 = unlimited)
func (c *RemoteLookupTransportConfig) GetMaxConnsPerHost() int {
	return c.MaxConnsPerHost // Default: 0 (unlimited)
}

// GetIdleConnTimeout returns the idle connection timeout duration
func (c *RemoteLookupTransportConfig) GetIdleConnTimeout() (time.Duration, error) {
	if c.IdleConnTimeout == "" {
		return 90 * time.Second, nil // Default: 90 seconds
	}
	return helpers.ParseDuration(c.IdleConnTimeout)
}

// GetDialTimeout returns the TCP dial timeout duration (includes DNS resolution)
func (c *RemoteLookupTransportConfig) GetDialTimeout() (time.Duration, error) {
	if c.DialTimeout == "" {
		return 10 * time.Second, nil // Default: 10 seconds
	}
	return helpers.ParseDuration(c.DialTimeout)
}

// GetTLSHandshakeTimeout returns the TLS handshake timeout duration
func (c *RemoteLookupTransportConfig) GetTLSHandshakeTimeout() (time.Duration, error) {
	if c.TLSHandshakeTimeout == "" {
		return 10 * time.Second, nil // Default: 10 seconds
	}
	return helpers.ParseDuration(c.TLSHandshakeTimeout)
}

// GetExpectContinueTimeout returns the expect continue timeout duration
func (c *RemoteLookupTransportConfig) GetExpectContinueTimeout() (time.Duration, error) {
	if c.ExpectContinueTimeout == "" {
		return 1 * time.Second, nil // Default: 1 second
	}
	return helpers.ParseDuration(c.ExpectContinueTimeout)
}

// GetKeepAlive returns the TCP keep-alive interval
func (c *RemoteLookupTransportConfig) GetKeepAlive() (time.Duration, error) {
	if c.KeepAlive == "" {
		return 30 * time.Second, nil // Default: 30 seconds
	}
	return helpers.ParseDuration(c.KeepAlive)
}

// GetRemotePort parses the remote port and returns it as an int.
func (c *RemoteLookupConfig) GetRemotePort() (int, error) {
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

// ServerLimitsConfig holds resource limits for a server
type ServerLimitsConfig struct {
	SearchRateLimitPerMin *int   `toml:"search_rate_limit_per_min,omitempty"` // Search rate limit (searches per minute, 0=disabled, default: 60)
	SearchRateLimitWindow string `toml:"search_rate_limit_window,omitempty"`  // Search rate limit time window (default: 1m)
	SearchRateLimitBurst  *int   `toml:"search_rate_limit_burst,omitempty"`   // Searches allowed back to back (default: search_rate_limit_per_min)
	ThreadMaxMessages     int    `toml:"thread_max_messages,omitempty"`       // Maximum matches per THREAD command (IMAP backend only, <=0 uses default: 50000)
	RedirectRateLimit     *int   `toml:"redirect_rate_limit,omitempty"`       // Redirect rate limit (per account across the window, 0=unlimited, default: 100)
	RedirectRateWindow    string `toml:"redirect_rate_window,omitempty"`      // Redirect rate limit time window (default: 1h)
	MaxRedirectHops       *int   `toml:"max_redirect_hops,omitempty"`         // Max times one message may be redirected before suppression (mail-loop backstop, 0=unlimited, default: 2)
	SessionMemoryLimit    string `toml:"session_memory_limit,omitempty"`      // Per-session memory limit (default: 100mb, 0=unlimited)
	MaxAuthErrors         int    `toml:"max_auth_errors,omitempty"`           // Maximum authentication errors before disconnection (default: 2)
	PreviewS3PerMin       *int   `toml:"preview_s3_per_min,omitempty"`        // S3 downloads per account per minute to answer FETCH PREVIEW without LAZY (IMAP backend only, 0=unlimited, default: 300)
	PreviewS3Burst        *int   `toml:"preview_s3_burst,omitempty"`          // Of those, how many may run back to back (default: min(200, positive per-minute limit))
	PreviewS3NodePerMin   *int   `toml:"preview_s3_node_per_min,omitempty"`   // The same downloads for the whole server per minute (0=unlimited, default: 3000)
	PreviewS3MaxSize      string `toml:"preview_s3_max_size,omitempty"`       // Largest message downloaded for a preview (unset or 0: [local_cache] max_object_size)
}

// ServerTimeoutsConfig holds timeout settings for a server
type ServerTimeoutsConfig struct {
	CommandTimeout             string                            `toml:"command_timeout,omitempty"`              // Maximum idle time before disconnection (default: protocol-specific)
	AbsoluteSessionTimeout     string                            `toml:"absolute_session_timeout,omitempty"`     // Maximum total session duration (default: 24h)
	MinBytesPerMinute          int64                             `toml:"min_bytes_per_minute,omitempty"`         // Minimum throughput to prevent slowloris (default: 0 = disabled, recommended: 512 bytes/min)
	SchedulerShardCount        int                               `toml:"scheduler_shard_count,omitempty"`        // Number of timeout scheduler shards (default: 0 = runtime.NumCPU(), -1 = runtime.NumCPU()/2 for physical cores)
	IMAPCommandTimeouts        *CommandTimeoutsConfig            `toml:"imap_command_timeouts,omitempty"`        // Per-command hard execution timeouts (IMAP only)
	ManageSieveCommandTimeouts *ManageSieveCommandTimeoutsConfig `toml:"managesieve_command_timeouts,omitempty"` // Per-command hard execution timeouts (ManageSieve only)
	POP3CommandTimeouts        *POP3CommandTimeoutsConfig        `toml:"pop3_command_timeouts,omitempty"`        // Per-command hard execution timeouts (POP3 only)
	LMTPCommandTimeouts        *LMTPCommandTimeoutsConfig        `toml:"lmtp_command_timeouts,omitempty"`        // Per-command hard execution timeouts (LMTP only)
}

// CommandTimeoutsConfig holds per-command hard timeout limits for expensive IMAP
// commands. All values are duration strings (e.g. "30s", "2m"). Omitted fields
// use generous defaults that act as safety nets against runaway queries.
type CommandTimeoutsConfig struct {
	Search      string `toml:"search,omitempty"`       // SEARCH timeout (default: "30s")
	Sort        string `toml:"sort,omitempty"`         // SORT timeout (default: "30s")
	Thread      string `toml:"thread,omitempty"`       // THREAD timeout (default: "30s")
	MultiSearch string `toml:"multi_search,omitempty"` // MULTISEARCH timeout (default: "30s")
	Fetch       string `toml:"fetch,omitempty"`        // FETCH timeout (default: "0" = uncapped)
	Store       string `toml:"store,omitempty"`        // STORE timeout (default: "15s")
	Copy        string `toml:"copy,omitempty"`         // COPY timeout (default: "30s")
	Move        string `toml:"move,omitempty"`         // MOVE timeout (default: "30s")
	Rename      string `toml:"rename,omitempty"`       // RENAME timeout (default: "60s")
}

// ManageSieveCommandTimeoutsConfig holds per-command hard timeout limits for
// ManageSieve script operations, mirroring the IMAP command timeouts. All
// values are duration strings (e.g. "30s", "2m"); "0" disables the timeout for
// that command. Omitted fields use generous defaults that act as safety nets
// against a wedged backend (slow database, stuck lock). AUTHENTICATE is
// deliberately not covered: it is paced by the progressive auth delay
// (auth_rate_limit), which a hard cap would fight.
type ManageSieveCommandTimeoutsConfig struct {
	ListScripts  string `toml:"listscripts,omitempty"`  // LISTSCRIPTS timeout (default: "10s")
	GetScript    string `toml:"getscript,omitempty"`    // GETSCRIPT timeout (default: "10s")
	PutScript    string `toml:"putscript,omitempty"`    // PUTSCRIPT timeout (default: "10s")
	CheckScript  string `toml:"checkscript,omitempty"`  // CHECKSCRIPT timeout (default: "10s")
	SetActive    string `toml:"setactive,omitempty"`    // SETACTIVE timeout (default: "10s")
	DeleteScript string `toml:"deletescript,omitempty"` // DELETESCRIPT timeout (default: "10s")
	RenameScript string `toml:"renamescript,omitempty"` // RENAMESCRIPT timeout (default: "10s")
	HaveSpace    string `toml:"havespace,omitempty"`    // HAVESPACE timeout (default: "10s")
}

// POP3CommandTimeoutsConfig holds per-command hard timeout limits for POP3
// maildrop operations, mirroring the IMAP and ManageSieve command timeouts.
// All values are duration strings (e.g. "10s", "1m"); "0" disables the timeout
// for that command. RETR/TOP get more generous defaults because they fetch the
// message body from cache/S3 (like IMAP FETCH); the timeout covers only the
// server-side load, not streaming the body to the client. USER/PASS/APOP/AUTH
// are deliberately not covered: they are paced by the progressive auth delay
// (auth_rate_limit), which a hard cap would fight.
type POP3CommandTimeoutsConfig struct {
	Stat string `toml:"stat,omitempty"` // STAT timeout (default: "10s")
	List string `toml:"list,omitempty"` // LIST timeout (default: "10s")
	Uidl string `toml:"uidl,omitempty"` // UIDL timeout (default: "10s")
	Retr string `toml:"retr,omitempty"` // RETR timeout (default: "30s")
	Top  string `toml:"top,omitempty"`  // TOP timeout (default: "30s")
	Dele string `toml:"dele,omitempty"` // DELE timeout (default: "10s")
	Quit string `toml:"quit,omitempty"` // QUIT timeout — UPDATE-phase expunge (default: "15s")
}

// LMTPCommandTimeoutsConfig holds per-command hard timeout limits for the two
// LMTP phases that do real server-side work. All values are duration strings
// (e.g. "10s", "1m"); "0" disables the timeout for that command. A timeout
// surfaces as a 4xx temporary failure, so the upstream MTA queues and retries.
// The DATA cap covers only the delivery pipeline (SIEVE, spool, DB insert) —
// wire reception from a slow MTA is governed by the server read timeout, not
// this cap.
type LMTPCommandTimeoutsConfig struct {
	Rcpt string `toml:"rcpt,omitempty"` // RCPT timeout (default: "10s")
	Data string `toml:"data,omitempty"` // DATA processing timeout (default: "60s")
}

// ServerConfig represents a single server instance
type ServerConfig struct {
	Type string `toml:"type"`
	Name string `toml:"name"`
	Addr string `toml:"addr"`
	// Enabled = false keeps the block in the file without starting or validating it.
	// nil (absent) or true starts it. See IsEnabled.
	Enabled *bool `toml:"enabled,omitempty"`

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
	MaxConnections             int `toml:"max_connections,omitempty"`
	MaxConnectionsPerIP        int `toml:"max_connections_per_ip,omitempty"`
	MaxConnectionsPerUser      int `toml:"max_connections_per_user,omitempty"`        // Cluster-wide per-user limit (proxy only, requires cluster mode)
	MaxConnectionsPerUserPerIP int `toml:"max_connections_per_user_per_ip,omitempty"` // Local per-user-per-IP limit
	ListenBacklog              int `toml:"listen_backlog,omitempty"`                  // TCP listen backlog size (0=system default, typically 128-512; recommended: 4096-8192)

	// IMAP specific
	AppendLimit        string `toml:"append_limit,omitempty"`
	MasterUsername     string `toml:"master_username,omitempty"`
	MasterPassword     string `toml:"master_password,omitempty" secret:"true"`
	MasterSASLUsername string `toml:"master_sasl_username,omitempty"`
	MasterSASLPassword string `toml:"master_sasl_password,omitempty" secret:"true"`
	// MasterSASLAllowedNetworks optionally restricts which source networks may use
	// master credentials to impersonate users on this backend: master SASL and the
	// master-username form (user@domain@master_username) alike, on IMAP, POP3 and
	// ManageSieve. It is anchored to the real socket peer (not forwardable via
	// PROXY/XCLIENT/IMAP ID), so it should list the proxy hosts. Empty = disabled
	// (master logins allowed from any source — legacy behavior; relies solely on
	// network isolation + secret secrecy).
	MasterSASLAllowedNetworks []string `toml:"master_sasl_allowed_networks,omitempty"`

	// STARTTLS on the listening port (requires tls = true): IMAP, LMTP, ManageSieve, POP3 and their proxies
	TLSUseStartTLS bool `toml:"tls_use_starttls,omitempty"`

	// LMTP specific
	MaxMessageSize string `toml:"max_message_size,omitempty"` // Maximum size for incoming LMTP messages

	// Auth security
	InsecureAuth bool `toml:"insecure_auth,omitempty"` // Allow PLAIN auth over non-TLS connections (default: false for ManageSieve, true for IMAP/LMTP behind proxy)

	// ManageSieve specific
	MaxScriptSize       string   `toml:"max_script_size,omitempty"`
	SupportedExtensions []string `toml:"supported_extensions,omitempty"` // List of supported Sieve extensions (additional to builtins)

	// Proxy specific
	RemoteAddrs            []string `toml:"remote_addrs,omitempty"`
	RemotePort             any      `toml:"remote_port,omitempty"` // Default port for backends if not in address
	RemoteTLS              bool     `toml:"remote_tls,omitempty"`
	RemoteTLSUseStartTLS   bool     `toml:"remote_tls_use_starttls,omitempty"` // Use STARTTLS for backend connections
	RemoteTLSVerify        bool     `toml:"remote_tls_verify,omitempty"`
	RemoteTLSCAFile        string   `toml:"remote_tls_ca_file,omitempty"` // PEM file with CA certs for backend verification (private-CA / self-signed backends); empty = system roots
	RemoteUseProxyProtocol bool     `toml:"remote_use_proxy_protocol,omitempty"`
	RemoteUseIDCommand     bool     `toml:"remote_use_id_command,omitempty"`
	RemoteUseXCLIENT       bool     `toml:"remote_use_xclient,omitempty"`
	RemoteUseUTF8          bool     `toml:"remote_use_utf8,omitempty"` // POP3 proxy only: advertise UTF8/LANG in pre-auth CAPA and mirror UTF8 to pool backends. Enable ONLY when every backend is sora: classic Outlook sends UTF8 post-auth when advertised, and non-sora backends reject it fatally (0x800CCC90).
	ConnectTimeout         string   `toml:"connect_timeout,omitempty"`
	AuthIdleTimeout        string   `toml:"auth_idle_timeout,omitempty"`
	EnableAffinity         bool     `toml:"enable_affinity,omitempty"`
	RemoteHealthChecks     *bool    `toml:"remote_health_checks,omitempty"` // Enable backend health checking (default: true)
	// RemoteDNSRefresh is how often the proxy re-resolves the hostnames in remote_addrs,
	// so a backend that changes address (rolling replacement, container reschedule, DNS
	// failover) is picked up without a restart. Empty = 5m. "0" pins the pool to the
	// addresses resolved at startup. A name that stops resolving always keeps its last
	// known addresses, whatever this is set to.
	RemoteDNSRefresh string `toml:"remote_dns_refresh,omitempty"`

	// HTTP API specific
	APIKey         string   `toml:"api_key,omitempty" secret:"true"`
	ReadOnlyAPIKey string   `toml:"read_only_api_key,omitempty" secret:"true"` // http_admin_api: optional second key, GET requests only
	AllowedHosts   []string `toml:"allowed_hosts,omitempty"`

	// Mail HTTP API specific (stateless JWT-based authentication)
	JWTSecret      string   `toml:"jwt_secret,omitempty" secret:"true"` // Secret key for signing JWT tokens
	TokenDuration  string   `toml:"token_duration,omitempty"`           // Token validity duration (e.g., "24h", "7d")
	TokenIssuer    string   `toml:"token_issuer,omitempty"`             // JWT issuer field
	AllowedOrigins []string `toml:"allowed_origins,omitempty"`          // CORS allowed origins for web clients

	// Metrics specific
	Path                 string `toml:"path,omitempty"`
	EnableUserMetrics    bool   `toml:"enable_user_metrics,omitempty"`
	EnableDomainMetrics  *bool  `toml:"enable_domain_metrics,omitempty"`  // nil = default (true); see GetEnableDomainMetrics
	UserMetricsThreshold *int   `toml:"user_metrics_threshold,omitempty"` // nil = default (1000); see GetUserMetricsThreshold
	MaxTrackedUsers      *int   `toml:"max_tracked_users,omitempty"`      // nil = default (1000); see GetMaxTrackedUsers
	HashUsernames        *bool  `toml:"hash_usernames,omitempty"`         // nil = default (true); see GetHashUsernames

	// Auth rate limiting (embedded)
	AuthRateLimit *AuthRateLimiterConfig `toml:"auth_rate_limit,omitempty"`

	// Auth caching (embedded) - for proxies
	LookupCache *LookupCacheConfig `toml:"lookup_cache,omitempty"`

	// Resource limits (embedded)
	Limits *ServerLimitsConfig `toml:"limits,omitempty"`

	// Session timeouts (embedded)
	Timeouts *ServerTimeoutsConfig `toml:"timeouts,omitempty"`

	// Pre-lookup (embedded)
	RemoteLookup *RemoteLookupConfig `toml:"remote_lookup,omitempty"`

	// Client capability filtering (IMAP specific)
	ClientFilters  []ClientCapabilityFilter `toml:"client_filters,omitempty"`
	DisabledCaps   []string                 `toml:"disabled_caps,omitempty"`   // Globally disabled capabilities (IMAP specific)
	AdditionalCaps []string                 `toml:"additional_caps,omitempty"` // Extra capability tokens advertised verbatim, e.g. "X-ICEWARP-SERVER" (IMAP specific)
	EnablePreview  bool                     `toml:"enable_preview,omitempty"`  // Advertise FETCH PREVIEW, RFC 8970 (IMAP backend only, default: false; limits in [limits] preview_s3_*)
	IDName         string                   `toml:"id_name,omitempty"`         // IMAP ID command 'name' field (IMAP specific)
	IDVersion      string                   `toml:"id_version,omitempty"`      // IMAP ID command 'version' field (IMAP specific)
	IDVendor       string                   `toml:"id_vendor,omitempty"`       // IMAP ID command 'vendor' field (IMAP specific)
	IDSupportURL   string                   `toml:"id_support_url,omitempty"`  // IMAP ID command 'support-url' field (IMAP specific)
}

// TimeoutSchedulerConfig holds global timeout scheduler configuration
type TimeoutSchedulerConfig struct {
	ShardCount int `toml:"shard_count"` // Number of timeout scheduler shards (0=runtime.NumCPU(), -1=runtime.NumCPU()/2, >0=specific value)
}

// ServersConfig holds all server configurations.
type ServersConfig struct {
	TrustedNetworks []string `toml:"trusted_networks"` // Global trusted networks for proxy parameter forwarding
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Output string `toml:"output"` // Log output: "stderr", "stdout", "syslog", or file path (reopened on SIGHUP for log rotation)
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

// InNamespace reports whether a mailbox of this name is created as a shared mailbox:
// the feature is enabled and the name is under the namespace prefix, or is its root.
func (c SharedMailboxesConfig) InNamespace(name string) bool {
	if !c.Enabled {
		return false
	}
	// Sora resolves every mailbox name case-insensitively. Classification must
	// use that same rule, or a case variant can bypass shared namespace policy.
	name, prefix := strings.ToLower(name), strings.ToLower(c.NamespacePrefix)
	return strings.HasPrefix(name, prefix) || name == strings.TrimSuffix(prefix, "/")
}

// Validate checks namespace_prefix when sharing is enabled. The personal namespace has
// the empty prefix, so InNamespace tells shared names apart by the prefix alone, and the
// prefix must be a mailbox name followed by the hierarchy delimiter: an empty prefix puts
// every mailbox in the shared namespace, and "Shared" also takes in "SharedDocs".
func (c SharedMailboxesConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	delim := string(consts.MailboxDelimiter)
	root, ok := strings.CutSuffix(c.NamespacePrefix, delim)
	if !ok || slices.Contains(strings.Split(root, delim), "") {
		return fmt.Errorf("namespace_prefix %q must be a mailbox name followed by the hierarchy delimiter %q, such as \"Shared/\"",
			c.NamespacePrefix, delim)
	}
	if strings.EqualFold(root, consts.MailboxInbox) {
		return fmt.Errorf("namespace_prefix %q conflicts with the reserved personal INBOX", c.NamespacePrefix)
	}
	return nil
}

// AdminCLIConfig holds configuration for sora-admin CLI tool
type AdminCLIConfig struct {
	Addr               string `toml:"addr"`                  // HTTP Admin API endpoint address
	APIKey             string `toml:"api_key" secret:"true"` // API key for authentication
	InsecureSkipVerify *bool  `toml:"insecure_skip_verify"`  // Skip TLS verification (default: auto; true for loopback, false for remote)
	ImportMessageLimit string `toml:"import_message_limit"`  // Maximum message size for import operations (e.g., "50mb")
}

// SieveConfig holds Sieve script engine configuration
type SieveConfig struct {
	EnabledExtensions []string `toml:"enabled_extensions"` // List of enabled Sieve extensions (empty = the default set, without editheader)
	MaxExecutionTime  string   `toml:"max_execution_time"` // Per-script execution budget, also the per-match regex soft-wait cap (e.g. "2s"); default 2s
}

// GetMaxExecutionTime returns the per-script Sieve execution budget. This bounds total
// script execution (CPU/resource-exhaustion guard) and is also used as the per-match
// regex soft-wait cap. Default 2s; an empty or invalid value falls back to the default.
func (s *SieveConfig) GetMaxExecutionTime() time.Duration {
	const def = 2 * time.Second
	if s.MaxExecutionTime == "" {
		return def
	}
	d, err := helpers.ParseDuration(s.MaxExecutionTime)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

// AuthCacheConfig holds persistent authentication cache configuration.
// The auth cache stores credential lookups in a local SQLite database to survive
// restarts and prevent thundering herd on the PostgreSQL database.
type AuthCacheConfig struct {
	Enabled         bool   `toml:"enabled"`          // Enable persistent auth cache (default: false)
	Path            string `toml:"path"`             // SQLite database path (default: DefaultAuthCachePath)
	MaxAge          string `toml:"max_age"`          // Max age for cached entries (default: "24h")
	CleanupInterval string `toml:"cleanup_interval"` // How often to purge old entries (default: "1h")
	PurgeUnused     string `toml:"purge_unused"`     // Purge entries unused for this duration (default: "168h" = 7 days)
}

// [auth_cache] defaults, used for absent and for unparsable values alike.
const (
	defaultAuthCacheMaxAge          = 24 * time.Hour
	defaultAuthCacheCleanupInterval = time.Hour
	defaultAuthCachePurgeUnused     = 7 * 24 * time.Hour
)

// GetMaxAge parses the max age duration
func (a *AuthCacheConfig) GetMaxAge() (time.Duration, error) {
	if a.MaxAge == "" {
		return defaultAuthCacheMaxAge, nil
	}
	return helpers.ParseDuration(a.MaxAge)
}

// GetMaxAgeWithDefault returns max_age, or its default if the value cannot be parsed.
func (a *AuthCacheConfig) GetMaxAgeWithDefault() time.Duration {
	d, err := a.GetMaxAge()
	if err != nil {
		warnf("Failed to parse auth_cache max_age: %v, using default (%s)", err, defaultAuthCacheMaxAge)
		return defaultAuthCacheMaxAge
	}
	return d
}

// GetCleanupInterval parses the cleanup interval duration
func (a *AuthCacheConfig) GetCleanupInterval() (time.Duration, error) {
	if a.CleanupInterval == "" {
		return defaultAuthCacheCleanupInterval, nil
	}
	return helpers.ParseDuration(a.CleanupInterval)
}

// GetCleanupIntervalWithDefault returns cleanup_interval, or its default if the value cannot be parsed.
func (a *AuthCacheConfig) GetCleanupIntervalWithDefault() time.Duration {
	d, err := a.GetCleanupInterval()
	if err != nil {
		warnf("Failed to parse auth_cache cleanup_interval: %v, using default (%s)", err, defaultAuthCacheCleanupInterval)
		return defaultAuthCacheCleanupInterval
	}
	return d
}

// GetPurgeUnused parses the purge unused duration
func (a *AuthCacheConfig) GetPurgeUnused() (time.Duration, error) {
	if a.PurgeUnused == "" {
		return defaultAuthCachePurgeUnused, nil
	}
	return helpers.ParseDuration(a.PurgeUnused)
}

// GetPurgeUnusedWithDefault returns purge_unused, or its default if the value cannot be parsed.
func (a *AuthCacheConfig) GetPurgeUnusedWithDefault() time.Duration {
	d, err := a.GetPurgeUnused()
	if err != nil {
		warnf("Failed to parse auth_cache purge_unused: %v, using default (%s)", err, defaultAuthCachePurgeUnused)
		return defaultAuthCachePurgeUnused
	}
	return d
}

// MaintenanceConfig ([backend_maintenance]) tunes how proxies honor backends an operator
// put in maintenance (`sora-admin backends maintenance on`), and when such a backend starts
// refusing new sessions itself. Both read the list from the database, so a node without
// one cannot honor it.
type MaintenanceConfig struct {
	PollInterval string  `toml:"poll_interval"` // How often proxies re-read the maintenance list (default: "5s")
	KickRate     float64 `toml:"kick_rate"`     // IMAP sessions per second each proxy closes on a backend in maintenance (default: 10)
	RefuseAfter  string  `toml:"refuse_after"`  // How long a backend in maintenance still accepts new sessions, so the proxies stop routing to it first (default: "30s")
}

// GetPollInterval returns how often proxies re-read the maintenance list.
func (b *MaintenanceConfig) GetPollInterval() (time.Duration, error) {
	if b.PollInterval == "" {
		return 5 * time.Second, nil
	}
	d, err := helpers.ParseDuration(b.PollInterval)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("backend_maintenance.poll_interval must be positive, got %q", b.PollInterval)
	}
	return d, nil
}

// GetRefuseAfter returns how long a backend in maintenance keeps accepting new sessions
// before it refuses them: long enough for every proxy to have re-read the list and stopped
// routing to it, so that only traffic bypassing them is refused. 0 refuses at once.
func (b *MaintenanceConfig) GetRefuseAfter() (time.Duration, error) {
	if b.RefuseAfter == "" {
		return 30 * time.Second, nil
	}
	d, err := helpers.ParseDuration(b.RefuseAfter)
	if err != nil {
		return 0, err
	}
	if d < 0 {
		return 0, fmt.Errorf("backend_maintenance.refuse_after must not be negative, got %q", b.RefuseAfter)
	}
	return d, nil
}

// GetKickRate returns how many sessions per second a proxy closes on a backend in
// maintenance. Anything but a positive finite number (TOML allows nan and inf) gets the
// default: those would leave the drain unpaced.
func (b *MaintenanceConfig) GetKickRate() float64 {
	if !(b.KickRate > 0) || math.IsInf(b.KickRate, 0) {
		return 10
	}
	return b.KickRate
}

// Config holds all configuration for the application.
type Config struct {
	Logging          LoggingConfig          `toml:"logging"`
	Database         DatabaseConfig         `toml:"database"`
	S3               S3Config               `toml:"s3"`
	TLS              TLSConfig              `toml:"tls"`
	Cluster          ClusterConfig          `toml:"cluster"`
	LocalCache       LocalCacheConfig       `toml:"local_cache"`
	AuthCache        AuthCacheConfig        `toml:"auth_cache"` // Persistent auth cache configuration
	Maintenance      MaintenanceConfig      `toml:"backend_maintenance"`
	Cleanup          CleanupConfig          `toml:"cleanup"`
	Servers          ServersConfig          `toml:"servers"`
	Uploader         UploaderConfig         `toml:"uploader"`
	Metadata         MetadataConfig         `toml:"metadata"`
	SharedMailboxes  SharedMailboxesConfig  `toml:"shared_mailboxes"`
	Sieve            SieveConfig            `toml:"sieve"`
	Relay            RelayConfig            `toml:"relay"`
	SpamTraining     SpamTrainingConfig     `toml:"spam_training"`     // Spam filter training configuration
	AdminCLI         AdminCLIConfig         `toml:"admin_cli"`         // Admin CLI tool configuration
	TimeoutScheduler TimeoutSchedulerConfig `toml:"timeout_scheduler"` // Global timeout scheduler configuration

	BcryptCost *int `toml:"bcrypt_cost,omitempty"` // bcrypt cost for password hashing (clamped 10..14, default 12)

	// Dynamic server instances (top-level array)
	DynamicServers []ServerConfig `toml:"server"`

	// Pools are the named backend groups ([[pool]] blocks) every proxy server on this node
	// routes into; see PoolConfig. Empty = each proxy uses its own remote_addrs.
	Pools []PoolConfig `toml:"pool"`
}

// GetBcryptCost returns the configured bcrypt cost for password hashing, clamped to
// [10, 14] (rejects weaker-than-current and absurdly slow values). Default 12.
func (c *Config) GetBcryptCost() int {
	cost := 12
	if c.BcryptCost != nil {
		cost = *c.BcryptCost
	}
	if cost < 10 {
		cost = 10
	}
	if cost > 14 {
		cost = 14
	}
	return cost
}

// Default local paths. Nothing sora must keep across a restart defaults to /tmp: a
// staged upload is the only copy of its message body until it reaches S3, and /tmp is
// emptied at boot on most systems and on every stop under systemd's PrivateTmp=. The
// directories match dist/sora.service (/var/spool/sora, CacheDirectory=sora).
const (
	DefaultUploaderPath   = "/var/spool/sora/uploads"
	DefaultLocalCachePath = "/var/cache/sora/cache"
	DefaultAuthCachePath  = "/var/cache/sora/auth_cache.db"

	// LegacyDefaultUploaderPath is the [uploader] path default of earlier releases.
	// Bodies a node staged there are stranded if it starts with the new default.
	LegacyDefaultUploaderPath = "/tmp/sora/uploads"
)

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
				Hosts:              []string{"localhost"},
				Port:               "5432",
				User:               "postgres",
				Password:           "",
				Name:               "sora_mail_db",
				TLSMode:            false,
				MaxConnections:     100,
				MinConnections:     0,
				MinIdleConnections: 5,
				MaxConnLifetime:    "1h",
				MaxConnIdleTime:    "5m",
				QueryTimeout:       "30s",
			},
			Read: &DatabaseEndpointConfig{
				Hosts:              []string{"localhost"},
				Port:               "5432",
				User:               "postgres",
				Password:           "",
				Name:               "sora_mail_db",
				TLSMode:            false,
				MaxConnections:     100,
				MinConnections:     0,
				MinIdleConnections: 10,
				MaxConnLifetime:    "1h",
				MaxConnIdleTime:    "5m",
				QueryTimeout:       "30s",
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
			HealthStatusRetention: "30d",
		},
		LocalCache: LocalCacheConfig{
			Capacity:           "1gb",
			MaxObjectSize:      "5mb",
			Path:               DefaultLocalCachePath,
			MetricsInterval:    "5m",
			MetricsRetention:   "30d",
			PurgeInterval:      "12h",
			OrphanCleanupAge:   "30d",
			EnableWarmup:       true,
			WarmupMessageCount: 50,
			WarmupMailboxes:    []string{"INBOX"},
			WarmupAsync:        true,
		},
		AuthCache: AuthCacheConfig{
			Path: DefaultAuthCachePath,
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
			// Empty by default (fail-closed): no host is trusted to assert a client IP via
			// PROXY/XCLIENT or to skip auth rate limiting. Set this explicitly to your proxy
			// IPs. proxy_protocol listeners REQUIRE a non-empty list (enforced at startup).
			// LMTP delivery admission keeps its own RFC1918 default, so mail flow is
			// unaffected. (security-audit M2)
			TrustedNetworks: nil,
		},
		Uploader: UploaderConfig{
			Path:          DefaultUploaderPath,
			BatchSize:     10,
			Concurrency:   20,
			MaxAttempts:   DefaultUploaderMaxAttempts,
			RetryInterval: "30s",
		},
		Cluster: ClusterConfig{
			// Only read with [cluster] enabled; on by default as documented.
			RateLimitSync: ClusterRateLimitSyncConfig{
				Enabled:           true,
				SyncBlocks:        true,
				SyncFailureCounts: true,
			},
			// On by default: cluster nodes ran affinity before this key was read.
			Affinity: ClusterAffinityConfig{
				Enabled: true,
			},
		},
	}
}

// Helper methods for ServerConfig
func (s *ServerConfig) GetAppendLimit() (int64, error) {
	if s.AppendLimit == "" {
		return 25 * 1024 * 1024, nil // 25MB default
	}
	return helpers.ParseSize(s.AppendLimit)
}

// IMAPAppendLimit returns the append limit of the first enabled IMAP server
// ([[server]] with type = "imap") in the given list, or an error if none is
// configured. Used by sora-admin as a fallback bound for batch imports.
func IMAPAppendLimit(servers []ServerConfig) (int64, error) {
	for i := range servers {
		s := &servers[i]
		if s.Type == "imap" && s.IsEnabled() {
			return s.GetAppendLimit()
		}
	}
	return 0, fmt.Errorf("no IMAP server configured")
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

// GetRemoteDNSRefresh returns the configured backend DNS re-resolution interval, or nil
// when the server does not configure one and the connection manager's default applies.
// An explicit "0" is returned as such and disables re-resolution.
func (s *ServerConfig) GetRemoteDNSRefresh() (*time.Duration, error) {
	if s.RemoteDNSRefresh == "" {
		return nil, nil
	}
	d, err := helpers.ParseDuration(s.RemoteDNSRefresh)
	if err != nil {
		return nil, err
	}
	if d < 0 {
		return nil, fmt.Errorf("remote_dns_refresh must not be negative, got %q", s.RemoteDNSRefresh)
	}
	return &d, nil
}

func (s *ServerConfig) GetAuthIdleTimeout() (time.Duration, error) {
	if s.AuthIdleTimeout == "" {
		// Default: 2 minutes idle during authentication for all proxy types
		return 2 * time.Minute, nil
	}
	return helpers.ParseDuration(s.AuthIdleTimeout)
}

// defaultTokenDuration is the http_user_api JWT lifetime when token_duration is absent.
const defaultTokenDuration = 24 * time.Hour

// GetTokenDuration parses token_duration (http_user_api). It takes the same
// syntax as the other duration keys, including days ("7d"); a negative value
// would mint tokens that are already expired and is an error.
func (s *ServerConfig) GetTokenDuration() (time.Duration, error) {
	if s.TokenDuration == "" {
		return defaultTokenDuration, nil
	}
	d, err := helpers.ParseDuration(s.TokenDuration)
	if err != nil {
		return 0, err
	}
	if d < 0 {
		return 0, fmt.Errorf("token_duration must not be negative, got %q", s.TokenDuration)
	}
	return d, nil
}

// GetTokenDurationWithDefault returns token_duration, or the default (24h) if
// the value is invalid.
func (s *ServerConfig) GetTokenDurationWithDefault() time.Duration {
	d, err := s.GetTokenDuration()
	if err != nil {
		warnf("Invalid token_duration for server '%s': %v, using default (%s)", s.Name, err, defaultTokenDuration)
		return defaultTokenDuration
	}
	return d
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

// GetRedirectRateLimit returns the redirect rate limit
func (s *ServerConfig) GetRedirectRateLimit() int {
	if s.Limits != nil && s.Limits.RedirectRateLimit != nil {
		return *s.Limits.RedirectRateLimit
	}
	return 100 // Default: 100
}

// GetRedirectRateWindow parses the redirect rate limit window duration
func (s *ServerConfig) GetRedirectRateWindow() (time.Duration, error) {
	if s.Limits != nil && s.Limits.RedirectRateWindow != "" {
		return helpers.ParseDuration(s.Limits.RedirectRateWindow)
	}
	return time.Hour, nil // Default: 1 hour
}

// LongestRedirectRateWindow returns the longest redirect_rate_window of the enabled
// servers that apply the Sieve redirect rate limit, LMTP and the Admin API, and at
// least the default (1h), which a server also uses for a window that does not parse.
// The limit counts redirect_log rows within the window, so the cleaner keeps them at
// least this long.
func (c *Config) LongestRedirectRateWindow() time.Duration {
	longest := time.Hour
	for _, server := range c.GetAllServers() {
		if server.Type != "lmtp" && server.Type != "http_admin_api" {
			continue
		}
		if window, err := server.GetRedirectRateWindow(); err == nil && window > longest {
			longest = window
		}
	}
	return longest
}

// GetMaxRedirectHops returns how many times one message may be redirected before
// further redirects are suppressed (mail-loop backstop). 0 means unlimited.
func (s *ServerConfig) GetMaxRedirectHops() int {
	if s.Limits != nil && s.Limits.MaxRedirectHops != nil {
		return *s.Limits.MaxRedirectHops
	}
	return helpers.DefaultMaxRedirectHops
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
	return s.defaultCommandTimeout(), nil
}

// GetCommandTimeoutWithDefault returns command_timeout, or the protocol default
// (the value an absent key gets) if the value cannot be parsed.
func (s *ServerConfig) GetCommandTimeoutWithDefault() time.Duration {
	timeout, err := s.GetCommandTimeout()
	if err != nil {
		def := s.defaultCommandTimeout()
		warnf("Failed to parse command_timeout for server '%s': %v, using default (%s)", s.Name, err, def)
		return def
	}
	return timeout
}

// defaultCommandTimeout is the protocol-specific command (idle) timeout.
func (s *ServerConfig) defaultCommandTimeout() time.Duration {
	switch s.Type {
	case "pop3", "pop3_proxy":
		// RFC 1939 §3: the POP3 autologout (inactivity) timer MUST be at least
		// 10 minutes. This value is wired as the session idle timeout, so the
		// default must not fall below that floor.
		return 10 * time.Minute
	case "imap", "imap_proxy":
		// RFC 3501 §5.4: an IMAP inactivity autologout timer MUST be at least
		// 30 minutes. Clients that poll without IDLE (Outlook, Thunderbird,
		// iOS fetch) assume it and sit quiet for 10-15 minutes between checks;
		// the old 5-minute default closed each of them once per interval.
		// Must stay below the IMAP library's hardcoded 35-minute read deadline,
		// which would otherwise close idle sessions silently before this timer
		// gets to send its BYE.
		return 30 * time.Minute
	case "managesieve", "managesieve_proxy":
		return 3 * time.Minute // 3 minutes for ManageSieve
	default:
		return 2 * time.Minute // Default: 2 minutes
	}
}

// GetAbsoluteSessionTimeout parses the absolute session timeout duration.
// Delivery proxy connections default to 5 minutes; other protocols use 24 hours.
func (s *ServerConfig) GetAbsoluteSessionTimeout() (time.Duration, error) {
	if s.Timeouts != nil && s.Timeouts.AbsoluteSessionTimeout != "" {
		return helpers.ParseDuration(s.Timeouts.AbsoluteSessionTimeout)
	}
	return s.defaultAbsoluteSessionTimeout(), nil
}

// GetAbsoluteSessionTimeoutWithDefault returns absolute_session_timeout, or the
// protocol default (the value an absent key gets) if the value cannot be parsed.
func (s *ServerConfig) GetAbsoluteSessionTimeoutWithDefault() time.Duration {
	timeout, err := s.GetAbsoluteSessionTimeout()
	if err != nil {
		def := s.defaultAbsoluteSessionTimeout()
		warnf("Failed to parse absolute_session_timeout for server '%s': %v, using default (%s)", s.Name, err, def)
		return def
	}
	return timeout
}

func (s *ServerConfig) defaultAbsoluteSessionTimeout() time.Duration {
	if s.Type == "lmtp_proxy" {
		return 5 * time.Minute
	}
	return 24 * time.Hour
}

// GetCommandTimeoutsOverrides returns a map of command name to timeout duration
// for any command timeouts explicitly configured in the TOML. Only non-empty
// fields are returned; the caller is responsible for merging with defaults.
func (s *ServerConfig) GetCommandTimeoutsOverrides() (map[string]time.Duration, error) {
	if s.Timeouts == nil || s.Timeouts.IMAPCommandTimeouts == nil {
		return nil, nil
	}

	ct := s.Timeouts.IMAPCommandTimeouts
	overrides := make(map[string]time.Duration)

	fields := []struct {
		name  string
		value string
	}{
		{"search", ct.Search},
		{"sort", ct.Sort},
		{"thread", ct.Thread},
		{"multi_search", ct.MultiSearch},
		{"fetch", ct.Fetch},
		{"store", ct.Store},
		{"copy", ct.Copy},
		{"move", ct.Move},
		{"rename", ct.Rename},
	}

	for _, f := range fields {
		if f.value == "" {
			continue
		}
		d, err := helpers.ParseDuration(f.value)
		if err != nil {
			return nil, fmt.Errorf("invalid command timeout %q for %s: %w", f.value, f.name, err)
		}
		overrides[f.name] = d
	}

	return overrides, nil
}

// GetManageSieveCommandTimeoutsOverrides returns a map of command name to
// timeout duration for any ManageSieve command timeouts explicitly configured
// in the TOML. Only non-empty fields are returned; the caller is responsible
// for merging with defaults. Mirrors GetCommandTimeoutsOverrides (IMAP).
func (s *ServerConfig) GetManageSieveCommandTimeoutsOverrides() (map[string]time.Duration, error) {
	if s.Timeouts == nil || s.Timeouts.ManageSieveCommandTimeouts == nil {
		return nil, nil
	}

	ct := s.Timeouts.ManageSieveCommandTimeouts
	overrides := make(map[string]time.Duration)

	fields := []struct {
		name  string
		value string
	}{
		{"listscripts", ct.ListScripts},
		{"getscript", ct.GetScript},
		{"putscript", ct.PutScript},
		{"checkscript", ct.CheckScript},
		{"setactive", ct.SetActive},
		{"deletescript", ct.DeleteScript},
		{"renamescript", ct.RenameScript},
		{"havespace", ct.HaveSpace},
	}

	for _, f := range fields {
		if f.value == "" {
			continue
		}
		d, err := helpers.ParseDuration(f.value)
		if err != nil {
			return nil, fmt.Errorf("invalid ManageSieve command timeout %q for %s: %w", f.value, f.name, err)
		}
		overrides[f.name] = d
	}

	return overrides, nil
}

// GetPOP3CommandTimeoutsOverrides returns a map of command name to timeout
// duration for any POP3 command timeouts explicitly configured in the TOML.
// Only non-empty fields are returned; the caller is responsible for merging
// with defaults. Mirrors GetCommandTimeoutsOverrides (IMAP).
func (s *ServerConfig) GetPOP3CommandTimeoutsOverrides() (map[string]time.Duration, error) {
	if s.Timeouts == nil || s.Timeouts.POP3CommandTimeouts == nil {
		return nil, nil
	}

	ct := s.Timeouts.POP3CommandTimeouts
	overrides := make(map[string]time.Duration)

	fields := []struct {
		name  string
		value string
	}{
		{"stat", ct.Stat},
		{"list", ct.List},
		{"uidl", ct.Uidl},
		{"retr", ct.Retr},
		{"top", ct.Top},
		{"dele", ct.Dele},
		{"quit", ct.Quit},
	}

	for _, f := range fields {
		if f.value == "" {
			continue
		}
		d, err := helpers.ParseDuration(f.value)
		if err != nil {
			return nil, fmt.Errorf("invalid POP3 command timeout %q for %s: %w", f.value, f.name, err)
		}
		overrides[f.name] = d
	}

	return overrides, nil
}

// GetLMTPCommandTimeoutsOverrides returns a map of command name to timeout
// duration for any LMTP command timeouts explicitly configured in the TOML.
// Only non-empty fields are returned; the caller is responsible for merging
// with defaults. Mirrors GetCommandTimeoutsOverrides (IMAP).
func (s *ServerConfig) GetLMTPCommandTimeoutsOverrides() (map[string]time.Duration, error) {
	if s.Timeouts == nil || s.Timeouts.LMTPCommandTimeouts == nil {
		return nil, nil
	}

	ct := s.Timeouts.LMTPCommandTimeouts
	overrides := make(map[string]time.Duration)

	fields := []struct {
		name  string
		value string
	}{
		{"rcpt", ct.Rcpt},
		{"data", ct.Data},
	}

	for _, f := range fields {
		if f.value == "" {
			continue
		}
		d, err := helpers.ParseDuration(f.value)
		if err != nil {
			return nil, fmt.Errorf("invalid LMTP command timeout %q for %s: %w", f.value, f.name, err)
		}
		overrides[f.name] = d
	}

	return overrides, nil
}

// GetSearchRateLimitPerMin returns search rate limit per minute
// (0 or less disables the limit; unset gets the default).
func (s *ServerConfig) GetSearchRateLimitPerMin() int {
	if s.Limits != nil && s.Limits.SearchRateLimitPerMin != nil {
		return *s.Limits.SearchRateLimitPerMin
	}
	return 60 // Default: 60 searches per minute
}

// GetSearchRateLimitBurst returns how many searches an account may run back to
// back before the search rate limit applies (unset, 0 or less: one window's
// worth, search_rate_limit_per_min).
func (s *ServerConfig) GetSearchRateLimitBurst() int {
	if s.Limits != nil && s.Limits.SearchRateLimitBurst != nil && *s.Limits.SearchRateLimitBurst > 0 {
		return *s.Limits.SearchRateLimitBurst
	}
	return s.GetSearchRateLimitPerMin()
}

// GetPreviewS3PerMin returns how many bodies one account may have downloaded
// from S3 per minute to answer FETCH PREVIEW without LAZY (0 or less: no limit).
func (s *ServerConfig) GetPreviewS3PerMin() int {
	if s.Limits != nil && s.Limits.PreviewS3PerMin != nil {
		return *s.Limits.PreviewS3PerMin
	}
	return 300
}

// GetPreviewS3Burst returns how many of those downloads may run back to back.
// Unless explicitly configured, it is at most one minute's positive budget.
func (s *ServerConfig) GetPreviewS3Burst() int {
	if s.Limits != nil && s.Limits.PreviewS3Burst != nil && *s.Limits.PreviewS3Burst > 0 {
		return *s.Limits.PreviewS3Burst
	}
	if perMin := s.GetPreviewS3PerMin(); perMin > 0 && perMin < 200 {
		return perMin
	}
	return 200
}

// GetPreviewS3NodePerMin returns how many bodies the whole server may download
// from S3 per minute for previews (0 or less: no limit).
func (s *ServerConfig) GetPreviewS3NodePerMin() int {
	if s.Limits != nil && s.Limits.PreviewS3NodePerMin != nil {
		return *s.Limits.PreviewS3NodePerMin
	}
	return 3000
}

// GetPreviewS3MaxSize returns the largest message downloaded for a preview, or
// defaultSize (the body cache's max_object_size) when unset or zero.
func (s *ServerConfig) GetPreviewS3MaxSize(defaultSize int64) (int64, error) {
	if s.Limits != nil && s.Limits.PreviewS3MaxSize != "" {
		maxSize, err := helpers.ParseSize(s.Limits.PreviewS3MaxSize)
		if err != nil {
			return 0, err
		}
		if maxSize > 0 {
			return maxSize, nil
		}
	}
	return defaultSize, nil
}

// DefaultThreadMaxMessages bounds the metadata fetched and threaded in memory
// by one IMAP THREAD command.
const DefaultThreadMaxMessages = 50000

// GetThreadMaxMessages returns the maximum number of matches one THREAD command
// may process. Unset, zero and negative values retain the bounded default.
func (s *ServerConfig) GetThreadMaxMessages() int {
	if s.Limits != nil && s.Limits.ThreadMaxMessages > 0 {
		return s.Limits.ThreadMaxMessages
	}
	return DefaultThreadMaxMessages
}

// GetMinBytesPerMinute returns minimum bytes per minute
func (s *ServerConfig) GetMinBytesPerMinute() int64 {
	if s.Timeouts != nil && s.Timeouts.MinBytesPerMinute > 0 {
		return s.Timeouts.MinBytesPerMinute
	}
	return 0 // Default: disabled (0 bytes/min = no throughput checking)
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

// GetRemoteHealthChecks returns whether backend health checking is enabled.
// Defaults to true if not explicitly set in config.
func (s *ServerConfig) GetRemoteHealthChecks() bool {
	if s.RemoteHealthChecks == nil {
		return true // Default: enabled
	}
	return *s.RemoteHealthChecks
}

// warnf reports a value a ...WithDefault method replaced with its default. It
// logs at WARN through slog's default logger, which the logger package (it
// imports config, so config cannot import it) points at the server log. The
// log package's output reaches that log only at INFO, so a typo logged with
// log.Printf was filtered out at level = "warn".
func warnf(format string, args ...any) {
	slog.Warn(fmt.Sprintf(format, args...))
}

// Metrics tuning keys: a key left out of the metrics block keeps the same default
// as pkg/metrics uses on a node without one.

// GetEnableDomainMetrics returns enable_domain_metrics (default: true).
func (s *ServerConfig) GetEnableDomainMetrics() bool {
	if s.EnableDomainMetrics == nil {
		return true
	}
	return *s.EnableDomainMetrics
}

// GetUserMetricsThreshold returns user_metrics_threshold (default: 1000).
func (s *ServerConfig) GetUserMetricsThreshold() int {
	if s.UserMetricsThreshold == nil {
		return 1000
	}
	return *s.UserMetricsThreshold
}

// GetMaxTrackedUsers returns max_tracked_users (default: 1000).
func (s *ServerConfig) GetMaxTrackedUsers() int {
	if s.MaxTrackedUsers == nil {
		return 1000
	}
	return *s.MaxTrackedUsers
}

// GetHashUsernames returns hash_usernames (default: true).
func (s *ServerConfig) GetHashUsernames() bool {
	if s.HashUsernames == nil {
		return true
	}
	return *s.HashUsernames
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

func (s *ServerConfig) GetAuthIdleTimeoutWithDefault() time.Duration {
	timeout, err := s.GetAuthIdleTimeout()
	if err != nil {
		warnf("Failed to parse auth idle timeout for server '%s': %v, using default 2m", s.Name, err)
		return 2 * time.Minute
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

// GetMaxAuthErrors returns the max auth errors with a default of 2
func (s *ServerConfig) GetMaxAuthErrors() int {
	if s.Limits == nil || s.Limits.MaxAuthErrors <= 0 {
		return 2 // Default: 2 authentication errors before disconnection
	}
	return s.Limits.MaxAuthErrors
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

func (c *CleanupConfig) GetPurgePollIntervalWithDefault() time.Duration {
	interval, err := c.GetPurgePollInterval()
	if err != nil {
		log.Printf("WARNING: Failed to parse cleanup purge_poll_interval: %v, using default (30s)", err)
		return 30 * time.Second
	}
	return interval
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
		log.Printf("WARNING: Failed to parse cleanup fts_retention: %v, using default (keep forever)", err)
		return 0
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

func (c *CleanupConfig) GetInstanceLivenessThresholdWithDefault() time.Duration {
	threshold, err := c.GetInstanceLivenessThreshold()
	if err != nil {
		log.Printf("WARNING: Failed to parse cleanup instance_liveness_threshold: %v, using default (7 days)", err)
		return 7 * 24 * time.Hour
	}
	if threshold <= 0 {
		// Non-positive would mean "every instance is dead", i.e. reaping on age alone.
		log.Printf("WARNING: cleanup instance_liveness_threshold must be positive, got %s, using default (7 days)", threshold)
		return 7 * 24 * time.Hour
	}
	return threshold
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

// IsEnabled reports whether the block is to be started: every [[server]] block is,
// unless it says enabled = false. An enabled block must pass Validate, which requires
// type, name and addr; a block missing one is an error, never skipped.
func (s *ServerConfig) IsEnabled() bool {
	return s.Enabled == nil || *s.Enabled
}

// ServerTypes are the [[server]] types the configuration accepts.
var ServerTypes = []string{"imap", "lmtp", "pop3", "managesieve", "imap_proxy", "pop3_proxy", "managesieve_proxy", "lmtp_proxy", "metrics", "http_admin_api", "http_user_api", "user_api_proxy"}

// ValidateServerConfig validates a server configuration
func (s *ServerConfig) Validate() error {
	if s.Type == "" {
		return fmt.Errorf("server type is required")
	}
	if s.Name == "" {
		return fmt.Errorf("server name is required (type %q, addr %q)", s.Type, s.Addr)
	}
	if s.Addr == "" {
		return fmt.Errorf("server address is required; set enabled = false to keep a [[server]] block without starting it")
	}

	isValidType := false
	for _, validType := range ServerTypes {
		if s.Type == validType {
			isValidType = true
			break
		}
	}
	if !isValidType {
		return fmt.Errorf("invalid server type '%s', must be one of: %s", s.Type, strings.Join(ServerTypes, ", "))
	}

	// Master credentials: a configured master username with an EMPTY master
	// password is dangerous — auth uses subtle.ConstantTimeCompare, and
	// ConstantTimeCompare("", "") == 1, so an empty client password would
	// authenticate as ANY account via the user@domain@MASTER mechanism.
	// Fail closed rather than start with a silent full-impersonation hole.
	if s.MasterUsername != "" && s.MasterPassword == "" {
		return fmt.Errorf("server %q: master_username is set but master_password is empty; refusing to start (an empty password would allow impersonation of any account)", s.Name)
	}
	if s.MasterSASLUsername != "" && s.MasterSASLPassword == "" {
		return fmt.Errorf("server %q: master_sasl_username is set but master_sasl_password is empty; refusing to start (an empty password would allow impersonation of any account)", s.Name)
	}

	if s.AuthRateLimit != nil {
		if err := s.AuthRateLimit.Validate(); err != nil {
			return fmt.Errorf("server %q: %w", s.Name, err)
		}
	}

	// A disabled lookup is never initialized, so its remote_port is never used.
	if s.RemoteLookup != nil && s.RemoteLookup.Enabled {
		if _, err := s.RemoteLookup.GetRemotePort(); err != nil {
			return fmt.Errorf("server %q: invalid remote_lookup.remote_port: %w", s.Name, err)
		}
	}

	if s.Type == "metrics" {
		if s.Path != "" && !strings.HasPrefix(s.Path, "/") {
			return fmt.Errorf("server %q: metrics path %q must begin with '/'", s.Name, s.Path)
		}
		if err := validateMetricsPattern(s.MetricsPath()); err != nil {
			return fmt.Errorf("server %q: invalid metrics path %q: %w", s.Name, s.Path, err)
		}
	}

	return nil
}

// ServeMux parses patterns when registering a handler and panics on invalid
// ones. Validate with that same parser before the metrics goroutine starts.
func validateMetricsPattern(pattern string) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("%v", p)
		}
	}()
	http.NewServeMux().HandleFunc(pattern, func(http.ResponseWriter, *http.Request) {})
	return nil
}

// MetricsPath returns the HTTP path the metrics handler is served on. An unset
// path defaults to "/metrics": net/http.ServeMux panics on an empty pattern,
// and the panic would run in the metrics goroutine, taking the whole process
// down with it.
func (s *ServerConfig) MetricsPath() string {
	if s.Path == "" {
		return "/metrics"
	}
	return s.Path
}

// WarnUnusedConfigOptions logs warnings for config options that don't apply to this server type
func (s *ServerConfig) WarnUnusedConfigOptions(logger func(format string, args ...any)) {
	if s.ReadOnlyAPIKey != "" && s.Type != "http_admin_api" {
		logger("WARNING: Server %s (type: %s) has 'read_only_api_key' configured, but this only applies to http_admin_api servers", s.Name, s.Type)
	}
	if s.TLSUseStartTLS {
		switch s.Type {
		case "imap", "lmtp", "managesieve", "pop3", "imap_proxy", "lmtp_proxy", "managesieve_proxy", "pop3_proxy":
			// The servers drop tls_use_starttls without tls (there is no certificate
			// to upgrade with), so the listener comes up plaintext with no STARTTLS.
			if !s.TLS {
				logger("WARNING: Server %s (type: %s) has 'tls_use_starttls' configured without 'tls = true'; it is ignored and the listener is plaintext with no STARTTLS", s.Name, s.Type)
			}
		default:
			logger("WARNING: Server %s (type: %s) has 'tls_use_starttls' configured, but this only applies to IMAP, LMTP, ManageSieve and POP3 servers and proxies", s.Name, s.Type)
		}
	}

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
	} else if s.Type == "user_api_proxy" {
		if s.RemoteTLSUseStartTLS {
			logger("WARNING: Server %s (type: %s) has 'remote_tls_use_starttls' configured, but the User API proxy speaks HTTP to its backends: 'remote_tls' alone selects HTTPS, there is no STARTTLS", s.Name, s.Type)
		}
		if s.RemoteLookup != nil && s.RemoteLookup.RemoteTLSUseStartTLS {
			logger("WARNING: Server %s (type: %s) has 'remote_lookup.remote_tls_use_starttls' configured, but the User API proxy speaks HTTP to its backends: 'remote_lookup.remote_tls' alone selects HTTPS, there is no STARTTLS", s.Name, s.Type)
		}
	} else {
		// STARTTLS is a way of doing remote_tls: without it the backend leg is plaintext.
		if s.RemoteTLSUseStartTLS && !s.RemoteTLS {
			logger("WARNING: Server %s (type: %s) has 'remote_tls_use_starttls' configured without 'remote_tls', so it is ignored and backend connections are plaintext; set 'remote_tls = true' to use STARTTLS", s.Name, s.Type)
		}
		if s.RemoteLookup != nil && s.RemoteLookup.RemoteTLSUseStartTLS && !s.RemoteLookup.RemoteTLS {
			logger("WARNING: Server %s (type: %s) has 'remote_lookup.remote_tls_use_starttls' configured without 'remote_lookup.remote_tls', so it is ignored and connections to lookup-routed backends are plaintext; set 'remote_lookup.remote_tls = true' to use STARTTLS", s.Name, s.Type)
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
		if s.Type == "metrics" && s.TLS {
			logger("WARNING: Server %s (type: metrics) has 'tls' configured, but the metrics endpoint is always served over plain HTTP; terminate TLS in front of it and restrict access with 'allowed_hosts'/'api_key'", s.Name)
		}
		if s.Type == "metrics" && s.ProxyProtocol {
			logger("WARNING: Server %s (type: metrics) has 'proxy_protocol' configured, but the metrics endpoint does not read PROXY protocol headers; it is ignored, and 'allowed_hosts' matches the connecting host", s.Name)
		}
	}
}

// GetAllServers returns every [[server]] block that does not say enabled = false,
// complete or not: the callers validate each one, so a block missing type, name or
// addr is reported instead of being dropped.
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

// ProxyProtocolListenersMissingTrust returns the names of enabled listeners that accept
// PROXY protocol while trusted_networks is empty. With no trusted proxies, a PROXY header
// from any reachable host could spoof the client IP, so this combination must fail closed
// at startup. (security-audit M2)
func (c *Config) ProxyProtocolListenersMissingTrust() []string {
	if len(c.Servers.TrustedNetworks) > 0 {
		return nil
	}
	var names []string
	for _, s := range c.GetAllServers() {
		// The metrics endpoint does not read PROXY headers (its proxy_protocol is warned
		// about and ignored), so no peer can spoof a client IP through it.
		if s.ProxyProtocol && s.Type != "metrics" {
			names = append(names, s.Name)
		}
	}
	return names
}

// ValidateTrustedNetworks checks that every [servers] trusted_networks entry is an IP
// address or a CIDR. The servers parse the list as a whole when they start, so one
// malformed entry would leave them with none: the LMTP backend and lmtp_proxy would
// refuse every connection.
func (c *Config) ValidateTrustedNetworks() error {
	_, err := helpers.ParseTrustedNetworks(c.Servers.TrustedNetworks)
	return err
}

// broadPrivateRanges are the full RFC1918 / IPv6-ULA / link-local supernets. Trusting any
// of these whole-cloth grants client-IP spoofing and rate-limit exemption to every host on
// the private network — almost always wider than intended. (security-audit M2)
var broadPrivateRanges = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10",
}

// TrustedNetworksHaveBroadPrivateRanges reports whether any configured trusted network is
// (or is broader than) a whole private supernet — the insecure-wide pattern that the old
// default shipped. Narrow CIDRs (e.g. a single proxy /32) do not trigger it.
func TrustedNetworksHaveBroadPrivateRanges(networks []string) bool {
	for _, broad := range broadPrivateRanges {
		_, broadNet, err := net.ParseCIDR(broad)
		if err != nil {
			continue
		}
		broadOnes, _ := broadNet.Mask.Size()
		for _, entry := range networks {
			_, n, err := net.ParseCIDR(strings.TrimSpace(entry))
			if err != nil {
				continue
			}
			// Match if the configured network covers the whole supernet: it contains the
			// supernet's base address and its mask is no narrower than the supernet's.
			ones, _ := n.Mask.Size()
			if ones <= broadOnes && n.Contains(broadNet.IP) {
				return true
			}
		}
	}
	return false
}

// LoadConfigFromFile loads configuration from a TOML file and trims whitespace from all string fields
// This function is lenient with:
//   - Duplicate keys: logs warning and uses first occurrence
//   - Unknown keys: logs warning and ignores them
//
// All other syntax errors will cause the server to fail with helpful error messages
func LoadConfigFromFile(configPath string, cfg *Config) error {
	_, err := LoadConfigFromFileWithMetadata(configPath, cfg)
	return err
}

// LoadConfigFromFileWithMetadata is LoadConfigFromFile that also returns the file's TOML
// metadata. cfg is usually seeded by NewDefaultConfig, so after the load a value equal to
// its default may be the default or may be set by the file; MetaData.IsDefined tells them
// apart.
func LoadConfigFromFileWithMetadata(configPath string, cfg *Config) (toml.MetaData, error) {
	// Read the file content first
	content, err := os.ReadFile(configPath)
	if err != nil {
		return toml.MetaData{}, err
	}

	// Try to decode - capture metadata to check for unknown keys
	metadata, err := toml.Decode(string(content), cfg)
	if err != nil {
		// Check if this is a duplicate key error using ParseError type
		// Note: toml.Decode returns ParseError by value, not by pointer
		var parseErr toml.ParseError
		if errors.As(err, &parseErr) && strings.Contains(parseErr.Message, "has already been defined") {
			log.Printf("WARNING: Configuration file '%s' contains duplicate keys: %s", configPath, parseErr.Error())
			log.Printf("WARNING: Ignoring duplicate entries. Only the first occurrence of each key will be used.")
			log.Printf("WARNING: Please fix your configuration file to remove duplicates.")

			// Parse again with a lenient approach by removing duplicate keys
			cleanedContent, cleanErr := removeDuplicateKeysFromTOML(string(content))
			if cleanErr != nil {
				// If we can't clean it, return a helpful error
				return toml.MetaData{}, enhanceConfigError(err)
			}

			// Try decoding the cleaned content
			metadata, err = toml.Decode(cleanedContent, cfg)
			if err != nil {
				return toml.MetaData{}, enhanceConfigError(err)
			}
		} else {
			// For other errors, provide enhanced error messages
			return toml.MetaData{}, enhanceConfigError(err)
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

	// Apply default values for fields where the Go zero value differs from the desired default
	applyConfigDefaults(cfg)

	return metadata, nil
}

// applyConfigDefaults sets default values for config fields where the desired default
// differs from Go's zero value. Called after loading config from file.
func applyConfigDefaults(cfg *Config) {
	// Set default remote_health_checks = true for all proxy servers.
	// NOTE: Since TOML/Go doesn't distinguish between "not set" and "set to false",
	// we cannot reliably detect if the user explicitly disabled health checks.
	// Users MUST explicitly set remote_health_checks = true in their config if they
	// want health checks enabled (which is the recommended default).
	// This is acceptable because:
	// 1. The field name is self-documenting (remote_health_checks = true is obvious)
	// 2. The example config shows remote_health_checks = true
	// 3. The safe/recommended default is "enabled" (true)
	// 4. Users who want to disable must be explicit (remote_health_checks = false)
	//
	// Alternative considered: Use *bool (pointer) to distinguish nil/true/false,
	// but that would require refactoring all config access. Deferred for now.

	// For now, we do nothing here - users must explicitly set remote_health_checks = true
	// in their config file. The config.toml.example shows this as the default.

	// Apply auth rate limiter defaults for enabled rate limiters
	// When auth_rate_limit.enabled = true is set without other fields,
	// merge with defaults so users don't have to specify every field
	applyAuthRateLimitDefaults(cfg)
}

// applyAuthRateLimitDefaults merges auth rate limit config with defaults for all server types
func applyAuthRateLimitDefaults(cfg *Config) {
	defaults := DefaultAuthRateLimiterConfig()

	// Helper to merge rate limit config with defaults
	mergeAuthRateLimit := func(config *AuthRateLimiterConfig) {
		// Only apply defaults if rate limiting is enabled
		if !config.Enabled {
			return
		}

		// For each field, if it's zero (not set), use the default
		if config.MaxAttemptsPerIPUsername == 0 {
			config.MaxAttemptsPerIPUsername = defaults.MaxAttemptsPerIPUsername
		}
		if config.IPUsernameBlockDuration == 0 {
			config.IPUsernameBlockDuration = defaults.IPUsernameBlockDuration
		}
		if config.IPUsernameWindowDuration == 0 {
			config.IPUsernameWindowDuration = defaults.IPUsernameWindowDuration
		}
		if config.MaxAttemptsPerIP == 0 {
			config.MaxAttemptsPerIP = defaults.MaxAttemptsPerIP
		}
		if config.IPBlockDuration == 0 {
			config.IPBlockDuration = defaults.IPBlockDuration
		}
		if config.IPWindowDuration == 0 {
			config.IPWindowDuration = defaults.IPWindowDuration
		}
		if config.MaxAttemptsPerUsername == 0 {
			config.MaxAttemptsPerUsername = defaults.MaxAttemptsPerUsername
		}
		if config.UsernameWindowDuration == 0 {
			config.UsernameWindowDuration = defaults.UsernameWindowDuration
		}
		if config.CleanupInterval == 0 {
			config.CleanupInterval = defaults.CleanupInterval
		}
		if config.DelayStartThreshold == 0 {
			config.DelayStartThreshold = defaults.DelayStartThreshold
		}
		if config.InitialDelay == 0 {
			config.InitialDelay = defaults.InitialDelay
		}
		if config.MaxDelay == 0 {
			config.MaxDelay = defaults.MaxDelay
		}
		if config.DelayMultiplier == 0 {
			config.DelayMultiplier = defaults.DelayMultiplier
		}
		if config.MaxIPUsernameEntries == 0 {
			config.MaxIPUsernameEntries = defaults.MaxIPUsernameEntries
		}
		if config.MaxIPEntries == 0 {
			config.MaxIPEntries = defaults.MaxIPEntries
		}
		if config.MaxUsernameEntries == 0 {
			config.MaxUsernameEntries = defaults.MaxUsernameEntries
		}
	}

	// Apply to dynamic servers array (multiple instances of same type)
	// This is where [[server]] entries from TOML are stored
	for i := range cfg.DynamicServers {
		serverCfg := &cfg.DynamicServers[i]

		// Check if this server config has auth_rate_limit field
		if serverCfg.AuthRateLimit != nil {
			mergeAuthRateLimit(serverCfg.AuthRateLimit)
		}
	}
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

			// Clear keys for this array table section
			// Each [[table]] is a new array element, so same keys are expected and not duplicates
			for k := range seenKeys {
				if strings.HasPrefix(k, currentSection+".") {
					delete(seenKeys, k)
				}
			}

			result = append(result, line)
			continue
		} else if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			// Regular table: [table.name]
			// Remove brackets to get the section name
			currentSection = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
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
		// Handle any values (like the Port field which can be string or int)
		if !v.IsNil() {
			elem := v.Elem()
			if elem.Kind() == reflect.String {
				v.Set(reflect.ValueOf(strings.TrimSpace(elem.String())))
			}
		}
	}
}
