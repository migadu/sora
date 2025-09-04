package main

import (
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

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

// Cleaner worker configuration.
type CleanupConfig struct {
	GracePeriod       string `toml:"grace_period"`
	WakeInterval      string `toml:"wake_interval"`
	MaxAgeRestriction string `toml:"max_age_restriction"`
}

// Local disk cache configuration.
type LocalCacheConfig struct {
	Capacity             string   `toml:"capacity"`
	MaxObjectSize        string   `toml:"max_object_size"`
	Path                 string   `toml:"path"`
	MetricsInterval      string   `toml:"metrics_interval"`
	MetricsRetention     string   `toml:"metrics_retention"`
	PurgeInterval        string   `toml:"purge_interval"`
	OrphanCleanupAge     string   `toml:"orphan_cleanup_age"`
	EnableWarmup         bool     `toml:"enable_warmup"`
	WarmupMessageCount   int      `toml:"warmup_message_count"`
	WarmupMailboxes      []string `toml:"warmup_mailboxes"`
	WarmupAsync          bool     `toml:"warmup_async"`
}

// IMAPServerConfig holds IMAP server configuration.
type IMAPServerConfig struct {
	Start               bool                         `toml:"start"`
	Addr                string                       `toml:"addr"`
	AppendLimit         string                       `toml:"append_limit"`
	MaxConnections      int                          `toml:"max_connections"`        // Maximum concurrent connections
	MaxConnectionsPerIP int                          `toml:"max_connections_per_ip"` // Maximum connections per IP address
	MasterUsername      string                       `toml:"master_username"`
	MasterPassword      string                       `toml:"master_password"`
	MasterSASLUsername  string                       `toml:"master_sasl_username"`
	MasterSASLPassword  string                       `toml:"master_sasl_password"`
	TLS                 bool                         `toml:"tls"`
	TLSCertFile         string                       `toml:"tls_cert_file"`
	TLSKeyFile          string                       `toml:"tls_key_file"`
	TLSVerify           bool                         `toml:"tls_verify"`
	ProxyProtocol       server.ProxyProtocolConfig   `toml:"proxy_protocol"`  // PROXY protocol configuration
	AuthRateLimit       server.AuthRateLimiterConfig `toml:"auth_rate_limit"` // Authentication rate limiting
}

// LMTPServerConfig holds LMTP server configuration.
type LMTPServerConfig struct {
	Start               bool                       `toml:"start"`
	Addr                string                     `toml:"addr"`
	MaxConnections      int                        `toml:"max_connections"`        // Maximum concurrent connections
	MaxConnectionsPerIP int                        `toml:"max_connections_per_ip"` // Maximum connections per IP address
	ExternalRelay       string                     `toml:"external_relay"`
	TLS                 bool                       `toml:"tls"`
	TLSUseStartTLS      bool                       `toml:"tls_use_starttls"`
	TLSCertFile         string                     `toml:"tls_cert_file"`
	TLSKeyFile          string                     `toml:"tls_key_file"`
	TLSVerify           bool                       `toml:"tls_verify"`
	ProxyProtocol       server.ProxyProtocolConfig `toml:"proxy_protocol"` // PROXY protocol configuration
}

// POP3ServerConfig holds POP3 server configuration.
type POP3ServerConfig struct {
	Start               bool                         `toml:"start"`
	Addr                string                       `toml:"addr"`
	MaxConnections      int                          `toml:"max_connections"`        // Maximum concurrent connections
	MaxConnectionsPerIP int                          `toml:"max_connections_per_ip"` // Maximum connections per IP address
	MasterSASLUsername  string                       `toml:"master_sasl_username"`
	MasterSASLPassword  string                       `toml:"master_sasl_password"`
	TLS                 bool                         `toml:"tls"`
	TLSCertFile         string                       `toml:"tls_cert_file"`
	TLSKeyFile          string                       `toml:"tls_key_file"`
	TLSVerify           bool                         `toml:"tls_verify"`
	ProxyProtocol       server.ProxyProtocolConfig   `toml:"proxy_protocol"`  // PROXY protocol configuration
	AuthRateLimit       server.AuthRateLimiterConfig `toml:"auth_rate_limit"` // Authentication rate limiting
}

// ManageSieveServerConfig holds ManageSieve server configuration.
type ManageSieveServerConfig struct {
	Start               bool                         `toml:"start"`
	Addr                string                       `toml:"addr"`
	MaxConnections      int                          `toml:"max_connections"`        // Maximum concurrent connections
	MaxConnectionsPerIP int                          `toml:"max_connections_per_ip"` // Maximum connections per IP address
	MaxScriptSize       string                       `toml:"max_script_size"`
	InsecureAuth        bool                         `toml:"insecure_auth"`
	MasterSASLUsername  string                       `toml:"master_sasl_username"`
	MasterSASLPassword  string                       `toml:"master_sasl_password"`
	TLS                 bool                         `toml:"tls"`
	TLSUseStartTLS      bool                         `toml:"tls_use_starttls"`
	TLSCertFile         string                       `toml:"tls_cert_file"`
	TLSKeyFile          string                       `toml:"tls_key_file"`
	TLSVerify           bool                         `toml:"tls_verify"`
	ProxyProtocol       server.ProxyProtocolConfig   `toml:"proxy_protocol"`  // PROXY protocol configuration
	AuthRateLimit       server.AuthRateLimiterConfig `toml:"auth_rate_limit"` // Authentication rate limiting
}

// IMAPProxyServerConfig holds IMAP proxy server configuration.
type IMAPProxyServerConfig struct {
	Start               bool                         `toml:"start"`
	Addr                string                       `toml:"addr"`
	RemoteAddrs         []string                     `toml:"remote_addrs"`
	MaxConnections      int                          `toml:"max_connections"`        // Maximum concurrent connections
	MaxConnectionsPerIP int                          `toml:"max_connections_per_ip"` // Maximum connections per IP address
	MasterSASLUsername  string                       `toml:"master_sasl_username"`
	MasterSASLPassword  string                       `toml:"master_sasl_password"`
	TLS                 bool                         `toml:"tls"`
	TLSCertFile         string                       `toml:"tls_cert_file"`
	TLSKeyFile          string                       `toml:"tls_key_file"`
	TLSVerify           bool                         `toml:"tls_verify"`
	RemoteTLS           bool                         `toml:"remote_tls"`
	RemoteTLSVerify     bool                         `toml:"remote_tls_verify"`
	ConnectTimeout      string                       `toml:"connect_timeout"`
	EnableAffinity      bool                         `toml:"enable_affinity"`
	AffinityStickiness  float64                      `toml:"affinity_stickiness"` // Probability (0.0 to 1.0) of using an affinity server.
	AffinityValidity    string                       `toml:"affinity_validity"`
	AuthRateLimit       server.AuthRateLimiterConfig `toml:"auth_rate_limit"` // Authentication rate limiting
	PreLookup           *proxy.PreLookupConfig       `toml:"prelookup"`       // Database-driven user routing
}

// POP3ProxyServerConfig holds POP3 proxy server configuration.
type POP3ProxyServerConfig struct {
	Start               bool                         `toml:"start"`
	Addr                string                       `toml:"addr"`
	RemoteAddrs         []string                     `toml:"remote_addrs"`
	MaxConnections      int                          `toml:"max_connections"`        // Maximum concurrent connections
	MaxConnectionsPerIP int                          `toml:"max_connections_per_ip"` // Maximum connections per IP address
	MasterSASLUsername  string                       `toml:"master_sasl_username"`
	MasterSASLPassword  string                       `toml:"master_sasl_password"`
	TLS                 bool                         `toml:"tls"`
	TLSCertFile         string                       `toml:"tls_cert_file"`
	TLSKeyFile          string                       `toml:"tls_key_file"`
	TLSVerify           bool                         `toml:"tls_verify"`
	RemoteTLS           bool                         `toml:"remote_tls"`
	RemoteTLSVerify     bool                         `toml:"remote_tls_verify"`
	ConnectTimeout      string                       `toml:"connect_timeout"`
	EnableAffinity      bool                         `toml:"enable_affinity"`
	AffinityStickiness  float64                      `toml:"affinity_stickiness"` // Probability (0.0 to 1.0) of using an affinity server.
	AffinityValidity    string                       `toml:"affinity_validity"`
	AuthRateLimit       server.AuthRateLimiterConfig `toml:"auth_rate_limit"` // Authentication rate limiting
	PreLookup           *proxy.PreLookupConfig       `toml:"prelookup"`       // Database-driven user routing
}

// ManageSieveProxyServerConfig holds ManageSieve proxy server configuration.
type ManageSieveProxyServerConfig struct {
	Start               bool                         `toml:"start"`
	Addr                string                       `toml:"addr"`
	RemoteAddrs         []string                     `toml:"remote_addrs"`
	MaxConnections      int                          `toml:"max_connections"`        // Maximum concurrent connections
	MaxConnectionsPerIP int                          `toml:"max_connections_per_ip"` // Maximum connections per IP address
	MasterSASLUsername  string                       `toml:"master_sasl_username"`
	MasterSASLPassword  string                       `toml:"master_sasl_password"`
	TLS                 bool                         `toml:"tls"`
	TLSCertFile         string                       `toml:"tls_cert_file"`
	TLSKeyFile          string                       `toml:"tls_key_file"`
	TLSVerify           bool                         `toml:"tls_verify"`
	RemoteTLS           bool                         `toml:"remote_tls"`
	RemoteTLSVerify     bool                         `toml:"remote_tls_verify"`
	ConnectTimeout      string                       `toml:"connect_timeout"`
	AuthRateLimit       server.AuthRateLimiterConfig `toml:"auth_rate_limit"` // Authentication rate limiting
	PreLookup           *proxy.PreLookupConfig       `toml:"prelookup"`       // Database-driven user routing
}

// LMTPProxyServerConfig holds LMTP proxy server configuration.
type LMTPProxyServerConfig struct {
	Start               bool                   `toml:"start"`
	Addr                string                 `toml:"addr"`
	RemoteAddrs         []string               `toml:"remote_addrs"`
	MaxConnections      int                    `toml:"max_connections"`        // Maximum concurrent connections
	MaxConnectionsPerIP int                    `toml:"max_connections_per_ip"` // Maximum connections per IP address
	TLS                 bool                   `toml:"tls"`
	TLSCertFile         string                 `toml:"tls_cert_file"`
	TLSKeyFile          string                 `toml:"tls_key_file"`
	TLSVerify           bool                   `toml:"tls_verify"`
	RemoteTLS           bool                   `toml:"remote_tls"`
	RemoteTLSVerify     bool                   `toml:"remote_tls_verify"`
	ConnectTimeout      string                 `toml:"connect_timeout"`
	EnableAffinity      bool                   `toml:"enable_affinity"`
	AffinityStickiness  float64                `toml:"affinity_stickiness"` // Probability (0.0 to 1.0) of using an affinity server.
	AffinityValidity    string                 `toml:"affinity_validity"`
	PreLookup           *proxy.PreLookupConfig `toml:"prelookup"` // Database-driven user routing
}

// ConnectionTrackingConfig holds connection tracking configuration.
type ConnectionTrackingConfig struct {
	Enabled        bool   `toml:"enabled"`
	UpdateInterval string `toml:"update_interval"`
	BatchUpdates   bool   `toml:"batch_updates"`
	PersistToDB    bool   `toml:"persist_to_db"`
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
}

// UploaderConfig holds upload worker configuration.
type UploaderConfig struct {
	Path          string `toml:"path"`
	BatchSize     int    `toml:"batch_size"`
	Concurrency   int    `toml:"concurrency"`
	MaxAttempts   int    `toml:"max_attempts"`
	RetryInterval string `toml:"retry_interval"`
}

// Config holds all configuration for the application.
type Config struct {
	LogOutput  string                `toml:"log_output"`
	Database   config.DatabaseConfig `toml:"database"`
	S3         S3Config              `toml:"s3"`
	LocalCache LocalCacheConfig      `toml:"local_cache"`
	Cleanup    CleanupConfig         `toml:"cleanup"`
	Servers    ServersConfig         `toml:"servers"`
	Uploader   UploaderConfig        `toml:"uploader"`
}

// newDefaultConfig creates a Config struct with default values.
func newDefaultConfig() Config {
	return Config{
		LogOutput: "syslog",
		Database: config.DatabaseConfig{
			LogQueries: false,
			Write: &config.DatabaseEndpointConfig{
				Hosts:           []string{"localhost"},
				Port:            5432,
				User:            "postgres",
				Password:        "",
				Name:            "sora_mail_db",
				TLSMode:         false,
				MaxConns:        100,
				MinConns:        10,
				MaxConnLifetime: "1h",
				MaxConnIdleTime: "30m",
			},
			Read: &config.DatabaseEndpointConfig{
				Hosts:           []string{"localhost"},
				Port:            5432,
				User:            "postgres",
				Password:        "",
				Name:            "sora_mail_db",
				TLSMode:         false,
				MaxConns:        100,
				MinConns:        10,
				MaxConnLifetime: "1h",
				MaxConnIdleTime: "30m",
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
			GracePeriod:  "14d",
			WakeInterval: "1h",
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
				Start:               false,
				Addr:                ":1143",
				MaxConnections:      2000,
				MaxConnectionsPerIP: 50,
				MasterSASLUsername:  "",
				MasterSASLPassword:  "",
				TLS:                 false,
				RemoteTLS:           false,
				RemoteTLSVerify:     true,
				EnableAffinity:      true,
				AffinityStickiness:  0.9,
				AffinityValidity:    "24h",
			},
			POP3Proxy: POP3ProxyServerConfig{
				Start:               false,
				Addr:                ":1110",
				MaxConnections:      1000,
				MaxConnectionsPerIP: 20,
				MasterSASLUsername:  "",
				MasterSASLPassword:  "",
				TLS:                 false,
				RemoteTLS:           false,
				RemoteTLSVerify:     true,
				EnableAffinity:      true,
				AffinityStickiness:  0.9,
				AffinityValidity:    "24h",
				AuthRateLimit:       server.DefaultAuthRateLimiterConfig(),
			},
			ManageSieveProxy: ManageSieveProxyServerConfig{
				Start:               false,
				Addr:                ":14190",
				MaxConnections:      500,
				MaxConnectionsPerIP: 10,
				MasterSASLUsername:  "",
				MasterSASLPassword:  "",
				TLS:                 false,
				RemoteTLS:           false,
				RemoteTLSVerify:     true,
				AuthRateLimit:       server.DefaultAuthRateLimiterConfig(),
			},
			LMTPProxy: LMTPProxyServerConfig{
				Start:               false,
				Addr:                ":124",
				MaxConnections:      1000,
				MaxConnectionsPerIP: 0, // Disable per-IP limits for proxy scenarios
				TLS:                 false,
				RemoteTLS:           false,
				RemoteTLSVerify:     true,
				EnableAffinity:      true,
				AffinityStickiness:  0.9,
				AffinityValidity:    "24h",
			},
			ConnectionTracking: ConnectionTrackingConfig{
				Enabled:        true,
				UpdateInterval: "15s",
				BatchUpdates:   true,
				PersistToDB:    true,
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

func (c *CleanupConfig) GetGracePeriod() (time.Duration, error) {
	if c.GracePeriod == "" {
		c.GracePeriod = "14d"
	}
	return helpers.ParseDuration(c.GracePeriod)
}

func (c *CleanupConfig) GetWakeInterval() (time.Duration, error) {
	if c.WakeInterval == "" {
		c.WakeInterval = "1h"
	}
	return helpers.ParseDuration(c.WakeInterval)
}

func (c *CleanupConfig) GetMaxAgeRestriction() (time.Duration, error) {
	if c.MaxAgeRestriction == "" {
		return 0, nil // 0 means no restriction
	}
	return helpers.ParseDuration(c.MaxAgeRestriction)
}

func (c *LocalCacheConfig) GetCapacity() (int64, error) {
	if c.Capacity == "" {
		c.Capacity = "1gb"
	}
	return helpers.ParseSize(c.Capacity)
}

func (c *LocalCacheConfig) GetMaxObjectSize() (int64, error) {
	if c.MaxObjectSize == "" {
		c.MaxObjectSize = "5mb"
	}
	return helpers.ParseSize(c.MaxObjectSize)
}

func (c *LocalCacheConfig) GetMetricsInterval() (time.Duration, error) {
	if c.MetricsInterval == "" {
		c.MetricsInterval = "5m"
	}
	return helpers.ParseDuration(c.MetricsInterval)
}

func (c *LocalCacheConfig) GetMetricsRetention() (time.Duration, error) {
	if c.MetricsRetention == "" {
		c.MetricsRetention = "30d"
	}
	return helpers.ParseDuration(c.MetricsRetention)
}

func (c *LocalCacheConfig) GetPurgeInterval() (time.Duration, error) {
	if c.PurgeInterval == "" {
		c.PurgeInterval = "12h"
	}
	return helpers.ParseDuration(c.PurgeInterval)
}

func (c *LocalCacheConfig) GetOrphanCleanupAge() (time.Duration, error) {
	if c.OrphanCleanupAge == "" {
		c.OrphanCleanupAge = "30d"
	}
	return helpers.ParseDuration(c.OrphanCleanupAge)
}

func (c *UploaderConfig) GetRetryInterval() (time.Duration, error) {
	if c.RetryInterval == "" {
		c.RetryInterval = "30s"
	}
	return helpers.ParseDuration(c.RetryInterval)
}

func (c *IMAPServerConfig) GetAppendLimit() (int64, error) {
	if c.AppendLimit == "" {
		c.AppendLimit = "25mb"
	}
	return helpers.ParseSize(c.AppendLimit)
}

func (c *ManageSieveServerConfig) GetMaxScriptSize() (int64, error) {
	if c.MaxScriptSize == "" {
		c.MaxScriptSize = "16kb"
	}
	return helpers.ParseSize(c.MaxScriptSize)
}

// GetAppendLimit gets the append limit
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

// GetUpdateInterval parses the update interval duration for connection tracking
func (c *ConnectionTrackingConfig) GetUpdateInterval() (time.Duration, error) {
	if c.UpdateInterval == "" {
		return 15 * time.Second, nil
	}
	return helpers.ParseDuration(c.UpdateInterval)
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

// GetAffinityValidity parses the affinity validity duration for LMTP proxy
func (c *IMAPProxyServerConfig) GetAffinityValidity() (time.Duration, error) {
	if c.AffinityValidity == "" {
		return 24 * time.Hour, nil
	}
	return helpers.ParseDuration(c.AffinityValidity)
}
