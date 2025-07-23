package main

import (
	"time"

	"github.com/migadu/sora/helpers"
)

// DatabaseConfig holds database configuration.
type DatabaseConfig struct {
	Host       string `toml:"host"`
	Port       string `toml:"port"`
	User       string `toml:"user"`
	Password   string `toml:"password"`
	Name       string `toml:"name"`
	TLSMode    bool   `toml:"tls"`
	LogQueries bool   `toml:"log_queries"`
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

// Cleaner worker configuration.
type CleanupConfig struct {
	GracePeriod       string `toml:"grace_period"`
	WakeInterval      string `toml:"wake_interval"`
	MaxAgeRestriction string `toml:"max_age_restriction"`
}

// Local disk cache configuration.
type LocalCacheConfig struct {
	Capacity      string `toml:"capacity"`
	MaxObjectSize string `toml:"max_object_size"`
	Path          string `toml:"path"`
}

// IMAPServerConfig holds IMAP server configuration.
type IMAPServerConfig struct {
	Start              bool   `toml:"start"`
	Addr               string `toml:"addr"`
	AppendLimit        string `toml:"append_limit"`
	MasterUsername     string `toml:"master_username"`
	MasterPassword     string `toml:"master_password"`
	MasterSASLUsername string `toml:"master_sasl_username"`
	MasterSASLPassword string `toml:"master_sasl_password"`
	TLS                bool   `toml:"tls"`
	TLSCertFile        string `toml:"tls_cert_file"`
	TLSKeyFile         string `toml:"tls_key_file"`
	TLSVerify          bool   `toml:"tls_verify"`
}

// LMTPServerConfig holds LMTP server configuration.
type LMTPServerConfig struct {
	Start          bool   `toml:"start"`
	Addr           string `toml:"addr"`
	ExternalRelay  string `toml:"external_relay"`
	TLS            bool   `toml:"tls"`
	TLSUseStartTLS bool   `toml:"tls_use_starttls"`
	TLSCertFile    string `toml:"tls_cert_file"`
	TLSKeyFile     string `toml:"tls_key_file"`
	TLSVerify      bool   `toml:"tls_verify"`
}

// POP3ServerConfig holds POP3 server configuration.
type POP3ServerConfig struct {
	Start       bool   `toml:"start"`
	Addr        string `toml:"addr"`
	TLS         bool   `toml:"tls"`
	TLSCertFile string `toml:"tls_cert_file"`
	TLSKeyFile  string `toml:"tls_key_file"`
	TLSVerify   bool   `toml:"tls_verify"`
}

// ManageSieveServerConfig holds ManageSieve server configuration.
type ManageSieveServerConfig struct {
	Start          bool   `toml:"start"`
	Addr           string `toml:"addr"`
	MaxScriptSize  string `toml:"max_script_size"`
	InsecureAuth   bool   `toml:"insecure_auth"`
	TLS            bool   `toml:"tls"`
	TLSUseStartTLS bool   `toml:"tls_use_starttls"`
	TLSCertFile    string `toml:"tls_cert_file"`
	TLSKeyFile     string `toml:"tls_key_file"`
	TLSVerify      bool   `toml:"tls_verify"`
}

// ServersConfig holds all server configurations.
type ServersConfig struct {
	Debug       bool                    `toml:"debug"`
	IMAP        IMAPServerConfig        `toml:"imap"`
	LMTP        LMTPServerConfig        `toml:"lmtp"`
	POP3        POP3ServerConfig        `toml:"pop3"`
	ManageSieve ManageSieveServerConfig `toml:"managesieve"`
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
	LogOutput  string           `toml:"log_output"`
	Database   DatabaseConfig   `toml:"database"`
	S3         S3Config         `toml:"s3"`
	LocalCache LocalCacheConfig `toml:"local_cache"`
	Cleanup    CleanupConfig    `toml:"cleanup"`
	Servers    ServersConfig    `toml:"servers"`
	Uploader   UploaderConfig   `toml:"uploader"`
}

// newDefaultConfig creates a Config struct with default values.
func newDefaultConfig() Config {
	return Config{
		LogOutput: "syslog",
		Database: DatabaseConfig{
			Host:       "localhost",
			Port:       "5432",
			User:       "postgres",
			Password:   "",
			Name:       "sora_mail_db",
			TLSMode:    false,
			LogQueries: false,
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
			Capacity:      "1gb",
			MaxObjectSize: "5mb",
			Path:          "/tmp/sora/cache",
		},
		Servers: ServersConfig{
			Debug: false,
			IMAP: IMAPServerConfig{
				Start:          true,
				Addr:           ":143",
				AppendLimit:    "25mb",
				MasterUsername: "",
				MasterPassword: "",
				TLS:            false,
				TLSCertFile:    "",
				TLSKeyFile:     "",
				TLSVerify:      true,
			},
			LMTP: LMTPServerConfig{
				Start:          true,
				Addr:           ":24",
				ExternalRelay:  "",
				TLS:            false,
				TLSUseStartTLS: false,
				TLSCertFile:    "",
				TLSKeyFile:     "",
				TLSVerify:      true,
			},
			POP3: POP3ServerConfig{
				Start:       true,
				Addr:        ":110",
				TLS:         false,
				TLSCertFile: "",
				TLSKeyFile:  "",
				TLSVerify:   true,
			},
			ManageSieve: ManageSieveServerConfig{
				Start:          true,
				Addr:           ":4190",
				MaxScriptSize:  "16kb",
				InsecureAuth:   false,
				TLS:            false,
				TLSUseStartTLS: false,
				TLSCertFile:    "",
				TLSKeyFile:     "",
				TLSVerify:      true,
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
