package config

import (
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
	Port            interface{} `toml:"port"`  // Database port (default: "5432"), can be string or integer
	User            string      `toml:"user"`
	Password        string      `toml:"password"`
	Name            string      `toml:"name"`
	TLSMode         bool        `toml:"tls"`
	MaxConns        int         `toml:"max_conns"`          // Maximum number of connections in the pool
	MinConns        int         `toml:"min_conns"`          // Minimum number of connections in the pool
	MaxConnLifetime string      `toml:"max_conn_lifetime"`  // Maximum lifetime of a connection
	MaxConnIdleTime string      `toml:"max_conn_idle_time"` // Maximum idle time before a connection is closed
}

// DatabaseConfig holds database configuration with separate read/write endpoints
type DatabaseConfig struct {
	LogQueries bool                    `toml:"log_queries"` // Global setting for query logging
	Write      *DatabaseEndpointConfig `toml:"write"`       // Write database configuration
	Read       *DatabaseEndpointConfig `toml:"read"`        // Read database configuration (can have multiple hosts for load balancing)
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
