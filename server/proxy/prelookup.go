package proxy

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/helpers"
	"golang.org/x/crypto/bcrypt"
)

// PreLookupConfig holds configuration for database-driven user routing
type PreLookupConfig struct {
	Enabled         bool        `toml:"enabled"`
	Hosts           []string    `toml:"hosts"`
	Port            interface{} `toml:"port"` // Database port (default: "5432"), can be string or integer
	User            string      `toml:"user"`
	Password        string      `toml:"password"`
	Name            string      `toml:"name"`
	TLS             bool        `toml:"tls"`
	MaxConns        int         `toml:"max_conns"`
	MinConns        int         `toml:"min_conns"`
	MaxConnLifetime string      `toml:"max_conn_lifetime"`
	MaxConnIdleTime string      `toml:"max_conn_idle_time"`
	CacheTTL        string      `toml:"cache_ttl"`
	CacheSize       int         `toml:"cache_size"`
	RoutingQuery    string      `toml:"routing_query"`
	FallbackDefault bool        `toml:"fallback_to_default"`
	AuthMode        string      `toml:"auth_mode"`   // "routing_only" or "auth_and_route"
	AuthMethod      string      `toml:"auth_method"` // "bcrypt", "plain", etc.
	AuthQuery       string      `toml:"auth_query"`  // Query to get password hash
}

// UserRoutingInfo represents routing information for a user
type UserRoutingInfo struct {
	ServerAddress string
}

// AuthResult represents the result of authentication
type AuthResult int

const (
	AuthUserNotFound AuthResult = iota // User doesn't exist in prelookup DB - fallback allowed
	AuthSuccess                        // User found and authenticated - proceed with routing
	AuthFailed                         // User found but auth failed - reject, no fallback
)

// UserRoutingLookup interface for routing lookups
type UserRoutingLookup interface {
	LookupUserRoute(ctx context.Context, email string) (*UserRoutingInfo, error)
	AuthenticateAndRoute(ctx context.Context, email, password string) (*UserRoutingInfo, AuthResult, error)
	Close() error
}

// cacheEntry represents a cached routing entry
type cacheEntry struct {
	info      *UserRoutingInfo
	timestamp time.Time
	userFound bool // Whether user exists in the database (for negative caching)
}

// PreLookupClient implements UserRoutingLookup with database queries and caching
type PreLookupClient struct {
	pool         *pgxpool.Pool
	routingQuery string
	authQuery    string
	authMode     string
	authMethod   string
	cacheTTL     time.Duration
	cache        map[string]*cacheEntry
	cacheMutex   sync.RWMutex
	fallbackMode bool
	stopJanitor  chan struct{}
}

// NewPreLookupClient creates a new PreLookupClient
func NewPreLookupClient(ctx context.Context, config *PreLookupConfig) (*PreLookupClient, error) {
	if config == nil || !config.Enabled {
		return nil, fmt.Errorf("prelookup not enabled")
	}

	// Parse durations - default to 10 minutes for better caching
	cacheTTL, err := config.GetCacheTTL()
	if err != nil {
		return nil, fmt.Errorf("invalid cache_ttl: %w", err)
	}

	maxConnLifetime, err := config.GetMaxConnLifetime()
	if err != nil {
		return nil, fmt.Errorf("invalid max_conn_lifetime: %w", err)
	}

	maxConnIdleTime, err := config.GetMaxConnIdleTime()
	if err != nil {
		return nil, fmt.Errorf("invalid max_conn_idle_time: %w", err)
	}

	// Set defaults
	if config.MaxConns == 0 {
		config.MaxConns = 10
	}
	if config.MinConns == 0 {
		config.MinConns = 2
	}
	if config.CacheSize == 0 {
		config.CacheSize = 10000
	}

	// Default queries if not specified
	routingQuery := config.RoutingQuery
	if routingQuery == "" {
		routingQuery = "SELECT server_address FROM user_routing WHERE email = $1 AND active = true"
	}

	authQuery := config.AuthQuery
	if authQuery == "" && config.AuthMode == "auth_and_route" {
		authQuery = "SELECT password_hash, server_address FROM user_routing WHERE email = $1 AND active = true"
	}

	authMode := config.AuthMode
	if authMode == "" {
		authMode = "routing_only" // Default to routing only
	}

	authMethod := config.AuthMethod
	if authMethod == "" {
		authMethod = "bcrypt" // Default to bcrypt
	}

	// Build connection string
	tlsMode := "disable"
	if config.TLS {
		tlsMode = "require"
	}

	var connString string
	if len(config.Hosts) > 0 {
		host := config.Hosts[0] // Use first host for now, can be enhanced for multiple hosts
		
		// Handle host:port combination
		// Priority: 1) host:port in hosts array, 2) separate port field, 3) default 5432
		if !strings.Contains(host, ":") {
			port := 5432 // Default PostgreSQL port
			if config.Port != nil {
				var p int64
				var err error
				switch v := config.Port.(type) {
				case string:
					p, err = strconv.ParseInt(v, 10, 32)
					if err != nil {
						return nil, fmt.Errorf("invalid string for port: %q", v)
					}
				case int:
					p = int64(v)
				case int64: // TOML parsers often use int64 for numbers
					p = v
				default:
					return nil, fmt.Errorf("invalid type for port: %T", v)
				}
				port = int(p)
			}
			if port <= 0 || port > 65535 {
				return nil, fmt.Errorf("port number %d is out of the valid range (1-65535)", port)
			}
			host = fmt.Sprintf("%s:%d", host, port)
		}
		
		connString = fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=%s",
			config.User, config.Password, host, config.Name, tlsMode)
	} else {
		return nil, fmt.Errorf("no database hosts configured")
	}

	// Configure pool
	poolConfig, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection string: %w", err)
	}

	poolConfig.MaxConns = int32(config.MaxConns)
	poolConfig.MinConns = int32(config.MinConns)
	poolConfig.MaxConnLifetime = maxConnLifetime
	poolConfig.MaxConnIdleTime = maxConnIdleTime

	// Create connection pool
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	log.Printf("PreLookup database connected successfully")

	client := &PreLookupClient{
		pool:         pool,
		routingQuery: routingQuery,
		authQuery:    authQuery,
		authMode:     authMode,
		authMethod:   authMethod,
		cacheTTL:     cacheTTL,
		cache:        make(map[string]*cacheEntry),
		fallbackMode: config.FallbackDefault,
		stopJanitor:  make(chan struct{}),
	}

	// Log the configuration for debugging
	log.Printf("[PreLookup] Initialized with auth_mode='%s', auth_method='%s', cache_ttl=%v", 
		authMode, authMethod, cacheTTL)
	log.Printf("[PreLookup] Routing query: %s", routingQuery)
	if authQuery != "" {
		log.Printf("[PreLookup] Auth query: %s", authQuery)
	}

	client.startCacheJanitor()
	return client, nil
}

// LookupUserRoute looks up routing information for a user
func (c *PreLookupClient) LookupUserRoute(ctx context.Context, email string) (*UserRoutingInfo, error) {
	// Check cache first
	c.cacheMutex.RLock()
	if entry, exists := c.cache[email]; exists {
		if time.Since(entry.timestamp) < c.cacheTTL {
			c.cacheMutex.RUnlock()
			if !entry.userFound {
				// User was cached as not found
				log.Printf("[PreLookup] Cache hit for user '%s': user not found (negative cache)", email)
				return nil, nil
			}
			log.Printf("[PreLookup] Cache hit for user '%s': server_address='%s'", email, entry.info.ServerAddress)
			return entry.info, nil
		}
	}
	c.cacheMutex.RUnlock()

	// Query database
	log.Printf("[PreLookup] Executing routing query for user '%s': %s", email, c.routingQuery)
	var serverAddress string
	err := c.pool.QueryRow(ctx, c.routingQuery, email).Scan(&serverAddress)
	if err != nil {
		if err == pgx.ErrNoRows || err == sql.ErrNoRows {
			log.Printf("[PreLookup] No routing found for user '%s'", email)
			// Cache negative result
			c.cacheMutex.Lock()
			c.cache[email] = &cacheEntry{
				info:      nil,
				timestamp: time.Now(),
				userFound: false,
			}
			c.cacheMutex.Unlock()
			return nil, nil
		}
		log.Printf("[PreLookup] Database query failed for user '%s': %v", email, err)
		return nil, fmt.Errorf("database query failed: %w", err)
	}

	log.Printf("[PreLookup] Routing result for user '%s': server_address='%s'", email, serverAddress)
	info := &UserRoutingInfo{
		ServerAddress: serverAddress,
	}

	// Cache the positive result
	c.cacheMutex.Lock()
	c.cache[email] = &cacheEntry{
		info:      info,
		timestamp: time.Now(),
		userFound: true,
	}
	c.cacheMutex.Unlock()

	return info, nil
}

// AuthenticateAndRoute performs both authentication and routing lookup
func (c *PreLookupClient) AuthenticateAndRoute(ctx context.Context, email, password string) (*UserRoutingInfo, AuthResult, error) {
	// If in routing-only mode, just do routing lookup
	if c.authMode == "routing_only" {
		log.Printf("[PreLookup] Using routing-only mode for user '%s'", email)
		info, err := c.LookupUserRoute(ctx, email)
		if err != nil {
			return nil, AuthUserNotFound, fmt.Errorf("routing lookup failed: %w", err)
		}
		if info != nil {
			log.Printf("[PreLookup] Routing-only mode found server for user '%s': %s", email, info.ServerAddress)
		} else {
			log.Printf("[PreLookup] Routing-only mode: no server found for user '%s'", email)
		}
		return info, AuthSuccess, nil
	}

	// Check cache first - we cache the routing info and "user found" status
	c.cacheMutex.RLock()
	if entry, exists := c.cache[email]; exists {
		if time.Since(entry.timestamp) < c.cacheTTL {
			c.cacheMutex.RUnlock()

			if !entry.userFound {
				// User was previously not found - still not found
				return nil, AuthUserNotFound, nil
			}

			// User exists in cache, but we still need to verify password from DB
			// (we never cache passwords for security)
			// We must scan into dummy variables for the other columns.
			var passwordHash, dummyAddr string
			err := c.pool.QueryRow(ctx, c.authQuery, email).Scan(&passwordHash, &dummyAddr)
			if err != nil {
				if err == pgx.ErrNoRows || err == sql.ErrNoRows {
					return nil, AuthUserNotFound, nil
				}
				return nil, AuthUserNotFound, fmt.Errorf("database query failed: %w", err)
			}

			// Verify password
			if !c.verifyPassword(password, passwordHash) {
				log.Printf("[PreLookup] Authentication failed for user: %s", email)
				return nil, AuthFailed, nil
			}

			// Return cached routing info
			return entry.info, AuthSuccess, nil
		}
	}
	c.cacheMutex.RUnlock()

	// Not in cache or expired - query database for everything
	log.Printf("[PreLookup] Executing auth query for user '%s': %s", email, c.authQuery)
	var passwordHash, serverAddress string
	err := c.pool.QueryRow(ctx, c.authQuery, email).Scan(&passwordHash, &serverAddress)
	if err != nil {
		if err == pgx.ErrNoRows || err == sql.ErrNoRows {
			log.Printf("[PreLookup] No auth record found for user '%s'", email)
			// Cache negative result
			c.cacheMutex.Lock()
			c.cache[email] = &cacheEntry{
				info:      nil,
				timestamp: time.Now(),
				userFound: false,
			}
			c.cacheMutex.Unlock()
			return nil, AuthUserNotFound, nil
		}
		log.Printf("[PreLookup] Auth query failed for user '%s': %v", email, err)
		return nil, AuthUserNotFound, fmt.Errorf("database query failed: %w", err)
	}

	log.Printf("[PreLookup] Auth query result for user '%s': found password hash and server_address='%s'", email, serverAddress)

	// User exists, now verify password
	if !c.verifyPassword(password, passwordHash) {
		log.Printf("[PreLookup] Authentication failed for user: %s", email)
		return nil, AuthFailed, nil
	}

	log.Printf("[PreLookup] Authentication successful for user '%s'", email)

	// Authentication successful, prepare routing info
	info := &UserRoutingInfo{
		ServerAddress: serverAddress,
	}

	// Cache the result (routing info and positive user found status)
	c.cacheMutex.Lock()
	c.cache[email] = &cacheEntry{
		info:      info,
		timestamp: time.Now(),
		userFound: true,
	}
	c.cacheMutex.Unlock()

	return info, AuthSuccess, nil
}

// verifyPassword verifies a password against a hash using the configured method
func (c *PreLookupClient) verifyPassword(password, hash string) bool {
	switch c.authMethod {
	case "bcrypt":
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
		if err != nil && err != bcrypt.ErrMismatchedHashAndPassword {
			log.Printf("[PreLookup] bcrypt verification error for hash '%s': %v", hash, err)
		}
		return err == nil
	case "plain":
		return password == hash
	default:
		log.Printf("[PreLookup] Unknown auth method: %s", c.authMethod)
		return false
	}
}

// startCacheJanitor runs a background goroutine to clean up expired cache entries.
func (c *PreLookupClient) startCacheJanitor() {
	// Run janitor periodically. Use a fraction of TTL for responsiveness.
	interval := c.cacheTTL / 5
	if interval < time.Minute {
		interval = time.Minute // Minimum cleanup interval
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				c.cleanupCache()
			case <-c.stopJanitor:
				return
			}
		}
	}()
}

// cleanupCache removes expired entries.
func (c *PreLookupClient) cleanupCache() {
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()
	now := time.Now()
	for email, entry := range c.cache {
		if now.Sub(entry.timestamp) > c.cacheTTL {
			delete(c.cache, email)
		}
	}
}

// Close closes the database connection pool
func (c *PreLookupClient) Close() error {
	if c.pool != nil {
		if c.stopJanitor != nil {
			close(c.stopJanitor)
		}
		c.pool.Close()
	}
	return nil
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

// InitializePrelookup is a helper function to create and configure the prelookup client.
// It centralizes the initialization logic used by all proxy servers.
func InitializePrelookup(ctx context.Context, config *PreLookupConfig, proxyName string) (UserRoutingLookup, error) {
	if config == nil || !config.Enabled {
		return nil, nil // Not an error, just not enabled.
	}

	prelookupClient, err := NewPreLookupClient(ctx, config)
	if err != nil {
		log.Printf("[%s Proxy] Failed to initialize prelookup client: %v", proxyName, err)
		if !config.FallbackDefault {
			return nil, fmt.Errorf("failed to initialize prelookup client: %w", err)
		}
		log.Printf("[%s Proxy] Continuing without prelookup due to fallback_to_default=true", proxyName)
		return nil, nil // Fallback is enabled, so we can continue without a client.
	}

	log.Printf("[%s Proxy] Prelookup database client initialized successfully", proxyName)
	return prelookupClient, nil
}
