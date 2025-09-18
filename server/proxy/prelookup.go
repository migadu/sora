package proxy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/circuitbreaker"
	"github.com/migadu/sora/pkg/retry"
)

// PreLookupConfig is an alias for config.PreLookupConfig for compatibility
type PreLookupConfig = config.PreLookupConfig

// UserRoutingInfo represents routing information for a user
type UserRoutingInfo struct {
	ServerAddress          string
	AccountID              int64
	IsPrelookupAccount     bool
	RemoteTLS              bool
	RemoteTLSVerify        bool
	RemoteUseProxyProtocol bool
	RemoteUseIDCommand     bool // Use IMAP ID command for forwarding (IMAP only)
	RemoteUseXCLIENT       bool // Use XCLIENT command for forwarding (POP3/LMTP/ManageSieve)
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
	pool                   *pgxpool.Pool
	query                  string
	cacheTTL               time.Duration
	cache                  map[string]*cacheEntry
	cacheMutex             sync.RWMutex
	fallbackMode           bool
	remoteTLS              bool
	remoteTLSVerify        bool
	remotePort             int
	remoteUseProxyProtocol bool
	remoteUseIDCommand     bool
	remoteUseXCLIENT       bool
	stopJanitor            chan struct{}
	breaker                *circuitbreaker.CircuitBreaker
}

// normalizeServerAddress adds the default port to a server address if no port is specified
func (c *PreLookupClient) normalizeServerAddress(addr string) string {
	if addr == "" || c.remotePort == 0 {
		return addr
	}

	// Check if a port is already present.
	// net.SplitHostPort is the robust way to do this, as it correctly
	// handles IPv6 addresses like "[::1]".
	_, _, err := net.SplitHostPort(addr)
	if err == nil {
		// Address already has a port, return as-is.
		return addr
	}

	// If there's an error, it's likely "missing port in address".
	// We can now safely add our default port.
	normalized := net.JoinHostPort(addr, strconv.Itoa(c.remotePort))
	log.Printf("[PreLookup] Normalized server address '%s' to '%s' using default port %d", addr, normalized, c.remotePort)
	return normalized
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

	// Use a single query that can handle both routing-only and auth+route modes.
	// The system will auto-detect the mode based on the number of columns returned.
	query := config.Query
	if query == "" {
		return nil, errors.New("prelookup query is not configured")
	}

	// Handle TLS settings for prelookup-routed connections
	remoteTLSVerify := true
	if config.RemoteTLSVerify != nil {
		remoteTLSVerify = *config.RemoteTLSVerify
	}
	log.Printf("[PreLookup] TLS configuration: RemoteTLS=%t, RemoteTLSVerify=%t (config.RemoteTLSVerify=%v)", config.RemoteTLS, remoteTLSVerify, config.RemoteTLSVerify)

	// Get remote port for prelookup results
	remotePort, err := config.GetRemotePort()
	if err != nil {
		return nil, fmt.Errorf("invalid remote_port: %w", err)
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

	// Initialize circuit breaker for prelookup database
	breakerSettings := circuitbreaker.DefaultSettings("prelookup_db")
	breakerSettings.OnStateChange = func(name string, from, to circuitbreaker.State) {
		log.Printf("[PreLookup] Circuit breaker '%s' changed from %s to %s", name, from, to)
	}
	breakerSettings.ReadyToTrip = func(counts circuitbreaker.Counts) bool {
		failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
		return counts.Requests >= 5 && failureRatio >= 0.6
	}

	client := &PreLookupClient{
		pool:                   pool,
		query:                  query,
		cacheTTL:               cacheTTL,
		cache:                  make(map[string]*cacheEntry),
		fallbackMode:           config.FallbackDefault,
		remoteTLS:              config.RemoteTLS,
		remoteTLSVerify:        remoteTLSVerify,
		remotePort:             remotePort,
		remoteUseProxyProtocol: config.RemoteUseProxyProtocol,
		remoteUseIDCommand:     config.RemoteUseIDCommand,
		remoteUseXCLIENT:       config.RemoteUseXCLIENT,
		stopJanitor:            make(chan struct{}),
		breaker:                circuitbreaker.NewCircuitBreaker(breakerSettings),
	}

	// Log the configuration for debugging
	log.Printf("[PreLookup] Initialized with auto-detect mode, unified auth (supports SSHA512, SHA512, bcrypt, BLF-CRYPT), cache_ttl=%v", cacheTTL)
	log.Printf("[PreLookup] Query: %s", query)

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

	var serverAddress string
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     3 * time.Second,
		Multiplier:      1.8,
		Jitter:          true,
		MaxRetries:      3,
	}

	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := c.breaker.Execute(func() (interface{}, error) {
			// Try to execute query and auto-detect the format based on columns
			rows, err := c.pool.Query(ctx, c.query, email)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
					return nil, err
				}
				return nil, err
			}
			defer rows.Close()

			if !rows.Next() {
				return nil, pgx.ErrNoRows
			}

			// Get field descriptions to determine the number of columns
			fieldDescs := rows.FieldDescriptions()
			numCols := len(fieldDescs)

			if numCols == 1 {
				// Single column: server_address only (routing-only mode)
				var addr string
				err := rows.Scan(&addr)
				if err != nil {
					return nil, err
				}
				return addr, nil
			} else if numCols >= 2 {
				// Multiple columns: assume it includes password_hash (auth+route mode)
				// For routing-only lookup, we just need the server address (assume it's the last column)
				values := make([]interface{}, numCols)
				valuePtrs := make([]interface{}, numCols)
				for i := range values {
					valuePtrs[i] = &values[i]
				}

				err := rows.Scan(valuePtrs...)
				if err != nil {
					return nil, err
				}

				// Return the last column as server address for routing purposes
				if values[numCols-1] != nil {
					addr, ok := values[numCols-1].(string)
					if !ok {
						return nil, fmt.Errorf("prelookup query: expected last column (server_address) to be a string, but got %T", values[numCols-1])
					}
					return addr, nil
				}
				return "", nil
			}

			return nil, fmt.Errorf("unexpected number of columns: %d", numCols)
		})

		if cbErr != nil {
			// Handle ErrNoRows: it's not a retryable error, it's a final result.
			if errors.Is(cbErr, pgx.ErrNoRows) || errors.Is(cbErr, sql.ErrNoRows) {
				serverAddress = ""       // Explicitly clear it
				return retry.Stop(cbErr) // Stop retrying, but we'll handle this "error" below.
			}
			if isRetryableError(cbErr) {
				log.Printf("[PreLookup] Retrying routing query for '%s' due to: %v", email, cbErr)
				return cbErr // Signal to retry
			}
			return retry.Stop(cbErr) // Non-retryable error
		}

		if result != nil {
			serverAddress = result.(string)
		} else {
			serverAddress = ""
		}
		return nil // Success
	}, config)

	if err != nil && !errors.Is(err, pgx.ErrNoRows) && !errors.Is(err, sql.ErrNoRows) {
		log.Printf("[PreLookup] Database query failed for user '%s': %v", email, err)
		return nil, fmt.Errorf("database query failed: %w", err)
	}

	log.Printf("[PreLookup] Routing result for user '%s': server_address='%s'", email, serverAddress)
	normalizedAddr := c.normalizeServerAddress(serverAddress)
	info := &UserRoutingInfo{
		ServerAddress:          normalizedAddr,
		RemoteTLS:              c.remoteTLS,
		RemoteTLSVerify:        c.remoteTLSVerify,
		RemoteUseProxyProtocol: c.remoteUseProxyProtocol,
		RemoteUseIDCommand:     c.remoteUseIDCommand,
		RemoteUseXCLIENT:       c.remoteUseXCLIENT,
	}

	if serverAddress == "" {
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
// Auto-detects mode based on query results: 1 column = routing only, 2+ columns = auth+route
func (c *PreLookupClient) AuthenticateAndRoute(ctx context.Context, email, password string) (*UserRoutingInfo, AuthResult, error) {
	// Check cache first - but never cache passwords for security
	c.cacheMutex.RLock()
	cachedEntry, hasCached := c.cache[email]
	if hasCached && time.Since(cachedEntry.timestamp) < c.cacheTTL {
		c.cacheMutex.RUnlock()
		if !cachedEntry.userFound {
			return nil, AuthUserNotFound, nil
		}
		// We have cached routing info, but still need to verify password from DB
		// Fall through to query the database for password verification
	} else {
		c.cacheMutex.RUnlock()
	}

	// Query database and auto-detect mode
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     3 * time.Second,
		Multiplier:      1.8,
		Jitter:          true,
		MaxRetries:      3,
	}

	var routingInfo *UserRoutingInfo
	var authResult AuthResult

	err := retry.WithRetryAdvanced(ctx, func() error {
		result, cbErr := c.breaker.Execute(func() (interface{}, error) {
			rows, err := c.pool.Query(ctx, c.query, email)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
					return nil, err
				}
				return nil, err
			}
			defer rows.Close()

			if !rows.Next() {
				return nil, pgx.ErrNoRows
			}

			// Auto-detect mode based on number of columns
			fieldDescs := rows.FieldDescriptions()
			numCols := len(fieldDescs)

			if numCols == 1 {
				// Single column: routing-only mode - just server address
				var serverAddr string
				err := rows.Scan(&serverAddr)
				if err != nil {
					return nil, err
				}

				log.Printf("[PreLookup] Auto-detected routing-only mode for user '%s'", email)
				normalizedAddr := c.normalizeServerAddress(serverAddr)
				info := &UserRoutingInfo{
					ServerAddress:          normalizedAddr,
					IsPrelookupAccount:     true,
					RemoteTLS:              c.remoteTLS,
					RemoteTLSVerify:        c.remoteTLSVerify,
					RemoteUseProxyProtocol: c.remoteUseProxyProtocol,
					RemoteUseIDCommand:     c.remoteUseIDCommand,
					RemoteUseXCLIENT:       c.remoteUseXCLIENT,
				}
				return map[string]interface{}{
					"mode":   "routing_only",
					"info":   info,
					"result": AuthSuccess,
				}, nil

			} else if numCols >= 2 {
				return c._handleAuthAndRoute(rows, email, password)
			}

			return nil, fmt.Errorf("unexpected number of columns: %d", numCols)
		})

		if cbErr != nil {
			if errors.Is(cbErr, pgx.ErrNoRows) || errors.Is(cbErr, sql.ErrNoRows) {
				routingInfo = nil
				authResult = AuthUserNotFound
				return retry.Stop(cbErr)
			}
			if isRetryableError(cbErr) {
				log.Printf("[PreLookup] Retrying auth query for '%s' due to: %v", email, cbErr)
				return cbErr
			}
			return retry.Stop(cbErr)
		}

		if result != nil {
			resultMap := result.(map[string]interface{})
			if resultMap["info"] != nil {
				routingInfo = resultMap["info"].(*UserRoutingInfo)
			} else {
				routingInfo = nil
			}
			authResult = resultMap["result"].(AuthResult)
		}
		return nil
	}, config)

	if err != nil && !errors.Is(err, pgx.ErrNoRows) && !errors.Is(err, sql.ErrNoRows) {
		log.Printf("[PreLookup] Query failed for user '%s': %v", email, err)
		return nil, AuthUserNotFound, fmt.Errorf("database query failed: %w", err)
	}

	// Cache the result
	c.cacheMutex.Lock()
	if authResult == AuthUserNotFound {
		c.cache[email] = &cacheEntry{
			info:      nil,
			timestamp: time.Now(),
			userFound: false,
		}
	} else if routingInfo != nil {
		c.cache[email] = &cacheEntry{
			info:      routingInfo,
			timestamp: time.Now(),
			userFound: true,
		}
	}
	c.cacheMutex.Unlock()

	return routingInfo, authResult, nil
}

// verifyPassword verifies a password against a hash using the same auth mechanisms as the main server
func (c *PreLookupClient) verifyPassword(password, hash string) bool {
	err := db.VerifyPassword(hash, password)
	if err != nil {
		log.Printf("[PreLookup] Password verification failed for hash '%s': %v", hash, err)
		return false
	}
	return true
}

// _handleAuthAndRoute processes a row for auth+route mode.
func (c *PreLookupClient) _handleAuthAndRoute(rows pgx.Rows, email, password string) (interface{}, error) {
	fieldDescs := rows.FieldDescriptions()
	numCols := len(fieldDescs)

	values := make([]interface{}, numCols)
	valuePtrs := make([]interface{}, numCols)
	for i := range values {
		valuePtrs[i] = &values[i]
	}

	err := rows.Scan(valuePtrs...)
	if err != nil {
		return nil, err
	}

	log.Printf("[PreLookup] Auto-detected auth+route mode for user '%s' (%d columns)", email, numCols)

	// Extract values - assume common patterns:
	// 2 cols: password_hash, server_address
	// 3+ cols: account_id, password_hash, server_address (last is server)
	var accountID int64
	var passwordHash, serverAddress string
	var ok bool

	if numCols == 2 {
		if values[0] == nil {
			log.Printf("[PreLookup] Authentication failed for user '%s': password_hash is NULL in prelookup result", email)
			return map[string]interface{}{"mode": "auth_and_route", "info": nil, "result": AuthFailed}, nil
		}
		passwordHash, ok = values[0].(string)
		if !ok {
			return nil, fmt.Errorf("prelookup query: expected column 1 (password_hash) to be a string, but got %T", values[0])
		}
		if strings.TrimSpace(passwordHash) == "" {
			log.Printf("[PreLookup] Authentication failed for user '%s': password_hash is empty in prelookup result", email)
			return map[string]interface{}{"mode": "auth_and_route", "info": nil, "result": AuthFailed}, nil
		}

		if values[1] == nil {
			log.Printf("[PreLookup] Authentication failed for user '%s': server_address is NULL in prelookup result", email)
			return map[string]interface{}{"mode": "auth_and_route", "info": nil, "result": AuthFailed}, nil
		}
		serverAddress, ok = values[1].(string)
		if !ok {
			return nil, fmt.Errorf("prelookup query: expected column 2 (server_address) to be a string, but got %T", values[1])
		}
		if strings.TrimSpace(serverAddress) == "" {
			log.Printf("[PreLookup] Authentication failed for user '%s': server_address is empty in prelookup result", email)
			return map[string]interface{}{"mode": "auth_and_route", "info": nil, "result": AuthFailed}, nil
		}
		// For 2-column mode, use a placeholder account ID since it's not provided
		accountID = -1 // Use -1 to distinguish from default 0
	} else { // 3+ columns
		if values[0] == nil {
			log.Printf("[PreLookup] Authentication failed for user '%s': account_id is NULL in prelookup result", email)
			return map[string]interface{}{"mode": "auth_and_route", "info": nil, "result": AuthFailed}, nil
		}
		accountID, ok = values[0].(int64)
		if !ok {
			return nil, fmt.Errorf("prelookup query: expected column 1 (account_id) to be an int64, but got %T", values[0])
		}
		if accountID <= 0 {
			log.Printf("[PreLookup] Authentication failed for user '%s': account_id is invalid (%d) in prelookup result", email, accountID)
			return map[string]interface{}{"mode": "auth_and_route", "info": nil, "result": AuthFailed}, nil
		}

		if values[1] == nil {
			log.Printf("[PreLookup] Authentication failed for user '%s': password_hash is NULL in prelookup result", email)
			return map[string]interface{}{"mode": "auth_and_route", "info": nil, "result": AuthFailed}, nil
		}
		passwordHash, ok = values[1].(string)
		if !ok {
			return nil, fmt.Errorf("prelookup query: expected column 2 (password_hash) to be a string, but got %T", values[1])
		}
		if strings.TrimSpace(passwordHash) == "" {
			log.Printf("[PreLookup] Authentication failed for user '%s': password_hash is empty in prelookup result", email)
			return map[string]interface{}{"mode": "auth_and_route", "info": nil, "result": AuthFailed}, nil
		}

		if values[numCols-1] == nil {
			log.Printf("[PreLookup] Authentication failed for user '%s': server_address is NULL in prelookup result", email)
			return map[string]interface{}{"mode": "auth_and_route", "info": nil, "result": AuthFailed}, nil
		}
		serverAddress, ok = values[numCols-1].(string)
		if !ok {
			return nil, fmt.Errorf("prelookup query: expected last column (server_address) to be a string, but got %T", values[numCols-1])
		}
		if strings.TrimSpace(serverAddress) == "" {
			log.Printf("[PreLookup] Authentication failed for user '%s': server_address is empty in prelookup result", email)
			return map[string]interface{}{"mode": "auth_and_route", "info": nil, "result": AuthFailed}, nil
		}
	}

	// Verify password
	if !c.verifyPassword(password, passwordHash) {
		log.Printf("[PreLookup] Authentication failed for user: %s", email)
		return map[string]interface{}{
			"mode":   "auth_and_route",
			"info":   nil,
			"result": AuthFailed,
		}, nil
	}

	log.Printf("[PreLookup] Authentication successful for user '%s'", email)
	normalizedAddr := c.normalizeServerAddress(serverAddress)
	info := &UserRoutingInfo{
		ServerAddress:          normalizedAddr,
		AccountID:              accountID,
		IsPrelookupAccount:     true,
		RemoteTLS:              c.remoteTLS,
		RemoteTLSVerify:        c.remoteTLSVerify,
		RemoteUseProxyProtocol: c.remoteUseProxyProtocol,
		RemoteUseIDCommand:     c.remoteUseIDCommand,
		RemoteUseXCLIENT:       c.remoteUseXCLIENT,
	}

	return map[string]interface{}{
		"mode":   "auth_and_route",
		"info":   info,
		"result": AuthSuccess,
	}, nil
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

// isRetryableError checks if an error is transient and the operation can be retried.
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Do not retry if the circuit breaker is open or the context is done.
	if errors.Is(err, circuitbreaker.ErrCircuitBreakerOpen) ||
		errors.Is(err, circuitbreaker.ErrTooManyRequests) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		// Check for PostgreSQL error codes that indicate transient issues.
		// See: https://www.postgresql.org/docs/current/errcodes-appendix.html
		switch pgErr.Code {
		// Class 40: Transaction Rollback (e.g., deadlock, serialization failure)
		case "40001", "40P01":
			return true
		// Class 53: Insufficient Resources (e.g., too many connections)
		case "53300":
			return true
		// Class 08: Connection Exception
		case "08000", "08001", "08003", "08004", "08006", "08007", "08P01":
			return true
		}
	}

	// Check for generic network errors that are temporary
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	return false
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
