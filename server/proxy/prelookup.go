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
	ActualEmail            string // Actual email address (without master token if present) - used for backend impersonation
	RemoteTLS              bool
	RemoteTLSUseStartTLS   bool // Use STARTTLS for backend connections
	RemoteTLSVerify        bool
	RemoteUseProxyProtocol bool
	RemoteUseIDCommand     bool // Use IMAP ID command for forwarding (IMAP only)
	RemoteUseXCLIENT       bool // Use XCLIENT command for forwarding (POP3/LMTP)
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
	remoteTLSUseStartTLS   bool // Use STARTTLS for backend connections
	remoteTLSVerify        bool
	remotePort             int
	remoteUseProxyProtocol bool
	remoteUseIDCommand     bool
	remoteUseXCLIENT       bool
	allowMasterToken       bool   // Enable master token authentication
	masterTokenSeparator   string // Separator for extracting master token from password
	stopJanitor            chan struct{}
	janitorWg              sync.WaitGroup // Wait for janitor to finish
	breaker                *circuitbreaker.CircuitBreaker
}

// normalizeHostPort ensures an address has a port, fixing malformed IPv6 addresses if necessary.
// If the address has no port, the defaultPort is added.
func normalizeHostPort(addr string, defaultPort int) string {
	if addr == "" {
		return ""
	}

	// net.SplitHostPort is the robust way to do this, as it correctly
	// handles IPv6 addresses like "[::1]:143".
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		// Address is already in a valid host:port format.
		// Re-join to ensure canonical format (e.g., for IPv6).
		return net.JoinHostPort(host, port)
	}

	// If parsing fails, it could be because:
	// 1. It's a host without a port (e.g., "localhost", "2001:db8::1").
	// 2. It's a malformed IPv6 with a port but no brackets (e.g., "2001:db8::1:143").

	// Let's test for case #2. This is a heuristic.
	// An IPv6 address will have more than one colon.
	if strings.Count(addr, ":") > 1 {
		lastColon := strings.LastIndex(addr, ":")
		// Assume the part after the last colon is the port.
		if lastColon != -1 && lastColon < len(addr)-1 {
			hostPart := addr[:lastColon]
			portPart := addr[lastColon+1:]

			// Check if the parts look like a valid IP and port.
			if net.ParseIP(hostPart) != nil {
				if _, pErr := strconv.Atoi(portPart); pErr == nil {
					// This looks like a valid but malformed IPv6:port. Fix it.
					fixedAddr := net.JoinHostPort(hostPart, portPart)
					log.Printf("[PreLookup] Corrected malformed IPv6 address '%s' to '%s'", addr, fixedAddr)
					return fixedAddr
				}
			}
		}
	}

	// If we're here, it's most likely case #1: a host without a port.
	// Add the default port if one is configured.
	if defaultPort > 0 {
		return net.JoinHostPort(addr, strconv.Itoa(defaultPort))
	}

	// No default port to add, and we couldn't fix it, so return as is.
	return addr
}

// normalizeServerAddress adds the default port to a server address if no port is specified
func (c *PreLookupClient) normalizeServerAddress(addr string) string {
	normalized := normalizeHostPort(addr, c.remotePort)
	if normalized != addr {
		log.Printf("[PreLookup] Normalized server address '%s' to '%s'", addr, normalized)
	}
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
	query := config.Query
	if query == "" {
		return nil, errors.New("prelookup query is not configured")
	}

	// Handle TLS settings for prelookup-routed connections
	remoteTLSVerify := true
	if config.RemoteTLSVerify != nil {
		remoteTLSVerify = *config.RemoteTLSVerify
	}
	log.Printf("[PreLookup] TLS configuration: RemoteTLS=%t, RemoteTLSUseStartTLS=%t, RemoteTLSVerify=%t (config.RemoteTLSVerify=%v)", config.RemoteTLS, config.RemoteTLSUseStartTLS, remoteTLSVerify, config.RemoteTLSVerify)

	// Log warning if StartTLS is configured (it's only supported for LMTP and ManageSieve proxies)
	if config.RemoteTLSUseStartTLS {
		log.Printf("[PreLookup] WARNING: remote_tls_use_starttls is enabled. This setting only affects LMTP and ManageSieve proxies. IMAP and POP3 proxies use implicit TLS and will ignore this setting.")
	}

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

		// Determine the default port to use if the host doesn't specify one.
		defaultPort := 5432 // Default PostgreSQL port
		if config.Port != nil {
			var p int64
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
			defaultPort = int(p)
		}
		if defaultPort <= 0 || defaultPort > 65535 {
			return nil, fmt.Errorf("port number %d is out of the valid range (1-65535)", defaultPort)
		}
		host = normalizeHostPort(host, defaultPort)

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

	// Set default master token separator if enabled but not specified
	masterTokenSeparator := config.MasterTokenSeparator
	if config.AllowMasterToken && masterTokenSeparator == "" {
		masterTokenSeparator = "@"
	}

	client := &PreLookupClient{
		pool:                   pool,
		query:                  query,
		cacheTTL:               cacheTTL,
		cache:                  make(map[string]*cacheEntry),
		fallbackMode:           config.FallbackDefault,
		remoteTLS:              config.RemoteTLS,
		remoteTLSUseStartTLS:   config.RemoteTLSUseStartTLS,
		remoteTLSVerify:        remoteTLSVerify,
		remotePort:             remotePort,
		remoteUseProxyProtocol: config.RemoteUseProxyProtocol,
		remoteUseIDCommand:     config.RemoteUseIDCommand,
		remoteUseXCLIENT:       config.RemoteUseXCLIENT,
		allowMasterToken:       config.AllowMasterToken,
		masterTokenSeparator:   masterTokenSeparator,
		stopJanitor:            make(chan struct{}),
		breaker:                circuitbreaker.NewCircuitBreaker(breakerSettings),
	}

	// Log the configuration for debugging
	log.Printf("[PreLookup] Initialized with auto-detect mode, unified auth (supports SSHA512, SHA512, bcrypt, BLF-CRYPT), cache_ttl=%v", cacheTTL)
	log.Printf("[PreLookup] Query: %s", query)
	if client.allowMasterToken {
		log.Printf("[PreLookup] Master token authentication enabled with separator: %q", client.masterTokenSeparator)
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
			rows, err := c.pool.Query(ctx, c.query, email)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
					return nil, retry.Stop(err)
				}
				return nil, err
			}
			defer rows.Close()

			if !rows.Next() {
				return nil, retry.Stop(pgx.ErrNoRows)
			}

			// Get field descriptions to build column name map
			fieldDescs := rows.FieldDescriptions()
			numCols := len(fieldDescs)

			// Build column name to index map
			colMap := make(map[string]int)
			for i, fd := range fieldDescs {
				colMap[strings.ToLower(string(fd.Name))] = i
			}

			// Scan all values
			values := make([]interface{}, numCols)
			valuePtrs := make([]interface{}, numCols)
			for i := range values {
				valuePtrs[i] = &values[i]
			}
			if err := rows.Scan(valuePtrs...); err != nil {
				return nil, err
			}

			// Extract named columns
			result := map[string]string{"server": "", "resolved": ""}

			// Try common column names for server address
			serverIdx := -1
			for _, name := range []string{"server_address", "server", "address"} {
				if idx, ok := colMap[name]; ok {
					serverIdx = idx
					break
				}
			}

			// If no named server column found, use last column as fallback
			if serverIdx == -1 {
				serverIdx = numCols - 1
			}

			if values[serverIdx] != nil {
				if addr, ok := values[serverIdx].(string); ok {
					result["server"] = addr
				}
			}

			// Try to find resolved_address column
			resolvedIdx := -1
			for _, name := range []string{"resolved_address", "resolved"} {
				if idx, ok := colMap[name]; ok {
					resolvedIdx = idx
					break
				}
			}

			if resolvedIdx != -1 && values[resolvedIdx] != nil {
				if addr, ok := values[resolvedIdx].(string); ok && strings.TrimSpace(addr) != "" {
					result["resolved"] = addr
				}
			}

			return result, nil
		})

		if cbErr != nil {
			// Handle ErrNoRows: already wrapped with retry.Stop() inside circuit breaker
			if errors.Is(cbErr, pgx.ErrNoRows) || errors.Is(cbErr, sql.ErrNoRows) {
				serverAddress = "" // Explicitly clear it
				return cbErr       // Already wrapped with retry.Stop() inside circuit breaker
			}
			if isRetryableError(cbErr) {
				log.Printf("[PreLookup] Retrying routing query for '%s' due to: %v", email, cbErr)
				return cbErr // Signal to retry
			}
			return retry.Stop(cbErr) // Non-retryable error
		}

		if result != nil {
			addrMap := result.(map[string]string)
			serverAddress = addrMap["server"]
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
		RemoteTLSUseStartTLS:   c.remoteTLSUseStartTLS,
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
					return nil, retry.Stop(err)
				}
				return nil, err
			}
			defer rows.Close()

			if !rows.Next() {
				return nil, retry.Stop(pgx.ErrNoRows)
			}

			fieldDescs := rows.FieldDescriptions()
			numCols := len(fieldDescs)

			// Special case: single unnamed column is treated as server_address (routing-only mode)
			// This is for backward compatibility with simple queries like "SELECT server FROM ..."
			if numCols == 1 {
				var serverAddr string
				err := rows.Scan(&serverAddr)
				if err != nil {
					return nil, err
				}

				log.Printf("[PreLookup] Routing-only mode for user '%s' (single column)", email)
				normalizedAddr := c.normalizeServerAddress(serverAddr)
				info := &UserRoutingInfo{
					ServerAddress:          normalizedAddr,
					IsPrelookupAccount:     true,
					RemoteTLS:              c.remoteTLS,
					RemoteTLSUseStartTLS:   c.remoteTLSUseStartTLS,
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
			}

			// For 2+ columns, use named column detection
			// The actual mode (routing vs auth+route) is determined by which named columns are present
			return c._handleAuthAndRoute(rows, email, password)
		})

		if cbErr != nil {
			if isRetryableError(cbErr) {
				log.Printf("[PreLookup] Retrying auth query for '%s' due to: %v", email, cbErr)
				return cbErr
			}
			// For non-retryable errors (including ErrNoRows wrapped in retry.Stop),
			// stop the retry loop.
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
	} else if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
		// User not found is an expected outcome, not an error to return.
		authResult = AuthUserNotFound
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

// splitEmailAndToken splits an email that may contain a master token
// Returns: (actualEmail, extractedToken, hasMasterToken)
// Example: "user@domain.com@MASTERTOKEN" with separator "@" -> ("user@domain.com", "MASTERTOKEN", true)
// IMPORTANT: The token must not contain the separator itself. We use the LAST occurrence
// to split, and the extracted token must not contain any more separators.
// Special handling for @ separator: requires at least 3 parts (user@domain@token) to avoid
// splitting normal email addresses.
func (c *PreLookupClient) splitEmailAndToken(email string) (string, string, bool) {
	if !c.allowMasterToken || c.masterTokenSeparator == "" {
		return email, "", false
	}

	// Special case for @ separator: need at least 3 parts (user, domain, token)
	// to distinguish from normal email address user@domain
	if c.masterTokenSeparator == "@" {
		parts := strings.Count(email, "@")
		if parts < 2 {
			// Not enough @ symbols for email@TOKEN pattern
			return email, "", false
		}
	}

	// Find the last occurrence of the separator
	idx := strings.LastIndex(email, c.masterTokenSeparator)
	if idx == -1 {
		// No separator found, treat as regular email
		return email, "", false
	}

	// Split at the last separator
	actualEmail := email[:idx]
	token := email[idx+len(c.masterTokenSeparator):]

	// If token is empty, treat as regular email
	if token == "" {
		return email, "", false
	}

	// IMPORTANT: Token must not contain the separator
	// This prevents attacks like "user@domain@token@anotherseparator"
	if strings.Contains(token, c.masterTokenSeparator) {
		log.Printf("[PreLookup] Master token contains separator %q, rejecting", c.masterTokenSeparator)
		return email, "", false
	}

	return actualEmail, token, true
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

	// Build column name to index map
	colMap := make(map[string]int)
	for i, fd := range fieldDescs {
		colMap[strings.ToLower(string(fd.Name))] = i
	}

	values := make([]interface{}, numCols)
	valuePtrs := make([]interface{}, numCols)
	for i := range values {
		valuePtrs[i] = &values[i]
	}

	err := rows.Scan(valuePtrs...)
	if err != nil {
		return nil, err
	}

	log.Printf("[PreLookup] Processing auth+route mode for user '%s'", email)

	// Extract named columns
	var accountID int64 = -1 // Default for 2-column mode
	var passwordHash, serverAddress string

	// Try to find account_id column
	if idx, ok := colMap["account_id"]; ok {
		if values[idx] != nil {
			if id, ok := values[idx].(int64); ok && id > 0 {
				accountID = id
			} else {
				log.Printf("[PreLookup] Authentication failed for user '%s': account_id is invalid in prelookup result", email)
				return map[string]interface{}{"mode": "auth_and_route", "info": nil, "result": AuthFailed}, nil
			}
		}
	}

	// Try to find password_hash column (required)
	passwordIdx := -1
	for _, name := range []string{"password_hash", "password"} {
		if idx, ok := colMap[name]; ok {
			passwordIdx = idx
			break
		}
	}
	if passwordIdx == -1 {
		return nil, fmt.Errorf("prelookup query: password_hash column not found")
	}
	if values[passwordIdx] == nil {
		log.Printf("[PreLookup] Authentication failed for user '%s': password_hash is NULL in prelookup result", email)
		return map[string]interface{}{"mode": "auth_and_route", "info": nil, "result": AuthFailed}, nil
	}
	var ok bool
	passwordHash, ok = values[passwordIdx].(string)
	if !ok {
		return nil, fmt.Errorf("prelookup query: expected password_hash to be a string, but got %T", values[passwordIdx])
	}
	passwordHash = strings.TrimSpace(passwordHash)
	if passwordHash == "" {
		log.Printf("[PreLookup] Authentication failed for user '%s': password_hash is empty in prelookup result", email)
		return map[string]interface{}{"mode": "auth_and_route", "info": nil, "result": AuthFailed}, nil
	}

	// Try to find server_address column (required)
	serverIdx := -1
	for _, name := range []string{"server_address", "server", "address"} {
		if idx, ok := colMap[name]; ok {
			serverIdx = idx
			break
		}
	}
	if serverIdx == -1 {
		return nil, fmt.Errorf("prelookup query: server_address column not found")
	}
	if values[serverIdx] == nil {
		log.Printf("[PreLookup] Authentication failed for user '%s': server_address is NULL in prelookup result", email)
		return map[string]interface{}{"mode": "auth_and_route", "info": nil, "result": AuthFailed}, nil
	}
	serverAddress, ok = values[serverIdx].(string)
	if !ok {
		return nil, fmt.Errorf("prelookup query: expected server_address to be a string, but got %T", values[serverIdx])
	}
	if strings.TrimSpace(serverAddress) == "" {
		log.Printf("[PreLookup] Authentication failed for user '%s': server_address is empty in prelookup result", email)
		return map[string]interface{}{"mode": "auth_and_route", "info": nil, "result": AuthFailed}, nil
	}

	// Try to find actual_email column (optional) - allows database to override email resolution
	// This is useful for alias resolution: alias@domain@TOKEN -> realuser@domain
	actualEmailFromDB := ""
	if idx, ok := colMap["actual_email"]; ok {
		if idx != -1 && values[idx] != nil {
			if email, ok := values[idx].(string); ok && strings.TrimSpace(email) != "" {
				actualEmailFromDB = strings.TrimSpace(email)
			}
		}
	}

	// Check for master token authentication
	// If master token is enabled and present in email, extract it
	actualEmail, masterToken, hasMasterToken := c.splitEmailAndToken(email)

	// If database provided an actual_email, use it (for alias resolution)
	if actualEmailFromDB != "" {
		actualEmail = actualEmailFromDB
		log.Printf("[PreLookup] Database provided actual email: '%s' (from input: '%s')", actualEmail, email)
	}

	// The database query should have been called with the ORIGINAL email (possibly including @TOKEN)
	// and should return the appropriate password_hash (either user's or master's)
	// We verify the password/token against the returned hash
	var credentialToVerify string
	var hashPrefix string
	if len(passwordHash) > 30 {
		hashPrefix = passwordHash[:30] + "..."
	} else {
		hashPrefix = passwordHash
	}

	if hasMasterToken {
		credentialToVerify = masterToken
		log.Printf("[PreLookup] Attempting master token authentication for user '%s' (actual: '%s', token length: %d, hash: %s)", email, actualEmail, len(masterToken), hashPrefix)
	} else {
		credentialToVerify = password
		log.Printf("[PreLookup] Attempting password authentication for user '%s' (password length: %d, hash: %s)", email, len(password), hashPrefix)
	}

	// Verify password/token against the hash returned by the database
	if !c.verifyPassword(credentialToVerify, passwordHash) {
		if hasMasterToken {
			log.Printf("[PreLookup] Master token authentication failed for user '%s'", email)
		} else {
			log.Printf("[PreLookup] Authentication failed for user: %s", email)
		}
		return map[string]interface{}{
			"mode":   "auth_and_route",
			"info":   nil,
			"result": AuthFailed,
		}, nil
	}

	if hasMasterToken {
		log.Printf("[PreLookup] Master token authentication successful for user '%s' (actual: '%s')", email, actualEmail)
	} else {
		log.Printf("[PreLookup] Authentication successful for user '%s'", email)
	}
	normalizedAddr := c.normalizeServerAddress(serverAddress)
	info := &UserRoutingInfo{
		ServerAddress:          normalizedAddr,
		AccountID:              accountID,
		IsPrelookupAccount:     true,
		ActualEmail:            actualEmail, // Set the actual email without token
		RemoteTLS:              c.remoteTLS,
		RemoteTLSUseStartTLS:   c.remoteTLSUseStartTLS,
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

	c.janitorWg.Add(1)
	go func() {
		defer c.janitorWg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				c.cleanupCache()
			case <-c.stopJanitor:
				log.Printf("[PreLookup] Cache janitor stopped")
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
			// Wait for janitor to finish before closing the pool
			log.Printf("[PreLookup] Waiting for cache janitor to finish...")
			c.janitorWg.Wait()
			log.Printf("[PreLookup] Cache janitor finished")
		}
		c.pool.Close()
	}
	return nil
}

// HealthCheck performs a health check on the prelookup database
func (c *PreLookupClient) HealthCheck(ctx context.Context) error {
	if c.pool == nil {
		return fmt.Errorf("prelookup database pool is nil")
	}
	return c.pool.Ping(ctx)
}

// GetCircuitBreaker returns the circuit breaker for health monitoring
func (c *PreLookupClient) GetCircuitBreaker() *circuitbreaker.CircuitBreaker {
	return c.breaker
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
