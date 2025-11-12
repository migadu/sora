package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/circuitbreaker"
	"github.com/migadu/sora/server"
)

// HTTP transport timeout defaults for prelookup client
// These control different phases of HTTP connection establishment and request lifecycle
const (
	// DefaultDialTimeout is the maximum time to establish a TCP connection (includes DNS resolution)
	// Typical values: DNS 100-500ms, TCP handshake 10-100ms
	// We set this to 10s to handle slow DNS and high-latency networks (100x typical)
	DefaultDialTimeout = 10 * time.Second

	// DefaultTLSHandshakeTimeout is the maximum time for TLS handshake to complete
	// Typical values: 50-300ms for TLS 1.3, 100-500ms for TLS 1.2
	// We set this to 10s to handle high-latency networks and slow servers (20-50x typical)
	DefaultTLSHandshakeTimeout = 10 * time.Second

	// DefaultExpectContinueTimeout limits time waiting for server's first response headers
	// after sending request headers (for 100-continue responses)
	// This should be short as it's just a protocol-level acknowledgment
	DefaultExpectContinueTimeout = 1 * time.Second

	// DefaultKeepAlive is the interval for TCP keep-alive probes on idle connections
	// Helps detect broken connections and prevent NAT/firewall timeouts
	DefaultKeepAlive = 30 * time.Second
)

// HTTPPreLookupClient performs user routing lookups via HTTP GET requests
type HTTPPreLookupClient struct {
	baseURL                string
	timeout                time.Duration
	authToken              string // Bearer token for HTTP authentication
	client                 *http.Client
	breaker                *circuitbreaker.CircuitBreaker
	cache                  *prelookupCache // In-memory cache for lookup results
	remotePort             int             // Default port for backend connections when not in server address
	remoteTLS              bool
	remoteTLSUseStartTLS   bool
	remoteTLSVerify        bool
	remoteUseProxyProtocol bool
	remoteUseIDCommand     bool
	remoteUseXCLIENT       bool
	dialTimeout            time.Duration // Stored for timeout calculation
	tlsHandshakeTimeout    time.Duration // Stored for timeout calculation
}

// HTTPPreLookupResponse represents the JSON response from the HTTP prelookup endpoint
type HTTPPreLookupResponse struct {
	Address      string `json:"address"`       // Email address for the user (required - used to derive account_id)
	PasswordHash string `json:"password_hash"` // Password hash to verify against (required)
	Server       string `json:"server"`        // Backend server IP/hostname:port (optional - if empty, uses auth-only mode)
	AccountID    int64  // Derived from Address, not part of JSON response
	AuthOnlyMode bool   // Internal flag: true when Server is empty (auth-only, local backend selection)
}

// CircuitBreakerSettings holds configurable circuit breaker settings
type CircuitBreakerSettings struct {
	MaxRequests  uint32        // Maximum concurrent requests in half-open state
	Interval     time.Duration // Time before resetting failure counts in closed state
	Timeout      time.Duration // Time before transitioning from open to half-open
	FailureRatio float64       // Failure ratio threshold to open circuit (0.0-1.0)
	MinRequests  uint32        // Minimum requests before evaluating failure ratio
}

// TransportSettings holds HTTP transport configuration for connection pooling and timeouts
type TransportSettings struct {
	MaxIdleConns          int           // Maximum idle connections across all hosts
	MaxIdleConnsPerHost   int           // Maximum idle connections per host
	MaxConnsPerHost       int           // Maximum total connections per host (0 = unlimited)
	IdleConnTimeout       time.Duration // How long idle connections stay open
	DialTimeout           time.Duration // TCP connection timeout (includes DNS)
	TLSHandshakeTimeout   time.Duration // TLS handshake timeout
	ExpectContinueTimeout time.Duration // 100-continue timeout
	KeepAlive             time.Duration // TCP keep-alive interval
}

// NewHTTPPreLookupClient creates a new HTTP-based prelookup client
func NewHTTPPreLookupClient(
	baseURL string,
	timeout time.Duration,
	authToken string,
	remotePort int,
	remoteTLS bool,
	remoteTLSUseStartTLS bool,
	remoteTLSVerify bool,
	remoteUseProxyProtocol bool,
	remoteUseIDCommand bool,
	remoteUseXCLIENT bool,
	cache *prelookupCache,
	cbSettings *CircuitBreakerSettings,
	transportSettings *TransportSettings,
) *HTTPPreLookupClient {
	// Apply defaults if settings not provided
	if cbSettings == nil {
		cbSettings = &CircuitBreakerSettings{
			MaxRequests:  3,
			Interval:     0, // Never reset automatically
			Timeout:      30 * time.Second,
			FailureRatio: 0.6,
			MinRequests:  3,
		}
	}

	// Create circuit breaker with configured settings
	settings := circuitbreaker.Settings{
		Name:        "http-prelookup",
		MaxRequests: cbSettings.MaxRequests,
		Interval:    cbSettings.Interval,
		Timeout:     cbSettings.Timeout,
	}

	// Capture values for closure
	failureRatio := cbSettings.FailureRatio
	minRequests := cbSettings.MinRequests

	settings.ReadyToTrip = func(counts circuitbreaker.Counts) bool {
		// Open circuit if failure ratio exceeds threshold
		ratio := float64(counts.TotalFailures) / float64(counts.Requests)
		return counts.Requests >= minRequests && ratio >= failureRatio
	}
	settings.OnStateChange = func(name string, from circuitbreaker.State, to circuitbreaker.State) {
		logger.Warn("Prelookup circuit breaker state changed", "name", name, "from", from, "to", to)
	}
	breaker := circuitbreaker.NewCircuitBreaker(settings)
	logger.Info("Initialized prelookup circuit breaker", "max_requests", cbSettings.MaxRequests, "timeout", cbSettings.Timeout, "failure_ratio", fmt.Sprintf("%.0f%%", cbSettings.FailureRatio*100), "min_requests", cbSettings.MinRequests)

	// Apply defaults for transport settings if not provided
	if transportSettings == nil {
		transportSettings = &TransportSettings{
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   100,
			MaxConnsPerHost:       0,
			IdleConnTimeout:       90 * time.Second,
			DialTimeout:           DefaultDialTimeout,
			TLSHandshakeTimeout:   DefaultTLSHandshakeTimeout,
			ExpectContinueTimeout: DefaultExpectContinueTimeout,
			KeepAlive:             DefaultKeepAlive,
		}
	}

	// Apply defaults for zero-value timeout fields
	if transportSettings.DialTimeout == 0 {
		transportSettings.DialTimeout = DefaultDialTimeout
	}
	if transportSettings.TLSHandshakeTimeout == 0 {
		transportSettings.TLSHandshakeTimeout = DefaultTLSHandshakeTimeout
	}
	if transportSettings.ExpectContinueTimeout == 0 {
		transportSettings.ExpectContinueTimeout = DefaultExpectContinueTimeout
	}
	if transportSettings.KeepAlive == 0 {
		transportSettings.KeepAlive = DefaultKeepAlive
	}

	// Configure HTTP transport with connection pooling for high concurrency
	// Create a custom dialer with timeout for TCP connection establishment
	dialer := &net.Dialer{
		Timeout:   transportSettings.DialTimeout, // Time to establish TCP connection (includes DNS)
		KeepAlive: transportSettings.KeepAlive,   // TCP keep-alive interval
	}

	transport := &http.Transport{
		DialContext:         dialer.DialContext, // Use custom dialer with timeout
		MaxIdleConns:        transportSettings.MaxIdleConns,
		MaxIdleConnsPerHost: transportSettings.MaxIdleConnsPerHost,
		MaxConnsPerHost:     transportSettings.MaxConnsPerHost,
		IdleConnTimeout:     transportSettings.IdleConnTimeout,
		DisableKeepAlives:   false, // Enable keep-alives for connection reuse
		DisableCompression:  false, // Enable compression
		ForceAttemptHTTP2:   true,  // Try HTTP/2 if available
		// Separate timeouts for different phases of connection establishment
		// This allows connection reuse to work while giving more time for initial setup
		TLSHandshakeTimeout:   transportSettings.TLSHandshakeTimeout,   // TLS handshake can take time, especially for slow networks
		ResponseHeaderTimeout: timeout,                                 // Response headers should arrive within configured timeout
		ExpectContinueTimeout: transportSettings.ExpectContinueTimeout, // Don't wait long for 100-continue
	}

	logger.Info("prelookup: Initialized HTTP transport", "max_idle_conns", transportSettings.MaxIdleConns, "max_idle_conns_per_host", transportSettings.MaxIdleConnsPerHost, "max_conns_per_host", transportSettings.MaxConnsPerHost, "idle_conn_timeout", transportSettings.IdleConnTimeout, "dial_timeout", transportSettings.DialTimeout, "tls_handshake_timeout", transportSettings.TLSHandshakeTimeout, "keep_alive", transportSettings.KeepAlive, "response_header_timeout", timeout)

	return &HTTPPreLookupClient{
		baseURL:   baseURL,
		timeout:   timeout,
		authToken: authToken,
		client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
		breaker:                breaker,
		cache:                  cache,
		remotePort:             remotePort,
		remoteTLS:              remoteTLS,
		remoteTLSUseStartTLS:   remoteTLSUseStartTLS,
		remoteTLSVerify:        remoteTLSVerify,
		remoteUseProxyProtocol: remoteUseProxyProtocol,
		remoteUseIDCommand:     remoteUseIDCommand,
		remoteUseXCLIENT:       remoteUseXCLIENT,
		dialTimeout:            transportSettings.DialTimeout,
		tlsHandshakeTimeout:    transportSettings.TLSHandshakeTimeout,
	}
}

// LookupUserRoute performs an HTTP GET request to lookup user routing information
func (c *HTTPPreLookupClient) LookupUserRoute(ctx context.Context, email, password string) (*UserRoutingInfo, AuthResult, error) {
	return c.LookupUserRouteWithClientIP(ctx, email, password, "", false)
}

// LookupUserRouteWithOptions performs prelookup with optional route-only mode
// routeOnly: if true, adds ?route_only=true to skip password validation (for master username auth)
func (c *HTTPPreLookupClient) LookupUserRouteWithOptions(ctx context.Context, email, password string, routeOnly bool) (*UserRoutingInfo, AuthResult, error) {
	return c.LookupUserRouteWithClientIP(ctx, email, password, "", routeOnly)
}

// LookupUserRouteWithClientIP performs prelookup with client IP and optional route-only mode
// clientIP: client IP address to include in URL (supports $ip placeholder)
// routeOnly: if true, adds ?route_only=true to skip password validation (for master username auth)
func (c *HTTPPreLookupClient) LookupUserRouteWithClientIP(ctx context.Context, email, password, clientIP string, routeOnly bool) (*UserRoutingInfo, AuthResult, error) {
	// Parse and validate email address with master token support
	// This also handles +detail addressing and validates format
	addr, err := server.NewAddress(email)
	if err != nil {
		logger.Info("prelookup: Invalid email format", "error", err)
		return nil, AuthFailed, nil
	}

	// For prelookup, use MasterAddress (base address + master token, without +detail)
	// This ensures:
	//   - user+tag@example.com and user@example.com authenticate the same way
	//   - user@example.com@TOKEN passes the master token to prelookup
	//   - user+tag@example.com@TOKEN strips +tag but keeps @TOKEN
	lookupEmail := addr.MasterAddress()

	// Use base address (without master token) for caching and authentication
	authEmail := addr.BaseAddress()

	// Log if we stripped +detail addressing
	if addr.Detail() != "" {
		logger.Debug("prelookup: Stripping +detail for authentication", "from", email, "to", lookupEmail)
	}

	// Cache key is just the email address (base address without +detail or @TOKEN)
	cacheKey := authEmail

	// Check cache first - atomically get both password hash and entry to avoid race condition
	if c.cache != nil {
		cachedHash, info, authResult, found := c.cache.GetWithPasswordHash(cacheKey)
		if found {
			// Verify submitted password against cached hash
			if c.verifyPassword(password, cachedHash) {
				// Password matches cached hash - return cached result
				logger.Info("Prelookup cache HIT - password verified against cached hash", "user", authEmail)
				// Mark as from cache if we have routing info
				if info != nil {
					info.FromCache = true
				}
				return info, authResult, nil
			} else {
				// Password doesn't match cached hash - fall through to fresh prelookup
				// DO NOT delete cache here! Concurrent wrong password attempts should not
				// invalidate cache for other threads. We'll update cache only if prelookup succeeds.
				hashPrefix := cachedHash
				if len(hashPrefix) > 30 {
					hashPrefix = hashPrefix[:30] + "..."
				}
				logger.Info("Prelookup cache STALE - password mismatch, verifying with prelookup", "user", authEmail, "cached_hash_prefix", hashPrefix)
				// Note: We intentionally do NOT call c.cache.Delete(cacheKey) here
			}
		} else {
			logger.Debug("Prelookup cache MISS - no cached entry", "user", authEmail)
		}
	}

	// Execute HTTP request through circuit breaker
	result, err := c.breaker.Execute(func() (any, error) {
		// Build request URL by interpolating placeholders:
		// - $email: user email (MasterAddress - includes master token but not +detail)
		// - $ip: client IP address
		requestURL := strings.ReplaceAll(c.baseURL, "$email", url.QueryEscape(lookupEmail))
		if clientIP != "" {
			requestURL = strings.ReplaceAll(requestURL, "$ip", url.QueryEscape(clientIP))
		}

		// Add route_only parameter if requested (for master username authentication)
		if routeOnly {
			// Check if URL already has query parameters
			if strings.Contains(requestURL, "?") {
				requestURL += "&route_only=true"
			} else {
				requestURL += "?route_only=true"
			}
		}

		logger.Debug("prelookup: Requesting lookup", "user", lookupEmail, "client_ip", clientIP, "url", requestURL, "route_only", routeOnly)

		// Make HTTP request
		req, err := http.NewRequestWithContext(ctx, "GET", requestURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		// Add Bearer token authentication if configured
		if c.authToken != "" {
			req.Header.Set("Authorization", "Bearer "+c.authToken)
		}

		resp, err := c.client.Do(req)
		if err != nil {
			// Check if error is due to context cancellation (server shutdown)
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				logger.Info("prelookup: Request cancelled due to context cancellation (server shutdown)")
				// Return temporarily unavailable to avoid penalizing as auth failure
				// Wrap server.ErrServerShuttingDown with ErrPrelookupTransient so it flows correctly
				return nil, fmt.Errorf("%w: %w", ErrPrelookupTransient, server.ErrServerShuttingDown)
			}
			// Network error - this is transient
			return nil, fmt.Errorf("%w: HTTP request failed: %v", ErrPrelookupTransient, err)
		}
		defer resp.Body.Close()

		// Check status code first - for error responses, status code is all we need
		// Don't waste time reading/parsing body for non-200 responses
		if resp.StatusCode == http.StatusNotFound {
			logger.Debug("prelookup: User not found (404)", "user", lookupEmail)
			return map[string]any{"result": AuthUserNotFound}, nil
		}

		// 401 Unauthorized and 403 Forbidden mean authentication failed (user exists but access denied)
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			logger.Debug("prelookup: Authentication failed", "status", resp.StatusCode, "user", lookupEmail)
			return map[string]any{"result": AuthFailed}, nil
		}

		// Other 4xx errors mean user lookup failed - treat as user not found to allow fallback
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			logger.Debug("prelookup: Client error - treating as user not found", "status", resp.StatusCode, "user", lookupEmail)
			return map[string]any{"result": AuthUserNotFound}, nil
		}

		// 5xx errors are transient - fallback controlled by config
		if resp.StatusCode >= 500 {
			logger.Warn("prelookup: Server error", "status", resp.StatusCode, "user", lookupEmail)
			return nil, fmt.Errorf("%w: server error %d", ErrPrelookupTransient, resp.StatusCode)
		}

		// Non-200 2xx responses - treat as transient
		if resp.StatusCode != http.StatusOK {
			logger.Warn("prelookup: Unexpected status", "status", resp.StatusCode, "user", lookupEmail)
			return nil, fmt.Errorf("%w: unexpected status code: %d", ErrPrelookupTransient, resp.StatusCode)
		}

		// Only read and parse body for 200 OK responses
		bodyBytes, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			logger.Warn("prelookup: Failed to read response body", "user", lookupEmail, "error", readErr)
			return nil, fmt.Errorf("%w: failed to read response body: %v", ErrPrelookupTransient, readErr)
		}

		// Parse JSON response - if this fails on a 200 response, it's a server bug
		var lookupResp HTTPPreLookupResponse
		if err := json.Unmarshal(bodyBytes, &lookupResp); err != nil {
			logger.Warn("prelookup: Failed to parse JSON", "user", lookupEmail, "error", err, "body", string(bodyBytes))
			return nil, fmt.Errorf("%w: failed to parse JSON response: %v", ErrPrelookupInvalidResponse, err)
		}

		// Validate required fields - invalid 200 response is a server bug
		if strings.TrimSpace(lookupResp.Address) == "" {
			logger.Warn("prelookup: Validation failed - address is empty", "user", lookupEmail)
			return nil, fmt.Errorf("%w: address is empty in response", ErrPrelookupInvalidResponse)
		}
		// Only validate password_hash if NOT route_only mode
		// In route_only mode (master username auth), password already validated locally
		if !routeOnly && strings.TrimSpace(lookupResp.PasswordHash) == "" {
			logger.Warn("prelookup: Validation failed - password_hash is empty", "user", lookupEmail)
			return nil, fmt.Errorf("%w: password_hash is empty in response", ErrPrelookupInvalidResponse)
		}

		// If server is null/empty, this is auth-only mode (prelookup handles authentication,
		// Sora handles backend selection via affinity/consistent-hash/round-robin)
		// We mark this with a special flag in the response so it can be processed differently
		if strings.TrimSpace(lookupResp.Server) == "" {
			logger.Debug("prelookup: Server is null/empty - auth-only mode (local backend selection)", "user", lookupEmail)
			lookupResp.AuthOnlyMode = true
		}

		// Derive account_id from the address field
		lookupResp.AccountID = deriveAccountIDFromEmail(lookupResp.Address)
		logger.Debug("prelookup: Derived account_id from address", "address", lookupResp.Address, "account_id", lookupResp.AccountID)

		return lookupResp, nil
	})

	// Handle circuit breaker errors
	if err != nil {
		if err == circuitbreaker.ErrCircuitBreakerOpen {
			logger.Warn("prelookup: Circuit breaker is open", "url", c.baseURL)
			// Circuit breaker open is a transient error - return temporarily unavailable
			return nil, AuthTemporarilyUnavailable, fmt.Errorf("%w: circuit breaker open: too many failures", ErrPrelookupTransient)
		}
		if err == circuitbreaker.ErrTooManyRequests {
			logger.Warn("prelookup: Circuit breaker is half-open - rate limiting requests", "url", c.baseURL)
			// Too many requests in half-open state is also a transient error - return temporarily unavailable
			return nil, AuthTemporarilyUnavailable, fmt.Errorf("%w: circuit breaker half-open: too many concurrent requests", ErrPrelookupTransient)
		}
		// Check if this is a transient error or invalid response
		if errors.Is(err, ErrPrelookupTransient) {
			// Transient errors (network, timeout, 5xx) - temporarily unavailable
			return nil, AuthTemporarilyUnavailable, err
		}
		// Invalid response errors (malformed 2xx) - authentication failed
		return nil, AuthFailed, err
	}

	// Handle special auth result cases (user not found, auth failed)
	if resultMap, ok := result.(map[string]any); ok {
		if authResult, ok := resultMap["result"].(AuthResult); ok {
			if authResult == AuthUserNotFound {
				// Don't cache user not found - these should always go to prelookup
				// This prevents issues with user creation between cache checks
				return nil, AuthUserNotFound, nil
			}
			if authResult == AuthFailed {
				// Don't cache auth failures - these could be typos or password changes
				// Better to always check prelookup for security
				return nil, AuthFailed, nil
			}
		}
	}

	// Extract lookup response
	lookupResp, ok := result.(HTTPPreLookupResponse)
	if !ok {
		return nil, AuthFailed, fmt.Errorf("unexpected result type from circuit breaker")
	}

	// Use the address from response (required field, already validated)
	actualEmail := strings.TrimSpace(lookupResp.Address)
	if actualEmail != lookupEmail {
		logger.Debug("prelookup: Using address from response", "response_email", actualEmail, "query_email", lookupEmail)
	}

	// Verify password against hash (skip if route_only mode)
	if !routeOnly {
		// Log authentication attempt
		hashPrefix := lookupResp.PasswordHash
		if len(hashPrefix) > 30 {
			hashPrefix = hashPrefix[:30] + "..."
		}
		logger.Debug("prelookup: Verifying credentials", "user", authEmail, "password_len", len(password), "hash_prefix", hashPrefix)

		// Verify password against hash returned by HTTP endpoint
		// Note: The HTTP endpoint handles all master token logic and returns the appropriate hash
		if !c.verifyPassword(password, lookupResp.PasswordHash) {
			// Don't cache auth failures - password verification failed
			// Could be wrong password or password change in progress
			logger.Info("prelookup: Password verification failed", "user", authEmail, "hash_prefix", hashPrefix)
			return nil, AuthFailed, nil
		}

		logger.Info("prelookup: Authentication successful", "user", authEmail)
	} else {
		// Route-only mode: password already validated by master username check
		logger.Info("prelookup: Skipping password verification (route_only mode)", "user", authEmail)
	}

	// Build routing info based on mode
	var normalizedServer string
	if !lookupResp.AuthOnlyMode {
		// Normal mode: prelookup specifies backend server
		normalizedServer = c.normalizeServerAddress(lookupResp.Server)
	}
	// else: Auth-only mode - ServerAddress will be empty, backend selected locally

	info := &UserRoutingInfo{
		ServerAddress:          normalizedServer,
		AccountID:              lookupResp.AccountID,
		IsPrelookupAccount:     true,
		ActualEmail:            actualEmail,
		RemoteTLS:              c.remoteTLS,
		RemoteTLSUseStartTLS:   c.remoteTLSUseStartTLS,
		RemoteTLSVerify:        c.remoteTLSVerify,
		RemoteUseProxyProtocol: c.remoteUseProxyProtocol,
		RemoteUseIDCommand:     c.remoteUseIDCommand,
		RemoteUseXCLIENT:       c.remoteUseXCLIENT,
	}

	// Store successful result in cache with password hash for invalidation on change
	if c.cache != nil {
		c.cache.SetWithHash(cacheKey, info, AuthSuccess, lookupResp.PasswordHash)
	}

	return info, AuthSuccess, nil
}

// verifyPassword verifies a password against a hash
func (c *HTTPPreLookupClient) verifyPassword(password, hash string) bool {
	err := db.VerifyPassword(hash, password)
	if err != nil {
		hashPrefix := hash
		if len(hashPrefix) > 30 {
			hashPrefix = hashPrefix[:30] + "..."
		}
		logger.Debug("prelookup: Password verification failed", "hash_prefix", hashPrefix, "error", err)
		return false
	}
	return true
}

// normalizeServerAddress ensures the server address has a port
func (c *HTTPPreLookupClient) normalizeServerAddress(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return addr
	}

	// If already has port, return as-is
	if strings.Contains(addr, ":") {
		return addr
	}

	// Add configured default port, or 143 if not specified
	defaultPort := c.remotePort
	if defaultPort == 0 {
		defaultPort = 143 // Default IMAP port
	}
	return fmt.Sprintf("%s:%d", addr, defaultPort)
}

// deriveAccountIDFromEmail creates a stable, unique int64 ID from an email address
// This allows connection tracking even when the prelookup endpoint doesn't provide an account_id
func deriveAccountIDFromEmail(email string) int64 {
	// Normalize the email (lowercase, trim spaces)
	normalized := strings.ToLower(strings.TrimSpace(email))

	// Hash the email using SHA256
	hash := sha256.Sum256([]byte(normalized))

	// Take the first 8 bytes and convert to int64
	// Use absolute value to ensure positive ID
	id := int64(binary.BigEndian.Uint64(hash[:8]))
	if id < 0 {
		id = -id
	}

	// Ensure it's never 0 (0 means "no account ID" in the code)
	if id == 0 {
		id = 1
	}

	return id
}

// HealthCheck performs a health check on the HTTP prelookup endpoint
func (c *HTTPPreLookupClient) HealthCheck(ctx context.Context) error {
	// Try a simple GET request to the base URL to check if the service is reachable
	// Note: We're not using a real email here since this is just a health check
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP prelookup endpoint unreachable: %w", err)
	}
	defer resp.Body.Close()

	// Accept any response that's not a 5xx error
	// (we expect 400 for missing email parameter, which is fine for health check)
	if resp.StatusCode >= 500 {
		return fmt.Errorf("HTTP prelookup endpoint returned error: %d", resp.StatusCode)
	}

	return nil
}

// GetCircuitBreaker returns the circuit breaker for health monitoring
func (c *HTTPPreLookupClient) GetCircuitBreaker() *circuitbreaker.CircuitBreaker {
	return c.breaker
}

// GetTimeout returns the configured HTTP request timeout
func (c *HTTPPreLookupClient) GetTimeout() time.Duration {
	return c.timeout
}

// GetTransportTimeouts returns the dial and TLS handshake timeouts
// Used for calculating total context timeout including connection establishment
func (c *HTTPPreLookupClient) GetTransportTimeouts() (dialTimeout, tlsHandshakeTimeout time.Duration) {
	return c.dialTimeout, c.tlsHandshakeTimeout
}

// GetHealth returns the health status of the HTTP prelookup service
func (c *HTTPPreLookupClient) GetHealth() map[string]any {
	health := make(map[string]any)
	health["endpoint"] = c.baseURL
	health["timeout"] = c.timeout.String()

	// Circuit breaker state
	state := c.breaker.State()
	health["circuit_breaker_state"] = state.String()

	// Overall status based on circuit breaker state
	switch state {
	case circuitbreaker.StateOpen:
		health["status"] = "unhealthy"
		health["message"] = "Circuit breaker is open due to too many failures"
	case circuitbreaker.StateHalfOpen:
		health["status"] = "degraded"
		health["message"] = "Circuit breaker is testing recovery"
	case circuitbreaker.StateClosed:
		health["status"] = "healthy"
	}

	return health
}

// Close cleans up resources
func (c *HTTPPreLookupClient) Close() error {
	logger.Debug("prelookup: Closing HTTP prelookup client")

	// Stop cache cleanup goroutine
	if c.cache != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := c.cache.Stop(ctx); err != nil {
			logger.Debug("prelookup: Cache cleanup stop error", "error", err)
		}

		// Log final cache stats
		hits, misses, size := c.cache.GetStats()
		if hits+misses > 0 {
			hitRate := float64(hits) / float64(hits+misses) * 100
			logger.Info("Prelookup cache final stats", "hits", hits, "misses", misses, "hit_rate", fmt.Sprintf("%.2f%%", hitRate), "size", size)
		}
	}

	return nil
}
