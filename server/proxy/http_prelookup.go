package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/circuitbreaker"
	"github.com/migadu/sora/server"
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
}

// HTTPPreLookupResponse represents the JSON response from the HTTP prelookup endpoint
type HTTPPreLookupResponse struct {
	Address      string `json:"address"`       // Email address for the user (required - used to derive account_id)
	PasswordHash string `json:"password_hash"` // Password hash to verify against (required)
	Server       string `json:"server"`        // Backend server IP/hostname:port (required)
	AccountID    int64  // Derived from Address, not part of JSON response
}

// CircuitBreakerSettings holds configurable circuit breaker settings
type CircuitBreakerSettings struct {
	MaxRequests  uint32        // Maximum concurrent requests in half-open state
	Interval     time.Duration // Time before resetting failure counts in closed state
	Timeout      time.Duration // Time before transitioning from open to half-open
	FailureRatio float64       // Failure ratio threshold to open circuit (0.0-1.0)
	MinRequests  uint32        // Minimum requests before evaluating failure ratio
}

// TransportSettings holds HTTP transport configuration for connection pooling
type TransportSettings struct {
	MaxIdleConns        int           // Maximum idle connections across all hosts
	MaxIdleConnsPerHost int           // Maximum idle connections per host
	MaxConnsPerHost     int           // Maximum total connections per host (0 = unlimited)
	IdleConnTimeout     time.Duration // How long idle connections stay open
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
		log.Printf("[HTTP-PreLookup] Circuit breaker '%s' changed from %s to %s", name, from, to)
	}
	breaker := circuitbreaker.NewCircuitBreaker(settings)
	log.Printf("[HTTP-PreLookup] Initialized circuit breaker: max_requests=%d, timeout=%v, failure_ratio=%.0f%%, min_requests=%d",
		cbSettings.MaxRequests, cbSettings.Timeout, cbSettings.FailureRatio*100, cbSettings.MinRequests)

	// Apply defaults for transport settings if not provided
	if transportSettings == nil {
		transportSettings = &TransportSettings{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			MaxConnsPerHost:     0,
			IdleConnTimeout:     90 * time.Second,
		}
	}

	// Configure HTTP transport with connection pooling for high concurrency
	transport := &http.Transport{
		MaxIdleConns:        transportSettings.MaxIdleConns,
		MaxIdleConnsPerHost: transportSettings.MaxIdleConnsPerHost,
		MaxConnsPerHost:     transportSettings.MaxConnsPerHost,
		IdleConnTimeout:     transportSettings.IdleConnTimeout,
		DisableKeepAlives:   false, // Enable keep-alives for connection reuse
		DisableCompression:  false, // Enable compression
		ForceAttemptHTTP2:   true,  // Try HTTP/2 if available
	}

	log.Printf("[HTTP-PreLookup] Initialized HTTP transport: max_idle_conns=%d, max_idle_conns_per_host=%d, max_conns_per_host=%d, idle_conn_timeout=%v",
		transportSettings.MaxIdleConns, transportSettings.MaxIdleConnsPerHost, transportSettings.MaxConnsPerHost, transportSettings.IdleConnTimeout)

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
	}
}

// LookupUserRoute performs an HTTP GET request to lookup user routing information
func (c *HTTPPreLookupClient) LookupUserRoute(ctx context.Context, email, password string) (*UserRoutingInfo, AuthResult, error) {
	// Parse and validate email address with master token support
	// This also handles +detail addressing and validates format
	addr, err := server.ParseAddressWithMasterToken(email)
	if err != nil {
		log.Printf("[HTTP-PreLookup] Invalid email format: %v", err)
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
		log.Printf("[HTTP-PreLookup] Stripping +detail from '%s' -> '%s' for authentication", email, lookupEmail)
	}

	// Build cache key from base email and password hash (for security, we hash the password)
	cacheKey := fmt.Sprintf("%s:%s", authEmail, hashPassword(password))

	// Check cache first
	if c.cache != nil {
		if info, authResult, found := c.cache.Get(cacheKey); found {
			log.Printf("[HTTP-PreLookup] Cache HIT for user '%s'", authEmail)
			return info, authResult, nil
		}
		log.Printf("[HTTP-PreLookup] Cache MISS for user '%s'", authEmail)
	}

	// Execute HTTP request through circuit breaker
	result, err := c.breaker.Execute(func() (any, error) {
		// Build request URL by interpolating $email placeholder
		// Use lookupEmail (MasterAddress) to include master token but not +detail
		requestURL := strings.ReplaceAll(c.baseURL, "$email", url.QueryEscape(lookupEmail))

		log.Printf("[HTTP-PreLookup] Requesting lookup for user '%s' from %s", lookupEmail, requestURL)

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
			// Network error - this is transient
			return nil, fmt.Errorf("%w: HTTP request failed: %v", ErrPrelookupTransient, err)
		}
		defer resp.Body.Close()

		// Read response body first so we can log it
		bodyBytes, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			log.Printf("[HTTP-PreLookup] Failed to read response body for user '%s': %v", lookupEmail, readErr)
			return nil, fmt.Errorf("%w: failed to read response body: %v", ErrPrelookupTransient, readErr)
		}

		// Check status code
		if resp.StatusCode == http.StatusNotFound {
			log.Printf("[HTTP-PreLookup] User '%s' not found (404)", lookupEmail)
			return map[string]interface{}{"result": AuthUserNotFound}, nil
		}

		// 4xx errors (except 404) mean user lookup failed - allow fallback
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			log.Printf("[HTTP-PreLookup] Client error %d for user '%s': %s - treating as user not found", resp.StatusCode, lookupEmail, string(bodyBytes))
			return map[string]interface{}{"result": AuthUserNotFound}, nil
		}

		// 5xx errors are transient - fallback controlled by config
		if resp.StatusCode >= 500 {
			log.Printf("[HTTP-PreLookup] Server error %d for user '%s': %s", resp.StatusCode, lookupEmail, string(bodyBytes))
			return nil, fmt.Errorf("%w: server error %d", ErrPrelookupTransient, resp.StatusCode)
		}

		// Non-200 2xx responses - treat as transient
		if resp.StatusCode != http.StatusOK {
			log.Printf("[HTTP-PreLookup] Unexpected status %d for user '%s': %s", resp.StatusCode, lookupEmail, string(bodyBytes))
			return nil, fmt.Errorf("%w: unexpected status code: %d", ErrPrelookupTransient, resp.StatusCode)
		}

		// Parse JSON response - if this fails on a 200 response, it's a server bug
		var lookupResp HTTPPreLookupResponse
		if err := json.Unmarshal(bodyBytes, &lookupResp); err != nil {
			log.Printf("[HTTP-PreLookup] Failed to parse JSON for user '%s': %v, body: %s", lookupEmail, err, string(bodyBytes))
			return nil, fmt.Errorf("%w: failed to parse JSON response: %v", ErrPrelookupInvalidResponse, err)
		}

		// If server is null/empty, treat as user not found (404)
		if strings.TrimSpace(lookupResp.Server) == "" {
			log.Printf("[HTTP-PreLookup] Server is null/empty for user '%s' - treating as user not found", lookupEmail)
			return map[string]interface{}{"result": AuthUserNotFound}, nil
		}

		// Validate other required fields - invalid 200 response is a server bug
		if strings.TrimSpace(lookupResp.Address) == "" {
			log.Printf("[HTTP-PreLookup] Validation failed for user '%s': address is empty", lookupEmail)
			return nil, fmt.Errorf("%w: address is empty in response", ErrPrelookupInvalidResponse)
		}
		if strings.TrimSpace(lookupResp.PasswordHash) == "" {
			log.Printf("[HTTP-PreLookup] Validation failed for user '%s': password_hash is empty", lookupEmail)
			return nil, fmt.Errorf("%w: password_hash is empty in response", ErrPrelookupInvalidResponse)
		}

		// Derive account_id from the address field
		lookupResp.AccountID = deriveAccountIDFromEmail(lookupResp.Address)
		log.Printf("[HTTP-PreLookup] Derived account_id from address '%s': %d", lookupResp.Address, lookupResp.AccountID)

		return lookupResp, nil
	})

	// Handle circuit breaker errors
	if err != nil {
		if err == circuitbreaker.ErrCircuitBreakerOpen {
			log.Printf("[HTTP-PreLookup] Circuit breaker is open for %s", c.baseURL)
			// Circuit breaker open is a transient error - return temporarily unavailable
			return nil, AuthTemporarilyUnavailable, fmt.Errorf("%w: circuit breaker open: too many failures", ErrPrelookupTransient)
		}
		if err == circuitbreaker.ErrTooManyRequests {
			log.Printf("[HTTP-PreLookup] Circuit breaker is half-open (testing recovery) for %s - rate limiting requests", c.baseURL)
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

	// Handle user not found case
	if resultMap, ok := result.(map[string]interface{}); ok {
		if authResult, ok := resultMap["result"].(AuthResult); ok && authResult == AuthUserNotFound {
			// Store user not found in cache (negative caching)
			if c.cache != nil {
				c.cache.Set(cacheKey, nil, AuthUserNotFound)
			}
			return nil, AuthUserNotFound, nil
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
		log.Printf("[HTTP-PreLookup] Using address from response: '%s' (differs from query: '%s')", actualEmail, lookupEmail)
	}

	// Log authentication attempt
	hashPrefix := lookupResp.PasswordHash
	if len(hashPrefix) > 30 {
		hashPrefix = hashPrefix[:30] + "..."
	}
	log.Printf("[HTTP-PreLookup] Verifying credentials for user '%s' (password length: %d, hash: %s)",
		authEmail, len(password), hashPrefix)

	// Verify password against hash returned by HTTP endpoint
	// Note: The HTTP endpoint handles all master token logic and returns the appropriate hash
	if !c.verifyPassword(password, lookupResp.PasswordHash) {
		log.Printf("[HTTP-PreLookup] Authentication failed for user: %s", authEmail)
		// Store failed auth in cache (negative caching)
		if c.cache != nil {
			c.cache.Set(cacheKey, nil, AuthFailed)
		}
		return nil, AuthFailed, nil
	}

	log.Printf("[HTTP-PreLookup] Authentication successful for user '%s'", authEmail)

	// Normalize server address (add default port if missing)
	normalizedServer := c.normalizeServerAddress(lookupResp.Server)

	// Build routing info
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

	// Store successful result in cache
	if c.cache != nil {
		c.cache.Set(cacheKey, info, AuthSuccess)
	}

	return info, AuthSuccess, nil
}

// verifyPassword verifies a password against a hash
func (c *HTTPPreLookupClient) verifyPassword(password, hash string) bool {
	err := db.VerifyPassword(hash, password)
	if err != nil {
		log.Printf("[HTTP-PreLookup] Password verification failed for hash '%s': %v", hash, err)
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

// GetHealth returns the health status of the HTTP prelookup service
func (c *HTTPPreLookupClient) GetHealth() map[string]interface{} {
	health := make(map[string]interface{})
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
	log.Printf("[HTTP-PreLookup] Closing HTTP prelookup client")

	// Stop cache cleanup goroutine
	if c.cache != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := c.cache.Stop(ctx); err != nil {
			log.Printf("[HTTP-PreLookup] Warning: cache cleanup stop error: %v", err)
		}

		// Log final cache stats
		hits, misses, size := c.cache.GetStats()
		if hits+misses > 0 {
			hitRate := float64(hits) / float64(hits+misses) * 100
			log.Printf("[HTTP-PreLookup-Cache] Final stats: hits=%d, misses=%d, hit_rate=%.2f%%, size=%d",
				hits, misses, hitRate, size)
		}
	}

	return nil
}

// hashPassword creates a simple hash of the password for cache keying
// This is NOT for storage, just for cache key generation
func hashPassword(password string) string {
	h := sha256.Sum256([]byte(password))
	return fmt.Sprintf("%x", h[:8]) // First 8 bytes as hex (16 chars)
}
