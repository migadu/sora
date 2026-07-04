package pop3proxy

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"

	"github.com/migadu/go-pop3/pop3"
	"github.com/migadu/go-pop3/pop3server"
)

// Compile-time checks: the library discovers SASL support via type assertion,
// so a signature drift would silently disable AUTH instead of failing the build.
var (
	_ pop3server.Session     = (*POP3ProxySession)(nil)
	_ pop3server.SessionSASL = (*POP3ProxySession)(nil)
	_ pop3server.SessionLang = (*POP3ProxySession)(nil)
	_ pop3server.SessionUTF8 = (*POP3ProxySession)(nil)
)

type POP3ProxySession struct {
	server                *POP3ProxyServer
	clientConn            net.Conn
	backendConn           net.Conn
	backendReader         *bufio.Reader // Buffered reader from authentication phase
	clientReader          *bufio.Reader // Buffered reader from the pre-auth phase; reused by the relay so a command pipelined with PASS/AUTH is not dropped
	ctx                   context.Context
	cancel                context.CancelFunc
	RemoteIP              string
	username              string
	accountID             int64
	isRemoteLookupAccount bool
	routingInfo           *proxy.UserRoutingInfo
	routingMethod         string // Routing method used: remotelookup, affinity, consistent_hash, roundrobin
	serverAddr            string
	sessionID             string // Proxy session ID for end-to-end tracing (also forwarded to the backend)
	authenticated         bool
	mutex                 sync.Mutex
	errorCount            int
	startTime             time.Time
	releaseConn           func() // Connection limiter cleanup function
	proxyInfo             *server.ProxyProtocolInfo
	gracefulShutdown      bool   // Set during server shutdown to prevent copy goroutine from closing clientConn
	submittedUsername     string // Username exactly as submitted by the client (lookup-cache key)
	connRejected          bool   // True when connTracker.RegisterConnection rejected this session (close() must not unregister)
	closed                bool   // Guards close() against double teardown (guarded by mutex)
	pop3Conn              *pop3server.Conn
}

// InfoLog logs a client command with password masking if debug is enabled.
// InfoLog logs at INFO level with session context
// getLogger returns a ProxySessionLogger for this session
func (s *POP3ProxySession) getLogger() *server.ProxySessionLogger {
	return &server.ProxySessionLogger{
		Protocol:   "pop3_proxy",
		ServerName: s.server.name,
		ClientConn: s.clientConn,
		Username:   s.username,
		AccountID:  s.accountID,
		SessionID:  s.sessionID,
		Debug:      s.server.debug,
	}
}

func (s *POP3ProxySession) InfoLog(msg string, keysAndValues ...any) {
	s.getLogger().InfoLog(msg, keysAndValues...)
}

// DebugLog logs at DEBUG level with session context
func (s *POP3ProxySession) DebugLog(msg string, keysAndValues ...any) {
	s.getLogger().DebugLog(msg, keysAndValues...)
}

// WarnLog logs at WARN level with session context
func (s *POP3ProxySession) WarnLog(msg string, keysAndValues ...any) {
	s.getLogger().WarnLog(msg, keysAndValues...)
}

// ErrorLog logs at ERROR level with session context
func (s *POP3ProxySession) ErrorLog(msg string, keysAndValues ...any) {
	s.getLogger().ErrorLog(msg, keysAndValues...)
}

func (s *POP3ProxySession) authenticate(username, password string) error {
	// Remember the username exactly as submitted: the lookup cache is keyed on
	// it (every Set below uses it), so invalidation must use the same value —
	// not the resolved s.username, which can differ for token/master/+detail logins.
	s.submittedUsername = username

	// Reject empty passwords immediately - no cache lookup, no rate limiting needed
	// Empty passwords are never valid under any condition
	if password == "" {
		return consts.ErrAuthenticationFailed
	}

	// Use configured remotelookup timeout instead of hardcoded value
	authTimeout := s.server.connManager.GetRemoteLookupTimeout()
	ctx, cancel := context.WithTimeout(s.ctx, authTimeout)
	defer cancel()

	// Apply progressive authentication delay BEFORE any other checks
	remoteAddr := s.clientConn.RemoteAddr()
	if err := server.ApplyAuthenticationDelay(ctx, s.server.authLimiter, remoteAddr, "POP3-PROXY"); err != nil {
		if errors.Is(err, server.ErrDelayQueueFull) {
			// Delay queue full - reject immediately to prevent goroutine exhaustion
			s.InfoLog("delay queue full, rejecting connection", "username", username)
			return errors.New("too many concurrent authentication attempts")
		}
		// Context cancelled or other error
		return err
	}

	// Check cache first (before rate limiter to avoid delays for cached successful auth)
	// Use server name as cache key to avoid collisions between different proxies/servers
	if s.server.lookupCache != nil {
		if cached, found := s.server.lookupCache.Get(s.server.name, username); found {
			// Hash the password (never empty - validated at function start)
			passwordHash := lookupcache.HashPassword(password)

			// Check password hash match
			// Note: cached.PasswordHash should also never be empty, but we check defensively
			// in case of cache corruption or edge cases
			passwordMatches := (cached.PasswordHash != "" && cached.PasswordHash == passwordHash)

			if cached.IsNegative {
				// Negative cache entry - authentication previously failed
				if passwordMatches {
					// Same wrong password - return cached failure
					// NOTE: We do NOT refresh negative cache entries. They should expire
					// after negative_ttl to allow retry. Brute force protection is handled
					// by rate limiting, not by extending cache TTL.
					s.DebugLog("cache hit - negative entry with same password", "username", username, "age", time.Since(cached.CreatedAt))
					metrics.CacheOperationsTotal.WithLabelValues("get", "hit_negative").Inc()
					s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, s.clientConn, s.proxyInfo, username, false)
					metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", s.server.name, s.server.hostname, "failure").Inc()
					return consts.ErrAuthenticationFailed
				} else {
					// Different password - ALWAYS revalidate (user might have fixed their password)
					// Brute force protection is handled by protocol-level rate limiting
					s.DebugLog("cache negative entry - revalidating with different password", "username", username, "age", time.Since(cached.CreatedAt))
					metrics.CacheOperationsTotal.WithLabelValues("get", "revalidate_negative_different_pw").Inc()
					// Fall through to full auth
				}
			} else {
				// Positive cache entry (successful auth)
				if passwordMatches {
					// Same password - use cached routing info
					// NOTE: We do NOT refresh routing cache. Entries should expire after
					// positive_ttl to allow periodic revalidation via remotelookup/database.
					// This ensures that when a domain moves backends or password changes,
					// active users eventually pick up the changes.
					s.DebugLog("cache hit - using cached auth", "username", username, "account_id", cached.AccountID, "backend", cached.ServerAddress, "age", time.Since(cached.CreatedAt))
					metrics.CacheOperationsTotal.WithLabelValues("get", "hit").Inc()

					s.accountID = cached.AccountID
					s.isRemoteLookupAccount = cached.FromRemoteLookup
					s.routingInfo = &proxy.UserRoutingInfo{
						AccountID:              cached.AccountID,
						ServerAddress:          cached.ServerAddress,
						RemoteTLS:              cached.RemoteTLS,
						RemoteTLSUseStartTLS:   cached.RemoteTLSUseStartTLS,
						RemoteTLSVerify:        cached.RemoteTLSVerify,
						RemoteUseProxyProtocol: cached.RemoteUseProxyProtocol,
					}
					if cached.ActualEmail != "" {
						s.username = cached.ActualEmail
					} else {
						s.username = username
					}

					// Use resolved username for rate limiting and metrics
					s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, s.clientConn, s.proxyInfo, s.username, true)
					metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", s.server.name, s.server.hostname, "success").Inc()

					// Track domain and user activity using resolved email
					if addr, err := server.NewAddress(s.username); err == nil {
						metrics.TrackDomainConnection("pop3_proxy", addr.Domain())
						metrics.TrackUserActivity("pop3_proxy", addr.FullAddress(), "connection", 1)
					}

					// Set username on client connection for timeout logging
					if soraConn, ok := s.clientConn.(interface{ SetUsername(string) }); ok {
						soraConn.SetUsername(s.username)
					}

					// Check if context is cancelled (server shutting down) before attempting backend connection
					if err := s.ctx.Err(); err != nil {
						s.WarnLog("context cancelled during cache hit, cannot connect to backend", "error", err)
						return server.ErrServerShuttingDown // Triggers UNAVAILABLE response instead of auth failed
					}

					// Connect to backend to set routing method and establish connection
					if err := s.connectToBackend(); err != nil {
						return fmt.Errorf("failed to connect to backend: %w", err)
					}

					// Single consolidated log for authentication success (AFTER backend connection succeeds)
					s.InfoLog("authentication successful", "cached", true, "method", "cache")

					return nil
				} else {
					// Different password on positive entry - always revalidate
					// Use configured window: revalidate if entry is older than positiveRevalidationWindow
					if cached.IsOld(s.server.positiveRevalidationWindow) {
						s.DebugLog("cache positive entry - revalidating with different password", "username", username, "age", time.Since(cached.CreatedAt), "window", s.server.positiveRevalidationWindow)
						metrics.CacheOperationsTotal.WithLabelValues("get", "revalidate_positive_different_pw").Inc()
						// Fall through to full auth
					} else {
						// Entry is fresh - likely wrong password attempt
						s.DebugLog("cache hit - wrong password on fresh positive entry", "username", username)
						metrics.CacheOperationsTotal.WithLabelValues("get", "hit_positive_wrong_pw").Inc()
						s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, s.clientConn, s.proxyInfo, username, false)
						metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", s.server.name, s.server.hostname, "failure").Inc()
						return consts.ErrAuthenticationFailed
					}
				}
			}
		} else {
			s.DebugLog("cache miss", "username", username)
			metrics.CacheOperationsTotal.WithLabelValues("get", "miss").Inc()
		}
	}

	// Check if the authentication attempt is allowed by the rate limiter using proxy-aware methods
	if err := s.server.authLimiter.CanAttemptAuthWithProxy(ctx, s.clientConn, s.proxyInfo, username); err != nil {
		// Check if this is a rate limit error
		var rateLimitErr *server.RateLimitError
		if errors.As(err, &rateLimitErr) {
			s.InfoLog("rate limit exceeded",
				"username", username,
				"reason", rateLimitErr.Reason,
				"failure_count", rateLimitErr.FailureCount,
				"blocked_until", rateLimitErr.BlockedUntil.Format(time.RFC3339))

			// Track rate limiting
			metrics.ProtocolErrors.WithLabelValues("pop3_proxy", "AUTH", "rate_limited", "client_error").Inc()

			// Return the error - caller will send appropriate POP3 response
			return rateLimitErr
		}

		// Unknown rate limiting error
		metrics.ProtocolErrors.WithLabelValues("pop3_proxy", "AUTH", "rate_limited", "client_error").Inc()
		return err
	}

	// Parse username to check for master username or token suffix
	// Format: user@domain.com@SUFFIX
	// If SUFFIX matches configured master username: validate locally, send base address to remotelookup
	// Otherwise: treat as token, send full username (including @SUFFIX) to remotelookup
	var usernameForRemoteLookup string
	var masterAuthValidated bool

	// Parse username (handles both regular addresses and addresses with @SUFFIX)
	parsedAddr, parseErr := server.NewAddress(username)

	if parseErr == nil && parsedAddr.HasSuffix() {
		// Has suffix - check if it matches configured master username
		if len(s.server.masterUsername) > 0 && checkMasterCredential(parsedAddr.Suffix(), []byte(s.server.masterUsername)) {
			// Suffix matches master username - validate master password locally
			if len(s.server.masterPassword) == 0 || !checkMasterCredential(password, []byte(s.server.masterPassword)) {
				// Wrong master password - fail immediately
				s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, s.clientConn, s.proxyInfo, parsedAddr.BaseAddress(), false)
				metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", s.server.name, s.server.hostname, "failure").Inc()
				return consts.ErrAuthenticationFailed
			}
			// Master credentials validated - use base address (without @MASTER suffix) for remotelookup
			s.DebugLog("master username authentication successful, using base address for routing", "base_address", parsedAddr.BaseAddress())
			usernameForRemoteLookup = parsedAddr.BaseAddress()
			masterAuthValidated = true
		} else {
			// Suffix doesn't match master username - treat as token
			// Send FULL username (including @TOKEN) to remotelookup for validation
			s.DebugLog("token detected in username, sending full username to remotelookup", "username", username)
			usernameForRemoteLookup = username
			masterAuthValidated = false
		}
	} else {
		// No suffix - regular username
		usernameForRemoteLookup = username
		masterAuthValidated = false
	}

	// Try remotelookup authentication/routing if configured
	// - For master username: sends base address to get routing info (password already validated)
	// - For others: sends full username (may contain token) for remotelookup authentication
	if s.server.connManager.HasRouting() {
		routingInfo, authResult, err := s.server.connManager.AuthenticateAndRouteWithOptions(ctx, usernameForRemoteLookup, password, masterAuthValidated)

		// Log remotelookup response with all details
		backend := "none"
		actualEmail := "none"
		if routingInfo != nil {
			if routingInfo.ServerAddress != "" {
				backend = routingInfo.ServerAddress
			}
			if routingInfo.ActualEmail != "" {
				actualEmail = routingInfo.ActualEmail
			}
		}
		if err != nil {
			s.DebugLog("remotelookup authentication", "client_username", username, "sent_to_remotelookup", usernameForRemoteLookup, "master_auth", masterAuthValidated, "result", authResult.String(), "backend", backend, "actual_email", actualEmail, "error", err)
		} else {
			s.DebugLog("remotelookup authentication", "client_username", username, "sent_to_remotelookup", usernameForRemoteLookup, "master_auth", masterAuthValidated, "result", authResult.String(), "backend", backend, "actual_email", actualEmail)
		}

		if err != nil {
			// Categorize the error type to determine fallback behavior
			if errors.Is(err, proxy.ErrRemoteLookupInvalidResponse) {
				// Invalid response from remotelookup (malformed 2xx) - this is a server bug, fail hard
				s.WarnLog("remotelookup returned invalid response - server bug, rejecting authentication", "error", err)
				s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, s.clientConn, s.proxyInfo, username, false)
				metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", s.server.name, s.server.hostname, "failure").Inc()
				return fmt.Errorf("remotelookup server error: invalid response")
			}

			if errors.Is(err, proxy.ErrRemoteLookupTransient) {
				// Check if this is due to context cancellation (server shutdown)
				if errors.Is(err, server.ErrServerShuttingDown) {
					s.InfoLog("remotelookup cancelled due to server shutdown")
					metrics.RemoteLookupResult.WithLabelValues("pop3", "shutdown").Inc()
					return server.ErrServerShuttingDown
				}

				// Transient error (network, 5xx, circuit breaker) - NEVER fallback to DB
				// These are service availability issues, not "user not found" cases
				s.WarnLog("remotelookup transient error - service unavailable", "error", err)
				metrics.RemoteLookupResult.WithLabelValues("pop3", "transient_error_rejected").Inc()
				s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, s.clientConn, s.proxyInfo, username, false)
				metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", s.server.name, s.server.hostname, "failure").Inc()
				return fmt.Errorf("remotelookup service unavailable")
			} else {
				// Unknown error type - fallthrough to main DB auth
			}
		} else {
			switch authResult {
			case proxy.AuthSuccess:
				// RemoteLookup returned success - use routing info
				s.DebugLog("remotelookup successful", "account_id", routingInfo.AccountID, "master_auth_validated", masterAuthValidated)
				metrics.RemoteLookupResult.WithLabelValues("pop3", "success").Inc()
				s.accountID = routingInfo.AccountID
				s.isRemoteLookupAccount = routingInfo.IsRemoteLookupAccount
				s.routingInfo = routingInfo

				// Determine the resolved email for caching and backend impersonation
				// Use ActualEmail from remotelookup response if available, otherwise derive from username
				var resolvedEmail string
				if routingInfo.ActualEmail != "" {
					resolvedEmail = routingInfo.ActualEmail
				} else if masterAuthValidated {
					resolvedEmail = usernameForRemoteLookup // Base address already
				} else {
					resolvedEmail = username // Fallback to original
				}
				s.username = resolvedEmail // Use for backend impersonation

				// Set username on client connection for timeout logging
				if soraConn, ok := s.clientConn.(interface{ SetUsername(string) }); ok {
					soraConn.SetUsername(s.username)
				}

				// Cache successful authentication with routing info
				// CRITICAL: Cache key is submitted username (e.g., "user@TOKEN")
				// BUT store ActualEmail so cache hits can use the resolved address
				// Always hash password, even for master auth, to prevent cache bypass
				if s.server.lookupCache != nil {
					passwordHash := ""
					if password != "" {
						passwordHash = lookupcache.HashPassword(password)
					}
					s.server.lookupCache.Set(s.server.name, username, &lookupcache.CacheEntry{
						AccountID:              routingInfo.AccountID,
						PasswordHash:           passwordHash,
						ActualEmail:            resolvedEmail, // Store resolved email for cache hits
						ServerAddress:          routingInfo.ServerAddress,
						RemoteTLS:              routingInfo.RemoteTLS,
						RemoteTLSUseStartTLS:   routingInfo.RemoteTLSUseStartTLS,
						RemoteTLSVerify:        routingInfo.RemoteTLSVerify,
						RemoteUseProxyProtocol: routingInfo.RemoteUseProxyProtocol,
						Result:                 lookupcache.AuthSuccess,
						FromRemoteLookup:       true,
						IsNegative:             false,
					})
				}

				s.authenticated = true
				// Use resolvedEmail for rate limiting (not submitted username with token)
				s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, s.clientConn, s.proxyInfo, resolvedEmail, true)
				metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", s.server.name, s.server.hostname, "success").Inc()

				// For metrics, use resolvedEmail for accurate tracking
				if addr, err := server.NewAddress(resolvedEmail); err == nil {
					metrics.TrackDomainConnection("pop3_proxy", addr.Domain())
					metrics.TrackUserActivity("pop3_proxy", addr.FullAddress(), "connection", 1)
				}

				// Single consolidated log for authentication success
				method := "remotelookup"
				if masterAuthValidated {
					method = "master"
				}
				s.InfoLog("authentication successful", "cached", false, "method", method)

				// Connect to backend
				if err := s.connectToBackend(); err != nil {
					return fmt.Errorf("failed to connect to backend: %w", err)
				}
				return nil // Authentication complete

			case proxy.AuthFailed:
				// User found in remotelookup, but password was wrong
				// For master username, this shouldn't happen (password already validated)
				// For others, reject immediately
				if masterAuthValidated {
					s.WarnLog("remotelookup failed but master auth was already validated - routing issue", "user", username)
				}

				// Cache negative result (wrong password)
				if s.server.lookupCache != nil {
					passwordHash := ""
					if password != "" {
						passwordHash = lookupcache.HashPassword(password)
					}
					s.server.lookupCache.Set(s.server.name, username, &lookupcache.CacheEntry{
						PasswordHash: passwordHash,
						Result:       lookupcache.AuthFailed,
						IsNegative:   true,
					})
				}

				s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, s.clientConn, s.proxyInfo, username, false)
				metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", s.server.name, s.server.hostname, "failure").Inc()

				// Single consolidated log for authentication failure
				s.InfoLog("authentication failed", "reason", "invalid_password", "cached", false, "method", "remotelookup")

				return consts.ErrAuthenticationFailed

			case proxy.AuthTemporarilyUnavailable:
				// RemoteLookup service is temporarily unavailable - tell user to retry later
				s.WarnLog("remotelookup service temporarily unavailable")
				metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", s.server.name, s.server.hostname, "unavailable").Inc()
				return fmt.Errorf("authentication service temporarily unavailable, please try again later")

			case proxy.AuthUserNotFound:
				// User not found in remotelookup (404/3xx)
				if s.server.remotelookupConfig != nil && s.server.remotelookupConfig.ShouldLookupLocalUsers() {
					s.InfoLog("user not found in remotelookup, local lookup enabled - attempting main DB")
					metrics.RemoteLookupResult.WithLabelValues("pop3", "user_not_found_fallback").Inc()
					// Fallthrough to main DB auth
				} else {
					s.InfoLog("user not found in remotelookup, local lookup disabled - rejecting")
					metrics.RemoteLookupResult.WithLabelValues("pop3", "user_not_found_rejected").Inc()
					s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, s.clientConn, s.proxyInfo, username, false)
					metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", s.server.name, s.server.hostname, "failure").Inc()
					return consts.ErrAuthenticationFailed
				}
			}
		}
	}

	// Fallback to main DB
	// If master auth was already validated, just get account ID and continue
	// Otherwise, authenticate via main DB
	var address server.Address
	var err error
	// Use already parsed address if available
	if parseErr == nil {
		address = parsedAddr
	} else {
		// Parse failed earlier - try again with NewAddress (shouldn't happen but handle it)
		address, err = server.NewAddress(username)
		if err != nil {
			return fmt.Errorf("invalid address format: %w", err)
		}
	}

	var accountID int64
	if masterAuthValidated {
		// Master authentication already validated - just get account ID
		s.DebugLog("master auth already validated, getting account ID from main database")
		accountID, err = s.server.rdb.GetActiveAccountIDByAddressWithRetry(ctx, address.BaseAddress())
		if err != nil {
			// Check if error is due to session context cancellation (server shutdown)
			// Note: Must check s.ctx.Err(), not just the query error, because the query context
			// can timeout (DeadlineExceeded) independently from server shutdown
			if s.ctx.Err() != nil {
				s.InfoLog("master auth cancelled due to server shutdown")
				return server.ErrServerShuttingDown
			}

			s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, s.clientConn, s.proxyInfo, address.BaseAddress(), false)
			metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", s.server.name, s.server.hostname, "failure").Inc()
			return fmt.Errorf("account not found: %w", err)
		}
	} else {
		// Regular authentication via main DB
		s.DebugLog("Authenticating user via main database")
		// Use base address (without +detail) for authentication
		accountID, err = s.server.rdb.AuthenticateWithRetry(ctx, address.BaseAddress(), password)
		if err != nil {
			// Check if error is due to session context cancellation (server shutdown)
			// Note: Must check s.ctx.Err(), not just the query error, because the query context
			// can timeout (DeadlineExceeded) independently from server shutdown
			if s.ctx.Err() != nil {
				s.InfoLog("authentication cancelled due to server shutdown")
				return server.ErrServerShuttingDown
			}

			// Determine failure reason for logging
			reason := "transient_error"
			if errors.Is(err, consts.ErrUserNotFound) || strings.Contains(err.Error(), "user not found") {
				reason = "user_not_found"
			} else if strings.Contains(err.Error(), "hashedPassword is not the hash") {
				reason = "invalid_password"
			}

			// Cache negative result (authentication failed)
			// Only cache auth failures, not transient DB errors
			isDefinitiveFailure := errors.Is(err, consts.ErrUserNotFound) ||
				strings.Contains(err.Error(), "hashedPassword is not the hash") ||
				strings.Contains(err.Error(), "user not found")

			if isDefinitiveFailure {
				if s.server.lookupCache != nil {
					passwordHash := ""
					if password != "" {
						passwordHash = lookupcache.HashPassword(password)
					}
					s.server.lookupCache.Set(s.server.name, username, &lookupcache.CacheEntry{
						PasswordHash: passwordHash,
						Result:       lookupcache.AuthFailed,
						IsNegative:   true,
					})
				}
				// Single consolidated log for authentication failure
				s.InfoLog("authentication failed", "reason", reason, "cached", false, "method", "main_db")
			} else {
				s.DebugLog("NOT caching transient error - circuit breaker will handle", "username", username, "error", err)
				// Single consolidated log for authentication failure (transient)
				s.InfoLog("authentication failed", "reason", reason, "cached", false, "method", "main_db")
			}

			s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, s.clientConn, s.proxyInfo, username, false)
			metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", s.server.name, s.server.hostname, "failure").Inc()
			return fmt.Errorf("%w: %w", consts.ErrAuthenticationFailed, err)
		}
	}

	s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, s.clientConn, s.proxyInfo, username, true)

	// Track successful authentication.
	metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", s.server.name, s.server.hostname, "success").Inc()
	metrics.TrackDomainConnection("pop3_proxy", address.Domain())
	metrics.TrackUserActivity("pop3_proxy", address.FullAddress(), "connection", 1)

	// Single consolidated log for authentication success
	method := "main_db"
	if masterAuthValidated {
		method = "master"
	}
	s.InfoLog("authentication successful", "cached", false, "method", method)

	// Cache successful authentication (main DB)
	if s.server.lookupCache != nil {
		passwordHash := ""
		if password != "" {
			passwordHash = lookupcache.HashPassword(password)
		}
		s.server.lookupCache.Set(s.server.name, username, &lookupcache.CacheEntry{
			AccountID:        accountID,
			PasswordHash:     passwordHash,
			ServerAddress:    "", // Will be populated by affinity/routing in next connection
			Result:           lookupcache.AuthSuccess,
			FromRemoteLookup: false,
			IsNegative:       false,
		})
	}

	// Store user details on the session
	s.authenticated = true
	// Use base address (without +detail) for backend impersonation
	s.username = address.BaseAddress()
	s.accountID = accountID
	s.isRemoteLookupAccount = false

	// Set username on client connection for timeout logging
	if soraConn, ok := s.clientConn.(interface{ SetUsername(string) }); ok {
		soraConn.SetUsername(s.username)
	}

	// Connect to backend
	if err := s.connectToBackend(); err != nil {
		return fmt.Errorf("failed to connect to backend: %w", err)
	}

	return nil
}

func (s *POP3ProxySession) connectToBackend() error {
	routeResult, err := proxy.DetermineRoute(proxy.RouteParams{
		Ctx:                   s.ctx,
		Username:              s.username,
		Protocol:              "pop3",
		IsRemoteLookupAccount: s.isRemoteLookupAccount,
		RoutingInfo:           s.routingInfo,
		ConnManager:           s.server.connManager,
		EnableAffinity:        s.server.enableAffinity,
		ProxyName:             "POP3 Proxy",
	})
	if err != nil {
		s.WarnLog("Error determining route", "error", err)
	}

	// Update session routing info if it was fetched by DetermineRoute
	s.routingInfo = routeResult.RoutingInfo
	s.routingMethod = routeResult.RoutingMethod
	preferredAddr := routeResult.PreferredAddr
	isRemoteLookupRoute := routeResult.IsRemoteLookupRoute

	// 4. Connect using the determined address (or round-robin if empty)
	// Track which routing method was used for this connection.
	metrics.ProxyRoutingMethod.WithLabelValues("pop3", routeResult.RoutingMethod).Inc()

	clientHost, clientPort := server.GetHostPortFromAddr(s.clientConn.RemoteAddr())
	serverHost, serverPort := server.GetHostPortFromAddr(s.clientConn.LocalAddr())
	backendConn, actualAddr, err := s.server.connManager.ConnectWithProxy(
		s.ctx,
		preferredAddr,
		clientHost, clientPort, serverHost, serverPort, s.routingInfo,
	)
	if err != nil {
		s.DebugLog("Failed to connect to backend", "error", err, "addr", preferredAddr)
		metrics.ProxyBackendConnections.WithLabelValues("pop3", "failure").Inc()
		// Invalidate the cache so the next attempt re-resolves routing: a
		// cached ServerAddress may be stale (e.g. account moved backends).
		s.invalidateLookupCache("backend connect failure")
		// Wrap with the sentinel so the client sees "[SYS/TEMP] Backend server
		// temporarily unavailable" instead of "Authentication failed".
		return fmt.Errorf("%w: failed to connect to backend: %w", server.ErrBackendConnectionFailed, err)
	}
	if isRemoteLookupRoute && actualAddr != preferredAddr {
		// The remotelookup route specified a server, but we connected to a different one.
		// This means the preferred server failed and the connection manager fell back.
		// For remotelookup routes, this is a hard failure.
		backendConn.Close()
		metrics.ProxyBackendConnections.WithLabelValues("pop3", "failure").Inc()
		s.invalidateLookupCache("remotelookup route unavailable")
		return fmt.Errorf("%w: remotelookup route to %s failed, and fallback is disabled for remotelookup routes", server.ErrBackendConnectionFailed, preferredAddr)
	}

	metrics.ProxyBackendConnections.WithLabelValues("pop3", "success").Inc()
	s.backendConn = backendConn
	s.serverAddr = actualAddr
	s.DebugLog("Backend connection established in connectToBackend()", "backend", actualAddr)

	// Record successful connection for future affinity if enabled
	// Auth-only remotelookup users (IsRemoteLookupAccount=true but ServerAddress="") should get affinity
	if s.server.enableAffinity && actualAddr != "" {
		proxy.UpdateAffinityAfterConnection(proxy.RouteParams{
			Username:              s.username,
			Protocol:              "pop3",
			IsRemoteLookupAccount: s.isRemoteLookupAccount,
			RoutingInfo:           s.routingInfo, // Pass routing info so UpdateAffinity can check ServerAddress
			ConnManager:           s.server.connManager,
			EnableAffinity:        s.server.enableAffinity,
			ProxyName:             "POP3 Proxy",
		}, actualAddr, routeResult.RoutingMethod == "affinity")
	}

	// Read backend greeting. Bounded, and with a read deadline so a backend
	// that accepts TCP but never speaks cannot hang authentication (the client
	// is blocked waiting for its PASS/AUTH reply while we wait here).
	greetingTimeout := s.server.connManager.GetConnectTimeout()
	if err := s.backendConn.SetReadDeadline(time.Now().Add(greetingTimeout)); err != nil {
		s.backendConn.Close()
		return fmt.Errorf("%w: failed to set greeting read deadline: %w", server.ErrBackendConnectionFailed, err)
	}
	backendReader := bufio.NewReader(s.backendConn)
	greeting, err := server.ReadBoundedLine(backendReader, 1024)
	if err != nil {
		s.backendConn.Close()
		return fmt.Errorf("%w: failed to read backend greeting: %w", server.ErrBackendConnectionFailed, err)
	}
	if err := s.backendConn.SetReadDeadline(time.Time{}); err != nil {
		s.backendConn.Close()
		return fmt.Errorf("%w: failed to clear greeting read deadline: %w", server.ErrBackendConnectionFailed, err)
	}

	if !strings.HasPrefix(greeting, "+OK") {
		s.backendConn.Close()
		return fmt.Errorf("%w: unexpected backend greeting: %s", server.ErrBackendConnectionFailed, greeting)
	}

	// Store backendReader for use in proxy phase to avoid losing buffered data
	s.backendReader = backendReader

	backendWriter := bufio.NewWriter(s.backendConn)

	// Send XCLIENT command to backend with forwarding parameters if enabled.
	// This MUST be done before authenticating.
	useXCLIENT := s.server.remoteUseXCLIENT
	// Override with routing-specific setting if available
	if s.routingInfo != nil {
		useXCLIENT = s.routingInfo.RemoteUseXCLIENT
	}
	if useXCLIENT {
		if err := s.sendForwardingParametersToBackend(backendWriter, backendReader); err != nil {
			s.WarnLog("Failed to send forwarding parameters to backend", "error", err)
			// Continue anyway - forwarding parameters are not critical for functionality
		}
	}

	// Authenticate to backend using master SASL credentials via AUTH PLAIN.
	// Bound the whole exchange with a deadline so a backend that wedges after
	// the greeting cannot hang the session (mirrors the IMAP proxy).
	if err := s.backendConn.SetDeadline(time.Now().Add(greetingTimeout)); err != nil {
		s.backendConn.Close()
		return fmt.Errorf("%w: failed to set auth deadline: %w", server.ErrBackendAuthFailed, err)
	}
	authString := fmt.Sprintf("%s\x00%s\x00%s", s.username, s.server.masterSASLUsername, s.server.masterSASLPassword)
	encoded := base64.StdEncoding.EncodeToString([]byte(authString))

	if _, err := backendWriter.WriteString(fmt.Sprintf("AUTH PLAIN %s\r\n", encoded)); err != nil {
		s.backendConn.Close()
		return fmt.Errorf("%w: failed to send AUTH PLAIN to backend: %w", server.ErrBackendAuthFailed, err)
	}
	if err := backendWriter.Flush(); err != nil {
		s.backendConn.Close()
		return fmt.Errorf("%w: failed to flush AUTH PLAIN to backend: %w", server.ErrBackendAuthFailed, err)
	}

	// Read auth response (bounded)
	authResp, err := server.ReadBoundedLine(backendReader, 1024)
	if err != nil {
		s.backendConn.Close()
		// CRITICAL: Invalidate cache on backend authentication failure
		// This ensures the next request does fresh remotelookup/database lookup
		s.invalidateLookupCache("backend auth read error")
		return fmt.Errorf("%w: failed to read auth response: %w", server.ErrBackendAuthFailed, err)
	}

	if !strings.HasPrefix(authResp, "+OK") {
		s.backendConn.Close()
		// CRITICAL: Invalidate cache on backend authentication failure
		// This ensures the next request does fresh remotelookup/database lookup
		// to pick up backend changes (e.g., domain moved to different server)
		s.invalidateLookupCache("backend auth rejection")
		return fmt.Errorf("%w: %s", server.ErrBackendAuthFailed, strings.TrimSpace(authResp))
	}

	// Clear the auth deadline; the relay phase manages its own deadlines.
	if err := s.backendConn.SetDeadline(time.Time{}); err != nil {
		s.backendConn.Close()
		return fmt.Errorf("%w: failed to clear auth deadline: %w", server.ErrBackendAuthFailed, err)
	}

	s.DebugLog("Authenticated to backend")

	return nil
}

// invalidateLookupCache removes this session's lookup-cache entry so the next
// attempt re-resolves authentication/routing. The cache is keyed on the
// username exactly as the client submitted it (which may carry a token,
// master suffix or +detail), NOT on the resolved s.username.
func (s *POP3ProxySession) invalidateLookupCache(reason string) {
	username := s.submittedUsername
	if username == "" {
		username = s.username
	}
	if username == "" {
		return
	}
	s.server.lookupCache.InvalidateUser(s.server.name, username)
	s.DebugLog("invalidated lookup cache", "reason", reason, "username", username)
}

func (s *POP3ProxySession) startProxying() {
	if s.backendConn == nil {
		s.WarnLog("Backend connection not established - startProxying() returning early")
		return
	}

	defer s.backendConn.Close()

	s.DebugLog("startProxying() called - backend connected to", "backend", s.serverAddr)

	var wg sync.WaitGroup

	s.DebugLog("Created waitgroup")

	// Start activity updater
	activityCtx, activityCancel := context.WithCancel(s.ctx)
	defer activityCancel()
	s.DebugLog("Starting activity updater")
	go s.updateActivityPeriodically(activityCtx)

	// Copy from client to backend with command filtering
	wg.Add(1)
	s.DebugLog("Starting client-to-backend copy goroutine")
	go func() {
		defer wg.Done()
		// If this copy returns, it means the client has closed the connection or there was an error.
		// We use half-close (CloseWrite) to signal EOF to the backend while allowing the backend
		// to finish sending its response. This prevents "broken pipe" errors on QUIT.
		// The backend-to-client goroutine will fully close the connection when it's done reading.
		defer func() {
			// Try to half-close the connection (shutdown writes, keep reads open)
			// This works for both *net.TCPConn and *tls.Conn (Go 1.23+)
			if closeWriter, ok := s.backendConn.(interface{ CloseWrite() error }); ok {
				if err := closeWriter.CloseWrite(); err != nil {
					s.DebugLog("Failed to half-close backend connection", "error", err)
				}
			} else {
				// Fallback for connections that don't support half-close
				s.backendConn.Close()
			}
		}()
		s.filteredCopyClientToBackend()
		s.DebugLog("Client-to-backend copy goroutine exiting")
	}()

	// Copy from backend to client with write deadline protection
	wg.Add(1)
	s.DebugLog("Starting backend-to-client copy goroutine")
	go func() {
		defer wg.Done()
		// If this copy returns, it means the backend has closed the connection or there was an error.
		// We close the client connection to unblock the client-to-backend copy operation.
		// The backend connection is NOT closed here — it is closed after wg.Wait() (via the
		// parent-level defer) to avoid racing with the client-to-backend goroutine's CloseWrite
		// (which would cause "broken pipe" on the storage backend).
		defer func() {
			s.mutex.Lock()
			if !s.gracefulShutdown {
				s.clientConn.Close()
			}
			s.mutex.Unlock()
		}()
		var bytesOut int64
		var err error
		// Use the buffered reader from authentication phase to avoid losing buffered data
		if s.backendReader != nil {
			// Copy from buffered reader with deadline protection
			// This ensures we don't lose any data that was buffered during authentication
			// or any subsequent data that gets read into the buffer during the proxy phase
			bytesOut, err = s.copyReaderToConnWithDeadline(s.clientConn, s.backendReader, "backend-to-client")
		} else {
			// Fallback to direct copy if no buffered reader (shouldn't happen in normal flow)
			bytesOut, err = server.CopyWithDeadline(s.ctx, s.clientConn, s.backendConn, "backend-to-client")
		}
		metrics.BytesThroughput.WithLabelValues("pop3_proxy", "out").Add(float64(bytesOut))
		if err != nil {
			if isClosingError(err) {
				s.DebugLog("backend-to-client copy ended normally (connection closed)", "error", err, "bytes_copied", bytesOut)
			} else {
				s.WarnLog("error copying backend to client", "error", err, "bytes_copied", bytesOut)
			}
		} else {
			s.DebugLog("backend-to-client copy completed successfully", "bytes_copied", bytesOut)
		}
		s.DebugLog("Backend-to-client copy goroutine exiting")
	}()

	// Context cancellation handler - ensures connections are closed when context is cancelled
	// This unblocks the copy goroutines if they're stuck in blocked Read() calls
	// NOTE: This is NOT part of the waitgroup to avoid circular dependency where:
	//   - wg.Wait() waits for this goroutine
	//   - this goroutine waits for ctx.Done()
	//   - ctx.Done() fires when handleConnection() returns
	//   - handleConnection() can't return because it's blocked in wg.Wait()
	s.DebugLog("Starting context cancellation handler goroutine")
	go func() {
		s.DebugLog("Context cancellation handler waiting for ctx.Done()")
		<-s.ctx.Done()
		s.DebugLog("Context cancelled - closing connections")
		s.clientConn.Close()
		s.backendConn.Close()
		s.DebugLog("Context cancellation handler goroutine exiting")
	}()

	s.DebugLog("Waiting for copy goroutines to finish")
	wg.Wait() // Wait for both copy operations to finish
	s.DebugLog("Copy goroutines finished - startProxying() returning")
}

// close closes all connections and unregisters from tracking. It is idempotent:
// teardown can be reached both from the library's Session.Close and from error
// paths during authentication.
func (s *POP3ProxySession) close() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.closed {
		return
	}
	s.closed = true

	// Cancel the session context so any helper goroutines (activity updater,
	// context-cancellation watchdog in startProxying) terminate with the session.
	if s.cancel != nil {
		s.cancel()
	}

	// Remove session from active tracking
	s.server.removeSession(s)

	// Release connection limiter slot IMMEDIATELY (don't wait for goroutine to exit)
	if s.releaseConn != nil {
		s.releaseConn()
		s.releaseConn = nil // Prevent double-release
		s.DebugLog("Connection limit released in close()")
	}

	// Log disconnection at INFO level
	duration := time.Since(s.startTime).Round(time.Second)
	s.InfoLog("disconnected", "duration", duration, "backend", s.serverAddr)

	// Decrement current connections metric
	metrics.ConnectionsCurrent.WithLabelValues("pop3_proxy", s.server.name, s.server.hostname).Dec()

	// Unregister connection SYNCHRONOUSLY to prevent leak
	// CRITICAL: Must be synchronous to ensure unregister completes before session goroutine exits
	// Background goroutine was causing leaks when server shutdown or high load prevented execution
	// NOTE: accountID can be 0 for remotelookup accounts, so we don't check accountID > 0
	// Skip unregister when registration was rejected; otherwise we would
	// decrement a slot this session never held (limit erosion for the account).
	if s.server.connTracker != nil && !s.connRejected {
		// Use a new background context for this final operation, as s.ctx is likely already cancelled.
		// UnregisterConnection is fast (in-memory only), so this won't block for long
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		if err := s.server.connTracker.UnregisterConnection(ctx, s.accountID, "POP3", s.RemoteIP); err != nil {
			// Connection tracking is non-critical monitoring data, so log but continue
			s.WarnLog("Failed to unregister connection", "error", err)
		}
	}

	if s.clientConn != nil {
		s.clientConn.Close()
	}

	if s.backendConn != nil {
		s.backendConn.Close()
	}
}

// registerConnection registers the connection in the database.
func (s *POP3ProxySession) registerConnection() error {
	// Use configured database query timeout for connection tracking (database INSERT)
	// Default to 30 seconds if database is not available (proxy-only mode)
	queryTimeout := 30 * time.Second
	if s.server.rdb != nil {
		queryTimeout = s.server.rdb.GetQueryTimeout()
	}
	ctx, cancel := context.WithTimeout(s.ctx, queryTimeout)
	defer cancel()

	if s.server.connTracker != nil {
		return s.server.connTracker.RegisterConnection(ctx, s.accountID, s.username, "POP3", s.RemoteIP)
	}
	return nil
}

// updateActivityPeriodically updates the connection activity in the database.
func (s *POP3ProxySession) updateActivityPeriodically(ctx context.Context) {
	// If connection tracking is disabled, do nothing and wait for session to end.
	if s.server.connTracker == nil {
		<-ctx.Done()
		return
	}

	// Register for kick notifications
	kickChan := s.server.connTracker.RegisterSession(s.accountID)
	defer s.server.connTracker.UnregisterSession(s.accountID, kickChan)

	for {
		select {
		case <-kickChan:
			// Kick notification received - close connections
			s.InfoLog("connection kicked - disconnecting", "backend", s.serverAddr)
			s.clientConn.Close()
			s.backendConn.Close()
			return
		case <-ctx.Done():
			return
		}
	}
}

func isClosingError(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)
}

// filteredCopyClientToBackend copies data from client to backend, filtering out empty commands
func (s *POP3ProxySession) filteredCopyClientToBackend() {
	// Reuse the pre-auth reader so any command the client pipelined with PASS/AUTH
	// (already buffered during authentication) is forwarded rather than dropped.
	reader := s.clientReader
	if reader == nil {
		reader = bufio.NewReader(s.clientConn)
	}
	writer := bufio.NewWriter(s.backendConn)
	var totalBytesIn int64
	defer func() {
		// Record total bytes when the copy loop exits
		metrics.BytesThroughput.WithLabelValues("pop3_proxy", "in").Add(float64(totalBytesIn))
	}()

	// Write deadline for backend writes (30 seconds should be enough for any command)
	const writeDeadline = 30 * time.Second

	for {
		// Idle control for the authenticated phase. command_timeout is the
		// post-auth idle knob (it also drives the SoraConn idle checker);
		// auth_idle_timeout is the pre-auth knob (2m default) and is only used
		// as a fallback so idle protection is never silently lost. RFC 1939
		// recommends an autologout timer of at least 10 minutes, which the
		// short pre-auth timeout would violate here.
		idleTimeout := s.server.commandTimeout
		if idleTimeout <= 0 {
			idleTimeout = s.server.authIdleTimeout
		}
		if idleTimeout > 0 {
			if err := s.clientConn.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
				s.WarnLog("Failed to set read deadline", "error", err)
				return
			}
		}

		// Bounded read: POP3 commands are tiny (RFC 1939 caps request lines at
		// 512 octets); an unbounded ReadString would let an authenticated
		// client grow the buffer without limit with a newline-less stream.
		line, err := server.ReadBoundedLine(reader, 4096)
		if err != nil {
			if err == server.ErrLineTooLong {
				// net.Conn writes are whole-write atomic, so writing directly to
				// clientConn cannot byte-interleave with the backend-to-client copy.
				_, _ = s.clientConn.Write([]byte("-ERR Line too long, closing connection\r\n"))
				s.WarnLog("relay line too long, closing connection")
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.DebugLog("Idle timeout for authenticated user, closing connection")
				// Account the idle timeout: this relay read deadline uses command_timeout,
				// the same value that drives the SoraConn idle checker, so it pre-empts the
				// checker for authenticated sessions. Without incrementing here, the
				// ConnectionTimeoutsTotal{type="idle"} counter would never move post-auth.
				metrics.ConnectionTimeoutsTotal.WithLabelValues("pop3_proxy", s.server.name, s.server.hostname, "idle").Inc()
				// Mirror the SoraConn OnTimeout notice so the client sees a reason
				// (whole-write atomic, so it cannot interleave with the backend->client copy).
				_, _ = s.clientConn.Write([]byte("-ERR [IN-USE] Idle timeout, please reconnect\r\n"))
				return
			}
			if err != io.EOF && !isClosingError(err) {
				s.WarnLog("error reading from client", "error", err)
			}
			return
		}

		// Check for context cancellation
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		// Skip empty lines (just \r\n or \n)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// Set write deadline to prevent blocking on slow backend
		if err := s.backendConn.SetWriteDeadline(time.Now().Add(writeDeadline)); err != nil {
			s.WarnLog("Failed to set write deadline", "error", err)
			return
		}

		// Forward the command to backend
		n, err := writer.WriteString(line)
		totalBytesIn += int64(n)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.WarnLog("Backend write timeout (slow backend), closing connection")
				return
			}
			if !isClosingError(err) {
				s.WarnLog("error writing to backend", "error", err)
			}
			return
		}

		if err := writer.Flush(); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.WarnLog("Backend flush timeout (slow backend), closing connection")
				return
			}
			if !isClosingError(err) {
				s.WarnLog("error flushing to backend", "error", err)
			}
			return
		}
	}
}

// copyReaderToConnWithDeadline copies data from a buffered reader to a connection with write deadline protection.
// This is used for backend-to-client copying when the backend connection has a buffered reader
// from the authentication phase. We must read from the buffered reader to avoid losing any data
// that was buffered but not yet read.
func (s *POP3ProxySession) copyReaderToConnWithDeadline(dst net.Conn, src *bufio.Reader, direction string) (int64, error) {
	const writeDeadline = 30 * time.Second
	// Generous backend read backstop: a steadily-streaming backend refreshes it
	// every iteration, so it only trips on prolonged backend silence — e.g. a
	// backend wedged mid-RETR that would otherwise block until the absolute
	// session timeout. It is longer than the client-side idle timeout (which
	// drops normal idle sessions first), so it never fires in normal use.
	const backendReadDeadline = 30 * time.Minute
	var totalBytes int64
	buf := make([]byte, 32*1024)
	nextDeadline := time.Now()

	// Enable TCP keepalive on the backend connection to detect dead peers
	// (mirrors CopyWithDeadline and the IMAP proxy's backend-to-client copy).
	if tcpConn, ok := s.backendConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(2 * time.Minute)
	}

	for {
		select {
		case <-s.ctx.Done():
			return totalBytes, s.ctx.Err()
		default:
		}

		if s.backendConn != nil {
			if err := s.backendConn.SetReadDeadline(time.Now().Add(backendReadDeadline)); err != nil {
				return totalBytes, fmt.Errorf("failed to set backend read deadline: %w", err)
			}
		}

		nr, err := src.Read(buf)
		if nr > 0 {
			// Only update write deadline once per second to reduce syscall frequency
			now := time.Now()
			if now.After(nextDeadline) {
				if err := dst.SetWriteDeadline(now.Add(writeDeadline)); err != nil {
					return totalBytes, fmt.Errorf("failed to set write deadline: %w", err)
				}
				nextDeadline = now.Add(time.Second)
			}

			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				totalBytes += int64(nw)
			}
			if ew != nil {
				if netErr, ok := ew.(net.Error); ok && netErr.Timeout() {
					return totalBytes, fmt.Errorf("write timeout in %s: %w", direction, ew)
				}
				return totalBytes, ew
			}
			if nr != nw {
				return totalBytes, io.ErrShortWrite
			}
		}
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return totalBytes, fmt.Errorf("read timeout in %s after %v (connection appears stale): %w", direction, backendReadDeadline, err)
			}
			if err != io.EOF {
				return totalBytes, err
			}
			return totalBytes, nil
		}
	}
}

func checkMasterCredential(provided string, actual []byte) bool {
	return subtle.ConstantTimeCompare([]byte(provided), actual) == 1
}

// Implement pop3server.Session and related interfaces

func (s *POP3ProxySession) Close() error {
	s.close()
	return nil
}

func (s *POP3ProxySession) Login(ctx context.Context, username, password string) error {
	s.username = username
	if err := s.authenticate(username, password); err != nil {
		var rateLimitErr *server.RateLimitError
		if errors.As(err, &rateLimitErr) {
			return &pop3server.Error{Code: "AUTH", Message: "Authentication failed", Close: true}
		}
		if server.IsTemporaryAuthFailure(err) {
			return &pop3server.Error{Code: "SYS/TEMP", Message: "Service temporarily unavailable, please try again later"}
		}
		if server.IsBackendError(err) {
			return &pop3server.Error{Code: "SYS/TEMP", Message: "Backend server temporarily unavailable"}
		}
		return &pop3server.Error{Code: "AUTH", Message: "Authentication failed"}
	}

	if err := s.registerConnection(); err != nil {
		s.InfoLog("connection rejected by connection tracker", "error", err)
		s.connRejected = true
		return &pop3server.Error{Code: "SYS/TEMP", Message: "Too many connections", Close: true}
	}

	clientConn, clientReader, err := s.pop3Conn.Hijack()
	if err != nil {
		// The library still owns the client connection; close only what we own
		// and let the normal teardown (Session.Close) do the rest.
		if s.backendConn != nil {
			s.backendConn.Close()
		}
		s.WarnLog("failed to hijack client connection", "error", err)
		return &pop3server.Error{Code: "SYS/TEMP", Message: "Service temporarily unavailable, please try again later", Close: true}
	}

	s.clientConn = clientConn
	s.clientReader = clientReader

	// Write "+OK Authentication successful" response to client
	writer := bufio.NewWriter(clientConn)
	writer.WriteString("+OK Authentication successful\r\n")
	writer.Flush()

	s.authenticated = true

	// Clear the read deadline before moving to the proxying phase, which sets its own.
	if s.server.authIdleTimeout > 0 {
		if err := s.clientConn.SetReadDeadline(time.Time{}); err != nil {
			s.WarnLog("Failed to clear read deadline", "error", err)
		}
	}

	// Run the relay synchronously: the library's command loop is parked in this
	// call until the relay finishes, and returning triggers session teardown
	// (Session.Close closes both connections and releases the limiter slot), so
	// the relay must complete first.
	s.startProxying()

	return nil
}

func (s *POP3ProxySession) AuthenticatePlain(ctx context.Context, identity, username, password string) error {
	// The proxy performs no impersonation of its own: an authorization identity
	// is only meaningful on the backend, where the proxy re-authenticates with
	// master SASL credentials. Reject mismatched identities rather than silently
	// dropping them (same policy as the previous implementation).
	if identity != "" && identity != username {
		return &pop3server.Error{Code: "AUTH", Message: "Authorization identity not supported on proxy (configure master SASL on backend)"}
	}
	return s.Login(ctx, username, password)
}

func (s *POP3ProxySession) AuthenticateMechanisms() []string {
	return []string{"PLAIN"}
}

// The proxy advertises LANG/UTF8 in its pre-auth CAPA because the sora
// backends honor them: a client that caches this CAPA must not conclude they
// are unsupported. The commands themselves are AUTHORIZATION-state (RFC 6856)
// and are answered locally; after authentication the connection is a raw relay
// and the backend answers everything.

func (s *POP3ProxySession) EnableUTF8(ctx context.Context) error {
	return nil
}

func (s *POP3ProxySession) SetLanguage(ctx context.Context, lang string) (string, error) {
	langTag := strings.ToLower(lang)
	if langTag != "en" && langTag != "*" && langTag != "i-default" {
		return "", &pop3server.Error{Message: "Unsupported language"}
	}
	if langTag == "i-default" {
		return "i-default", nil
	}
	return "en", nil
}

func (s *POP3ProxySession) ListLanguages(ctx context.Context) ([]pop3server.LanguageInfo, error) {
	return []pop3server.LanguageInfo{
		{Tag: "en", Description: "English"},
		{Tag: "i-default", Description: "Default"},
	}, nil
}

func (s *POP3ProxySession) Stat(ctx context.Context) (int, int64, error) {
	return 0, 0, errors.New("not implemented")
}

func (s *POP3ProxySession) List(ctx context.Context, msg int) ([]pop3.MessageInfo, error) {
	return nil, errors.New("not implemented")
}

func (s *POP3ProxySession) Uidl(ctx context.Context, msg int) ([]pop3.MessageUidl, error) {
	return nil, errors.New("not implemented")
}

func (s *POP3ProxySession) Retr(ctx context.Context, msgNum int) (io.ReadCloser, error) {
	return nil, errors.New("not implemented")
}

func (s *POP3ProxySession) Top(ctx context.Context, msgNum int, lines int) (io.ReadCloser, error) {
	return nil, errors.New("not implemented")
}

func (s *POP3ProxySession) Dele(ctx context.Context, msgNum int) error {
	return errors.New("not implemented")
}

func (s *POP3ProxySession) Rset(ctx context.Context) error {
	return errors.New("not implemented")
}

func (s *POP3ProxySession) Noop(ctx context.Context) error {
	return errors.New("not implemented")
}

func (s *POP3ProxySession) Quit(ctx context.Context) (int, error) {
	return 0, errors.New("not implemented")
}
