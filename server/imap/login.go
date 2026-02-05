package imap

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
)

func (s *IMAPSession) Login(address, password string) error {
	authStart := time.Now()

	// Reject empty passwords immediately - no cache lookup, no rate limiting needed
	// Empty passwords are never valid under any condition
	if password == "" {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAuthenticationFailed,
			Text: "Authentication failed",
		}
	}

	// Get the underlying net.Conn for proxy-aware rate limiting
	netConn := s.conn.NetConn()

	// Create proxy info from session data
	var proxyInfo *server.ProxyProtocolInfo
	if s.ProxyIP != "" {
		// This is a proxied connection, reconstruct proxy info
		proxyInfo = &server.ProxyProtocolInfo{
			SrcIP: s.RemoteIP,
			// Note: ProxyIP is not a field in ProxyProtocolInfo,
			// but GetConnectionIPs will extract the proxy from the connection
		}
	}

	// Apply progressive authentication delay BEFORE any other checks
	// Create a fake net.Addr from the RemoteIP for delay calculation
	remoteAddr := &server.StringAddr{Addr: s.RemoteIP}
	server.ApplyAuthenticationDelay(s.ctx, s.server.authLimiter, remoteAddr, "IMAP-LOGIN")

	// Check authentication rate limiting after delay using proxy-aware method
	if s.server.authLimiter != nil {
		if err := s.server.authLimiter.CanAttemptAuthWithProxy(s.ctx, netConn, proxyInfo, address); err != nil {
			// Check if this is a rate limit error
			var rateLimitErr *server.RateLimitError
			if errors.As(err, &rateLimitErr) {
				logger.Info("IMAP: Rate limit exceeded",
					"address", address,
					"ip", rateLimitErr.IP,
					"reason", rateLimitErr.Reason,
					"failure_count", rateLimitErr.FailureCount,
					"blocked_until", rateLimitErr.BlockedUntil.Format(time.RFC3339))

				// Track rate limiting as a specific error type
				metrics.ProtocolErrors.WithLabelValues("imap", "LOGIN", "rate_limited", "client_error").Inc()

				// Send BYE with ALERT per RFC 3501
				// This immediately closes the connection with an informative message
				return &imap.Error{
					Type: imap.StatusResponseTypeBye,
					Code: imap.ResponseCodeAlert,
					Text: "Too many failed authentication attempts. Please try again later.",
				}
			}

			// Unknown rate limiting error (shouldn't happen, but handle gracefully)
			s.DebugLog("rate limited", "error", err)
			metrics.ProtocolErrors.WithLabelValues("imap", "LOGIN", "rate_limited", "client_error").Inc()
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeAuthenticationFailed,
				Text: "Too many authentication attempts. Please try again later.",
			}
		}
	}

	// Parse address with potential suffix (master username or remotelookup token)
	addressParsed, err := server.NewAddress(address)
	if err != nil {
		s.DebugLog("failed to parse address", "error", err)
		// Track invalid address format as client error
		metrics.ProtocolErrors.WithLabelValues("imap", "LOGIN", "invalid_address", "client_error").Inc()
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAuthenticationFailed,
			Text: "Address not in the correct format",
		}
	}

	// Master username authentication: user@domain.com@MASTER_USERNAME
	// Check if suffix matches configured MasterUsername
	if len(s.server.masterUsername) > 0 && addressParsed.HasSuffix() && checkMasterCredential(addressParsed.Suffix(), s.server.masterUsername) {
		// Suffix matches MasterUsername, authenticate with MasterPassword
		if checkMasterCredential(password, s.server.masterPassword) {
			// Use base address (without suffix) to get account
			AccountID, err := s.server.rdb.GetAccountIDByAddressWithRetry(s.ctx, addressParsed.BaseAddress())
			if err != nil {
				return err
			}

			// Get primary email address for this account
			// User.Address should always be the primary address (not the login address with suffix)
			primaryAddr, err := s.server.rdb.GetPrimaryEmailForAccountWithRetry(s.ctx, AccountID)
			if err != nil {
				return s.internalError("failed to get primary email: %v", err)
			}

			s.IMAPUser = NewIMAPUser(primaryAddr, AccountID)
			s.Session.User = &s.IMAPUser.User

			s.server.authenticatedConnections.Add(1)
			duration := time.Since(authStart)

			// Log authentication with alias detection
			loginAddr := addressParsed.BaseAddress()
			if loginAddr != primaryAddr.FullAddress() {
				s.InfoLog("authentication successful", "login_address", loginAddr, "primary_address", primaryAddr.FullAddress(), "account_id", AccountID, "cached", false, "method", "master", "duration", fmt.Sprintf("%.3fs", duration.Seconds()))
			} else {
				s.InfoLog("authentication successful", "address", loginAddr, "account_id", AccountID, "cached", false, "method", "master", "duration", fmt.Sprintf("%.3fs", duration.Seconds()))
			}

			// Prometheus metrics - successful authentication
			metrics.AuthenticationAttempts.WithLabelValues("imap", s.server.name, s.server.hostname, "success").Inc()
			metrics.AuthenticatedConnectionsCurrent.WithLabelValues("imap", s.server.name, s.server.hostname).Inc()

			// Record successful authentication
			if s.server.authLimiter != nil {
				s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, addressParsed.BaseAddress(), true)
			}

			// Register connection for tracking
			if err := s.registerConnection(addressParsed.BaseAddress()); err != nil {
				// Connection limit reached - undo authentication and reject
				metrics.AuthenticatedConnectionsCurrent.WithLabelValues("imap", s.server.name, s.server.hostname).Dec()
				s.IMAPUser = nil
				s.Session.User = nil
				return &imap.Error{
					Type: imap.StatusResponseTypeNo,
					Code: imap.ResponseCodeLimit,
					Text: "Maximum connections reached",
				}
			}

			// Start termination poller to check for kick commands
			s.startTerminationPoller()

			// Clear auth idle timeout after successful authentication
			// Post-auth timeouts are handled by SoraConn (command_timeout)
			if s.server.authIdleTimeout > 0 {
				if err := netConn.SetReadDeadline(time.Time{}); err != nil {
					s.WarnLog("failed to clear auth idle timeout", "error", err)
				}
			}

			return nil
		}

		// Record failed master password authentication
		metrics.AuthenticationAttempts.WithLabelValues("imap", s.server.name, s.server.hostname, "failure").Inc()
		if s.server.authLimiter != nil {
			s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, addressParsed.BaseAddress(), false)
		}

		// Master username suffix was provided but master password was wrong - fail immediately
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAuthenticationFailed,
			Text: "Invalid master credentials",
		}
	}

	// Regular authentication - use the already parsed address
	// If it has a suffix but didn't match MasterUsername, fall through to regular auth
	// (this allows the suffix to be used for remotelookup in proxy scenarios)

	s.DebugLog("authentication attempt", "address", addressParsed.BaseAddress())

	// Use base address (without +detail and without suffix) for authentication
	AccountID, err := s.server.Authenticate(s.ctx, addressParsed.BaseAddress(), password)
	if err != nil {
		s.DebugLog("authentication failed", "error", err)

		// Check if error is due to context cancellation (server shutdown)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			// Server is shutting down - return temporary failure without recording as auth failure
			s.InfoLog("authentication cancelled due to server shutdown")
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeUnavailable,
				Text: server.ErrServerShuttingDown.Error(),
			}
		}

		// Record failed authentication
		metrics.AuthenticationAttempts.WithLabelValues("imap", s.server.name, s.server.hostname, "failure").Inc()
		if s.server.authLimiter != nil {
			s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, addressParsed.BaseAddress(), false)
		}

		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAuthenticationFailed,
			Text: "Invalid address or password",
		}
	}

	// Ensure default mailboxes (INBOX/Drafts/Sent/Spam/Trash) exist
	err = s.server.rdb.CreateDefaultMailboxesWithRetry(s.ctx, AccountID)
	if err != nil {
		return s.internalError("failed to create default mailboxes: %v", err)
	}

	// Get primary email address for this account
	// User.Address should always be the primary address (not the login address with +alias)
	primaryAddr, err := s.server.rdb.GetPrimaryEmailForAccountWithRetry(s.ctx, AccountID)
	if err != nil {
		return s.internalError("failed to get primary email: %v", err)
	}

	s.IMAPUser = NewIMAPUser(primaryAddr, AccountID)
	s.Session.User = &s.IMAPUser.User

	s.server.authenticatedConnections.Add(1)
	duration := time.Since(authStart)

	// Log authentication with alias detection
	loginAddr := addressParsed.BaseAddress()
	if loginAddr != primaryAddr.FullAddress() {
		s.InfoLog("authentication successful", "login_address", loginAddr, "primary_address", primaryAddr.FullAddress(), "account_id", AccountID, "cached", false, "method", "main_db", "duration", fmt.Sprintf("%.3fs", duration.Seconds()))
	} else {
		s.InfoLog("authentication successful", "address", loginAddr, "account_id", AccountID, "cached", false, "method", "main_db", "duration", fmt.Sprintf("%.3fs", duration.Seconds()))
	}

	// Prometheus metrics - successful authentication
	metrics.AuthenticationAttempts.WithLabelValues("imap", s.server.name, s.server.hostname, "success").Inc()
	metrics.AuthenticatedConnectionsCurrent.WithLabelValues("imap", s.server.name, s.server.hostname).Inc()

	// Domain and user tracking
	metrics.TrackDomainConnection("imap", addressParsed.Domain())
	metrics.TrackUserActivity("imap", addressParsed.BaseAddress(), "connection", 1)

	// Record successful authentication
	if s.server.authLimiter != nil {
		s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, addressParsed.BaseAddress(), true)
	}

	// Register connection for tracking
	if err := s.registerConnection(addressParsed.BaseAddress()); err != nil {
		// Connection limit reached - undo authentication and reject
		metrics.AuthenticatedConnectionsCurrent.WithLabelValues("imap", s.server.name, s.server.hostname).Dec()
		s.IMAPUser = nil
		s.Session.User = nil
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeLimit,
			Text: "Maximum connections reached",
		}
	}

	// Start termination poller to check for kick commands
	s.startTerminationPoller()

	// Trigger cache warmup for the authenticated user
	s.triggerCacheWarmup()

	// Clear auth idle timeout after successful authentication
	// Post-auth timeouts are handled by SoraConn (command_timeout)
	if s.server.authIdleTimeout > 0 {
		if err := netConn.SetReadDeadline(time.Time{}); err != nil {
			s.WarnLog("failed to clear auth idle timeout", "error", err)
		}
	}

	return nil
}

func checkMasterCredential(provided string, actual []byte) bool {
	return subtle.ConstantTimeCompare([]byte(provided), actual) == 1
}
