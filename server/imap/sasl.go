package imap

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-sasl"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
)

// AuthenticateMechanisms returns a list of supported SASL mechanisms
func (s *IMAPSession) AuthenticateMechanisms() []string {
	return []string{"PLAIN"}
}

// Authenticate handles SASL authentication for the IMAPSession
func (s *IMAPSession) Authenticate(mechanism string) (sasl.Server, error) {
	authStart := time.Now()
	s.DebugLog("authentication attempt", "mechanism", mechanism)

	switch mechanism {
	case "PLAIN":
		return sasl.NewPlainServer(func(identity, username, password string) error {
			// SASL PLAIN payload: [authorization-identity] \0 authentication-identity \0 password
			// callback `identity`: authorization-identity (user to act as, can be empty)
			// callback `username`: authentication-identity (user whose credentials are provided)
			// callback `password`: password for authentication-identity

			// Get the underlying net.Conn for proxy-aware rate limiting
			netConn := s.conn.NetConn()

			// Create proxy info from session data
			var proxyInfo *server.ProxyProtocolInfo
			if s.ProxyIP != "" {
				// This is a proxied connection, reconstruct proxy info
				proxyInfo = &server.ProxyProtocolInfo{
					SrcIP: s.RemoteIP,
				}
			}

			// Apply progressive authentication delay BEFORE any other checks
			remoteAddr := &server.StringAddr{Addr: s.RemoteIP}
			server.ApplyAuthenticationDelay(s.ctx, s.server.authLimiter, remoteAddr, "IMAP-SASL")

			// Check authentication rate limiting after delay
			if s.server.authLimiter != nil {
				targetUser := username
				if identity != "" {
					targetUser = identity // Use authorization identity if provided
				}
				if err := s.server.authLimiter.CanAttemptAuthWithProxy(s.ctx, netConn, proxyInfo, targetUser); err != nil {
					s.DebugLog("SASL PLAIN rate limited", "error", err)
					return &imap.Error{
						Type: imap.StatusResponseTypeNo,
						Code: imap.ResponseCodeAuthenticationFailed,
						Text: "Too many authentication attempts. Please try again later.",
					}
				}
			}

			s.DebugLog("SASL PLAIN", "authorization_id", identity, "authentication_id", username)

			// Parse username to check for suffix (master username or remotelookup token)
			usernameParsed, parseErr := server.NewAddress(username)

			// 1. Check for Master Username Authentication (user@domain.com@MASTER_USERNAME)
			if parseErr == nil && len(s.server.masterUsername) > 0 && usernameParsed.HasSuffix() && checkMasterCredential(usernameParsed.Suffix(), s.server.masterUsername) {
				// Suffix matches MasterUsername, authenticate with MasterPassword
				if checkMasterCredential(password, s.server.masterPassword) {
					// Determine target user to impersonate
					targetUserToImpersonate := identity
					if targetUserToImpersonate == "" {
						// No authorization identity provided, use base address from username
						targetUserToImpersonate = usernameParsed.BaseAddress()
					}

					s.DebugLog("master username authenticated, attempting to impersonate", "master_username", usernameParsed.Suffix(), "target_user", targetUserToImpersonate)

					// Parse target user address
					address, err := server.NewAddress(targetUserToImpersonate)
					if err != nil {
						s.DebugLog("failed to parse impersonation target user", "target_user", targetUserToImpersonate, "error", err)
						metrics.AuthenticationAttempts.WithLabelValues("imap", s.server.name, s.server.hostname, "failure").Inc()
						return &imap.Error{
							Type: imap.StatusResponseTypeNo,
							Code: imap.ResponseCodeAuthorizationFailed,
							Text: "Impersonation target user address is not in the correct format.",
						}
					}

					AccountID, err := s.server.rdb.GetAccountIDByAddressWithRetry(s.ctx, address.BaseAddress())
					if err != nil {
						s.DebugLog("failed to get account ID for impersonation target", "target_user", targetUserToImpersonate, "error", err)

						// Check if error is due to context cancellation (server shutdown)
						if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
							s.InfoLog("master username auth cancelled due to server shutdown")
							return &imap.Error{
								Type: imap.StatusResponseTypeNo,
								Code: imap.ResponseCodeUnavailable,
								Text: server.ErrServerShuttingDown.Error(),
							}
						}

						metrics.AuthenticationAttempts.WithLabelValues("imap", s.server.name, s.server.hostname, "failure").Inc()
						return &imap.Error{
							Type: imap.StatusResponseTypeNo,
							Code: imap.ResponseCodeAuthorizationFailed,
							Text: "Impersonation target user account not found.",
						}
					}

					// Get primary email address for this account
					// User.Address should always be the primary address
					primaryAddr, primErr := s.server.rdb.GetPrimaryEmailForAccountWithRetry(s.ctx, AccountID)
					if primErr != nil {
						return s.internalError("failed to get primary email: %v", primErr)
					}

					s.IMAPUser = NewIMAPUser(primaryAddr, AccountID)
					s.Session.User = &s.IMAPUser.User
					// Ensure default mailboxes for the impersonated user
					if dbErr := s.server.rdb.CreateDefaultMailboxesWithRetry(s.ctx, AccountID); dbErr != nil {
						return s.internalError("failed to prepare impersonated user session: %v", dbErr)
					}

					s.server.authenticatedConnections.Add(1)
					duration := time.Since(authStart)

					// Log authentication with alias detection
					loginAddr := address.BaseAddress()
					if loginAddr != primaryAddr.FullAddress() {
						s.InfoLog("authentication successful", "login_address", loginAddr, "primary_address", primaryAddr.FullAddress(), "account_id", AccountID, "cached", false, "method", "master", "duration", fmt.Sprintf("%.3fs", duration.Seconds()))
					} else {
						s.InfoLog("authentication successful", "address", loginAddr, "account_id", AccountID, "cached", false, "method", "master", "duration", fmt.Sprintf("%.3fs", duration.Seconds()))
					}

					metrics.AuthenticationAttempts.WithLabelValues("imap", s.server.name, s.server.hostname, "success").Inc()
					metrics.AuthenticatedConnectionsCurrent.WithLabelValues("imap", s.server.name, s.server.hostname).Inc()

					// Trigger cache warmup for the authenticated user (if configured)
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

				// Record failed master password authentication
				metrics.AuthenticationAttempts.WithLabelValues("imap", s.server.name, s.server.hostname, "failure").Inc()
				if s.server.authLimiter != nil {
					s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, usernameParsed.BaseAddress(), false)
				}

				// Master username suffix was provided but master password was wrong - fail immediately
				return &imap.Error{
					Type: imap.StatusResponseTypeNo,
					Code: imap.ResponseCodeAuthenticationFailed,
					Text: "Invalid master credentials",
				}
			}

			// 2. Check for Master SASL Authentication (traditional SASL proxy authentication)
			if len(s.server.masterSASLUsername) > 0 && len(s.server.masterSASLPassword) > 0 {
				// Check if the provided authentication identity and password match the server's master SASL credentials
				if checkMasterCredential(username, s.server.masterSASLUsername) &&
					checkMasterCredential(password, s.server.masterSASLPassword) {

					// Master SASL credentials match. The user to log in as is the authorization-identity.
					targetUserToImpersonate := identity
					if targetUserToImpersonate == "" {
						s.DebugLog("master SASL authentication successful but no authorization identity provided", "username", username)
						metrics.AuthenticationAttempts.WithLabelValues("imap", s.server.name, s.server.hostname, "failure").Inc()
						return &imap.Error{
							Type: imap.StatusResponseTypeNo,
							Code: imap.ResponseCodeAuthorizationFailed,
							Text: "Master SASL login requires an authorization identity (target user to impersonate).",
						}
					}

					s.DebugLog("master SASL user authenticated, attempting to impersonate", "username", username, "target_user", targetUserToImpersonate)

					// Log in as the targetUserToImpersonate.
					// For master impersonation, we directly establish the session for them.
					address, err := server.NewAddress(targetUserToImpersonate)
					if err != nil {
						s.DebugLog("failed to parse impersonation target user", "target_user", targetUserToImpersonate, "error", err)
						metrics.AuthenticationAttempts.WithLabelValues("imap", s.server.name, s.server.hostname, "failure").Inc()
						return &imap.Error{
							Type: imap.StatusResponseTypeNo,
							Code: imap.ResponseCodeAuthorizationFailed,
							Text: "Impersonation target user address is not in the correct format.",
						}
					}

					AccountID, err := s.server.rdb.GetAccountIDByAddressWithRetry(s.ctx, address.BaseAddress())
					if err != nil {
						s.DebugLog("failed to get account ID for impersonation target", "target_user", targetUserToImpersonate, "error", err)

						// Check if error is due to context cancellation (server shutdown)
						if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
							s.InfoLog("master SASL auth cancelled due to server shutdown")
							return &imap.Error{
								Type: imap.StatusResponseTypeNo,
								Code: imap.ResponseCodeUnavailable,
								Text: server.ErrServerShuttingDown.Error(),
							}
						}

						metrics.AuthenticationAttempts.WithLabelValues("imap", s.server.name, s.server.hostname, "failure").Inc()
						return &imap.Error{
							Type: imap.StatusResponseTypeNo,
							Code: imap.ResponseCodeAuthorizationFailed, // Target user does not exist
							Text: "Impersonation target user account not found.",
						}
					}

					// Get primary email address for this account
					// User.Address should always be the primary address
					primaryAddr, primErr := s.server.rdb.GetPrimaryEmailForAccountWithRetry(s.ctx, AccountID)
					if primErr != nil {
						return s.internalError("failed to get primary email: %v", primErr)
					}

					s.IMAPUser = NewIMAPUser(primaryAddr, AccountID)
					s.Session.User = &s.IMAPUser.User
					// Ensure default mailboxes for the impersonated user
					if dbErr := s.server.rdb.CreateDefaultMailboxesWithRetry(s.ctx, AccountID); dbErr != nil {
						return s.internalError("failed to prepare impersonated user session: %v", dbErr)
					}

					s.server.authenticatedConnections.Add(1)
					duration := time.Since(authStart)

					// Log authentication with alias detection
					loginAddr := address.BaseAddress()
					if loginAddr != primaryAddr.FullAddress() {
						s.InfoLog("authentication successful", "login_address", loginAddr, "primary_address", primaryAddr.FullAddress(), "account_id", AccountID, "cached", false, "method", "master", "duration", fmt.Sprintf("%.3fs", duration.Seconds()))
					} else {
						s.InfoLog("authentication successful", "address", loginAddr, "account_id", AccountID, "cached", false, "method", "master", "duration", fmt.Sprintf("%.3fs", duration.Seconds()))
					}

					metrics.AuthenticationAttempts.WithLabelValues("imap", s.server.name, s.server.hostname, "success").Inc()
					metrics.AuthenticatedConnectionsCurrent.WithLabelValues("imap", s.server.name, s.server.hostname).Inc()

					// Trigger cache warmup for the authenticated user (if configured)
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
			}

			// 3. Regular User Authentication
			// The user identified by `username` (authentication-identity) is logging in with `password`.
			// If `identity` (authorization-identity) is provided and is different from `username`,
			// it's a proxy request by a non-master user. This is typically disallowed.
			if identity != "" && identity != username {
				s.DebugLog("proxy login not allowed for non-master users", "username", username, "identity", identity)
				return &imap.Error{
					Type: imap.StatusResponseTypeNo,
					Code: imap.ResponseCodeAuthorizationFailed,
					Text: "Proxy login not permitted for this user.",
				}
			}

			// Authenticate as `username` (authentication-identity).
			s.DebugLog("proceeding with regular authentication", "username", username)
			return s.Login(username, password)
		}), nil
	default:
		s.DebugLog("unsupported authentication mechanism", "mechanism", mechanism)
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAuthenticationFailed,
			Text: "Unsupported authentication mechanism",
		}
	}
}
