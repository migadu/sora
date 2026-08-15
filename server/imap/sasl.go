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
			if err := server.ApplyAuthenticationDelay(s.ctx, s.server.authLimiter, remoteAddr, "IMAP-SASL"); err != nil {
				if errors.Is(err, server.ErrDelayQueueFull) {
					// Delay queue full - reject immediately to prevent goroutine exhaustion
					s.InfoLog("delay queue full, rejecting connection", "username", username)
					return &imap.Error{
						Type: imap.StatusResponseTypeBye,
						Code: imap.ResponseCodeAlert,
						Text: "Too many concurrent authentication attempts. Please try again later.",
					}
				}
				// Context cancelled or other error
				return &imap.Error{
					Type: imap.StatusResponseTypeBye,
					Text: "Connection closed",
				}
			}

			// Rate-limit key for this AUTHENTICATE command. Derived from the
			// AUTHENTICATION identity (the credential actually being verified), never
			// from the authorization identity: the latter is the account being
			// impersonated, so keying on it would make a failed master credential land
			// a block on the victim. A master SASL username is not an address and
			// keeps a stable key of its own; the master form
			// "user@domain.com@MASTERUSER" carries the target INSIDE the
			// authentication identity and canonicalises to it, so it is keyed on the
			// master credential instead (AuthRateLimitKeyWithMaster). Must match every
			// RecordAuthAttempt* key used below.
			authKey := server.AuthRateLimitKeyWithMaster(username, s.server.masterUsername)

			// Check authentication rate limiting after delay
			if s.server.authLimiter != nil {
				if err := s.server.authLimiter.CanAttemptAuthWithProxy(s.ctx, netConn, proxyInfo, authKey); err != nil {
					s.DebugLog("SASL PLAIN rate limited", "error", err)
					// Same response as a bad-credential failure (matches Login below) so the
					// rate-limit state isn't an observable oracle. (security-audit M14)
					return authFailedError()
				}
			}

			s.DebugLog("SASL PLAIN", "authorization_id", identity, "authentication_id", username)

			// Parse username to check for suffix (master username or remotelookup token)
			usernameParsed, parseErr := server.NewAddress(username)

			// 1. Check for Master Username Authentication (user@domain.com@MASTER_USERNAME)
			if parseErr == nil && len(s.server.masterUsername) > 0 && usernameParsed.HasSuffix() && checkMasterCredential(usernameParsed.Suffix(), s.server.masterUsername) {
				// Suffix matches MasterUsername, authenticate with MasterPassword
				if len(s.server.masterPassword) > 0 && checkMasterCredential(password, s.server.masterPassword) {
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
						// A rejected impersonation target is answered exactly like a bad
						// credential, and recorded exactly like one. This site is reachable
						// ONLY with the correct master password, so a distinguishable reply
						// — or a failure the master credential is not charged for, which
						// diverges from a wrong password at the block threshold — confirms a
						// guessed tenant-wide password without completing an authentication.
						// The real reason stays in the log for the operator.
						s.WarnLog("impersonation target rejected (address not in the correct format)", "target_user", targetUserToImpersonate, "error", err)
						metrics.AuthenticationAttempts.WithLabelValues("imap", s.server.name, s.server.hostname, "failure").Inc()
						if s.server.authLimiter != nil {
							s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, authKey, false)
						}
						return authFailedError()
					}

					AccountID, err := s.server.rdb.GetActiveAccountIDByAddressWithRetry(s.ctx, address.BaseAddress())
					if err != nil {
						// Check if error is due to context cancellation (server shutdown)
						if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
							s.InfoLog("master username auth cancelled due to server shutdown")
							return &imap.Error{
								Type: imap.StatusResponseTypeNo,
								Code: imap.ResponseCodeUnavailable,
								Text: server.ErrServerShuttingDown.Error(),
							}
						}

						// Same reply and same accounting as a bad credential (see above).
						s.WarnLog("impersonation target rejected (account not found)", "target_user", targetUserToImpersonate, "error", err)
						metrics.AuthenticationAttempts.WithLabelValues("imap", s.server.name, s.server.hostname, "failure").Inc()
						if s.server.authLimiter != nil {
							s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, authKey, false)
						}
						return authFailedError()
					}

					// Get primary email address for this account
					// User.Address should always be the primary address
					primaryAddr, primErr := s.server.rdb.GetPrimaryEmailForAccountWithRetry(s.ctx, AccountID)
					if primErr != nil {
						return s.internalError("failed to get primary email: %v", primErr)
					}

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

					// IMPORTANT: Set user state AFTER incrementing both counters to prevent race condition
					// If session closes between counter increments and user state setting, cleanup won't decrement
					s.IMAPUser = NewIMAPUser(primaryAddr, AccountID)
					s.Session.User = &s.IMAPUser.User

					// Register connection for tracking
					if err := s.registerConnection(address.BaseAddress()); err != nil {
						// Connection limit reached - undo authentication and reject
						s.server.authenticatedConnections.Add(-1)
						metrics.AuthenticatedConnectionsCurrent.WithLabelValues("imap", s.server.name, s.server.hostname).Dec()
						s.IMAPUser = nil
						s.Session.User = nil
						return &imap.Error{
							Type: imap.StatusResponseTypeNo,
							Code: imap.ResponseCodeLimit,
							Text: "Maximum connections reached",
						}
					}

					// Start termination poller to check for kick commands. Required on
					// every authenticated path: it is the only delivery path for kicks,
					// and imapproxy authenticates to its backends with exactly this
					// master AUTHENTICATE, so without it proxied backend sessions are
					// tracked but unkickable.
					s.startTerminationPoller()

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
					s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, authKey, false)
				}

				// Answer exactly like any other bad credential: a distinct reply is
				// reachable with only the master USERNAME and confirms it to an
				// attacker (see login.go). Reason kept for the operator at WARN.
				s.WarnLog("master username authentication failed (invalid master password)")
				return authFailedError()
			}

			// 2. Check for Master SASL Authentication (traditional SASL proxy authentication)
			// Only ever a master login when the client asked to act as somebody: the
			// authorization identity IS the impersonation target. A submission without
			// one cannot be a master login, so it is not answered from here at all —
			// see the no-authorization-identity note below.
			if identity != "" && len(s.server.masterSASLUsername) > 0 && len(s.server.masterSASLPassword) > 0 {
				// Check if the provided authentication identity and password match the server's master SASL credentials
				if checkMasterCredential(username, s.server.masterSASLUsername) &&
					checkMasterCredential(password, s.server.masterSASLPassword) {

					// Network gate: master SASL is a tenant-wide impersonation capability,
					// so it may optionally be restricted to the proxy hosts. Anchored to the
					// real socket peer (NetConn().RemoteAddr()), which cannot be forged via
					// PROXY/XCLIENT/ID forwarding (those only rewrite s.RemoteIP/s.ProxyIP).
					if !s.server.masterSASLGate.Allowed(netConn.RemoteAddr()) {
						s.WarnLog("master SASL credentials valid but source not in master_sasl_allowed_networks; rejecting", "peer", server.GetAddrString(netConn.RemoteAddr()))
						metrics.AuthenticationAttempts.WithLabelValues("imap", s.server.name, s.server.hostname, "failure").Inc()
						// Recorded and answered exactly like a wrong master password.
						// This site is reachable ONLY with the CORRECT one, so anything
						// that distinguishes it — a different reply, or a failure the
						// credential is not charged for, which diverges at the block
						// threshold — confirms a guessed tenant-wide password to a peer
						// that is not even allowed to use it. The reason stays in the log.
						if s.server.authLimiter != nil {
							s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, authKey, false)
						}
						return authFailedError()
					}

					// Master SASL credentials match. The user to log in as is the
					// authorization-identity, which is non-empty here by construction.
					targetUserToImpersonate := identity

					s.DebugLog("master SASL user authenticated, attempting to impersonate", "username", username, "target_user", targetUserToImpersonate)

					// Log in as the targetUserToImpersonate.
					// For master impersonation, we directly establish the session for them.
					address, err := server.NewAddress(targetUserToImpersonate)
					if err != nil {
						// Same reply and same accounting as a bad credential: see the
						// master-username path above.
						s.WarnLog("impersonation target rejected (address not in the correct format)", "target_user", targetUserToImpersonate, "error", err)
						metrics.AuthenticationAttempts.WithLabelValues("imap", s.server.name, s.server.hostname, "failure").Inc()
						if s.server.authLimiter != nil {
							s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, authKey, false)
						}
						return authFailedError()
					}

					AccountID, err := s.server.rdb.GetActiveAccountIDByAddressWithRetry(s.ctx, address.BaseAddress())
					if err != nil {
						// Check if error is due to context cancellation (server shutdown)
						if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
							s.InfoLog("master SASL auth cancelled due to server shutdown")
							return &imap.Error{
								Type: imap.StatusResponseTypeNo,
								Code: imap.ResponseCodeUnavailable,
								Text: server.ErrServerShuttingDown.Error(),
							}
						}

						// Same reply and same accounting as a bad credential (see above).
						s.WarnLog("impersonation target rejected (account not found)", "target_user", targetUserToImpersonate, "error", err)
						metrics.AuthenticationAttempts.WithLabelValues("imap", s.server.name, s.server.hostname, "failure").Inc()
						if s.server.authLimiter != nil {
							s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, authKey, false)
						}
						return authFailedError()
					}

					// Get primary email address for this account
					// User.Address should always be the primary address
					primaryAddr, primErr := s.server.rdb.GetPrimaryEmailForAccountWithRetry(s.ctx, AccountID)
					if primErr != nil {
						return s.internalError("failed to get primary email: %v", primErr)
					}

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

					// IMPORTANT: Set user state AFTER incrementing both counters to prevent race condition
					// If session closes between counter increments and user state setting, cleanup won't decrement
					s.IMAPUser = NewIMAPUser(primaryAddr, AccountID)
					s.Session.User = &s.IMAPUser.User

					// Register connection for tracking
					if err := s.registerConnection(address.BaseAddress()); err != nil {
						// Connection limit reached - undo authentication and reject
						s.server.authenticatedConnections.Add(-1)
						metrics.AuthenticatedConnectionsCurrent.WithLabelValues("imap", s.server.name, s.server.hostname).Dec()
						s.IMAPUser = nil
						s.Session.User = nil
						return &imap.Error{
							Type: imap.StatusResponseTypeNo,
							Code: imap.ResponseCodeLimit,
							Text: "Maximum connections reached",
						}
					}

					// Start termination poller to check for kick commands. Required on
					// every authenticated path: it is the only delivery path for kicks,
					// and imapproxy authenticates to its backends with exactly this
					// master AUTHENTICATE, so without it proxied backend sessions are
					// tracked but unkickable.
					s.startTerminationPoller()

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
				} else if checkMasterCredential(username, s.server.masterSASLUsername) && identity != username {
					// The authentication identity IS the master SASL username, a
					// DIFFERENT user was named as the impersonation target, but the
					// password is wrong. This must
					// be recorded as an authentication failure and must not fall through
					// to regular authentication: master SASL is a tenant-wide
					// impersonation capability, and the regular path records nothing for
					// it (the master SASL username is not an address), which left the
					// credential brute-forceable at connection rate. Recorded under
					// authKey — the master username's own bucket — so the impersonation
					// target is not locked out.
					//
					// The identity != username guard keeps this off an ordinary login:
					// RFC 4616 lets a client send an authorization identity equal to the
					// authentication identity to mean "no impersonation", and several SASL
					// libraries always fill the field in. For an account whose address
					// happens to be the master SASL username, answering that from here
					// would refuse its own password forever. Such a submission falls
					// through to regular authentication instead, which records its own
					// failure under the same authKey — so a master-password guess dressed
					// up as a self-login is still metered, just not privileged.
					s.WarnLog("master SASL authentication failed (invalid password)", "peer", server.GetAddrString(netConn.RemoteAddr()))
					metrics.AuthenticationAttempts.WithLabelValues("imap", s.server.name, s.server.hostname, "failure").Inc()
					if s.server.authLimiter != nil {
						s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, netConn, proxyInfo, authKey, false)
					}
					// Same response as any other bad credential: a distinct one would
					// confirm the master SASL username to an attacker.
					return authFailedError()
				}
			}

			// Master SASL credentials submitted WITHOUT an authorization identity.
			// There is nothing to impersonate, so this is not a master login and must
			// not be answered differently from any other login by that username: the
			// old "requires an authorization identity" reply was reachable only with
			// the CORRECT master password, so anyone who could reach the port could
			// confirm a guessed tenant-wide password without completing an
			// authentication. It falls through to regular authentication instead —
			// same reply, same rate-limit accounting, whatever the password — which
			// also lets an account whose address happens to be the master SASL
			// username log in with its own password. Logged for the operator
			// debugging a proxy that forgot to send the target user.
			if identity == "" && len(s.server.masterSASLUsername) > 0 && len(s.server.masterSASLPassword) > 0 &&
				checkMasterCredential(username, s.server.masterSASLUsername) &&
				checkMasterCredential(password, s.server.masterSASLPassword) {
				s.WarnLog("master SASL password presented without an authorization identity; not a master login, falling through to regular authentication", "peer", server.GetAddrString(netConn.RemoteAddr()))
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
			// Use the non-gating login variant: the progressive auth delay and
			// rate-limit check were already applied once above for this
			// AUTHENTICATE command (ApplyAuthenticationDelay + CanAttemptAuthWithProxy).
			// Calling s.Login here would apply both a second time.
			// The SASL server callback (go-sasl's Next) carries no per-command
			// context, so use the session context here — it is the best available
			// signal for the AUTHENTICATE path.
			s.DebugLog("proceeding with regular authentication", "username", username)
			return s.login(s.ctx, username, password, false)
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
