package imap

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
)

// authFailedError is the ONE bad-credential reply. Every path that must be
// indistinguishable from a wrong password returns this rather than a hand-written
// copy: a copy drifts from the original and re-creates, inverted, the very oracle
// it was written to close.
func authFailedError() *imap.Error {
	return &imap.Error{
		Type: imap.StatusResponseTypeNo,
		Code: imap.ResponseCodeAuthenticationFailed,
		Text: "Invalid address or password",
	}
}

// refusedInMaintenance answers a login the maintenance gate refused, after the credentials
// checked out: a temporary failure, so the client (or the proxy, which answers its own
// client the same way) tries again, by when the proxies route it to another backend.
func (s *IMAPSession) refusedInMaintenance() *imap.Error {
	s.InfoLog("login refused: this backend is in maintenance")
	return &imap.Error{
		Type: imap.StatusResponseTypeNo,
		Code: imap.ResponseCodeUnavailable,
		Text: "Server in maintenance, please try again later",
	}
}

// createDefaultMailboxes makes sure the account has its default mailboxes
// (consts.DefaultMailboxes), as every login does before the session starts. When the
// read pool did not show them, this is the account's first login: they have just
// been created on the writer, and a replica that has not replayed that yet has no
// INBOX. The session then reads from the writer, as after any write of its own.
func (s *IMAPSession) createDefaultMailboxes(ctx context.Context, accountID int64) error {
	onWriter, err := s.server.rdb.EnsureDefaultMailboxesWithRetry(ctx, accountID)
	if err != nil {
		return err
	}
	if onWriter {
		s.useMasterDB.Store(true)
	}
	return nil
}

// Login handles the IMAP LOGIN command. It always applies the authentication
// gate (progressive delay + rate-limit check) before authenticating.
func (s *IMAPSession) Login(ctx context.Context, address, password string) error {
	return s.login(ctx, address, password, "", true)
}

// login authenticates address/password. applyGate controls whether the
// progressive authentication delay and per-IP/username rate-limit check are
// applied here.
//
// authzid is the SASL authorization identity, empty for LOGIN. One naming somebody
// other than address is refused, but only after the credentials checked out: RFC
// 4616 section 2 verifies the authentication identity and password first, then that
// they permit acting as the authorization identity.
//
// The LOGIN command passes applyGate=true. The SASL PLAIN handler (sasl.go)
// passes applyGate=false for the regular-user path because it has ALREADY
// applied the delay + rate-limit once for the AUTHENTICATE command. Without
// this, AUTHENTICATE would apply both twice — roughly doubling auth latency and
// double-counting against the rate limiter relative to LOGIN.
func (s *IMAPSession) login(ctx context.Context, address, password, authzid string, applyGate bool) error {
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

	// Rate-limit key for this attempt. Canonicalised from the submitted address so
	// that the check below and every RecordAuthAttempt* call in this function use
	// the SAME key. Checking the raw string while recording the parsed address let
	// an attacker vary the case or the +detail to sidestep Tier 1 entirely, while
	// the resulting block landed on the victim's canonical address. The master form
	// "user@domain.com@MASTERUSER" canonicalises to the TARGET's address, so it is
	// keyed on the master credential instead (AuthRateLimitKeyWithMaster) — an
	// attempt at the master password must never charge the account it named.
	authKey := server.AuthRateLimitKeyWithMaster(address, s.server.masterUsername)

	if applyGate {
		// Apply progressive authentication delay BEFORE any other checks
		// Create a fake net.Addr from the RemoteIP for delay calculation
		remoteAddr := &server.StringAddr{Addr: s.RemoteIP}
		if err := server.ApplyAuthenticationDelay(ctx, s.server.authLimiter, remoteAddr, "imap"); err != nil {
			if errors.Is(err, server.ErrDelayQueueFull) {
				// Delay queue full - reject immediately to prevent goroutine exhaustion
				s.InfoLog("delay queue full, rejecting connection", "address", address)
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

		// Check authentication rate limiting after delay using proxy-aware method
		if s.server.authLimiter != nil {
			if err := s.server.authLimiter.CanAttemptAuthWithProxy(ctx, netConn, proxyInfo, authKey); err != nil {
				// Check if this is a rate limit error
				var rateLimitErr *server.RateLimitError
				if errors.As(err, &rateLimitErr) {
					s.InfoLog("rate limit exceeded",
						"address", address,
						"reason", rateLimitErr.Reason,
						"failure_count", rateLimitErr.FailureCount,
						"blocked_until", rateLimitErr.BlockedUntil.Format(time.RFC3339))

					// Track rate limiting as a specific error type
					metrics.ProtocolErrors.WithLabelValues("imap", "LOGIN", "rate_limited", "client_error").Inc()
				} else {
					// Unknown rate limiting error (shouldn't happen, but handle gracefully)
					s.DebugLog("rate limited", "error", err)
					metrics.ProtocolErrors.WithLabelValues("imap", "LOGIN", "rate_limited", "client_error").Inc()
				}

				// Return the SAME response as a bad-credential failure (NO [AUTHENTICATIONFAILED],
				// identical text to the regular-auth path below) instead of a distinct BYE/ALERT.
				// A divergent rate-limit response is an oracle: it confirms a targeted account/IP is
				// being limited, which on a shared egress IP signals a deliberate lockout. The block
				// is still enforced — only its observable form is made indistinguishable. (security-audit M14)
				return authFailedError()
			}
		}
	}

	// Parse address with potential suffix (master username or remotelookup token)
	addressParsed, err := server.NewAddress(address)
	if err != nil {
		s.DebugLog("failed to parse address", "error", err)
		// Track invalid address format as client error
		metrics.ProtocolErrors.WithLabelValues("imap", "LOGIN", "invalid_address", "client_error").Inc()
		// A failed login like any other: recorded, counted and answered exactly
		// like a wrong password. A master SASL self-login (authorization identity
		// = authentication identity = a non-address master SASL username) falls
		// through to here with any password but the master SASL one, which
		// sasl.go section 2 answers with authFailedError(), so a different reply
		// or count here confirms a guessed master SASL password. It holds for
		// every username, or the reply would single out the master SASL one.
		metrics.AuthenticationAttempts.WithLabelValues("imap", s.server.name, s.server.hostname, "failure").Inc()
		if s.server.authLimiter != nil {
			s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, authKey, false)
		}
		return authFailedError()
	}

	// The account the session is for, and how it was authenticated. Both branches
	// below only establish these; the session is then set up by ONE path after
	// them, so a master login prepares the account exactly like a regular one
	// (default mailboxes, cache warmup, connection tracking, kick poller).
	var AccountID int64
	var method string

	// Master username authentication: user@domain.com@MASTER_USERNAME, with the master
	// password. Any other password in that form is not answered here: it is the base
	// address's own login, checked below as under any other suffix. Its answer must not
	// depend on whether the suffix is the master username: a distinct reply, a quicker
	// one (#801), or a refusal of the account's own password (#949) confirms the
	// configured master username, the precondition for every other master-form attack.
	// Its failure is still recorded under authKey, the master credential's key, so
	// guesses at the master password stay metered; only a success is the account's.
	masterForm := len(s.server.masterUsername) > 0 && addressParsed.HasSuffix() && checkMasterCredential(addressParsed.Suffix(), s.server.masterUsername)
	if masterForm && len(s.server.masterPassword) > 0 && checkMasterCredential(password, s.server.masterPassword) {
		if !s.AdmitMasterLogin(ctx, s.server.settings.Load().masterSASLGate, s.server.authLimiter, netConn, proxyInfo, authKey, "master username") {
			metrics.AuthenticationAttempts.WithLabelValues("imap", s.server.name, s.server.hostname, "failure").Inc()
			return authFailedError()
		}
		// Use base address (without suffix) to get account
		AccountID, err = s.server.rdb.GetMasterLoginTargetWithRetry(ctx, addressParsed.BaseAddress())
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

			// The database could not be asked, so nothing is known about the target:
			// a temporary failure (RFC 5530 section 3), not a failed login charged to
			// the master credential.
			if server.IsTemporaryAuthFailure(err) {
				s.WarnLog("impersonation target lookup unavailable", "target_user", addressParsed.BaseAddress(), "error", err)
				metrics.AuthenticationAttempts.WithLabelValues("imap", s.server.name, s.server.hostname, "unavailable").Inc()
				return &imap.Error{
					Type: imap.StatusResponseTypeNo,
					Code: imap.ResponseCodeUnavailable,
					Text: server.ErrAuthServiceUnavailable.Error(),
				}
			}

			// Same reply and same accounting as a bad credential, as in the
			// AUTHENTICATE PLAIN master path (sasl.go). This site is reachable
			// ONLY with the correct master password, so a distinguishable reply,
			// or a failure the master credential is not charged for, confirms a
			// guessed tenant-wide password without completing an authentication.
			s.WarnLog("impersonation target rejected (account not found)", "target_user", addressParsed.BaseAddress(), "error", err)
			metrics.AuthenticationAttempts.WithLabelValues("imap", s.server.name, s.server.hostname, "failure").Inc()
			if s.server.authLimiter != nil {
				s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, authKey, false)
			}
			return authFailedError()
		}
		method = "master"
	} else {
		// Regular authentication - use the already parsed address. A suffix other than
		// the master username (a remotelookup token in proxy scenarios), or the master
		// username without the master password, is ignored: the base address is checked.

		s.DebugLog("authentication attempt", "address", addressParsed.BaseAddress())

		// Use base address (without +detail and without suffix) for authentication.
		// Its result is logged here, once, with the session's fields.
		var reason string
		AccountID, method, reason, err = s.server.Authenticate(ctx, addressParsed.BaseAddress(), password)
		if err != nil {
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

			// The database could not be asked, or the stored hash cannot be checked, so
			// nothing is known about the credentials: a temporary failure (RFC 5530
			// section 3, "a subsystem is down"), not counted as a failed login, or clients
			// retrying a saved password through an outage stay blocked after it.
			if server.IsTemporaryAuthFailure(err) {
				s.WarnLog("authentication unavailable", "address", addressParsed.BaseAddress(), "reason", reason, "method", method, "error", err)
				metrics.AuthenticationAttempts.WithLabelValues("imap", s.server.name, s.server.hostname, "unavailable").Inc()
				return &imap.Error{
					Type: imap.StatusResponseTypeNo,
					Code: imap.ResponseCodeUnavailable,
					Text: server.ErrAuthServiceUnavailable.Error(),
				}
			}

			s.InfoLog("authentication failed", "address", addressParsed.BaseAddress(), "reason", reason, "cached", false, "method", method)
			if masterForm {
				// Kept for the operator debugging a client with the wrong master password.
				s.WarnLog("master username authentication failed (invalid master password)")
			}

			// Record failed authentication
			metrics.AuthenticationAttempts.WithLabelValues("imap", s.server.name, s.server.hostname, "failure").Inc()
			if s.server.authLimiter != nil {
				s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, authKey, false)
			}

			return authFailedError()
		}
	}

	// The credentials checked out; now the authorization (RFC 4616 section 2). Acting
	// as somebody else is the master SASL credentials' privilege (sasl.go), so this
	// account may act only as itself. Refused here, not before the password, so only a
	// client that proved its credentials learns it is not permitted, which is what RFC
	// 5530 section 3 defines AUTHORIZATIONFAILED as: "Authentication succeeded in using
	// the authentication identity, but the server cannot or will not allow the
	// authentication identity to act as the requested authorization identity".
	// Refusing it earlier answered every username but the master SASL one without a
	// password check, which confirmed the master SASL username. Not recorded as a
	// failure: the credentials were right.
	if authzid != "" && authzid != address {
		s.DebugLog("proxy login not allowed for non-master users", "username", address, "identity", authzid)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAuthorizationFailed,
			Text: "Proxy login not permitted for this user.",
		}
	}

	// Ensure the default mailboxes (INBOX/Sent/Drafts/Archive/Junk/Trash, consts.DefaultMailboxes) exist
	if err := s.createDefaultMailboxes(ctx, AccountID); err != nil {
		return s.internalError("failed to create default mailboxes: %v", err)
	}

	// Get primary email address for this account
	// User.Address should always be the primary address (not the login address with +alias)
	primaryAddr, err := s.server.rdb.GetPrimaryEmailForAccountWithRetry(ctx, AccountID)
	if err != nil {
		return s.internalError("failed to get primary email: %v", err)
	}

	if !s.server.maintenanceGate.Admit(&s.server.authenticatedConnections, "imap") {
		return s.refusedInMaintenance()
	}
	duration := time.Since(authStart)

	// Prometheus metrics - successful authentication
	metrics.AuthenticationAttempts.WithLabelValues("imap", s.server.name, s.server.hostname, "success").Inc()
	metrics.AuthenticatedConnectionsCurrent.WithLabelValues("imap", s.server.name, s.server.hostname).Inc()

	// IMPORTANT: Set user state AFTER incrementing both counters to prevent race condition
	// If session closes between counter increments and user state setting, cleanup won't decrement
	s.IMAPUser = NewIMAPUser(primaryAddr, AccountID)
	s.Session.User = &s.IMAPUser.User

	// Log authentication with alias detection, once the session's user and account_id
	// fields name the account
	loginAddr := addressParsed.BaseAddress()
	cached := method == "cache"
	if loginAddr != primaryAddr.FullAddress() {
		s.InfoLog("authentication successful", "login_address", loginAddr, "primary_address", primaryAddr.FullAddress(), "cached", cached, "method", method, "duration", fmt.Sprintf("%.3fs", duration.Seconds()))
	} else {
		s.InfoLog("authentication successful", "address", loginAddr, "cached", cached, "method", method, "duration", fmt.Sprintf("%.3fs", duration.Seconds()))
	}

	// Domain and user tracking
	metrics.TrackDomainConnection("imap", addressParsed.Domain())
	metrics.TrackUserActivity("imap", addressParsed.BaseAddress(), "connection", 1)

	// Record successful authentication: a master login under the master credential's
	// key, any other under the account's, the master form with its own password too
	// (#949): under the master key it would clear the failed guesses at the master
	// password.
	if s.server.authLimiter != nil {
		s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, server.AuthSuccessRateLimitKey(address, password, s.server.masterUsername, s.server.masterPassword), true)
	}

	// Register connection for tracking
	if err := s.registerConnection(addressParsed.BaseAddress()); err != nil {
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

	// Start termination poller to check for kick commands
	s.startTerminationPoller()

	// Trigger cache warmup for the authenticated user
	s.triggerCacheWarmup()

	return nil
}

func checkMasterCredential(provided string, actual []byte) bool {
	return subtle.ConstantTimeCompare([]byte(provided), actual) == 1
}
