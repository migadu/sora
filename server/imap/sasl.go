package imap

import (
	"bytes"
	"context"
	"errors"
	"net"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/migadu/go-imap"
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
		return &plainServer{session: s, Server: sasl.NewPlainServer(func(identity, username, password string) error {
			// SASL PLAIN payload: [authorization-identity] \0 authentication-identity \0 password
			// callback `identity`: authorization-identity (user to act as, can be empty)
			// callback `username`: authentication-identity (user whose credentials are provided)
			// callback `password`: password for authentication-identity

			// Get the underlying net.Conn for proxy-aware rate limiting
			netConn := s.conn.NetConn()

			// One copy of the master SASL settings for the whole login, however a
			// config reload replaces them meanwhile.
			settings := s.server.settings.Load()

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
			if err := server.ApplyAuthenticationDelay(s.ctx, s.server.authLimiter, remoteAddr, "imap"); err != nil {
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
					// Every refusal of the correct master password below costs what a
					// wrong one costs (refuseLikeWrongPassword, see login.go). No
					// limiter: the helper records the failure, once.
					if !s.AdmitMasterLogin(s.ctx, settings.masterSASLGate, nil, netConn, proxyInfo, authKey, "master username") {
						return s.refuseLikeWrongPassword(s.ctx, username, password, netConn, proxyInfo, authKey)
					}
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
						// credential, recorded exactly like one, and after the same
						// password-verification work. This site is reachable ONLY with the
						// correct master password, so a distinguishable reply, a failure the
						// master credential is not charged for (which diverges from a wrong
						// password at the block threshold), or a quicker one confirms a
						// guessed tenant-wide password without completing an authentication.
						// The real reason stays in the log for the operator.
						s.WarnLog("impersonation target rejected (address not in the correct format)", "target_user", targetUserToImpersonate, "error", err)
						return s.refuseLikeWrongPassword(s.ctx, username, password, netConn, proxyInfo, authKey)
					}

					AccountID, err := s.server.rdb.GetMasterLoginTargetWithRetry(s.ctx, address.BaseAddress())
					if err != nil {
						// The database could not be asked, so nothing is known about the
						// target: a temporary failure (RFC 5530 section 3), not a failed
						// login charged to the master credential. Checked before the
						// context errors, as in login.go: a lookup that timed out because
						// the database hangs is no shutdown, and a wrong master password,
						// which the regular path answers, must get the same reply.
						if server.IsTemporaryAuthFailure(err) {
							s.WarnLog("impersonation target lookup unavailable", "target_user", targetUserToImpersonate, "error", err)
							metrics.AuthenticationAttempts.WithLabelValues("imap", s.server.name, s.server.hostname, "unavailable").Inc()
							return &imap.Error{
								Type: imap.StatusResponseTypeNo,
								Code: imap.ResponseCodeUnavailable,
								Text: server.ErrAuthServiceUnavailable.Error(),
							}
						}

						// Check if error is due to context cancellation (server shutdown)
						if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
							s.InfoLog("master username auth cancelled due to server shutdown")
							return &imap.Error{
								Type: imap.StatusResponseTypeNo,
								Code: imap.ResponseCodeUnavailable,
								Text: server.ErrServerShuttingDown.Error(),
							}
						}

						// Same reply, accounting and password-verification work as a bad
						// credential (see above).
						s.WarnLog("impersonation target rejected (account not found)", "target_user", targetUserToImpersonate, "error", err)
						return s.refuseLikeWrongPassword(s.ctx, username, password, netConn, proxyInfo, authKey)
					}

					// Get primary email address for this account
					// User.Address should always be the primary address
					primaryAddr, primErr := s.server.rdb.GetPrimaryEmailForAccountWithRetry(s.ctx, AccountID)
					if primErr != nil {
						return s.loginSetupError("failed to get primary email", address.BaseAddress(), "master", primErr)
					}

					// Ensure default mailboxes for the impersonated user
					if dbErr := s.createDefaultMailboxes(s.ctx, AccountID); dbErr != nil {
						return s.loginSetupError("failed to prepare impersonated user session", address.BaseAddress(), "master", dbErr)
					}

					return s.completeAuthentication(AccountID, address, primaryAddr, "master", authStart, false)
				}

				// Any other password is the base address's own login, answered by regular
				// authentication exactly as under any other suffix (see login.go, #801,
				// #949). Already gated above, under the same authKey.
				return s.login(s.ctx, username, password, identity, false)
			}

			// 2. Check for Master SASL Authentication (traditional SASL proxy authentication)
			// Only ever a master login when the client asked to act as somebody: the
			// authorization identity IS the impersonation target. A submission without
			// one cannot be a master login, so it is not answered from here at all —
			// see the no-authorization-identity note below.
			//
			// A self-login (authorization identity = authentication identity) is handed
			// on to regular authentication unless it logs in here, as a self-login with
			// a wrong password is (see the wrong-password branch below). The master
			// SASL password logs in here only from a peer master_sasl_allowed_networks
			// admits and only as an account that exists (imapproxy logging in an
			// account whose address is the master SASL username): a gate refusal skips
			// this block, and a target that does not exist is handed on after the
			// lookup. Regular authentication verifies a password even for an unknown
			// address, so refusing the master SASL password here without one let the
			// response time confirm a guessed master SASL password. The gate refusal is
			// logged but not recorded (no limiter is passed): regular authentication
			// records the attempt. A target that does not parse is refused below
			// exactly as regular authentication refuses that username.
			if identity != "" && len(settings.masterSASLUsername) > 0 && len(settings.masterSASLPassword) > 0 {
				selfLogin := identity == username
				// Check if the provided authentication identity and password match the server's master SASL credentials
				if checkMasterCredential(username, settings.masterSASLUsername) &&
					checkMasterCredential(password, settings.masterSASLPassword) &&
					(!selfLogin || s.AdmitMasterLogin(s.ctx, settings.masterSASLGate, nil, netConn, proxyInfo, authKey, "master SASL self-login")) {

					// Network gate, anchored to the real socket peer (NetConn().RemoteAddr()),
					// which PROXY/XCLIENT/ID forwarding cannot rewrite. Pass nil limiter so
					// failure accounting happens once in refuseLikeWrongPassword after
					// equalizing password-verification work with regular authentication.
					if !s.AdmitMasterLogin(s.ctx, settings.masterSASLGate, nil, netConn, proxyInfo, authKey, "master SASL") {
						return s.refuseLikeWrongPassword(s.ctx, username, password, netConn, proxyInfo, authKey)
					}

					// Master SASL credentials match. The user to log in as is the
					// authorization-identity, which is non-empty here by construction.
					targetUserToImpersonate := identity

					s.DebugLog("master SASL user authenticated, attempting to impersonate", "username", username, "target_user", targetUserToImpersonate)

					// Log in as the targetUserToImpersonate.
					// For master impersonation, we directly establish the session for them.
					address, err := server.NewAddress(targetUserToImpersonate)
					if err != nil {
						// Same reply, accounting, and password-verification work as a bad credential.
						s.WarnLog("impersonation target rejected (address not in the correct format)", "target_user", targetUserToImpersonate, "error", err)
						return s.refuseLikeWrongPassword(s.ctx, username, password, netConn, proxyInfo, authKey)
					}

					AccountID, err := s.server.rdb.GetMasterLoginTargetWithRetry(s.ctx, address.BaseAddress())
					if err != nil {
						// The database could not be asked, so nothing is known about the
						// target: a temporary failure (RFC 5530 section 3), not a failed
						// login charged to the master credential. Checked before the
						// context errors: a lookup that timed out because the database
						// hangs is no shutdown (see the master username path above).
						if server.IsTemporaryAuthFailure(err) {
							s.WarnLog("impersonation target lookup unavailable", "target_user", targetUserToImpersonate, "error", err)
							metrics.AuthenticationAttempts.WithLabelValues("imap", s.server.name, s.server.hostname, "unavailable").Inc()
							return &imap.Error{
								Type: imap.StatusResponseTypeNo,
								Code: imap.ResponseCodeUnavailable,
								Text: server.ErrAuthServiceUnavailable.Error(),
							}
						}

						// Check if error is due to context cancellation (server shutdown)
						if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
							s.InfoLog("master SASL auth cancelled due to server shutdown")
							return &imap.Error{
								Type: imap.StatusResponseTypeNo,
								Code: imap.ResponseCodeUnavailable,
								Text: server.ErrServerShuttingDown.Error(),
							}
						}

						s.WarnLog("impersonation target rejected (account not found)", "target_user", targetUserToImpersonate, "error", err)
						if selfLogin {
							// Answered by regular authentication (see the self-login note above).
							return s.login(s.ctx, username, password, identity, false)
						}
						// Same reply, accounting, and password-verification work as a bad credential.
						return s.refuseLikeWrongPassword(s.ctx, username, password, netConn, proxyInfo, authKey)
					}

					// Get primary email address for this account
					// User.Address should always be the primary address
					primaryAddr, primErr := s.server.rdb.GetPrimaryEmailForAccountWithRetry(s.ctx, AccountID)
					if primErr != nil {
						return s.loginSetupError("failed to get primary email", address.BaseAddress(), "master", primErr)
					}

					// Ensure default mailboxes for the impersonated user
					if dbErr := s.createDefaultMailboxes(s.ctx, AccountID); dbErr != nil {
						return s.loginSetupError("failed to prepare impersonated user session", address.BaseAddress(), "master", dbErr)
					}

					return s.completeAuthentication(AccountID, address, primaryAddr, "master", authStart, false)
				} else if checkMasterCredential(username, settings.masterSASLUsername) && identity != username {
					// The master SASL username asking to act as somebody else, with a
					// wrong password. Not answered from here: like any other password
					// but the master SASL one, it falls through to regular
					// authentication, which verifies these credentials like any other
					// username's and answers and records their failure under the same
					// authKey (login.go). A reply or accounting of its own, beside the
					// authorization refusal any other username got, confirmed the master
					// SASL username to anyone who could reach the port. Logged for the
					// operator debugging a proxy with the wrong master SASL password.
					s.WarnLog("master SASL authentication failed (invalid password)", "peer", server.GetAddrString(netConn.RemoteAddr()))
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
			if identity == "" && len(settings.masterSASLUsername) > 0 && len(settings.masterSASLPassword) > 0 &&
				checkMasterCredential(username, settings.masterSASLUsername) &&
				checkMasterCredential(password, settings.masterSASLPassword) {
				s.WarnLog("master SASL password presented without an authorization identity; not a master login, falling through to regular authentication", "peer", server.GetAddrString(netConn.RemoteAddr()))
			}

			// 3. Regular User Authentication
			// The user identified by `username` (authentication-identity) is logging in with `password`.
			// An `identity` (authorization-identity) naming somebody else is a proxy request by a
			// non-master user: login refuses it, but only once these credentials have checked out.

			// Authenticate as `username` (authentication-identity).
			// Use the non-gating login variant: the progressive auth delay and
			// rate-limit check were already applied once above for this
			// AUTHENTICATE command (ApplyAuthenticationDelay + CanAttemptAuthWithProxy).
			// Calling s.Login here would apply both a second time.
			// The SASL server callback (go-sasl's Next) carries no per-command
			// context, so use the session context here — it is the best available
			// signal for the AUTHENTICATE path.
			s.DebugLog("proceeding with regular authentication", "username", username)
			return s.login(s.ctx, username, password, identity, false)
		})}, nil
	default:
		s.DebugLog("unsupported authentication mechanism", "mechanism", mechanism)
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAuthenticationFailed,
			Text: "Unsupported authentication mechanism",
		}
	}
}

// plainServer refuses a PLAIN message that is not three NUL-separated fields
// (RFC 4616 §2) before go-sasl sees it. go-sasl reports one with a plain
// error, which go-imap answers NO [SERVERBUG] and logs as a server failure,
// when it is the client's error. The answer is the IMAP proxy's (session.go),
// so a client gets the same one from either. No credential is checked, as
// before.
type plainServer struct {
	sasl.Server
	session *IMAPSession
}

func (p *plainServer) Next(response []byte) ([]byte, bool, error) {
	// nil means no initial response, answered with the empty challenge. A
	// zero-length message (an initial response of "=", or an empty reply) is
	// malformed.
	if response != nil && bytes.Count(response, []byte{0}) != 2 {
		p.session.DebugLog("malformed SASL PLAIN message")
		return nil, true, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Invalid SASL PLAIN response",
		}
	}
	return p.Server.Next(response)
}

// refuseLikeWrongPassword refuses a login that must not succeed with what regular
// authentication gives username with a wrong password: the credential check of its
// base address (password verification and lookup-cache update), whose verdict is
// discarded, then the same rate-limit accounting and reply. A refusal that skipped the
// check would be answered one verification sooner and confirm what made it one. Used
// for a refused master SASL impersonation (#846), which must not answer
// AUTHORIZATIONFAILED when username names an account whose own password is the master
// SASL password, and for every refusal of the correct password in the master username
// form (gate, target), which must cost what a wrong one costs (#801).
// The caller logs why the login is refused; only a check that could not be made is
// logged here, because it changes the reply.
func (s *IMAPSession) refuseLikeWrongPassword(ctx context.Context, username, password string, netConn net.Conn, proxyInfo *server.ProxyProtocolInfo, authKey string) error {
	if authnAddr, err := server.NewAddress(username); err == nil {
		if _, method, reason, authErr := s.server.Authenticate(ctx, authnAddr.BaseAddress(), password); authErr != nil {
			// In the regular login's order (login.go), so the reply is the same.
			if server.IsTemporaryAuthFailure(authErr) {
				s.WarnLog("authentication unavailable", "address", authnAddr.BaseAddress(), "reason", reason, "method", method, "error", authErr)
				metrics.AuthenticationAttempts.WithLabelValues("imap", s.server.name, s.server.hostname, "unavailable").Inc()
				return &imap.Error{
					Type: imap.StatusResponseTypeNo,
					Code: imap.ResponseCodeUnavailable,
					Text: server.ErrAuthServiceUnavailable.Error(),
				}
			}
			if errors.Is(authErr, context.Canceled) || errors.Is(authErr, context.DeadlineExceeded) {
				s.InfoLog("authentication cancelled due to server shutdown")
				return &imap.Error{
					Type: imap.StatusResponseTypeNo,
					Code: imap.ResponseCodeUnavailable,
					Text: server.ErrServerShuttingDown.Error(),
				}
			}
		}
	}
	metrics.AuthenticationAttempts.WithLabelValues("imap", s.server.name, s.server.hostname, "failure").Inc()
	if s.server.authLimiter != nil {
		s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, authKey, false)
	}
	return authFailedError()
}
