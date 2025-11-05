package imap

import (
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
	s.DebugLog("Authentication: authentication attempt with mechanism %s", mechanism)

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
					s.DebugLog("Authentication: SASL PLAIN rate limited: %v", err)
					return &imap.Error{
						Type: imap.StatusResponseTypeNo,
						Code: imap.ResponseCodeAuthenticationFailed,
						Text: "Too many authentication attempts. Please try again later.",
					}
				}
			}

			s.DebugLog("Authentication: SASL PLAIN AuthorizationID: '%s', AuthenticationID: '%s'", identity, username)

			// Parse username to check for suffix (master username or prelookup token)
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

					s.DebugLog("Authentication: master username '%s' authenticated. Attempting to impersonate '%s'.", usernameParsed.Suffix(), targetUserToImpersonate)

					// Parse target user address
					address, err := server.NewAddress(targetUserToImpersonate)
					if err != nil {
						s.DebugLog("Authentication: failed to parse impersonation target user '%s' as address: %v", targetUserToImpersonate, err)
						metrics.AuthenticationAttempts.WithLabelValues("imap", "failure").Inc()
						return &imap.Error{
							Type: imap.StatusResponseTypeNo,
							Code: imap.ResponseCodeAuthorizationFailed,
							Text: "Impersonation target user address is not in the correct format.",
						}
					}

					AccountID, err := s.server.rdb.GetAccountIDByAddressWithRetry(s.ctx, address.BaseAddress())
					if err != nil {
						s.DebugLog("Authentication: failed to get account ID for impersonation target user '%s': %v", targetUserToImpersonate, err)
						metrics.AuthenticationAttempts.WithLabelValues("imap", "failure").Inc()
						return &imap.Error{
							Type: imap.StatusResponseTypeNo,
							Code: imap.ResponseCodeAuthorizationFailed,
							Text: "Impersonation target user account not found.",
						}
					}

					s.IMAPUser = NewIMAPUser(address, AccountID)
					s.Session.User = &s.IMAPUser.User
					// Ensure default mailboxes for the impersonated user
					if dbErr := s.server.rdb.CreateDefaultMailboxesWithRetry(s.ctx, AccountID); dbErr != nil {
						return s.internalError("failed to prepare impersonated user session: %v", dbErr)
					}

					authCount := s.server.authenticatedConnections.Add(1)
					totalCount := s.server.totalConnections.Load()
					s.InfoLog("Authentication: session established for impersonated user '%s' (ID: %d) via master username login (connections: total=%d, authenticated=%d)", address.BaseAddress(), AccountID, totalCount, authCount)

					metrics.AuthenticationAttempts.WithLabelValues("imap", "success").Inc()
					metrics.AuthenticatedConnectionsCurrent.WithLabelValues("imap").Inc()

					// Trigger cache warmup for the authenticated user (if configured)
					s.triggerCacheWarmup()

					return nil
				}

				// Record failed master password authentication
				metrics.AuthenticationAttempts.WithLabelValues("imap", "failure").Inc()
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
						s.DebugLog("Authentication: Master SASL authentication for '%s' successful, but no authorization identity (target user to impersonate) provided.", username)
						metrics.AuthenticationAttempts.WithLabelValues("imap", "failure").Inc()
						return &imap.Error{
							Type: imap.StatusResponseTypeNo,
							Code: imap.ResponseCodeAuthorizationFailed,
							Text: "Master SASL login requires an authorization identity (target user to impersonate).",
						}
					}

					s.DebugLog("Authentication: master SASL user '%s' authenticated. Attempting to impersonate '%s'.", username, targetUserToImpersonate)

					// Log in as the targetUserToImpersonate.
					// For master impersonation, we directly establish the session for them.
					address, err := server.NewAddress(targetUserToImpersonate)
					if err != nil {
						s.DebugLog("Authentication: failed to parse impersonation target user '%s' as address: %v", targetUserToImpersonate, err)
						metrics.AuthenticationAttempts.WithLabelValues("imap", "failure").Inc()
						return &imap.Error{
							Type: imap.StatusResponseTypeNo,
							Code: imap.ResponseCodeAuthorizationFailed,
							Text: "Impersonation target user address is not in the correct format.",
						}
					}

					AccountID, err := s.server.rdb.GetAccountIDByAddressWithRetry(s.ctx, address.BaseAddress())
					if err != nil {
						s.DebugLog("Authentication: failed to get account ID for impersonation target user '%s': %v", targetUserToImpersonate, err)
						metrics.AuthenticationAttempts.WithLabelValues("imap", "failure").Inc()
						return &imap.Error{
							Type: imap.StatusResponseTypeNo,
							Code: imap.ResponseCodeAuthorizationFailed, // Target user does not exist
							Text: "Impersonation target user account not found.",
						}
					}

					s.IMAPUser = NewIMAPUser(address, AccountID)
					s.Session.User = &s.IMAPUser.User
					// Ensure default mailboxes for the impersonated user
					if dbErr := s.server.rdb.CreateDefaultMailboxesWithRetry(s.ctx, AccountID); dbErr != nil {
						return s.internalError("failed to prepare impersonated user session: %v", dbErr)
					}

					authCount := s.server.authenticatedConnections.Add(1)
					totalCount := s.server.totalConnections.Load()
					s.InfoLog("Authentication: session established for impersonated user '%s' (ID: %d) via master SASL login (connections: total=%d, authenticated=%d)", address.BaseAddress(), AccountID, totalCount, authCount)

					metrics.AuthenticationAttempts.WithLabelValues("imap", "success").Inc()
					metrics.AuthenticatedConnectionsCurrent.WithLabelValues("imap").Inc()

					// Trigger cache warmup for the authenticated user (if configured)
					s.triggerCacheWarmup()

					return nil
				}
			}

			// 3. Regular User Authentication
			// The user identified by `username` (authentication-identity) is logging in with `password`.
			// If `identity` (authorization-identity) is provided and is different from `username`,
			// it's a proxy request by a non-master user. This is typically disallowed.
			if identity != "" && identity != username {
				s.DebugLog("Authentication: attempt by '%s' to authorize as '%s' is not allowed for non-master users.", username, identity)
				return &imap.Error{
					Type: imap.StatusResponseTypeNo,
					Code: imap.ResponseCodeAuthorizationFailed,
					Text: "Proxy login not permitted for this user.",
				}
			}

			// Authenticate as `username` (authentication-identity).
			s.DebugLog("Authentication: proceeding with regular authentication for user '%s'", username)
			return s.Login(username, password)
		}), nil
	default:
		s.DebugLog("Authentication: unsupported authentication mechanism: %s", mechanism)
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAuthenticationFailed,
			Text: "Unsupported authentication mechanism",
		}
	}
}
