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
	s.Log("[AUTH] authentication attempt with mechanism %s", mechanism)

	switch mechanism {
	case "PLAIN":
		return sasl.NewPlainServer(func(identity, username, password string) error {
			// SASL PLAIN payload: [authorization-identity] \0 authentication-identity \0 password
			// callback `identity`: authorization-identity (user to act as, can be empty)
			// callback `username`: authentication-identity (user whose credentials are provided)
			// callback `password`: password for authentication-identity

			// Check authentication rate limiting before attempting any authentication
			if s.server.authLimiter != nil {
				remoteAddr := &server.StringAddr{Addr: s.RemoteIP}
				targetUser := username
				if identity != "" {
					targetUser = identity // Use authorization identity if provided
				}
				if err := s.server.authLimiter.CanAttemptAuth(s.ctx, remoteAddr, targetUser); err != nil {
					s.Log("[SASL PLAIN] rate limited: %v", err)
					return &imap.Error{
						Type: imap.StatusResponseTypeNo,
						Code: imap.ResponseCodeAuthenticationFailed,
						Text: "Too many authentication attempts. Please try again later.",
					}
				}
			}

			s.Log("[SASL PLAIN] AuthorizationID: '%s', AuthenticationID: '%s'", identity, username)

			// 1. Check for Master SASL Authentication
			if len(s.server.masterSASLUsername) > 0 && len(s.server.masterSASLPassword) > 0 {
				// Check if the provided authentication identity and password match the server's master SASL credentials
				if checkMasterCredential(username, s.server.masterSASLUsername) &&
					checkMasterCredential(password, s.server.masterSASLPassword) {

					// Master SASL credentials match. The user to log in as is the authorization-identity.
					targetUserToImpersonate := identity
					if targetUserToImpersonate == "" {
						s.Log("[AUTH] Master SASL authentication for '%s' successful, but no authorization identity (target user to impersonate) provided.", username)
						metrics.AuthenticationAttempts.WithLabelValues("imap", "failure").Inc()
						return &imap.Error{
							Type: imap.StatusResponseTypeNo,
							Code: imap.ResponseCodeAuthorizationFailed,
							Text: "Master SASL login requires an authorization identity (target user to impersonate).",
						}
					}

					s.Log("[AUTH] Master SASL user '%s' authenticated. Attempting to impersonate '%s'.", username, targetUserToImpersonate)

					// Log in as the targetUserToImpersonate.
					// For master impersonation, we directly establish the session for them.
					address, err := server.NewAddress(targetUserToImpersonate)
					if err != nil {
						s.Log("[AUTH] Failed to parse impersonation target user '%s' as address: %v", targetUserToImpersonate, err)
						metrics.AuthenticationAttempts.WithLabelValues("imap", "failure").Inc()
						return &imap.Error{
							Type: imap.StatusResponseTypeNo,
							Code: imap.ResponseCodeAuthorizationFailed,
							Text: "Impersonation target user address is not in the correct format.",
						}
					}

					userID, err := s.server.db.GetAccountIDByAddress(s.ctx, address.FullAddress())
					if err != nil {
						s.Log("[AUTH] Failed to get account ID for impersonation target user '%s': %v", targetUserToImpersonate, err)
						metrics.AuthenticationAttempts.WithLabelValues("imap", "failure").Inc()
						return &imap.Error{
							Type: imap.StatusResponseTypeNo,
							Code: imap.ResponseCodeAuthorizationFailed, // Target user does not exist
							Text: "Impersonation target user account not found.",
						}
					}

					s.IMAPUser = NewIMAPUser(address, userID)
					s.Session.User = &s.IMAPUser.User
					// Ensure default mailboxes for the impersonated user
					if dbErr := s.server.db.CreateDefaultMailboxes(s.ctx, userID); dbErr != nil {
						return s.internalError("failed to prepare impersonated user session: %v", dbErr)
					}

					authCount := s.server.authenticatedConnections.Add(1)
					totalCount := s.server.totalConnections.Load()
					s.Log("[AUTH] Session established for impersonated user '%s' (ID: %d) via master SASL login. (connections: total=%d, authenticated=%d)", targetUserToImpersonate, userID, totalCount, authCount)

					metrics.AuthenticationAttempts.WithLabelValues("imap", "success").Inc()
					metrics.AuthenticatedConnectionsCurrent.WithLabelValues("imap").Inc()

					// Trigger cache warmup for the authenticated user (if configured)
					s.triggerCacheWarmup()

					return nil
				}
			}

			// 2. Regular User Authentication
			// The user identified by `username` (authentication-identity) is logging in with `password`.
			// If `identity` (authorization-identity) is provided and is different from `username`,
			// it's a proxy request by a non-master user. This is typically disallowed.
			if identity != "" && identity != username {
				s.Log("[AUTH] Attempt by '%s' to authorize as '%s' is not allowed for non-master users.", username, identity)
				return &imap.Error{
					Type: imap.StatusResponseTypeNo,
					Code: imap.ResponseCodeAuthorizationFailed,
					Text: "Proxy login not permitted for this user.",
				}
			}

			// Authenticate as `username` (authentication-identity).
			s.Log("[AUTH] Proceeding with regular authentication for user '%s'", username)
			return s.Login(username, password)
		}), nil
	default:
		s.Log("[AUTH] unsupported authentication mechanism: %s", mechanism)
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAuthenticationFailed,
			Text: "Unsupported authentication mechanism",
		}
	}
}
