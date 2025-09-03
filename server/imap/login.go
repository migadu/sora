package imap

import (
	"crypto/subtle"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
)

// Tilde is default separator for master password
const MasterUsernameSeparator = "~"

func (s *IMAPSession) Login(address, password string) error {
	// Create a fake net.Addr from the RemoteIP for rate limiting
	remoteAddr := &server.StringAddr{Addr: s.RemoteIP}
	
	// Apply progressive authentication delay BEFORE any other checks
	server.ApplyAuthenticationDelay(s.ctx, s.server.authLimiter, remoteAddr, "IMAP-LOGIN")
	
	// Check authentication rate limiting after delay
	if s.server.authLimiter != nil {
		if err := s.server.authLimiter.CanAttemptAuth(s.ctx, remoteAddr, address); err != nil {
			s.Log("[LOGIN] rate limited: %v", err)
			// Track rate limiting as a specific error type
			metrics.ProtocolErrors.WithLabelValues("imap", "LOGIN", "rate_limited", "client_error").Inc()
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeAuthenticationFailed,
				Text: "Too many authentication attempts. Please try again later.",
			}
		}
	}

	authAddress, proxyUser := parseMasterLogin(address)

	// Master password login
	if len(s.server.masterUsername) > 0 && proxyUser != "" && checkMasterCredential(proxyUser, s.server.masterUsername) {
		address, err := server.NewAddress(authAddress)
		if err != nil {
			s.Log("[LOGIN] failed to parse address: %v", err)
			// Track invalid address format as client error
			metrics.ProtocolErrors.WithLabelValues("imap", "LOGIN", "invalid_address", "client_error").Inc()
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeAuthenticationFailed,
				Text: "Address not in the correct format",
			}
		}

		if checkMasterCredential(password, s.server.masterPassword) {
			userID, err := s.server.db.GetAccountIDByAddress(s.ctx, address.FullAddress())
			if err != nil {
				return err
			}

			s.IMAPUser = NewIMAPUser(address, userID)
			s.Session.User = &s.IMAPUser.User

			authCount := s.server.authenticatedConnections.Add(1)
			totalCount := s.server.totalConnections.Load()
			s.Log("[LOGIN] user %s/%s authenticated with master password (connections: total=%d, authenticated=%d)",
				address, proxyUser, totalCount, authCount)
			
			// Prometheus metrics - successful authentication
			metrics.AuthenticationAttempts.WithLabelValues("imap", "success").Inc()
			metrics.AuthenticatedConnectionsCurrent.WithLabelValues("imap").Inc()
			
			// Record successful authentication
			if s.server.authLimiter != nil {
				remoteAddr := &server.StringAddr{Addr: s.RemoteIP}
				s.server.authLimiter.RecordAuthAttempt(s.ctx, remoteAddr, address.FullAddress(), true)
			}
			
			// Trigger cache warmup for the authenticated user (if configured)
			s.triggerCacheWarmup(userID)
			
			return nil
		}
		
		// Record failed master password authentication
		metrics.AuthenticationAttempts.WithLabelValues("imap", "failure").Inc()
		if s.server.authLimiter != nil {
			remoteAddr := &server.StringAddr{Addr: s.RemoteIP}
			s.server.authLimiter.RecordAuthAttempt(s.ctx, remoteAddr, authAddress, false)
		}
	}

	addressSt, err := server.NewAddress(address)
	if err != nil {
		s.Log("[LOGIN] failed to parse address: %v", err)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAuthenticationFailed,
			Text: "Address not in the correct format",
		}
	}

	s.Log("[LOGIN] authentication attempt with address %s", addressSt.FullAddress())

	userID, err := s.server.db.Authenticate(s.ctx, addressSt.FullAddress(), password)
	if err != nil {
		s.Log("[LOGIN] authentication failed: %v", err)

		// Record failed authentication
		metrics.AuthenticationAttempts.WithLabelValues("imap", "failure").Inc()
		if s.server.authLimiter != nil {
			remoteAddr := &server.StringAddr{Addr: s.RemoteIP}
			s.server.authLimiter.RecordAuthAttempt(s.ctx, remoteAddr, addressSt.FullAddress(), false)
		}

		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAuthenticationFailed,
			Text: "Invalid address or password",
		}
	}

	// Ensure default mailboxes (INBOX/Drafts/Sent/Spam/Trash) exist
	err = s.server.db.CreateDefaultMailboxes(s.ctx, userID)
	if err != nil {
		return s.internalError("failed to create default mailboxes: %v", err)
	}

	s.IMAPUser = NewIMAPUser(addressSt, userID)
	s.Session.User = &s.IMAPUser.User

	authCount := s.server.authenticatedConnections.Add(1)
	totalCount := s.server.totalConnections.Load()
	s.Log("[LOGIN] user %s authenticated (connections: total=%d, authenticated=%d)",
		address, totalCount, authCount)
	
	// Prometheus metrics - successful authentication
	metrics.AuthenticationAttempts.WithLabelValues("imap", "success").Inc()
	metrics.AuthenticatedConnectionsCurrent.WithLabelValues("imap").Inc()
	
	// Domain and user tracking
	metrics.TrackDomainConnection("imap", addressSt.Domain())
	metrics.TrackUserActivity("imap", addressSt.FullAddress(), "connection", 1)
	
	// Record successful authentication
	if s.server.authLimiter != nil {
		remoteAddr := &server.StringAddr{Addr: s.RemoteIP}
		s.server.authLimiter.RecordAuthAttempt(s.ctx, remoteAddr, addressSt.FullAddress(), true)
	}
	
	// Trigger cache warmup for the authenticated user (if configured)
	// This happens after successful authentication and improves performance for reconnections
	s.triggerCacheWarmup(userID)
	
	return nil
}

func parseMasterLogin(username string) (realuser, authuser string) {
	parts := strings.SplitN(username, MasterUsernameSeparator, 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return username, ""
}

func checkMasterCredential(provided string, actual []byte) bool {
	return subtle.ConstantTimeCompare([]byte(provided), actual) == 1
}

// triggerCacheWarmup triggers cache warmup for a user if enabled
func (s *IMAPSession) triggerCacheWarmup(userID int64) {
	// Check if warmup is enabled
	if !s.server.enableWarmup || s.server.warmupMessageCount <= 0 {
		return
	}

	// Use configured mailboxes or default to INBOX
	mailboxes := s.server.warmupMailboxes
	if len(mailboxes) == 0 {
		mailboxes = []string{"INBOX"}
	}

	// Trigger warmup (this handles async/sync based on configuration)
	err := s.server.WarmupCache(s.ctx, userID, mailboxes, s.server.warmupMessageCount, s.server.warmupAsync)
	if err != nil {
		s.Log("[WARMUP] failed to trigger cache warmup for user %d: %v", userID, err)
	}
}
