package imap

import (
	"crypto/subtle"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/server"
)

// Tilde is default separator for master password
const MasterUsernameSeparator = "~"

func (s *IMAPSession) Login(address, password string) error {
	authAddress, proxyUser := parseMasterLogin(address)

	// Master password login
	if len(s.server.masterUsername) > 0 && proxyUser != "" && checkMasterCredential(proxyUser, s.server.masterUsername) {
		address, err := server.NewAddress(authAddress)
		if err != nil {
			s.Log("[LOGIN] failed to parse address: %v", err)
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
			return nil
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
