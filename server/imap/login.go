package imap

import (
	"context"
	"log"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/server"
)

func (s *IMAPSession) Login(address, password string) error {

	addressSt, err := server.NewAddress(address)
	if err != nil {
		s.Log("Failed to parse address: %v", err)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAuthenticationFailed,
			Text: "Username not in the correct format",
		}
	}

	userID, err := s.server.db.GetUserIDByAddress(context.Background(), addressSt.FullAddress())
	if err != nil {
		if err == consts.ErrUserNotFound {
			s.Log("Unknown user: %s", address)
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeAuthenticationFailed,
				Text: "Unknown user",
			}
		}
		return s.internalError("failed to fetch user: %v", err)
	}

	log.Printf("Authentication attempt for user: %s", address)
	ctx := context.Background()

	err = s.server.db.Authenticate(ctx, userID, password)
	if err != nil {
		s.Log("Authentication failed: %v", err)

		// Return a specific authentication error
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAuthenticationFailed,
			Text: "Invalid username or password",
		}
	}

	// Ensure default mailboxes (INBOX/Drafts/Sent/Spam/Trash) exist
	err = s.server.db.CreateDefaultMailboxes(ctx, userID)
	if err != nil {
		return s.internalError("failed to create default mailboxes: %v", err)
	}

	// Fetch mailboxes, converting them to IMAP mailboxes
	mboxes, err := s.server.db.GetMailboxes(ctx, userID)
	if err != nil {
		return s.internalError("failed to fetch mailboxes: %v", err)
	}
	mailboxes := make(map[string]*Mailbox)
	for _, mbox := range mboxes {
		mailboxes[mbox.Name] = NewMailbox(mbox)
	}

	s.IMAPUser = NewIMAPUser(addressSt, userID, mailboxes)

	s.Log("User %s successfully authenticated", address)
	return nil
}
