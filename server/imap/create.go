package imap

import (
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
)

// Create a new mailbox
func (s *IMAPSession) Create(name string, options *imap.CreateOptions) error {
	// First phase: validation and mailbox lookup using read lock
	s.mutex.RLock()
	userID := s.UserID()
	s.mutex.RUnlock()

	// Check if mailbox already exists
	_, err := s.server.db.GetMailboxByName(s.ctx, userID, name)
	if err == nil {
		s.Log("[CREATE] mailbox '%s' already exists", name)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAlreadyExists,
			Text: "Mailbox already exists",
		}
	}

	// Split the mailbox name by the delimiter to check if it's nested
	parts := strings.Split(name, string(consts.MailboxDelimiter))
	var parentMailboxID *int64

	// For nested mailboxes, we need to find the immediate parent
	if len(parts) > 1 {
		// Remove empty part if name ends with delimiter (e.g., "folder/" -> ["folder", ""])
		if parts[len(parts)-1] == "" && len(parts) > 1 {
			parts = parts[:len(parts)-1]
		}

		// Still nested after cleanup?
		if len(parts) > 1 {
			// Auto-create missing parent mailboxes (like Dovecot)
			var currentParentID *int64
			
			// Create each level of the hierarchy if it doesn't exist
			for i := 1; i < len(parts); i++ {
				parentPathWithoutDelim := strings.Join(parts[:i], string(consts.MailboxDelimiter))
				parentPathWithDelim := parentPathWithoutDelim + string(consts.MailboxDelimiter)
				
				var parentMailbox *db.DBMailbox
				
				// Check if without-delimiter version exists
				parentMailbox, err := s.server.db.GetMailboxByName(s.ctx, userID, parentPathWithoutDelim)
				withoutDelimExists := (err == nil)
				
				// Check if with-delimiter version exists  
				_, err = s.server.db.GetMailboxByName(s.ctx, userID, parentPathWithDelim)
				withDelimExists := (err == nil)
				
				// Create missing versions
				if !withoutDelimExists {
					s.Log("[CREATE] auto-creating parent mailbox '%s'", parentPathWithoutDelim)
					err = s.server.db.CreateMailbox(s.ctx, userID, parentPathWithoutDelim, currentParentID)
					if err != nil {
						return s.internalError("failed to auto-create parent mailbox '%s': %v", parentPathWithoutDelim, err)
					}
					
					// Get the newly created parent
					parentMailbox, err = s.server.db.GetMailboxByName(s.ctx, userID, parentPathWithoutDelim)
					if err != nil {
						return s.internalError("failed to fetch auto-created parent mailbox '%s': %v", parentPathWithoutDelim, err)
					}
				}
				
				if !withDelimExists {
					s.Log("[CREATE] auto-creating parent mailbox '%s'", parentPathWithDelim)
					err = s.server.db.CreateMailbox(s.ctx, userID, parentPathWithDelim, currentParentID)
					if err != nil {
						return s.internalError("failed to auto-create parent mailbox '%s': %v", parentPathWithDelim, err)
					}
				}
				
				if parentMailbox != nil {
					currentParentID = &parentMailbox.ID
				}
			}
			
			parentMailboxID = currentParentID
		}
	}

	// Final phase: actual creation - no locks needed as it's a DB operation
	err = s.server.db.CreateMailbox(s.ctx, userID, name, parentMailboxID)
	if err != nil {
		return s.internalError("failed to create mailbox '%s': %v", name, err)
	}

	s.Log("[CREATE] mailbox created: %s", name)
	return nil
}
