package imap

import (
	"context"
	"fmt"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
)

// Create a new mailbox
func (s *IMAPSession) Create(name string, options *imap.CreateOptions) error {
	ctx := context.Background()

	// Split the mailbox name by the delimiter to check if it's nested
	parts := strings.Split(name, string(consts.MailboxDelimiter))

	// Check if this is a nested mailbox (i.e., it has a parent)
	if len(parts) > 1 {
		lastComponent := parts[len(parts)-1]

		parentPathComponents := parts[:len(parts)-1]
		parentPath := strings.Join(parentPathComponents, string(consts.MailboxDelimiter))

		parentMailbox, err := s.server.db.GetMailboxByFullPath(ctx, s.user.UserID(), parentPathComponents)
		if err != nil {
			if err == consts.ErrMailboxNotFound {
				s.Log("Parent mailbox '%s' does not exist", parentPath)
				return &imap.Error{
					Type: imap.StatusResponseTypeNo,
					Code: imap.ResponseCodeNonExistent,
					Text: fmt.Sprintf("parent mailbox '%s' does not exist", parentPath),
				}
			}
			return s.internalError("failed to fetch parent mailbox '%s': %v", parentPath, err)
		}

		err = s.server.db.CreateChildMailbox(ctx, s.user.UserID(), lastComponent, parentMailbox.ID, parentPath)
		if err != nil {
			return s.internalError("failed to create mailbox '%s': %v", name, err)
		}
		return nil
	}

	err := s.server.db.CreateMailbox(ctx, s.user.UserID(), name)
	if err != nil {
		return s.internalError("failed to create mailbox '%s': %v", name, err)
	}
	s.Log("Mailbox created: %s", name)
	return nil
}
