package imap

import (
	"context"
	"fmt"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
)

// Delete a mailbox
func (s *IMAPSession) Delete(mboxName string) error {
	ctx := context.Background()

	for _, specialMailbox := range consts.DefaultMailboxes {
		if strings.EqualFold(mboxName, specialMailbox) {
			s.Log("Attempt to delete special mailbox '%s'", mboxName)
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNoPerm,
				Text: fmt.Sprintf("Mailbox '%s' is a special mailbox and cannot be deleted", mboxName),
			}
		}
	}

	pathComponents := strings.Split(mboxName, string(consts.MailboxDelimiter))

	// Fetch the mailbox from the database using the full path
	mailbox, err := s.server.db.GetMailboxByFullPath(ctx, s.user.UserID(), pathComponents)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			s.Log("Mailbox '%s' not found", mboxName)
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("Mailbox '%s' not found", mboxName),
			}
		}
		return s.internalError("failed to fetch mailbox '%s': %v", mboxName, err)
	}

	// Delete the mailbox; the database will automatically delete any child mailboxes due to ON DELETE CASCADE
	err = s.server.db.DeleteMailbox(ctx, mailbox.ID, mboxName)
	if err != nil {
		return s.internalError("failed to delete mailbox '%s': %v", mboxName, err)
	}

	s.Log("Mailbox deleted: %s", mboxName)
	return nil
}
