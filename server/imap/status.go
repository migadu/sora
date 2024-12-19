package imap

import (
	"context"
	"fmt"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
)

func (s *IMAPSession) Status(mboxName string, options *imap.StatusOptions) (*imap.StatusData, error) {
	ctx := context.Background()
	pathComponents := strings.Split(mboxName, string(consts.MailboxDelimiter))
	mailbox, err := s.server.db.GetMailboxByFullPath(ctx, s.user.UserID(), pathComponents)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("mailbox '%s' does not exist", mboxName),
			}
		}
		return nil, s.internalError("failed to fetch mailbox '%s': %v", mboxName, err)
	}

	statusData := &imap.StatusData{
		Mailbox: mailbox.Name,
	}

	if options.NumMessages {
		messageCount, _, err := s.server.db.GetMessageCount(ctx, mailbox.ID)
		if err != nil {
			return nil, s.internalError("failed to get message count for mailbox '%s': %v", mboxName, err)
		}
		numMessages := uint32(messageCount)
		statusData.NumMessages = &numMessages
	}

	if options.UIDNext {
		uidNext, err := s.server.db.GetMailboxNextUID(ctx, mailbox.ID)
		if err != nil {
			return nil, s.internalError("failed to get next UID for mailbox '%s': %v", mboxName, err)
		}
		statusData.UIDNext = imap.UID(uidNext)
	}

	if options.UIDValidity {
		statusData.UIDValidity = mailbox.UIDValidity
	}

	if options.NumUnseen {
		unseenCount, err := s.server.db.GetMailboxUnseenCount(ctx, mailbox.ID)
		if err != nil {
			return nil, s.internalError("failed to get unseen message count for mailbox '%s': %v", mboxName, err)
		}
		numUnseen := uint32(unseenCount)
		statusData.NumUnseen = &numUnseen
	}

	return statusData, nil
}
