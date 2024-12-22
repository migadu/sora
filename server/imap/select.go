package imap

import (
	"context"
	"fmt"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
)

func (s *IMAPSession) Select(mboxName string, options *imap.SelectOptions) (*imap.SelectData, error) {
	ctx := context.Background()

	pathComponents := strings.Split(mboxName, string(consts.MailboxDelimiter))
	mailbox, err := s.server.db.GetMailboxByFullPath(ctx, s.UserID(), pathComponents)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			s.Log("Mailbox '%s' does not exist", mboxName)
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("mailbox '%s' does not exist", mboxName),
			}
		}

		return nil, s.internalError("failed to fetch mailbox '%s': %v", mboxName, err)
	}

	messagesCount, _, err := s.server.db.GetMailboxMessageCountAndSizeSum(ctx, mailbox.ID)
	if err != nil {
		return nil, s.internalError("failed to get message count for mailbox '%s': %v", mboxName, err)
	}

	uidNext, err := s.server.db.GetMailboxNextUID(ctx, mailbox.ID)
	if err != nil {
		return nil, s.internalError("failed to get next UID for mailbox '%s': %v", mboxName, err)
	}

	s.mailbox = NewMailbox(mailbox)

	selectData := &imap.SelectData{
		Flags:       s.mailbox.PermittedFlags(),
		NumMessages: uint32(messagesCount),
		UIDNext:     imap.UID(uidNext),
		UIDValidity: mailbox.UIDValidity,
	}
	s.Log("Mailbox selected: %s", mboxName)
	return selectData, nil
}

func (s *IMAPSession) Unselect() error {
	s.Log("Mailbox %s unselected", s.mailbox.Name)
	s.mailbox = nil
	return nil
}
