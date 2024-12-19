package imap

import (
	"context"
	"fmt"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/google/uuid"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/server"
)

func (s *IMAPSession) Copy(seqSet imap.NumSet, mboxName string) (*imap.CopyData, error) {
	if s.mailbox == nil {
		s.Log("Copy failed: no mailbox selected")
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "no mailbox selected",
		}
	}

	ctx := context.Background()

	pathComponents := strings.Split(mboxName, string(consts.MailboxDelimiter))
	destMailbox, err := s.server.db.GetMailboxByFullPath(ctx, s.user.UserID(), pathComponents)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			s.Log("Copy failed: destination mailbox '%s' does not exist", mboxName)
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("destination mailbox '%s' does not exist", mboxName),
			}
		}
		return nil, s.internalError("failed to fetch destination mailbox '%s': %v", mboxName, err)
	}

	messages, err := s.server.db.GetMessagesBySeqSet(ctx, s.mailbox.ID, seqSet)
	if err != nil {
		return nil, s.internalError("failed to retrieve messages for copy: %v", err)
	}

	var sourceUIDs imap.UIDSet
	var destUIDs imap.UIDSet
	for _, msg := range messages {
		sourceUIDs.AddNum(imap.UID(msg.ID))
		copiedUID, err := s.server.db.InsertMessageCopy(ctx, destMailbox.ID, imap.UID(msg.ID), func(destUID imap.UID) error {
			// Copy message body from source mailbox to destination mailbox in S3
			srcUUIDKey, err := uuid.Parse(msg.S3UUID)
			if err != nil {
				return s.internalError("failed to parse message UUID: %v", err)
			}
			destUUID := uuid.New()
			sourceS3Key := server.S3Key(s.user, srcUUIDKey)
			destS3Key := server.S3Key(s.user, destUUID)
			err = s.server.s3.CopyMessage(sourceS3Key, destS3Key)
			if err != nil {
				return s.internalError("failed to copy message body in S3: %v", err)
			}
			return nil
		})
		if err != nil {
			return nil, s.internalError("failed to insert copied message: %v", err)
		}
		destUIDs.AddNum(imap.UID(copiedUID))
	}

	copyData := &imap.CopyData{
		UIDValidity: destMailbox.UIDValidity,
		SourceUIDs:  sourceUIDs,
		DestUIDs:    destUIDs,
	}

	s.Log("Messages copied from %s to %s", s.mailbox.Name(), mboxName)

	return copyData, nil
}
