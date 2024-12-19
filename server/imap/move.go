package imap

import (
	"context"
	"fmt"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/consts"
)

func (s *IMAPSession) Move(w *imapserver.MoveWriter, numSet imap.NumSet, dest string) error {
	// Ensure a mailbox is selected
	if s.mailbox == nil {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "no mailbox selected",
		}
	}

	ctx := context.Background()

	// Find the destination mailbox by its name
	destMailbox, err := s.server.db.GetMailboxByFullPath(ctx, s.user.UserID(), strings.Split(dest, string(consts.MailboxDelimiter)))
	if err != nil {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: fmt.Sprintf("destination mailbox '%s' not found", dest),
		}
	}

	// Get messages by sequence or UID set (based on NumKind, which is SeqNum or UID)
	messages, err := s.server.db.GetMessagesBySeqSet(ctx, s.mailbox.ID, numSet)
	if err != nil {
		return s.internalError("failed to retrieve messages: %v", err)
	}

	// Collect message IDs for moving and sequence numbers for expunge
	var sourceUIDs []imap.UID
	var seqNums []uint32
	var destUIDs []imap.UID

	for _, msg := range messages {
		sourceUIDs = append(sourceUIDs, imap.UID(msg.ID))
		seqNums = append(seqNums, uint32(msg.Seq))
	}

	// Move messages in the database
	messageUIDMap, err := s.server.db.MoveMessages(ctx, &sourceUIDs, s.mailbox.ID, destMailbox.ID)
	if err != nil {
		return s.internalError("failed to move messages: %v", err)
	}

	// messageUIDMap holds the mapping between original UIDs and new UIDs
	for originalUID, newUID := range messageUIDMap {
		sourceUIDs = append(sourceUIDs, imap.UID(originalUID))
		destUIDs = append(destUIDs, imap.UID(newUID))
	}

	// Prepare CopyData (UID data for the COPYUID response)
	copyData := &imap.CopyData{
		UIDValidity: s.mailbox.uidValidity,         // UIDVALIDITY of the source mailbox
		SourceUIDs:  imap.UIDSetNum(sourceUIDs...), // Original UIDs (source mailbox)
		DestUIDs:    imap.UIDSetNum(destUIDs...),   // New UIDs in the destination mailbox
	}

	// Write the CopyData (COPYUID response)
	if err := w.WriteCopyData(copyData); err != nil {
		return s.internalError("failed to write COPYUID: %v", err)
	}

	// Expunge messages in the source mailbox (optional)
	for _, seqNum := range seqNums {
		if err := w.WriteExpunge(seqNum); err != nil {
			return s.internalError("failed to write EXPUNGE: %v", err)
		}
	}

	return nil
}
