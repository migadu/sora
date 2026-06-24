package imap

import (
	"context"
	"io"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/spamtraining"
)

// triggerSpamTraining submits messages for spam filter training when moved to/from Junk folder
func (s *IMAPSession) triggerSpamTraining(ctx context.Context, destMailboxID int64, srcMailboxName, destMailboxName string, messageUIDMap map[imap.UID]imap.UID) {
	// Determine if this is a spam training operation
	var trainingType spamtraining.TrainingType
	var isTraining bool

	srcIsJunk := strings.EqualFold(srcMailboxName, "Junk") || srcMailboxName == consts.MailboxJunk
	destIsJunk := strings.EqualFold(destMailboxName, "Junk") || destMailboxName == consts.MailboxJunk

	if destIsJunk && !srcIsJunk {
		// Moving TO Junk = mark as spam
		trainingType = spamtraining.TrainingTypeSpam
		isTraining = true
	} else if srcIsJunk && !destIsJunk {
		// Moving FROM Junk = mark as ham (not spam)
		trainingType = spamtraining.TrainingTypeHam
		isTraining = true
	}

	if !isTraining {
		return // Not a spam training operation
	}

	// Get user email from session (already available, no need for DB lookup)
	userEmail := s.FullAddress()

	// Process each moved message
	for _, destUID := range messageUIDMap {
		// Submit training asynchronously for each message using destination UID
		go s.submitMessageTraining(ctx, destMailboxID, destUID, trainingType, userEmail, srcMailboxName, destMailboxName)
	}
}

// submitMessageTraining fetches message from S3 and submits it for training
func (s *IMAPSession) submitMessageTraining(ctx context.Context, mailboxID int64, uid imap.UID, trainingType spamtraining.TrainingType, userEmail, srcMailbox, destMailbox string) {
	// Detach from the caller's cancellation — this runs as a fire-and-forget goroutine
	// that must outlive the IMAP command — while preserving the context's values (trace IDs, etc.).
	bgCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
	defer cancel()

	// Get message metadata
	numSet := imap.UIDSetNum(uid)
	messages, err := s.server.rdb.GetMessagesByNumSetWithRetry(bgCtx, mailboxID, numSet)
	if err != nil {
		s.WarnLog("failed to get message for spam training",
			"mailbox_id", mailboxID,
			"uid", uid,
			"type", trainingType,
			"error", err)
		return
	}

	if len(messages) == 0 {
		s.WarnLog("message not found for spam training",
			"mailbox_id", mailboxID,
			"uid", uid,
			"type", trainingType)
		return
	}

	msg := messages[0]

	// Validate S3 key components before attempting fetch
	if msg.S3Domain == "" || msg.S3Localpart == "" || msg.ContentHash == "" {
		s.WarnLog("message missing S3 key information - skipping spam training",
			"uid", uid,
			"type", trainingType,
			"has_domain", msg.S3Domain != "",
			"has_localpart", msg.S3Localpart != "",
			"has_hash", msg.ContentHash != "")
		return
	}

	// Construct S3 key
	s3Key := helpers.NewS3Key(msg.S3Domain, msg.S3Localpart, msg.ContentHash)

	// Fetch message body from S3
	reader, err := s.server.s3.GetWithRetry(bgCtx, s3Key)
	if err != nil {
		s.WarnLog("failed to fetch message body from S3 for spam training",
			"content_hash", msg.ContentHash,
			"uid", uid,
			"type", trainingType,
			"error", err)
		return
	}
	defer reader.Close()

	// Read message body
	messageBodyBytes, err := io.ReadAll(reader)
	if err != nil {
		s.WarnLog("failed to read message body for spam training",
			"content_hash", msg.ContentHash,
			"uid", uid,
			"type", trainingType,
			"error", err)
		return
	}

	// Strip attachments from message
	strippedBody, err := spamtraining.StripAttachments(messageBodyBytes)
	if err != nil {
		s.WarnLog("failed to strip attachments for spam training",
			"uid", uid,
			"type", trainingType,
			"error", err)
		// Continue with original body if stripping fails
		strippedBody = messageBodyBytes
	}

	// Create training request
	req := &spamtraining.TrainingRequest{
		Type:          trainingType,
		Message:       string(strippedBody),
		User:          userEmail,
		SourceMailbox: srcMailbox,
		DestMailbox:   destMailbox,
		Timestamp:     time.Now(),
	}

	// Submit training (async submission happens inside the client)
	s.server.spamTraining.SubmitTrainingAsync(bgCtx, req)
}
