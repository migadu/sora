package imap

import (
	"context"
	"errors"
	"io"
	"strings"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/spamtraining"
)

// triggerSpamTraining queues the messages a MOVE put into or took out of Junk for
// spam filter training. moved holds the source rows the MOVE read, and uidMap maps
// the source UIDs it actually moved. The spam training client's workers fetch and
// submit the messages; nothing here waits for S3 or the training endpoint.
func (s *IMAPSession) triggerSpamTraining(srcMailboxName, destMailboxName string, moved []db.Message, uidMap map[imap.UID]imap.UID, destAccountID int64, destS3Domain, destS3Localpart string) {
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
	s3 := s.server.s3

	var queued, tooLarge, dropped int
	for _, msg := range moved {
		if _, ok := uidMap[msg.UID]; !ok {
			continue // not moved
		}

		// The moved row keeps the body's S3 key within one account and takes the
		// destination owner's key across accounts (db.MoveMessages).
		s3Domain, s3Localpart := msg.S3Domain, msg.S3Localpart
		if msg.AccountID != destAccountID {
			s3Domain, s3Localpart = destS3Domain, destS3Localpart
		}
		if s3Domain == "" || s3Localpart == "" || msg.ContentHash == "" {
			s.WarnLog("message missing S3 key information - skipping spam training",
				"uid", msg.UID,
				"type", trainingType,
				"has_domain", s3Domain != "",
				"has_localpart", s3Localpart != "",
				"has_hash", msg.ContentHash != "")
			continue
		}
		s3Key := helpers.NewS3Key(s3Domain, s3Localpart, msg.ContentHash)

		err := s.server.spamTraining.Enqueue(spamtraining.Job{
			Type:          trainingType,
			User:          userEmail,
			SourceMailbox: srcMailboxName,
			DestMailbox:   destMailboxName,
			Size:          int64(msg.Size),
			Open: func(ctx context.Context) (io.ReadCloser, error) {
				return s3.GetWithRetry(ctx, s3Key)
			},
		})
		switch {
		case err == nil:
			queued++
		case errors.Is(err, spamtraining.ErrMessageTooLarge):
			tooLarge++
		default:
			dropped++
		}
	}

	if dropped > 0 {
		s.WarnLog("spam training queue full - messages not submitted",
			"type", trainingType, "queued", queued, "too_large", tooLarge, "dropped", dropped)
	} else if tooLarge > 0 {
		s.DebugLog("spam training skipped messages over max_message_size",
			"type", trainingType, "queued", queued, "too_large", tooLarge)
	}
}
