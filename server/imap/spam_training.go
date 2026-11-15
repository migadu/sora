package imap

import (
	"context"
	"errors"
	"io"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/spamtraining"
)

// triggerSpamTraining queues the messages a MOVE put into or took out of Junk for
// spam filter training. Junk and Trash are the mailboxes carrying the RFC 6154
// \Junk and \Trash attributes, whatever their names. A MOVE into Junk trains spam
// and one out of Junk trains ham, except into Trash: that is how clients delete a
// message, and deleting spam does not say it was not spam. moved holds the source
// rows the MOVE read, and uidMap maps the source UIDs it actually moved. The spam
// training client's workers fetch and submit the messages; nothing here waits for
// S3 or the training endpoint.
func (s *IMAPSession) triggerSpamTraining(src, dest *db.DBMailbox, moved []db.Message, uidMap map[imap.UID]imap.UID, destS3Domain, destS3Localpart string) {
	srcIsJunk := src.SpecialUse == string(imap.MailboxAttrJunk)
	destIsJunk := dest.SpecialUse == string(imap.MailboxAttrJunk)

	var trainingType spamtraining.TrainingType
	switch {
	case destIsJunk && !srcIsJunk:
		trainingType = spamtraining.TrainingTypeSpam
	case srcIsJunk && !destIsJunk && dest.SpecialUse != string(imap.MailboxAttrTrash):
		trainingType = spamtraining.TrainingTypeHam
	default:
		return // Not a spam training operation
	}
	destAccountID := dest.AccountID

	// Get user email from session (already available, no need for DB lookup)
	userEmail := s.FullAddress()
	srv := s.server // the jobs run on training workers: capture the server, not the session

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
		contentHash, size := msg.ContentHash, msg.Size

		err := s.server.spamTraining.Enqueue(spamtraining.Job{
			Type:          trainingType,
			User:          userEmail,
			SourceMailbox: src.Name,
			DestMailbox:   dest.Name,
			Size:          int64(msg.Size),
			Open: func(ctx context.Context) (io.ReadCloser, error) {
				// The moved row, and the staged body with it, belongs to the
				// destination mailbox's owner (Move links it there across accounts).
				return srv.openTrainingBody(ctx, contentHash, destAccountID, s3Key, size)
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

// openTrainingBody opens a moved message's body for a training worker from the
// places FETCH (loadMessageBody) reads it: the body cache, the uploader's staging
// file, then S3. A message moved before its upload completed is only in staging,
// and S3 answers NoSuchKey for it. The local copies come first whatever the row's
// upload state was at the MOVE: the upload may finish before the worker runs, and
// a whole staged copy is the body either way. The worker runs after the MOVE,
// often after the session has ended, so this uses no session state.
func (srv *IMAPServer) openTrainingBody(ctx context.Context, contentHash string, accountID int64, s3Key string, size int) (io.ReadCloser, error) {
	if srv.cache != nil {
		if f := openLocalBody(srv.cache.GetPathForContentHash(contentHash), size); f != nil {
			return f, nil
		}
	}
	if srv.uploader != nil {
		if f := openLocalBody(srv.uploader.FilePath(contentHash, accountID), size); f != nil {
			return f, nil
		}
	}
	return srv.s3.GetWithRetry(ctx, s3Key)
}
