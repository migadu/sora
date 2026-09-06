package userapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/storage"
)

// bodyStatus is what loadMessageBody could establish about a message body.
type bodyStatus int

const (
	// bodyAvailable: the bytes are in hand.
	bodyAvailable bodyStatus = iota
	// bodyPending: not in hand yet, but on its way — staged on another node, or an
	// upload still being retried. The client should try again shortly.
	bodyPending
	// bodyTransient: storage did not answer (timeout, 5xx, circuit open). Try later.
	bodyTransient
	// bodyGone: the body is not coming: no staged copy, no object, no pending upload.
	bodyGone
)

// bodySizeMatches: a local copy (spool, cache) that disagrees with the row's size is a
// leftover of an interrupted write and is a miss, never served. S3 is the authority.
func bodySizeMatches(data []byte, size int) bool {
	if size <= 0 {
		return len(data) > 0
	}
	return len(data) == size
}

// loadMessageBody resolves a message body the same way IMAP FETCH and POP3 RETR do
// (server/imap/fetch.go loadMessageBody is the reference): local cache, then S3 through
// the resilient wrapper, then this node's staging spool; and for a body not yet in S3,
// the spool first, then a bounded look at S3, then the pending-upload state that tells
// "retry later" from "gone". The HTTP API once answered every miss with 500, so a body
// still being uploaded looked exactly like permanent loss.
func (s *Server) loadMessageBody(ctx context.Context, message *db.DBMessage) ([]byte, bodyStatus, error) {
	if s.rs3 == nil {
		return nil, bodyTransient, errors.New("storage not configured")
	}

	if s.cache != nil {
		if data, err := s.cache.Get(message.ContentHash); err == nil {
			if bodySizeMatches(data, message.Size) {
				return data, bodyAvailable, nil
			}
			logger.Warn("HTTP Mail API: cache body size disagrees with the message, dropping it",
				"name", s.name, "content_hash", message.ContentHash, "cached", len(data), "expected", message.Size)
			_ = s.cache.Delete(message.ContentHash)
		}
	}

	if message.Uploaded {
		data, err := s.fetchBodyFromS3(ctx, message)
		if err == nil {
			return data, bodyAvailable, nil
		}
		// S3 could not serve it: the staging copy may still be on this node.
		if data, ok := s.readStagedBody(message); ok {
			return data, bodyAvailable, nil
		}
		if resilient.IsNotFoundError(err) || errors.Is(err, storage.ErrCorruptObject) {
			logger.Warn("HTTP Mail API: message marked uploaded but its object is missing or corrupt",
				"name", s.name, "content_hash", message.ContentHash, "s3_domain", message.S3Domain, "s3_localpart", message.S3Localpart, "error", err)
			return nil, bodyGone, err
		}
		return nil, bodyTransient, err
	}

	// Not yet uploaded: the body should be in this node's staging spool.
	if data, ok := s.readStagedBody(message); ok {
		return data, bodyAvailable, nil
	}
	// Staged on another node, or already uploaded there while this row still reads
	// uploaded=false: S3 may have it.
	pending := s.bodyUploadStillPending(ctx, message)
	if message.S3Domain != "" && message.S3Localpart != "" {
		data, err := s.fetchBodyFromS3(ctx, message)
		if err == nil {
			return data, bodyAvailable, nil
		}
		if !resilient.IsNotFoundError(err) {
			return nil, bodyTransient, err
		}
	}
	if pending {
		return nil, bodyPending, nil
	}
	return nil, bodyGone, errors.New("body not on disk and not in S3")
}

// readStagedBody reads the body from this node's upload staging spool, if it is there
// and complete.
func (s *Server) readStagedBody(message *db.DBMessage) ([]byte, bool) {
	if s.uploader == nil {
		return nil, false
	}
	data, err := os.ReadFile(s.uploader.FilePath(message.ContentHash, message.AccountID))
	if err != nil || !bodySizeMatches(data, message.Size) {
		return nil, false
	}
	return data, true
}

// bodyUploadStillPending mirrors the IMAP/POP3 check: a pending upload the worker will
// still lease, or a row already marked uploaded elsewhere, means the body is on its way.
// A database error counts as pending (a retry is safer than "gone"). Reads the master:
// the pending row and the message row committed together.
func (s *Server) bodyUploadStillPending(ctx context.Context, message *db.DBMessage) bool {
	ctx = context.WithValue(ctx, consts.UseMasterDBKey, true)
	var pending bool
	var err error
	if s.uploader != nil {
		pending, err = s.rdb.PendingUploadRetryableWithRetry(ctx, message.ContentHash, message.AccountID, s.uploader.MaxAttempts())
	} else {
		pending, err = s.rdb.PendingUploadExistsWithRetry(ctx, message.ContentHash, message.AccountID)
	}
	if err != nil {
		logger.Warn("HTTP Mail API: could not check pending-upload status; treating body as pending", "name", s.name, "error", err)
		return true
	}
	if pending {
		return true
	}
	uploaded, err := s.rdb.IsContentHashUploadedWithRetry(ctx, message.ContentHash, message.AccountID, message.S3Domain, message.S3Localpart)
	if err != nil {
		logger.Warn("HTTP Mail API: could not check uploaded status; treating body as pending", "name", s.name, "error", err)
		return true
	}
	return uploaded
}

// fetchBodyFromS3 reads the object the row points at through the resilient wrapper
// (retries, circuit breaker, error classification) and warms the cache.
func (s *Server) fetchBodyFromS3(ctx context.Context, message *db.DBMessage) ([]byte, error) {
	if message.S3Domain == "" || message.S3Localpart == "" || message.ContentHash == "" {
		return nil, fmt.Errorf("message %d is missing S3 key information", message.ID)
	}
	key := helpers.NewS3Key(message.S3Domain, message.S3Localpart, message.ContentHash)
	reader, err := s.rs3.GetWithRetry(ctx, key)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("S3 object %s is empty", key)
	}
	if s.cache != nil {
		if err := s.cache.Put(message.ContentHash, data); err != nil {
			logger.Warn("HTTP Mail API: failed to cache message body", "name", s.name, "error", err)
		}
	}
	return data, nil
}

// writeBodyUnavailable answers a request for a body that is not in hand, with a status
// the client can act on: 503 + Retry-After while the body is on its way or storage is
// down, 410 when it is gone for good. Never 500 for a body that exists.
func (s *Server) writeBodyUnavailable(w http.ResponseWriter, status bodyStatus, err error, messageID int64) {
	switch status {
	case bodyPending:
		logger.Info("HTTP Mail API: message body not yet available", "name", s.name, "message_id", messageID)
		w.Header().Set("Retry-After", "5")
		s.writeError(w, http.StatusServiceUnavailable, "Message body not yet available, retry shortly")
	case bodyTransient:
		logger.Warn("HTTP Mail API: storage temporarily unavailable", "name", s.name, "message_id", messageID, "error", err)
		w.Header().Set("Retry-After", "30")
		s.writeError(w, http.StatusServiceUnavailable, "Storage temporarily unavailable, retry later")
	default:
		logger.Warn("HTTP Mail API: message body is gone", "name", s.name, "message_id", messageID, "error", err)
		s.writeError(w, http.StatusGone, "Message body is no longer available")
	}
}

// newResilientStorage wraps the raw S3 client the way the IMAP and POP3 servers do:
// retries, circuit breaker and error classification. nil stays nil (metadata-only
// deployments and tests).
func newResilientStorage(s3 *storage.S3Storage) *resilient.ResilientS3Storage {
	if s3 == nil {
		return nil
	}
	return resilient.NewResilientS3Storage(s3)
}
