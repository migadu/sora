package adminapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/cleaner"
)

// handlePurgeAccount serves DELETE /admin/accounts/{email}?purge=true: the account and
// everything it holds are deleted now instead of after the grace period, irreversibly.
// It takes the account out of service, ends its sessions, and runs the cleaner's purge
// (see cleaner.PurgeAccount). If the purge fails, the account stays out of service with
// its address, and the same request resumes it.
func (s *Server) handlePurgeAccount(w http.ResponseWriter, r *http.Request, email string) {
	if s.storage == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Purge unavailable: no object storage configured")
		return
	}

	// Detached from the request: a large account can outlive the server's WriteTimeout
	// and a client that gives up. Stopping midway would be safe, but there is no reason to
	// throw away a purge that is making progress.
	ctx := context.WithoutCancel(r.Context())

	accountID, err := cleaner.DisableAccount(ctx, s.rdb, email)
	if err != nil {
		if errors.Is(err, consts.ErrUserNotFound) {
			s.writeError(w, http.StatusNotFound, err.Error())
			return
		}
		logger.Warn("HTTP API: Error taking account out of service for purge", "name", s.name, "email", email, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Error purging account")
		return
	}
	// Before any data goes: an open session could otherwise keep writing into the
	// account while it is being emptied.
	s.endAccountSessions(accountID, email)

	logger.Info("HTTP API: Purging account", "name", s.name, "email", email, "account_id", accountID)
	stats, err := cleaner.PurgeAccount(ctx, s.rdb, resilient.NewResilientS3Storage(s.storage), accountID)
	if err != nil {
		logger.Warn("HTTP API: Error purging account", "name", s.name, "email", email, "account_id", accountID,
			"s3_objects_deleted", stats.S3Objects, "messages_deleted", stats.Messages, "error", err)
		if errors.Is(err, cleaner.ErrAccountInService) {
			s.writeError(w, http.StatusConflict, "Account was restored while it was being purged")
			return
		}
		s.writeError(w, http.StatusInternalServerError,
			"Account is out of service but not fully purged; repeat the request to finish: "+err.Error())
		return
	}

	logger.Info("HTTP API: Account purged", "name", s.name, "email", email, "account_id", accountID,
		"s3_objects_deleted", stats.S3Objects, "messages_deleted", stats.Messages)
	s.writeJSON(w, http.StatusOK, map[string]any{
		"email":              email,
		"s3_objects_deleted": stats.S3Objects,
		"messages_deleted":   stats.Messages,
		"message":            "Account purged. All of its data has been permanently deleted.",
	})
}
