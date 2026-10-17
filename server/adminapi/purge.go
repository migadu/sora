package adminapi

import (
	"errors"
	"net/http"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/logger"
)

// handlePurgeAccount serves DELETE /admin/accounts/{email}?purge=true. It is a request:
// the account is taken out of service, its sessions are ended, and it is marked for
// purging; a purge worker on a node with object storage deletes it (see
// cleaner.PurgeWorker). So it works on any node, a proxy without S3 included. The mark
// shows as purge_requested_at on GET /admin/accounts/{email} until the account is gone.
func (s *Server) handlePurgeAccount(w http.ResponseWriter, r *http.Request, email string) {
	ctx := r.Context()

	accountID, requestedAt, err := s.rdb.RequestAccountPurgeWithRetry(ctx, email)
	if err != nil {
		if errors.Is(err, consts.ErrUserNotFound) {
			s.writeError(w, http.StatusNotFound, err.Error())
			return
		}
		logger.Warn("HTTP API: Error requesting account purge", "name", s.name, "email", email, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Error requesting account purge")
		return
	}

	// Before any data goes: an open session could otherwise keep writing into the
	// account while it is being emptied. Through gossiping trackers this reaches the
	// whole cluster.
	s.endAccountSessions(accountID, email)

	if s.purgeWorker != nil {
		s.purgeWorker.Wake()
	}

	logger.Info("HTTP API: Account purge requested", "name", s.name, "email", email, "account_id", accountID, "requested_at", requestedAt)
	s.writeJSON(w, http.StatusAccepted, map[string]any{
		"email":              email,
		"purge_requested_at": requestedAt,
		"message": "Account is out of service and marked for purging; a purge worker on a node with object storage deletes it. " +
			"GET /admin/accounts/{email} shows purge_requested_at until the account is gone.",
	})
}
