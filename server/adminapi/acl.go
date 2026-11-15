package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/server/aclservice"
)

// ACLGrantRequest represents the request body for granting ACL rights
type ACLGrantRequest struct {
	Owner      string `json:"owner"`      // Email address of the mailbox owner
	Mailbox    string `json:"mailbox"`    // Mailbox name (e.g., "Shared/Sales")
	Identifier string `json:"identifier"` // Email address or "anyone"
	Rights     string `json:"rights"`     // ACL rights string (e.g., "lrs")
}

// ACLRevokeRequest represents the request body for revoking ACL rights
type ACLRevokeRequest struct {
	Owner      string `json:"owner"`      // Email address of the mailbox owner
	Mailbox    string `json:"mailbox"`    // Mailbox name (e.g., "Shared/Sales")
	Identifier string `json:"identifier"` // Email address or "anyone"
}

// ACLListResponse represents the response for listing ACL entries
type ACLListResponse struct {
	Mailbox string                `json:"mailbox"` // Mailbox name
	Owner   string                `json:"owner"`   // Owner email
	ACLs    []aclservice.ACLEntry `json:"acls"`    // List of ACL entries
}

// aclErrorStatus maps an aclservice error to its HTTP status: a refused grant, or an
// owner, mailbox or user that does not resolve, is the caller's to fix (4xx), and
// anything else is a server fault (500).
func aclErrorStatus(err error) int {
	switch {
	case errors.Is(err, consts.ErrUserNotFound), errors.Is(err, consts.ErrMailboxNotFound):
		return http.StatusNotFound
	case errors.Is(err, db.ErrInvalidACLRight), errors.Is(err, db.ErrMailboxNotShared),
		errors.Is(err, db.ErrCrossDomainGrant), errors.Is(err, db.ErrOwnerACL), errors.Is(err, db.ErrAnyoneDisabled):
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

// aclContext carries the shared mailbox config to the ACL service, which decides
// with it whether "anyone" may be granted rights.
func (s *Server) aclContext(r *http.Request) context.Context {
	return context.WithValue(r.Context(), consts.ConfigContextKey, &config.Config{SharedMailboxes: s.sharedMailboxes})
}

// handleACLGrant handles POST /admin/mailboxes/acl/grant
func (s *Server) handleACLGrant(w http.ResponseWriter, r *http.Request) {
	var req ACLGrantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate required fields
	if strings.TrimSpace(req.Owner) == "" {
		s.writeError(w, http.StatusBadRequest, "owner is required")
		return
	}
	if req.Mailbox == "" {
		s.writeError(w, http.StatusBadRequest, "mailbox is required")
		return
	}
	if req.Identifier == "" {
		s.writeError(w, http.StatusBadRequest, "identifier is required")
		return
	}
	if req.Rights == "" {
		s.writeError(w, http.StatusBadRequest, "rights is required")
		return
	}

	// Create ACL service
	aclSvc := aclservice.New(s.rdb)

	// Grant ACL
	if err := aclSvc.Grant(s.aclContext(r), req.Owner, req.Mailbox, req.Identifier, req.Rights); err != nil {
		if status := aclErrorStatus(err); status != http.StatusInternalServerError {
			s.writeError(w, status, err.Error())
			return
		}
		logger.Debug("Admin API: ACL grant failed", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to grant ACL")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":     "success",
		"message":    "ACL rights granted successfully",
		"owner":      req.Owner,
		"mailbox":    req.Mailbox,
		"identifier": req.Identifier,
		"rights":     req.Rights,
	})
}

// handleACLRevoke handles POST /admin/mailboxes/acl/revoke
func (s *Server) handleACLRevoke(w http.ResponseWriter, r *http.Request) {
	var req ACLRevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate required fields
	if strings.TrimSpace(req.Owner) == "" {
		s.writeError(w, http.StatusBadRequest, "owner is required")
		return
	}
	if req.Mailbox == "" {
		s.writeError(w, http.StatusBadRequest, "mailbox is required")
		return
	}
	if req.Identifier == "" {
		s.writeError(w, http.StatusBadRequest, "identifier is required")
		return
	}

	// Create ACL service
	aclSvc := aclservice.New(s.rdb)

	// Revoke ACL
	// Revoking what is not there leaves the ACL as asked (RFC 4314 §3.2), so it
	// succeeds, whether or not the identifier names an account.
	if err := aclSvc.Revoke(r.Context(), req.Owner, req.Mailbox, req.Identifier); err != nil && !errors.Is(err, consts.ErrDBNotFound) {
		if status := aclErrorStatus(err); status != http.StatusInternalServerError {
			s.writeError(w, status, err.Error())
			return
		}
		logger.Debug("Admin API: ACL revoke failed", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to revoke ACL")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":     "success",
		"message":    "ACL rights revoked successfully",
		"owner":      req.Owner,
		"mailbox":    req.Mailbox,
		"identifier": req.Identifier,
	})
}

// handleACLList handles GET /admin/mailboxes/acl?owner=X&mailbox=Y
func (s *Server) handleACLList(w http.ResponseWriter, r *http.Request) {
	// Get query parameters
	owner := r.URL.Query().Get("owner")
	mailbox := r.URL.Query().Get("mailbox")

	// Validate required parameters
	if strings.TrimSpace(owner) == "" {
		s.writeError(w, http.StatusBadRequest, "owner parameter is required")
		return
	}
	if mailbox == "" {
		s.writeError(w, http.StatusBadRequest, "mailbox parameter is required")
		return
	}

	// Create ACL service
	aclSvc := aclservice.New(s.rdb)

	// List ACLs
	acls, err := aclSvc.List(r.Context(), owner, mailbox)
	if err != nil {
		if status := aclErrorStatus(err); status != http.StatusInternalServerError {
			s.writeError(w, status, err.Error())
			return
		}
		logger.Debug("Admin API: ACL list failed", "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to list ACLs")
		return
	}

	// Return response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ACLListResponse{
		Mailbox: mailbox,
		Owner:   owner,
		ACLs:    acls,
	})
}
