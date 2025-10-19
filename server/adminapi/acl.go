package adminapi

import (
	"encoding/json"
	"log"
	"net/http"

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

// handleACLGrant handles POST /admin/mailboxes/acl/grant
func (s *Server) handleACLGrant(w http.ResponseWriter, r *http.Request) {
	var req ACLGrantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "Invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Owner == "" {
		http.Error(w, `{"error": "owner is required"}`, http.StatusBadRequest)
		return
	}
	if req.Mailbox == "" {
		http.Error(w, `{"error": "mailbox is required"}`, http.StatusBadRequest)
		return
	}
	if req.Identifier == "" {
		http.Error(w, `{"error": "identifier is required"}`, http.StatusBadRequest)
		return
	}
	if req.Rights == "" {
		http.Error(w, `{"error": "rights is required"}`, http.StatusBadRequest)
		return
	}

	// Create ACL service
	aclSvc := aclservice.New(s.rdb)

	// Grant ACL
	if err := aclSvc.Grant(r.Context(), req.Owner, req.Mailbox, req.Identifier, req.Rights); err != nil {
		log.Printf("[ADMIN-API] ACL grant failed: %v", err)
		http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)
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
		http.Error(w, `{"error": "Invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Owner == "" {
		http.Error(w, `{"error": "owner is required"}`, http.StatusBadRequest)
		return
	}
	if req.Mailbox == "" {
		http.Error(w, `{"error": "mailbox is required"}`, http.StatusBadRequest)
		return
	}
	if req.Identifier == "" {
		http.Error(w, `{"error": "identifier is required"}`, http.StatusBadRequest)
		return
	}

	// Create ACL service
	aclSvc := aclservice.New(s.rdb)

	// Revoke ACL
	if err := aclSvc.Revoke(r.Context(), req.Owner, req.Mailbox, req.Identifier); err != nil {
		log.Printf("[ADMIN-API] ACL revoke failed: %v", err)
		http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)
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
	if owner == "" {
		http.Error(w, `{"error": "owner parameter is required"}`, http.StatusBadRequest)
		return
	}
	if mailbox == "" {
		http.Error(w, `{"error": "mailbox parameter is required"}`, http.StatusBadRequest)
		return
	}

	// Create ACL service
	aclSvc := aclservice.New(s.rdb)

	// List ACLs
	acls, err := aclSvc.List(r.Context(), owner, mailbox)
	if err != nil {
		log.Printf("[ADMIN-API] ACL list failed: %v", err)
		http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)
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
