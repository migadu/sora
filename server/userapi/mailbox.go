package userapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/migadu/sora/logger"

	"github.com/migadu/sora/consts"
)

// MailboxInfo represents mailbox information for API responses
type MailboxInfo struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	Subscribed bool   `json:"subscribed"`
	Total      int    `json:"total"`
	Unseen     int    `json:"unseen"`
	UIDNext    int64  `json:"uid_next"`
}

// CreateMailboxRequest represents the request to create a new mailbox
type CreateMailboxRequest struct {
	Name string `json:"name"`
}

// handleListMailboxes returns all mailboxes for the authenticated user
func (s *Server) handleListMailboxes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	accountID, err := getAccountIDFromContext(ctx)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Check if we should filter by subscribed status
	subscribedOnly := r.URL.Query().Get("subscribed") == "true"

	// Get mailboxes from database
	mailboxes, err := s.rdb.GetMailboxesForUserWithRetry(ctx, accountID, subscribedOnly)
	if err != nil {
		logger.Warn("HTTP Mail API: Error retrieving mailboxes", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to retrieve mailboxes")
		return
	}

	// Convert to API response format with counts
	mailboxInfos := make([]MailboxInfo, 0, len(mailboxes))
	for _, mb := range mailboxes {
		// Get message counts
		total, err := s.rdb.GetMessageCountForMailboxWithRetry(ctx, accountID, mb.Name)
		if err != nil {
			logger.Warn("HTTP Mail API: Error getting message count", "name", s.name, "mailbox", mb.Name, "error", err)
			total = 0 // Continue with zero count on error
		}

		unseen, err := s.rdb.GetUnseenCountForMailboxWithRetry(ctx, accountID, mb.Name)
		if err != nil {
			logger.Warn("HTTP Mail API: Error getting unseen count", "name", s.name, "mailbox", mb.Name, "error", err)
			unseen = 0 // Continue with zero count on error
		}

		mailboxInfos = append(mailboxInfos, MailboxInfo{
			Name:       mb.Name,
			Path:       mb.Name, // Same as name for now
			Subscribed: mb.Subscribed,
			Total:      total,
			Unseen:     unseen,
			UIDNext:    0, // Will be populated when needed
		})
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"mailboxes": mailboxInfos,
		"count":     len(mailboxInfos),
	})
}

// handleCreateMailbox creates a new mailbox for the authenticated user
func (s *Server) handleCreateMailbox(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	ctx := r.Context()

	accountID, err := getAccountIDFromContext(ctx)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var req CreateMailboxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Name == "" {
		s.writeError(w, http.StatusBadRequest, "Mailbox name is required")
		return
	}

	// Validate mailbox name
	if err := validateMailboxName(req.Name); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Create mailbox
	if err := s.rdb.CreateMailboxForUserWithRetry(ctx, accountID, req.Name); err != nil {
		if errors.Is(err, consts.ErrMailboxAlreadyExists) || err.Error() == "unique violation" {
			s.writeError(w, http.StatusConflict, "Mailbox already exists")
			return
		}
		logger.Warn("HTTP Mail API: Error creating mailbox", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to create mailbox")
		return
	}

	s.writeJSON(w, http.StatusCreated, map[string]any{
		"message": "Mailbox created successfully",
		"name":    req.Name,
	})
}

// handleDeleteMailbox deletes a mailbox for the authenticated user
func (s *Server) handleDeleteMailbox(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	accountID, err := getAccountIDFromContext(ctx)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Extract mailbox name from path: /user/mailboxes/{name}
	name := extractPathParam(r.URL.Path, "/user/mailboxes/", "")
	name, err = url.QueryUnescape(name)
	if err != nil || name == "" {
		s.writeError(w, http.StatusBadRequest, "Invalid mailbox name")
		return
	}

	// Prevent deletion of INBOX
	if strings.EqualFold(name, "INBOX") {
		s.writeError(w, http.StatusForbidden, "Cannot delete INBOX")
		return
	}

	// Delete mailbox
	if err := s.rdb.DeleteMailboxForUserWithRetry(ctx, accountID, name); err != nil {
		if errors.Is(err, consts.ErrDBNotFound) || err.Error() == "mailbox not found" {
			s.writeError(w, http.StatusNotFound, "Mailbox not found")
			return
		}
		logger.Warn("HTTP Mail API: Error deleting mailbox", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to delete mailbox")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"message": "Mailbox deleted successfully",
		"name":    name,
	})
}

// handleSubscribeMailbox marks a mailbox as subscribed
func (s *Server) handleSubscribeMailbox(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	accountID, err := getAccountIDFromContext(ctx)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Extract mailbox name from path: /user/mailboxes/{name}/subscribe
	name := extractPathParam(r.URL.Path, "/user/mailboxes/", "/subscribe")
	name, err = url.QueryUnescape(name)
	if err != nil || name == "" {
		s.writeError(w, http.StatusBadRequest, "Invalid mailbox name")
		return
	}

	// Subscribe to mailbox
	if err := s.rdb.SubscribeToMailboxWithRetry(ctx, accountID, name); err != nil {
		if errors.Is(err, consts.ErrDBNotFound) {
			s.writeError(w, http.StatusNotFound, "Mailbox not found")
			return
		}
		logger.Warn("HTTP Mail API: Error subscribing to mailbox", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to subscribe to mailbox")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"message":    "Subscribed to mailbox successfully",
		"name":       name,
		"subscribed": true,
	})
}

// handleUnsubscribeMailbox marks a mailbox as unsubscribed
func (s *Server) handleUnsubscribeMailbox(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	accountID, err := getAccountIDFromContext(ctx)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Extract mailbox name from path: /user/mailboxes/{name}/unsubscribe
	name := extractPathParam(r.URL.Path, "/user/mailboxes/", "/unsubscribe")
	name, err = url.QueryUnescape(name)
	if err != nil || name == "" {
		s.writeError(w, http.StatusBadRequest, "Invalid mailbox name")
		return
	}

	// Unsubscribe from mailbox
	if err := s.rdb.UnsubscribeFromMailboxWithRetry(ctx, accountID, name); err != nil {
		if errors.Is(err, consts.ErrDBNotFound) {
			s.writeError(w, http.StatusNotFound, "Mailbox not found")
			return
		}
		logger.Warn("HTTP Mail API: Error unsubscribing from mailbox", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to unsubscribe from mailbox")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"message":    "Unsubscribed from mailbox successfully",
		"name":       name,
		"subscribed": false,
	})
}

// validateMailboxName validates a mailbox name
func validateMailboxName(name string) error {
	if name == "" {
		return errors.New("mailbox name cannot be empty")
	}

	// Check for invalid characters
	if strings.ContainsAny(name, "\x00\r\n") {
		return errors.New("mailbox name contains invalid characters")
	}

	// Check length (reasonable limit)
	if len(name) > 255 {
		return errors.New("mailbox name too long (max 255 characters)")
	}

	return nil
}
