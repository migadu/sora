package userapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/migadu/sora/logger"

	"github.com/migadu/sora/consts"
)

// UpdateMessageRequest represents the request to update message flags
type UpdateMessageRequest struct {
	AddFlags    []string `json:"add_flags,omitempty"`
	RemoveFlags []string `json:"remove_flags,omitempty"`
}

// handleUpdateMessage updates message flags
func (s *Server) handleUpdateMessage(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	ctx := r.Context()

	accountID, err := getAccountIDFromContext(ctx)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Extract message ID from path: /user/messages/{id}
	messageIDStr := extractLastPathSegment(r.URL.Path)
	messageID, err := strconv.ParseInt(messageIDStr, 10, 64)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid message ID")
		return
	}

	var req UpdateMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate that at least one operation is specified
	if len(req.AddFlags) == 0 && len(req.RemoveFlags) == 0 {
		s.writeError(w, http.StatusBadRequest, "At least one of add_flags or remove_flags must be specified")
		return
	}

	// Validate flag names
	for _, flag := range req.AddFlags {
		if !isValidFlag(flag) {
			s.writeError(w, http.StatusBadRequest, "Invalid flag: "+flag)
			return
		}
	}
	for _, flag := range req.RemoveFlags {
		if !isValidFlag(flag) {
			s.writeError(w, http.StatusBadRequest, "Invalid flag: "+flag)
			return
		}
	}

	// Update message flags
	err = s.rdb.UpdateMessageFlagsWithRetry(ctx, accountID, messageID, req.AddFlags, req.RemoveFlags)
	if err != nil {
		if errors.Is(err, consts.ErrDBNotFound) {
			s.writeError(w, http.StatusNotFound, "Message not found")
			return
		}
		logger.Warn("HTTP Mail API: Error updating message flags", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to update message flags")
		return
	}

	// Get updated message to return
	message, err := s.rdb.GetMessageByIDWithRetry(ctx, accountID, messageID)
	if err != nil {
		// Even if we can't retrieve the updated message, the update succeeded
		s.writeJSON(w, http.StatusOK, map[string]any{
			"message": "Message flags updated successfully",
			"id":      messageID,
		})
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"message": "Message flags updated successfully",
		"data":    message,
	})
}

// handleDeleteMessage marks a message as deleted
func (s *Server) handleDeleteMessage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	accountID, err := getAccountIDFromContext(ctx)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Extract message ID from path: /user/messages/{id}
	messageIDStr := extractLastPathSegment(r.URL.Path)
	messageID, err := strconv.ParseInt(messageIDStr, 10, 64)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid message ID")
		return
	}

	// Mark message as deleted by adding the \Deleted flag
	err = s.rdb.UpdateMessageFlagsWithRetry(ctx, accountID, messageID, []string{"\\Deleted"}, nil)
	if err != nil {
		if errors.Is(err, consts.ErrDBNotFound) {
			s.writeError(w, http.StatusNotFound, "Message not found")
			return
		}
		logger.Warn("HTTP Mail API: Error marking message as deleted", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to delete message")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"message": "Message marked as deleted successfully",
		"id":      messageID,
	})
}

// isValidFlag checks if a flag name is valid
func isValidFlag(flag string) bool {
	// System flags start with backslash
	if len(flag) > 0 && flag[0] == '\\' {
		validSystemFlags := map[string]bool{
			"\\Seen":     true,
			"\\Answered": true,
			"\\Flagged":  true,
			"\\Deleted":  true,
			"\\Draft":    true,
			"\\Recent":   true,
		}
		return validSystemFlags[flag]
	}

	// Custom flags can be any non-empty string without special characters
	if len(flag) == 0 {
		return false
	}

	// Custom flags should not contain certain characters
	for _, c := range flag {
		if c < 0x20 || c > 0x7E || c == '\\' || c == '"' || c == '(' || c == ')' || c == '{' {
			return false
		}
	}

	return true
}
