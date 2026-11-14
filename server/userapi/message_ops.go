package userapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/migadu/sora/logger"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
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
			s.writeError(w, http.StatusBadRequest, invalidFlagMessage(flag))
			return
		}
	}
	for _, flag := range req.RemoveFlags {
		if !isValidFlag(flag) {
			s.writeError(w, http.StatusBadRequest, invalidFlagMessage(flag))
			return
		}
	}

	// RFC 9979 §3.2, as for IMAP STORE (server/imap/flag_color.go): clearing
	// \Flagged also clears the flag color keywords, so no stale color is left for
	// the next time the message is flagged.
	if helpers.HasFlag(helpers.StringsToFlags(req.RemoveFlags), imap.FlagFlagged) {
		for _, k := range helpers.FlagColorKeywords {
			req.RemoveFlags = append(req.RemoveFlags, string(k))
		}
	}

	// Update message flags
	err = s.rdb.UpdateMessageFlagsWithRetry(ctx, accountID, messageID, req.AddFlags, req.RemoveFlags)
	if err != nil {
		if errors.Is(err, consts.ErrDBNotFound) {
			s.writeError(w, http.StatusNotFound, "Message not found")
			return
		}
		if errors.Is(err, consts.ErrNotPermitted) {
			s.writeError(w, http.StatusForbidden, "Not permitted to change these flags in this mailbox")
			return
		}
		// Backstop: the loop above already rejected these, so reaching this means
		// a caller path that skipped validation. Still answer 400, not 500.
		if errors.Is(err, consts.ErrInvalidFlag) {
			s.writeError(w, http.StatusBadRequest, "Invalid flag")
			return
		}
		if errors.Is(err, consts.ErrTooManyKeywords) {
			s.writeError(w, http.StatusUnprocessableEntity,
				fmt.Sprintf("Too many keywords on a message (maximum %d)", db.MaxCustomKeywordsPerMessage))
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
		if errors.Is(err, consts.ErrNotPermitted) {
			s.writeError(w, http.StatusForbidden, "Not permitted to delete messages in this mailbox")
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

// isValidFlag checks if a flag name is valid.
//
// System flags are restricted to the set this API lets a client set (see
// isSettableSystemFlag). Keywords must be valid IMAP flag-keywords (RFC 9051 §9):
// the API is a write path into the same mailbox an IMAP client reads, so a
// keyword that cannot be encoded as an atom -- non-ASCII, but equally a space or
// a "]" or "%" -- would wedge SELECT of that mailbox for every IMAP client. Defer
// to the shared check rather than keeping a second, looser copy of the rule here.
//
// A keyword spelled like a system flag without its backslash ("Seen") is refused
// too. It is a client that meant \Seen: taken as a keyword it would add a "Seen"
// keyword and leave the message unread, and the client would never find "Seen"
// in the "\Seen" this API returns.
func isValidFlag(flag string) bool {
	// System flags start with backslash
	if strings.HasPrefix(flag, "\\") {
		return isSettableSystemFlag(flag)
	}
	if isSettableSystemFlag("\\" + flag) {
		return false
	}

	return helpers.IsValidFlagName(imap.Flag(flag))
}

// isSettableSystemFlag reports whether flag is a system flag this API lets a
// client set, in any case: IMAP flag names are case-insensitive (RFC 9051 §9),
// and db.UpdateMessageFlags folds them. \Recent is not one: it "can not be used
// as an argument in a STORE or APPEND command" (RFC 3501 §2.3.2), and IMAP no
// longer stores it (see db.FlagToBitwise).
func isSettableSystemFlag(flag string) bool {
	switch strings.ToLower(flag) {
	case "\\seen", "\\answered", "\\flagged", "\\deleted", "\\draft":
		return true
	}
	return false
}

// invalidFlagMessage is the 400 text for a flag isValidFlag refused. A system
// flag name given without its backslash gets a pointer to the right spelling.
func invalidFlagMessage(flag string) string {
	if isSettableSystemFlag("\\" + flag) {
		return fmt.Sprintf("Invalid flag: %s (system flags take a backslash: \\%s)", flag, flag)
	}
	return "Invalid flag: " + flag
}
