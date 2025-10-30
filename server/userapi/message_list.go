package userapi

import (
	"errors"
	"github.com/migadu/sora/logger"
	"net/http"
	"net/url"
	"strconv"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
)

// MessageListResponse represents the response for message listing
type MessageListResponse struct {
	Messages []*db.DBMessage `json:"messages"`
	Total    int             `json:"total"`
	Limit    int             `json:"limit"`
	Offset   int             `json:"offset"`
}

// handleListMessages lists messages in a mailbox with pagination
func (s *Server) handleListMessages(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	accountID, err := getAccountIDFromContext(ctx)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Extract mailbox name from path: /user/mailboxes/{name}/messages
	mailboxName := extractPathParam(r.URL.Path, "/user/mailboxes/", "/messages")
	mailboxName, err = url.QueryUnescape(mailboxName)
	if err != nil || mailboxName == "" {
		s.writeError(w, http.StatusBadRequest, "Invalid mailbox name")
		return
	}

	// Parse query parameters
	query := r.URL.Query()

	// Limit (default: 50, max: 1000)
	limit := 50
	if limitStr := query.Get("limit"); limitStr != "" {
		parsedLimit, err := strconv.Atoi(limitStr)
		if err != nil || parsedLimit < 1 {
			s.writeError(w, http.StatusBadRequest, "Invalid limit parameter")
			return
		}
		if parsedLimit > 1000 {
			parsedLimit = 1000
		}
		limit = parsedLimit
	}

	// Offset (default: 0)
	offset := 0
	if offsetStr := query.Get("offset"); offsetStr != "" {
		parsedOffset, err := strconv.Atoi(offsetStr)
		if err != nil || parsedOffset < 0 {
			s.writeError(w, http.StatusBadRequest, "Invalid offset parameter")
			return
		}
		offset = parsedOffset
	}

	// Unseen only filter
	unseenOnly := query.Get("unseen") == "true"

	// Get messages from database
	messages, err := s.rdb.GetMessagesForMailboxWithRetry(ctx, accountID, mailboxName, limit, offset, unseenOnly)
	if err != nil {
		if errors.Is(err, consts.ErrMailboxNotFound) {
			s.writeError(w, http.StatusNotFound, "Mailbox not found")
			return
		}
		logger.Debug("HTTP Mail API: Error retrieving messages: %v", "name", s.name, "param", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to retrieve messages")
		return
	}

	// Get total count for the mailbox
	var total int
	if unseenOnly {
		total, err = s.rdb.GetUnseenCountForMailboxWithRetry(ctx, accountID, mailboxName)
	} else {
		total, err = s.rdb.GetMessageCountForMailboxWithRetry(ctx, accountID, mailboxName)
	}
	if err != nil {
		logger.Debug("HTTP Mail API: Error getting message count: %v", "name", s.name, "param", err)
		total = len(messages) // Fallback to returned count
	}

	response := MessageListResponse{
		Messages: messages,
		Total:    total,
		Limit:    limit,
		Offset:   offset,
	}

	s.writeJSON(w, http.StatusOK, response)
}

// handleSearchMessages searches messages in a mailbox
func (s *Server) handleSearchMessages(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	accountID, err := getAccountIDFromContext(ctx)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Extract mailbox name from path: /user/mailboxes/{name}/search
	mailboxName := extractPathParam(r.URL.Path, "/user/mailboxes/", "/search")
	mailboxName, err = url.QueryUnescape(mailboxName)
	if err != nil || mailboxName == "" {
		s.writeError(w, http.StatusBadRequest, "Invalid mailbox name")
		return
	}

	// Get search query
	query := r.URL.Query()
	searchQuery := query.Get("q")
	if searchQuery == "" {
		s.writeError(w, http.StatusBadRequest, "Search query parameter 'q' is required")
		return
	}

	// Perform search
	messages, err := s.rdb.SearchMessagesInMailboxWithRetry(ctx, accountID, mailboxName, searchQuery)
	if err != nil {
		if errors.Is(err, consts.ErrMailboxNotFound) {
			s.writeError(w, http.StatusNotFound, "Mailbox not found")
			return
		}
		logger.Debug("HTTP Mail API: Error searching messages: %v", "name", s.name, "param", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to search messages")
		return
	}

	response := map[string]interface{}{
		"messages": messages,
		"total":    len(messages),
		"query":    searchQuery,
	}

	s.writeJSON(w, http.StatusOK, response)
}
