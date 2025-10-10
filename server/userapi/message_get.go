package userapi

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/mail"
	"strconv"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/helpers"
)

// handleGetMessage retrieves a message in JSON format
func (s *Server) handleGetMessage(w http.ResponseWriter, r *http.Request) {
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

	// Get message metadata from database
	message, err := s.rdb.GetMessageByIDWithRetry(ctx, accountID, messageID)
	if err != nil {
		if errors.Is(err, consts.ErrDBNotFound) {
			s.writeError(w, http.StatusNotFound, "Message not found")
			return
		}
		log.Printf("HTTP Mail API [%s] Error retrieving message: %v", s.name, err)
		s.writeError(w, http.StatusInternalServerError, "Failed to retrieve message")
		return
	}

	// Return message metadata as JSON
	s.writeJSON(w, http.StatusOK, message)
}

// handleGetMessageBody retrieves the message body (text or HTML)
func (s *Server) handleGetMessageBody(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	accountID, err := getAccountIDFromContext(ctx)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Extract message ID from path: /user/messages/{id}/body
	messageIDStr := extractPathParam(r.URL.Path, "/user/messages/", "/body")
	messageID, err := strconv.ParseInt(messageIDStr, 10, 64)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid message ID")
		return
	}

	// Get message metadata from database
	message, err := s.rdb.GetMessageByIDWithRetry(ctx, accountID, messageID)
	if err != nil {
		if errors.Is(err, consts.ErrDBNotFound) {
			s.writeError(w, http.StatusNotFound, "Message not found")
			return
		}
		log.Printf("HTTP Mail API [%s] Error retrieving message metadata: %v", s.name, err)
		s.writeError(w, http.StatusInternalServerError, "Failed to retrieve message")
		return
	}

	// Check if storage and cache are available
	if s.storage == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Storage not configured")
		return
	}

	// Retrieve message body from cache or S3
	var bodyData []byte

	// Try cache first if available
	if s.cache != nil {
		bodyData, err = s.cache.Get(message.ContentHash)
		if err != nil {
			log.Printf("HTTP Mail API [%s] Cache miss for message %d: %v", s.name, messageID, err)
		}
	}

	// Fallback to S3 if not in cache
	if bodyData == nil {
		s3Key := helpers.NewS3Key(message.S3Domain, message.S3Localpart, message.ContentHash)
		reader, err := s.storage.Get(s3Key)
		if err != nil {
			log.Printf("HTTP Mail API [%s] Error retrieving message body from S3: %v", s.name, err)
			s.writeError(w, http.StatusInternalServerError, "Failed to retrieve message body")
			return
		}
		defer reader.Close()

		bodyData, err = io.ReadAll(reader)
		if err != nil {
			log.Printf("HTTP Mail API [%s] Error reading message body from S3: %v", s.name, err)
			s.writeError(w, http.StatusInternalServerError, "Failed to read message body")
			return
		}

		// Store in cache for future requests
		if s.cache != nil {
			if err := s.cache.Put(message.ContentHash, bodyData); err != nil {
				log.Printf("HTTP Mail API [%s] Failed to cache message body: %v", s.name, err)
			}
		}
	}

	// Parse the RFC822 message
	reader := bytes.NewReader(bodyData)
	parsedMsg, err := mail.ReadMessage(reader)
	if err != nil {
		log.Printf("HTTP Mail API [%s] Error parsing RFC822 message: %v", s.name, err)
		s.writeError(w, http.StatusInternalServerError, "Failed to parse message")
		return
	}

	// Read the body
	body, err := io.ReadAll(parsedMsg.Body)
	if err != nil {
		log.Printf("HTTP Mail API [%s] Error reading message body: %v", s.name, err)
		s.writeError(w, http.StatusInternalServerError, "Failed to read message body")
		return
	}

	// Determine content type
	contentType := parsedMsg.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "text/plain; charset=utf-8"
	}

	// Return the body
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

// handleGetMessageRaw retrieves the raw RFC822 message
func (s *Server) handleGetMessageRaw(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	accountID, err := getAccountIDFromContext(ctx)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Extract message ID from path: /user/messages/{id}/raw
	messageIDStr := extractPathParam(r.URL.Path, "/user/messages/", "/raw")
	messageID, err := strconv.ParseInt(messageIDStr, 10, 64)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid message ID")
		return
	}

	// Get message metadata from database
	message, err := s.rdb.GetMessageByIDWithRetry(ctx, accountID, messageID)
	if err != nil {
		if errors.Is(err, consts.ErrDBNotFound) {
			s.writeError(w, http.StatusNotFound, "Message not found")
			return
		}
		log.Printf("HTTP Mail API [%s] Error retrieving message metadata: %v", s.name, err)
		s.writeError(w, http.StatusInternalServerError, "Failed to retrieve message")
		return
	}

	// Check if storage is available
	if s.storage == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Storage not configured")
		return
	}

	// Retrieve message body from cache or S3
	var bodyData []byte

	// Try cache first if available
	if s.cache != nil {
		bodyData, err = s.cache.Get(message.ContentHash)
		if err != nil {
			log.Printf("HTTP Mail API [%s] Cache miss for message %d: %v", s.name, messageID, err)
		}
	}

	// Fallback to S3 if not in cache
	if bodyData == nil {
		s3Key := helpers.NewS3Key(message.S3Domain, message.S3Localpart, message.ContentHash)
		reader, err := s.storage.Get(s3Key)
		if err != nil {
			log.Printf("HTTP Mail API [%s] Error retrieving message from S3: %v", s.name, err)
			s.writeError(w, http.StatusInternalServerError, "Failed to retrieve message")
			return
		}
		defer reader.Close()

		bodyData, err = io.ReadAll(reader)
		if err != nil {
			log.Printf("HTTP Mail API [%s] Error reading message from S3: %v", s.name, err)
			s.writeError(w, http.StatusInternalServerError, "Failed to read message")
			return
		}

		// Store in cache for future requests
		if s.cache != nil {
			if err := s.cache.Put(message.ContentHash, bodyData); err != nil {
				log.Printf("HTTP Mail API [%s] Failed to cache message: %v", s.name, err)
			}
		}
	}

	// Return the raw RFC822 message
	w.Header().Set("Content-Type", "message/rfc822")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"message-%d.eml\"", messageID))
	w.Header().Set("Content-Length", strconv.Itoa(len(bodyData)))
	w.WriteHeader(http.StatusOK)
	w.Write(bodyData)
}
