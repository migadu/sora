package userapi

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"

	"github.com/migadu/sora/consts"
)

// SieveScriptResponse represents a Sieve script in API responses
type SieveScriptResponse struct {
	Name      string `json:"name"`
	Script    string `json:"script,omitempty"`
	Active    bool   `json:"active"`
	UpdatedAt string `json:"updated_at"`
}

// SieveScriptRequest represents a request to create/update a Sieve script
type SieveScriptRequest struct {
	Script string `json:"script"`
}

// handleListFilters lists all Sieve scripts for the authenticated user
func (s *Server) handleListFilters(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	accountID, err := getAccountIDFromContext(ctx)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Get all scripts
	scripts, err := s.rdb.GetUserScriptsWithRetry(ctx, accountID)
	if err != nil {
		log.Printf("HTTP Mail API [%s] Error retrieving Sieve scripts: %v", s.name, err)
		s.writeError(w, http.StatusInternalServerError, "Failed to retrieve scripts")
		return
	}

	// Convert to API response format
	scriptResponses := make([]SieveScriptResponse, 0, len(scripts))
	for _, script := range scripts {
		scriptResponses = append(scriptResponses, SieveScriptResponse{
			Name:      script.Name,
			Active:    script.Active,
			UpdatedAt: script.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
		})
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"scripts": scriptResponses,
		"count":   len(scriptResponses),
	})
}

// handleGetFilter retrieves a specific Sieve script
func (s *Server) handleGetFilter(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	accountID, err := getAccountIDFromContext(ctx)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Extract script name from path: /user/filters/{name}
	name := extractPathParam(r.URL.Path, "/user/filters/", "")
	name, err = url.QueryUnescape(name)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid script name")
		return
	}

	if name == "" {
		s.writeError(w, http.StatusBadRequest, "Script name is required")
		return
	}

	// Get script
	script, err := s.rdb.GetScriptByNameWithRetry(ctx, name, accountID)
	if err != nil {
		if errors.Is(err, consts.ErrDBNotFound) {
			s.writeError(w, http.StatusNotFound, "Script not found")
			return
		}
		log.Printf("HTTP Mail API [%s] Error retrieving Sieve script: %v", s.name, err)
		s.writeError(w, http.StatusInternalServerError, "Failed to retrieve script")
		return
	}

	response := SieveScriptResponse{
		Name:      script.Name,
		Script:    script.Script,
		Active:    script.Active,
		UpdatedAt: script.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	s.writeJSON(w, http.StatusOK, response)
}

// handlePutFilter creates or updates a Sieve script
func (s *Server) handlePutFilter(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	ctx := r.Context()

	accountID, err := getAccountIDFromContext(ctx)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Extract script name from path: /user/filters/{name}
	name := extractPathParam(r.URL.Path, "/user/filters/", "")
	name, err = url.QueryUnescape(name)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid script name")
		return
	}

	if name == "" {
		s.writeError(w, http.StatusBadRequest, "Script name is required")
		return
	}

	var req SieveScriptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Script == "" {
		s.writeError(w, http.StatusBadRequest, "Script content is required")
		return
	}

	// Validate script name
	if err := validateScriptName(name); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Create or update script
	script, err := s.rdb.CreateOrUpdateScriptWithRetry(ctx, accountID, name, req.Script)
	if err != nil {
		log.Printf("HTTP Mail API [%s] Error creating/updating Sieve script: %v", s.name, err)
		s.writeError(w, http.StatusInternalServerError, "Failed to save script")
		return
	}

	response := SieveScriptResponse{
		Name:      script.Name,
		Script:    script.Script,
		Active:    script.Active,
		UpdatedAt: script.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	s.writeJSON(w, http.StatusOK, response)
}

// handleDeleteFilter deletes a Sieve script
func (s *Server) handleDeleteFilter(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	accountID, err := getAccountIDFromContext(ctx)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Extract script name from path: /user/filters/{name}
	name := extractPathParam(r.URL.Path, "/user/filters/", "")
	name, err = url.QueryUnescape(name)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid script name")
		return
	}

	if name == "" {
		s.writeError(w, http.StatusBadRequest, "Script name is required")
		return
	}

	// Delete script
	if err := s.rdb.DeleteScriptWithRetry(ctx, name, accountID); err != nil {
		if errors.Is(err, consts.ErrDBNotFound) {
			s.writeError(w, http.StatusNotFound, "Script not found")
			return
		}
		log.Printf("HTTP Mail API [%s] Error deleting Sieve script: %v", s.name, err)
		s.writeError(w, http.StatusInternalServerError, "Failed to delete script")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Script deleted successfully",
		"name":    name,
	})
}

// handleActivateFilter activates a Sieve script (deactivates all others)
func (s *Server) handleActivateFilter(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	accountID, err := getAccountIDFromContext(ctx)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Extract script name from path: /user/filters/{name}/activate
	name := extractPathParam(r.URL.Path, "/user/filters/", "/activate")
	name, err = url.QueryUnescape(name)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid script name")
		return
	}

	if name == "" {
		s.writeError(w, http.StatusBadRequest, "Script name is required")
		return
	}

	// Activate script
	if err := s.rdb.ActivateScriptWithRetry(ctx, name, accountID); err != nil {
		if errors.Is(err, consts.ErrDBNotFound) {
			s.writeError(w, http.StatusNotFound, "Script not found")
			return
		}
		log.Printf("HTTP Mail API [%s] Error activating Sieve script: %v", s.name, err)
		s.writeError(w, http.StatusInternalServerError, "Failed to activate script")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Script activated successfully",
		"name":    name,
		"active":  true,
	})
}

// validateScriptName validates a Sieve script name
func validateScriptName(name string) error {
	if name == "" {
		return errors.New("script name cannot be empty")
	}

	// Check for invalid characters
	if containsInvalidChars(name) {
		return errors.New("script name contains invalid characters")
	}

	// Check length (reasonable limit)
	if len(name) > 128 {
		return errors.New("script name too long (max 128 characters)")
	}

	return nil
}

// containsInvalidChars checks if a string contains invalid characters for script names
func containsInvalidChars(s string) bool {
	for _, c := range s {
		// Allow alphanumeric, dash, underscore, dot
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return true
		}
	}
	return false
}

// handleGetCapabilities returns the Sieve capabilities supported by the server
func (s *Server) handleGetCapabilities(w http.ResponseWriter, r *http.Request) {
	// Return the Sieve capabilities
	// These are the extensions supported by the server
	capabilities := map[string]interface{}{
		"implementation": "Sora Mail Server",
		"version":        "1.0",
		"extensions": []string{
			"fileinto",
			"reject",
			"envelope",
			"body",
			"vacation",
			"imap4flags",
			"relational",
			"comparator-i;ascii-numeric",
			"subaddress",
			"copy",
			"mailbox",
			"date",
			"index",
			"variables",
			"editheader",
		},
		"notify_methods":  []string{},
		"max_redirects":   4,
		"max_script_size": 65536, // 64KB default
	}

	s.writeJSON(w, http.StatusOK, capabilities)
}
