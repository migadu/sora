package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// AffinityRequest represents a request to set user affinity
type AffinityRequest struct {
	User     string `json:"user"`     // Email address
	Protocol string `json:"protocol"` // "imap", "pop3", "managesieve"
	Backend  string `json:"backend"`  // Backend server address (e.g., "192.168.1.10:993")
}

// AffinityResponse represents the current affinity for a user
type AffinityResponse struct {
	User     string `json:"user"`
	Protocol string `json:"protocol"`
	Backend  string `json:"backend"`
	Found    bool   `json:"found"`
}

// AffinityListResponse represents a list of all affinities
type AffinityListResponse struct {
	Affinities []AffinityResponse `json:"affinities"`
	Count      int                `json:"count"`
}

// AffinityHTTPHandler provides HTTP endpoints for managing user affinity
type AffinityHTTPHandler struct {
	connManager *ConnectionManager
}

// NewAffinityHTTPHandler creates a new affinity HTTP handler
func NewAffinityHTTPHandler(connManager *ConnectionManager) *AffinityHTTPHandler {
	return &AffinityHTTPHandler{
		connManager: connManager,
	}
}

// ServeHTTP handles affinity HTTP requests
func (h *AffinityHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set JSON content type
	w.Header().Set("Content-Type", "application/json")

	// Route based on method and path
	switch r.Method {
	case http.MethodPost:
		h.handleSet(w, r)
	case http.MethodGet:
		if strings.Contains(r.URL.Path, "/list") {
			h.handleList(w, r)
		} else {
			h.handleGet(w, r)
		}
	case http.MethodDelete:
		h.handleDelete(w, r)
	default:
		http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

// handleSet sets affinity for a user
func (h *AffinityHTTPHandler) handleSet(w http.ResponseWriter, r *http.Request) {
	var req AffinityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Invalid JSON: %v"}`, err), http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.User == "" || req.Protocol == "" || req.Backend == "" {
		http.Error(w, `{"error": "user, protocol, and backend are required"}`, http.StatusBadRequest)
		return
	}

	// Validate protocol
	req.Protocol = strings.ToLower(req.Protocol)
	if req.Protocol != "imap" && req.Protocol != "pop3" && req.Protocol != "managesieve" {
		http.Error(w, `{"error": "protocol must be imap, pop3, or managesieve"}`, http.StatusBadRequest)
		return
	}

	// Get affinity manager
	affinityMgr := h.connManager.GetAffinityManager()
	if affinityMgr == nil {
		http.Error(w, `{"error": "Affinity manager not enabled"}`, http.StatusServiceUnavailable)
		return
	}

	// Set affinity (this will gossip to all nodes)
	affinityMgr.SetBackend(req.User, req.Backend, req.Protocol)

	// Return success
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"success":  true,
		"message":  fmt.Sprintf("Affinity set for %s (%s) -> %s", req.User, req.Protocol, req.Backend),
		"user":     req.User,
		"protocol": req.Protocol,
		"backend":  req.Backend,
	})
}

// handleGet gets affinity for a user
func (h *AffinityHTTPHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	protocol := strings.ToLower(r.URL.Query().Get("protocol"))

	if user == "" || protocol == "" {
		http.Error(w, `{"error": "user and protocol query parameters are required"}`, http.StatusBadRequest)
		return
	}

	// Get affinity manager
	affinityMgr := h.connManager.GetAffinityManager()
	if affinityMgr == nil {
		http.Error(w, `{"error": "Affinity manager not enabled"}`, http.StatusServiceUnavailable)
		return
	}

	// Get affinity
	backend, found := affinityMgr.GetBackend(user, protocol)

	resp := AffinityResponse{
		User:     user,
		Protocol: protocol,
		Backend:  backend,
		Found:    found,
	}

	json.NewEncoder(w).Encode(resp)
}

// handleList lists all affinities (if supported by AffinityManager)
func (h *AffinityHTTPHandler) handleList(w http.ResponseWriter, _ *http.Request) {
	// Get affinity manager
	affinityMgr := h.connManager.GetAffinityManager()
	if affinityMgr == nil {
		http.Error(w, `{"error": "Affinity manager not enabled"}`, http.StatusServiceUnavailable)
		return
	}

	// Note: The AffinityManager interface doesn't have a List method
	// This would require extending the interface or returning an error
	http.Error(w, `{"error": "List operation not yet implemented - affinity is distributed via gossip"}`, http.StatusNotImplemented)
}

// handleDelete deletes affinity for a user
func (h *AffinityHTTPHandler) handleDelete(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	protocol := strings.ToLower(r.URL.Query().Get("protocol"))

	if user == "" || protocol == "" {
		http.Error(w, `{"error": "user and protocol query parameters are required"}`, http.StatusBadRequest)
		return
	}

	// Get affinity manager
	affinityMgr := h.connManager.GetAffinityManager()
	if affinityMgr == nil {
		http.Error(w, `{"error": "Affinity manager not enabled"}`, http.StatusServiceUnavailable)
		return
	}

	// Delete affinity (this will gossip to all nodes)
	affinityMgr.DeleteBackend(user, protocol)

	// Return success
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"success":  true,
		"message":  fmt.Sprintf("Affinity deleted for %s (%s)", user, protocol),
		"user":     user,
		"protocol": protocol,
	})
}

// RegisterAffinityEndpoints registers affinity HTTP endpoints on a mux
func RegisterAffinityEndpoints(mux *http.ServeMux, connManager *ConnectionManager, pathPrefix string) {
	if connManager == nil {
		return
	}

	handler := NewAffinityHTTPHandler(connManager)

	// Register endpoints
	mux.HandleFunc(pathPrefix+"/affinity", handler.ServeHTTP)
	mux.HandleFunc(pathPrefix+"/affinity/list", handler.ServeHTTP)
}
