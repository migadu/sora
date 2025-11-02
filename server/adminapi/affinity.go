package adminapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// AffinitySetRequest represents a request to set user affinity
type AffinitySetRequest struct {
	User     string `json:"user"`     // Email address
	Protocol string `json:"protocol"` // "imap", "pop3", "managesieve"
	Backend  string `json:"backend"`  // Backend server address (e.g., "192.168.1.10:993")
}

// AffinityGetResponse represents the current affinity for a user
type AffinityGetResponse struct {
	User     string `json:"user"`
	Protocol string `json:"protocol"`
	Backend  string `json:"backend"`
	Found    bool   `json:"found"`
}

// handleAffinitySet handles POST /admin/affinity - set affinity for a user
func (s *Server) handleAffinitySet(w http.ResponseWriter, r *http.Request) {
	var req AffinitySetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "Invalid JSON"}`, http.StatusBadRequest)
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

	// Check if affinity manager is available
	if s.affinityManager == nil {
		http.Error(w, `{"error": "Affinity manager not enabled on this server"}`, http.StatusServiceUnavailable)
		return
	}

	// Validate that backend is in the configured list for this protocol
	if validBackends, ok := s.validBackends[req.Protocol]; ok {
		found := false
		for _, validBackend := range validBackends {
			if validBackend == req.Backend {
				found = true
				break
			}
		}
		if !found {
			http.Error(w, fmt.Sprintf(`{"error": "Backend %s is not configured for protocol %s. Valid backends: %v"}`, req.Backend, req.Protocol, validBackends), http.StatusBadRequest)
			return
		}
	} else {
		// If no backends configured for this protocol, reject
		http.Error(w, fmt.Sprintf(`{"error": "No backends configured for protocol %s"}`, req.Protocol), http.StatusBadRequest)
		return
	}

	// Set affinity (this will gossip to all nodes in the cluster)
	s.affinityManager.SetBackend(req.User, req.Backend, req.Protocol)

	// Return success
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success":  true,
		"message":  fmt.Sprintf("Affinity set for %s (%s) -> %s and gossiped to cluster", req.User, req.Protocol, req.Backend),
		"user":     req.User,
		"protocol": req.Protocol,
		"backend":  req.Backend,
	})
}

// handleAffinityGet handles GET /admin/affinity?user=x&protocol=y - get affinity for a user
func (s *Server) handleAffinityGet(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	protocol := strings.ToLower(r.URL.Query().Get("protocol"))

	if user == "" || protocol == "" {
		http.Error(w, `{"error": "user and protocol query parameters are required"}`, http.StatusBadRequest)
		return
	}

	// Check if affinity manager is available
	if s.affinityManager == nil {
		http.Error(w, `{"error": "Affinity manager not enabled on this server"}`, http.StatusServiceUnavailable)
		return
	}

	// Get affinity
	backend, found := s.affinityManager.GetBackend(user, protocol)

	if !found {
		http.Error(w, fmt.Sprintf(`{"error": "No affinity set for %s (%s)"}`, user, protocol), http.StatusNotFound)
		return
	}

	resp := map[string]any{
		"user":     user,
		"protocol": protocol,
		"backend":  backend,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleAffinityDelete handles DELETE /admin/affinity?user=x&protocol=y - delete affinity for a user
func (s *Server) handleAffinityDelete(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	protocol := strings.ToLower(r.URL.Query().Get("protocol"))

	if user == "" || protocol == "" {
		http.Error(w, `{"error": "user and protocol query parameters are required"}`, http.StatusBadRequest)
		return
	}

	// Check if affinity manager is available
	if s.affinityManager == nil {
		http.Error(w, `{"error": "Affinity manager not enabled on this server"}`, http.StatusServiceUnavailable)
		return
	}

	// Delete affinity (this will gossip to all nodes in the cluster)
	s.affinityManager.DeleteBackend(user, protocol)

	// Return success
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success":  true,
		"message":  fmt.Sprintf("Affinity deleted for %s (%s) and gossiped to cluster", user, protocol),
		"user":     user,
		"protocol": protocol,
	})
}

// handleAffinityList handles GET /admin/affinity/list - list all affinities
func (s *Server) handleAffinityList(w http.ResponseWriter, r *http.Request) {
	// Check if affinity manager is available
	if s.affinityManager == nil {
		http.Error(w, `{"error": "Affinity manager not enabled on this server"}`, http.StatusServiceUnavailable)
		return
	}

	// Note: The AffinityManager interface doesn't have a List method
	// Affinities are distributed via gossip and stored in memory on each node
	// To list all affinities, you would need to query each node individually
	// or extend the AffinityManager interface to support listing
	http.Error(w, `{"error": "List operation not yet implemented - affinities are distributed via gossip. Use GET with specific user/protocol to check affinity."}`, http.StatusNotImplemented)
}
