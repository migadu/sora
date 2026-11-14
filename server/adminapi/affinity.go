package adminapi

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
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

// AffinityListEntry is one affinity in GET /admin/affinity/list
type AffinityListEntry struct {
	User       string    `json:"user"`
	Protocol   string    `json:"protocol"`
	Backend    string    `json:"backend"`
	AssignedAt time.Time `json:"assigned_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	NodeID     string    `json:"node_id"` // node that assigned the affinity
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

	s.writeJSON(w, http.StatusOK, AffinityGetResponse{
		User:     user,
		Protocol: protocol,
		Backend:  backend,
		Found:    true,
	})
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

// handleAffinityList handles GET /admin/affinity/list[?protocol=x][&backend=y] - lists
// this node's affinities, optionally of one protocol or one backend. Every node applies
// the affinities the others gossip, so any node of a converged cluster lists the same set.
func (s *Server) handleAffinityList(w http.ResponseWriter, r *http.Request) {
	protocol := strings.ToLower(r.URL.Query().Get("protocol"))
	backend := r.URL.Query().Get("backend")

	// Check if affinity manager is available
	if s.affinityManager == nil {
		http.Error(w, `{"error": "Affinity manager not enabled on this server"}`, http.StatusServiceUnavailable)
		return
	}

	affinities := []AffinityListEntry{}
	for _, e := range s.affinityManager.List() {
		if (protocol != "" && e.Protocol != protocol) || (backend != "" && e.Backend != backend) {
			continue
		}
		affinities = append(affinities, AffinityListEntry{
			User:       e.Username,
			Protocol:   e.Protocol,
			Backend:    e.Backend,
			AssignedAt: e.AssignedAt,
			ExpiresAt:  e.ExpiresAt,
			NodeID:     e.NodeID,
		})
	}
	slices.SortFunc(affinities, func(a, b AffinityListEntry) int {
		return cmp.Or(strings.Compare(a.User, b.User), strings.Compare(a.Protocol, b.Protocol))
	})

	s.writeJSON(w, http.StatusOK, map[string]any{
		"affinities": affinities,
		"count":      len(affinities),
	})
}

// handleAffinityStats handles GET /admin/affinity/stats - returns affinity statistics
func (s *Server) handleAffinityStats(w http.ResponseWriter, r *http.Request) {
	if s.affinityManager == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Affinity manager not enabled on this server")
		return
	}

	stats := s.affinityManager.GetStats(r.Context())
	if stats == nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to get affinity stats")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"stats": stats,
	})
}
