package tlsmanager

import (
	"net/http"
	"strings"

	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/logger"
)

// ClusterHTTPHandler wraps the autocert HTTP handler to provide cluster-aware routing
// It ensures HTTP-01 challenges work across all cluster nodes, not just the leader
type ClusterHTTPHandler struct {
	autocertHandler http.Handler
	clusterManager  *cluster.Manager
}

// NewClusterHTTPHandler creates a cluster-aware HTTP-01 challenge handler
func NewClusterHTTPHandler(autocertHandler http.Handler, clusterMgr *cluster.Manager) http.Handler {
	if clusterMgr == nil {
		// No cluster, return autocert handler as-is
		return autocertHandler
	}

	return &ClusterHTTPHandler{
		autocertHandler: autocertHandler,
		clusterManager:  clusterMgr,
	}
}

// ServeHTTP handles HTTP-01 challenge requests
// In cluster mode, all nodes can respond to challenges because:
// 1. autocert.Manager stores challenge tokens in the cache (S3)
// 2. All nodes share the same cache
// 3. All nodes can retrieve and respond to challenges
func (h *ClusterHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check if this is an ACME challenge request
	if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
		isLeader := h.clusterManager.IsLeader()
		leaderID := h.clusterManager.GetLeaderID()

		logger.Debug("HTTP-01 challenge request received", "path", r.URL.Path, "is_leader", isLeader, "leader", leaderID)

		// Note: autocert.Manager's HTTPHandler already handles the challenge
		// It retrieves the challenge token from the cache (S3)
		// So all nodes can respond, not just the leader
		//
		// This is safe because:
		// - Challenge tokens are stored in S3 by the leader
		// - All nodes can read from S3
		// - autocert validates the challenge before responding
	}

	// Forward to autocert handler
	h.autocertHandler.ServeHTTP(w, r)
}
