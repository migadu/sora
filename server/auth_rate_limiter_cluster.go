package server

import (
	"bytes"
	"encoding/gob"
	"sync"
	"time"

	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/logger"
)

// RateLimitEventType represents the type of rate limiting event
type RateLimitEventType string

const (
	// RateLimitEventBlockIP indicates an IP should be blocked
	RateLimitEventBlockIP RateLimitEventType = "BLOCK_IP"

	// RateLimitEventUnblockIP indicates an IP block should be lifted
	RateLimitEventUnblockIP RateLimitEventType = "UNBLOCK_IP"

	// RateLimitEventFailureCount indicates progressive delay failure count update
	RateLimitEventFailureCount RateLimitEventType = "FAILURE_COUNT"

	// RateLimitEventUsernameFailure indicates a username authentication failure
	RateLimitEventUsernameFailure RateLimitEventType = "USERNAME_FAILURE"

	// RateLimitEventUsernameSuccess indicates a username authentication success (clears failures)
	RateLimitEventUsernameSuccess RateLimitEventType = "USERNAME_SUCCESS"
)

// RateLimitEvent represents a cluster-wide rate limiting event
type RateLimitEvent struct {
	Type      RateLimitEventType `json:"type"`
	IP        string             `json:"ip"`
	Timestamp time.Time          `json:"timestamp"`
	NodeID    string             `json:"node_id"`

	// For BLOCK_IP events
	BlockedUntil time.Time `json:"blocked_until,omitempty"`
	FailureCount int       `json:"failure_count,omitempty"`
	Protocol     string    `json:"protocol,omitempty"`
	FirstFailure time.Time `json:"first_failure,omitempty"`

	// For FAILURE_COUNT events (progressive delays)
	LastDelay time.Duration `json:"last_delay,omitempty"`

	// For USERNAME_FAILURE and USERNAME_SUCCESS events
	Username string `json:"username,omitempty"`
}

// ClusterRateLimiter wraps an AuthRateLimiter with cluster synchronization
type ClusterRateLimiter struct {
	limiter        *AuthRateLimiter
	clusterManager *cluster.Manager

	// Broadcast queue for outgoing events
	broadcastQueue []RateLimitEvent
	queueMu        sync.Mutex

	// Configuration
	syncBlocks        bool
	syncFailureCounts bool
	broadcastInterval time.Duration

	// Shutdown
	stopBroadcast chan struct{}
}

// NewClusterRateLimiter creates a new cluster-aware rate limiter
func NewClusterRateLimiter(limiter *AuthRateLimiter, clusterMgr *cluster.Manager, syncBlocks, syncFailureCounts bool) *ClusterRateLimiter {
	if limiter == nil || clusterMgr == nil {
		return nil
	}

	crl := &ClusterRateLimiter{
		limiter:           limiter,
		clusterManager:    clusterMgr,
		syncBlocks:        syncBlocks,
		syncFailureCounts: syncFailureCounts,
		broadcastInterval: 100 * time.Millisecond,
		broadcastQueue:    make([]RateLimitEvent, 0, 100),
		stopBroadcast:     make(chan struct{}),
	}

	// Register with cluster manager to receive rate limit events
	clusterMgr.RegisterRateLimitHandler(crl.HandleClusterEvent)

	// Register as broadcaster for outgoing events
	clusterMgr.RegisterRateLimitBroadcaster(crl.GetBroadcasts)

	// Start broadcast routine
	go crl.broadcastRoutine()

	logger.Info("CLUSTER-LIMITER: initialized cluster rate limiting", "protocol", limiter.protocol,
		"sync_blocks", syncBlocks, "sync_failure_counts", syncFailureCounts)

	return crl
}

// BroadcastBlockIP broadcasts an IP block event to the cluster
func (crl *ClusterRateLimiter) BroadcastBlockIP(ip string, blockedUntil time.Time, failureCount int, protocol string, firstFailure time.Time) {
	if !crl.syncBlocks {
		return
	}

	event := RateLimitEvent{
		Type:         RateLimitEventBlockIP,
		IP:           ip,
		Timestamp:    time.Now(),
		NodeID:       crl.clusterManager.GetNodeID(),
		BlockedUntil: blockedUntil,
		FailureCount: failureCount,
		Protocol:     protocol,
		FirstFailure: firstFailure,
	}

	crl.queueEvent(event)
}

// BroadcastUnblockIP broadcasts an IP unblock event to the cluster
func (crl *ClusterRateLimiter) BroadcastUnblockIP(ip string) {
	if !crl.syncBlocks {
		return
	}

	event := RateLimitEvent{
		Type:      RateLimitEventUnblockIP,
		IP:        ip,
		Timestamp: time.Now(),
		NodeID:    crl.clusterManager.GetNodeID(),
	}

	crl.queueEvent(event)
}

// BroadcastFailureCount broadcasts a progressive delay failure count update
func (crl *ClusterRateLimiter) BroadcastFailureCount(ip string, failureCount int, lastDelay time.Duration, firstFailure time.Time) {
	if !crl.syncFailureCounts {
		return
	}

	event := RateLimitEvent{
		Type:         RateLimitEventFailureCount,
		IP:           ip,
		Timestamp:    time.Now(),
		NodeID:       crl.clusterManager.GetNodeID(),
		FailureCount: failureCount,
		LastDelay:    lastDelay,
		FirstFailure: firstFailure,
	}

	crl.queueEvent(event)
}

// BroadcastUsernameFailure broadcasts a username authentication failure to the cluster
func (crl *ClusterRateLimiter) BroadcastUsernameFailure(username string) {
	// Username tracking always syncs when cluster is enabled
	event := RateLimitEvent{
		Type:      RateLimitEventUsernameFailure,
		Username:  username,
		Timestamp: time.Now(),
		NodeID:    crl.clusterManager.GetNodeID(),
	}

	crl.queueEvent(event)
}

// BroadcastUsernameSuccess broadcasts a username authentication success (clears failures)
func (crl *ClusterRateLimiter) BroadcastUsernameSuccess(username string) {
	// Username tracking always syncs when cluster is enabled
	event := RateLimitEvent{
		Type:      RateLimitEventUsernameSuccess,
		Username:  username,
		Timestamp: time.Now(),
		NodeID:    crl.clusterManager.GetNodeID(),
	}

	crl.queueEvent(event)
}

// queueEvent adds an event to the broadcast queue
func (crl *ClusterRateLimiter) queueEvent(event RateLimitEvent) {
	crl.queueMu.Lock()
	defer crl.queueMu.Unlock()

	// Enforce reasonable size limit to prevent unbounded growth
	const maxQueueSize = 10000
	if len(crl.broadcastQueue) >= maxQueueSize {
		// Drop oldest 10% of events when queue is full
		dropCount := maxQueueSize / 10
		logger.Warn("Cluster limiter: Broadcast queue overflow - dropping oldest events",
			"protocol", crl.limiter.protocol, "current", len(crl.broadcastQueue),
			"max", maxQueueSize, "dropping", dropCount)
		crl.broadcastQueue = crl.broadcastQueue[dropCount:]
	}

	crl.broadcastQueue = append(crl.broadcastQueue, event)
	logger.Info("CLUSTER-LIMITER: Event queued for broadcast", "protocol", crl.limiter.protocol,
		"type", event.Type, "ip", event.IP, "username", event.Username, "queue_size", len(crl.broadcastQueue))
}

// GetBroadcasts returns events to broadcast (called by cluster manager)
func (crl *ClusterRateLimiter) GetBroadcasts(overhead, limit int) [][]byte {
	crl.queueMu.Lock()
	defer crl.queueMu.Unlock()

	queueLen := len(crl.broadcastQueue)
	if queueLen == 0 {
		return nil
	}

	logger.Info("CLUSTER-LIMITER: GetBroadcasts called", "protocol", crl.limiter.protocol,
		"queued_events", queueLen, "overhead", overhead, "limit", limit)

	broadcasts := make([][]byte, 0, len(crl.broadcastQueue))
	totalSize := 0

	for i := 0; i < len(crl.broadcastQueue); i++ {
		event := crl.broadcastQueue[i]
		encoded, err := encodeRateLimitEvent(event)
		if err != nil {
			logger.Warn("Cluster limiter: Failed to encode rate limit event", "error", err)
			continue
		}

		// Check if adding this message would exceed the limit
		msgSize := overhead + len(encoded)
		if totalSize+msgSize > limit && len(broadcasts) > 0 {
			// Keep remaining events for next broadcast
			crl.broadcastQueue = crl.broadcastQueue[i:]
			logger.Debug("CLUSTER-LIMITER: Broadcast limit reached, queuing remaining",
				"broadcasted", i, "remaining", len(crl.broadcastQueue))
			return broadcasts
		}

		broadcasts = append(broadcasts, encoded)
		totalSize += msgSize
		logger.Debug("CLUSTER-LIMITER: Queued event for broadcast", "type", event.Type,
			"ip", event.IP, "username", event.Username)
	}

	// All events broadcasted, clear queue
	crl.broadcastQueue = crl.broadcastQueue[:0]
	logger.Debug("CLUSTER-LIMITER: Broadcasting all events", "count", len(broadcasts))
	return broadcasts
}

// HandleClusterEvent processes a rate limit event from another node
func (crl *ClusterRateLimiter) HandleClusterEvent(data []byte) {
	event, err := decodeRateLimitEvent(data)
	if err != nil {
		logger.Warn("Cluster limiter: Failed to decode rate limit event", "error", err)
		return
	}

	// Skip events from this node (we already applied them locally)
	if event.NodeID == crl.clusterManager.GetNodeID() {
		return
	}

	// Check if event is too old (prevent replays after network partition)
	age := time.Since(event.Timestamp)
	if age > 5*time.Minute {
		logger.Debug("Cluster limiter: Ignoring stale rate limit event", "node_id", event.NodeID, "age", age)
		return
	}

	switch event.Type {
	case RateLimitEventBlockIP:
		crl.handleBlockIP(event)
	case RateLimitEventUnblockIP:
		crl.handleUnblockIP(event)
	case RateLimitEventFailureCount:
		crl.handleFailureCount(event)
	case RateLimitEventUsernameFailure:
		crl.handleUsernameFailure(event)
	case RateLimitEventUsernameSuccess:
		crl.handleUsernameSuccess(event)
	default:
		logger.Warn("Cluster limiter: Unknown rate limit event type", "type", event.Type)
	}
}

// handleBlockIP applies an IP block from another node
func (crl *ClusterRateLimiter) handleBlockIP(event RateLimitEvent) {
	if !crl.syncBlocks {
		return
	}

	// Check if block is still valid (not expired)
	if time.Now().After(event.BlockedUntil) {
		logger.Debug("Cluster limiter: Ignoring expired block", "ip", event.IP, "from_node", event.NodeID)
		return
	}

	crl.limiter.ipMu.Lock()
	defer crl.limiter.ipMu.Unlock()

	// Check if we already have a more recent block for this IP
	existing, exists := crl.limiter.blockedIPs[event.IP]
	if exists && existing.BlockedUntil.After(event.BlockedUntil) {
		logger.Debug("Cluster limiter: Ignoring older block", "ip", event.IP, "from_node", event.NodeID)
		return
	}

	// Apply the block
	crl.limiter.blockedIPs[event.IP] = &BlockedIPInfo{
		BlockedUntil: event.BlockedUntil,
		FailureCount: event.FailureCount,
		FirstFailure: event.FirstFailure,
		LastFailure:  event.Timestamp,
		Protocol:     event.Protocol,
	}

	logger.Info("CLUSTER-LIMITER: Applied cluster block for IP", "protocol", crl.limiter.protocol,
		"ip", event.IP, "node", event.NodeID, "until", event.BlockedUntil, "failures", event.FailureCount)
}

// handleUnblockIP removes an IP block from another node
func (crl *ClusterRateLimiter) handleUnblockIP(event RateLimitEvent) {
	if !crl.syncBlocks {
		return
	}

	crl.limiter.ipMu.Lock()
	defer crl.limiter.ipMu.Unlock()

	if _, exists := crl.limiter.blockedIPs[event.IP]; exists {
		delete(crl.limiter.blockedIPs, event.IP)
		logger.Debug("Cluster limiter: Applied cluster unblock", "protocol", crl.limiter.protocol, "ip", event.IP, "from_node", event.NodeID)
	}
}

// handleFailureCount updates progressive delay tracking from another node
func (crl *ClusterRateLimiter) handleFailureCount(event RateLimitEvent) {
	if !crl.syncFailureCounts {
		return
	}

	crl.limiter.ipMu.Lock()
	defer crl.limiter.ipMu.Unlock()

	// Check if we already have more recent failure info for this IP
	existing, exists := crl.limiter.ipFailureCounts[event.IP]
	if exists && existing.LastFailure.After(event.Timestamp) {
		return
	}

	// Update failure count
	crl.limiter.ipFailureCounts[event.IP] = &IPFailureInfo{
		FailureCount: event.FailureCount,
		FirstFailure: event.FirstFailure,
		LastFailure:  event.Timestamp,
		LastDelay:    event.LastDelay,
	}

	logger.Debug("Cluster limiter: Updated failure count", "protocol", crl.limiter.protocol, "ip", event.IP, "from_node", event.NodeID, "failures", event.FailureCount, "delay", event.LastDelay)
}

// handleUsernameFailure applies a username failure from another node
func (crl *ClusterRateLimiter) handleUsernameFailure(event RateLimitEvent) {
	if event.Username == "" {
		return
	}

	crl.limiter.usernameMu.Lock()
	defer crl.limiter.usernameMu.Unlock()

	info, exists := crl.limiter.usernameFailureCounts[event.Username]
	if !exists {
		info = &UsernameFailureInfo{FirstFailure: event.Timestamp}
		crl.limiter.usernameFailureCounts[event.Username] = info
	}

	// Increment failure count (each node broadcasts its local failure)
	info.FailureCount++
	info.LastFailure = event.Timestamp

	logger.Debug("CLUSTER-LIMITER: Applied username failure from cluster", "protocol", crl.limiter.protocol,
		"username", event.Username, "from_node", event.NodeID, "total_failures", info.FailureCount)
}

// handleUsernameSuccess clears username failures (successful auth)
func (crl *ClusterRateLimiter) handleUsernameSuccess(event RateLimitEvent) {
	if event.Username == "" {
		return
	}

	crl.limiter.usernameMu.Lock()
	delete(crl.limiter.usernameFailureCounts, event.Username)
	crl.limiter.usernameMu.Unlock()

	logger.Debug("CLUSTER-LIMITER: Cleared username failures from cluster", "protocol", crl.limiter.protocol,
		"username", event.Username, "from_node", event.NodeID)
}

// broadcastRoutine periodically triggers broadcasts
func (crl *ClusterRateLimiter) broadcastRoutine() {
	ticker := time.NewTicker(crl.broadcastInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Trigger broadcast by notifying cluster manager
			// (actual broadcast happens via GetBroadcasts callback)
			crl.queueMu.Lock()
			hasEvents := len(crl.broadcastQueue) > 0
			crl.queueMu.Unlock()

			if hasEvents {
				// Cluster manager will call GetBroadcasts()
				logger.Debug("Cluster limiter: Triggering broadcast", "queued_events", len(crl.broadcastQueue))
			}

		case <-crl.stopBroadcast:
			return
		}
	}
}

// Stop stops the cluster rate limiter
func (crl *ClusterRateLimiter) Stop() {
	close(crl.stopBroadcast)
}

// encodeRateLimitEvent encodes an event to bytes using gob
func encodeRateLimitEvent(event RateLimitEvent) ([]byte, error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	if err := encoder.Encode(event); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decodeRateLimitEvent decodes an event from bytes using gob
func decodeRateLimitEvent(data []byte) (RateLimitEvent, error) {
	var event RateLimitEvent
	decoder := gob.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&event); err != nil {
		return event, err
	}
	return event, nil
}
