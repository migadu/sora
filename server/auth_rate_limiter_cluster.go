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

// queueEvent adds an event to the broadcast queue
func (crl *ClusterRateLimiter) queueEvent(event RateLimitEvent) {
	crl.queueMu.Lock()
	defer crl.queueMu.Unlock()

	crl.broadcastQueue = append(crl.broadcastQueue, event)
}

// GetBroadcasts returns events to broadcast (called by cluster manager)
func (crl *ClusterRateLimiter) GetBroadcasts(overhead, limit int) [][]byte {
	crl.queueMu.Lock()
	defer crl.queueMu.Unlock()

	if len(crl.broadcastQueue) == 0 {
		return nil
	}

	broadcasts := make([][]byte, 0, len(crl.broadcastQueue))
	totalSize := 0

	for i := 0; i < len(crl.broadcastQueue); i++ {
		encoded, err := encodeRateLimitEvent(crl.broadcastQueue[i])
		if err != nil {
			logger.Warn("Cluster limiter: Failed to encode rate limit event", "error", err)
			continue
		}

		// Check if adding this message would exceed the limit
		msgSize := overhead + len(encoded)
		if totalSize+msgSize > limit && len(broadcasts) > 0 {
			// Keep remaining events for next broadcast
			crl.broadcastQueue = crl.broadcastQueue[i:]
			return broadcasts
		}

		broadcasts = append(broadcasts, encoded)
		totalSize += msgSize
	}

	// All events broadcasted, clear queue
	crl.broadcastQueue = crl.broadcastQueue[:0]
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

	crl.limiter.blockMu.Lock()
	defer crl.limiter.blockMu.Unlock()

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

	crl.limiter.blockMu.Lock()
	defer crl.limiter.blockMu.Unlock()

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

	crl.limiter.delayMu.Lock()
	defer crl.limiter.delayMu.Unlock()

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
