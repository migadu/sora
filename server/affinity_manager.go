package server

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"sync"
	"time"

	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/logger"
)

// AffinityEventType represents the type of affinity event
type AffinityEventType string

const (
	// AffinityEventSet indicates a user is assigned to a backend
	AffinityEventSet AffinityEventType = "AFFINITY_SET"

	// AffinityEventUpdate indicates a user is reassigned to a different backend
	AffinityEventUpdate AffinityEventType = "AFFINITY_UPDATE"

	// AffinityEventDelete indicates a user's affinity should be removed
	AffinityEventDelete AffinityEventType = "AFFINITY_DELETE"
)

// AffinityEvent represents a cluster-wide affinity event
type AffinityEvent struct {
	Type       AffinityEventType `json:"type"`
	Username   string            `json:"username"`
	Backend    string            `json:"backend"`     // New backend address
	OldBackend string            `json:"old_backend"` // Previous backend (for UPDATE events)
	Protocol   string            `json:"protocol"`    // "imap", "pop3", "managesieve"
	Timestamp  time.Time         `json:"timestamp"`
	NodeID     string            `json:"node_id"`
	TTL        time.Duration     `json:"ttl"` // How long affinity is valid
}

// AffinityInfo tracks affinity information for a user
type AffinityInfo struct {
	Backend    string
	Protocol   string
	AssignedAt time.Time
	ExpiresAt  time.Time
	NodeID     string // Which node assigned this affinity
}

// AffinityManager manages user-to-backend affinity mappings with cluster synchronization
type AffinityManager struct {
	affinityMap map[string]*AffinityInfo // key: "username:protocol" → backend
	mu          sync.RWMutex

	clusterManager *cluster.Manager

	// Configuration
	enabled         bool
	defaultTTL      time.Duration
	cleanupInterval time.Duration

	// Broadcast queue for outgoing events
	broadcastQueue []AffinityEvent
	queueMu        sync.Mutex

	// Shutdown
	stopCleanup   chan struct{}
	stopBroadcast chan struct{}
}

// NewAffinityManager creates a new affinity manager with cluster synchronization
func NewAffinityManager(clusterMgr *cluster.Manager, enabled bool, ttl, cleanupInterval time.Duration) *AffinityManager {
	if !enabled || clusterMgr == nil {
		return nil
	}

	if ttl == 0 {
		ttl = 24 * time.Hour // Default: 24 hours
	}

	if cleanupInterval == 0 {
		cleanupInterval = 1 * time.Hour // Default: 1 hour
	}

	am := &AffinityManager{
		affinityMap:     make(map[string]*AffinityInfo),
		clusterManager:  clusterMgr,
		enabled:         enabled,
		defaultTTL:      ttl,
		cleanupInterval: cleanupInterval,
		broadcastQueue:  make([]AffinityEvent, 0, 100),
		stopCleanup:     make(chan struct{}),
		stopBroadcast:   make(chan struct{}),
	}

	// Register with cluster manager
	clusterMgr.RegisterAffinityHandler(am.HandleClusterEvent)
	clusterMgr.RegisterAffinityBroadcaster(am.GetBroadcasts)

	// Start background routines
	go am.cleanupRoutine()
	go am.broadcastRoutine()

	logger.Infof("[AFFINITY] Initialized gossip affinity: ttl=%v, cleanup=%v", ttl, cleanupInterval)

	return am
}

// GetBackend returns the backend affinity for a user, if any
func (am *AffinityManager) GetBackend(username, protocol string) (string, bool) {
	if am == nil || !am.enabled {
		return "", false
	}

	am.mu.RLock()
	defer am.mu.RUnlock()

	key := fmt.Sprintf("%s:%s", username, protocol)
	info, exists := am.affinityMap[key]
	if !exists {
		return "", false
	}

	// Check if expired
	if time.Now().After(info.ExpiresAt) {
		return "", false // Expired, will be cleaned up later
	}

	return info.Backend, true
}

// SetBackend assigns a user to a backend and broadcasts to cluster
func (am *AffinityManager) SetBackend(username, backend, protocol string) {
	if am == nil || !am.enabled {
		return
	}

	am.mu.Lock()
	defer am.mu.Unlock()

	key := fmt.Sprintf("%s:%s", username, protocol)
	now := time.Now()

	am.affinityMap[key] = &AffinityInfo{
		Backend:    backend,
		Protocol:   protocol,
		AssignedAt: now,
		ExpiresAt:  now.Add(am.defaultTTL),
		NodeID:     am.clusterManager.GetNodeID(),
	}

	logger.Infof("[AFFINITY] Set affinity: %s → %s (broadcasting to cluster)", username, backend)

	// Broadcast to cluster
	am.queueEvent(AffinityEvent{
		Type:      AffinityEventSet,
		Username:  username,
		Backend:   backend,
		Protocol:  protocol,
		Timestamp: now,
		NodeID:    am.clusterManager.GetNodeID(),
		TTL:       am.defaultTTL,
	})
}

// UpdateBackend reassigns a user from one backend to another (atomic update)
func (am *AffinityManager) UpdateBackend(username, oldBackend, newBackend, protocol string) {
	if am == nil || !am.enabled {
		return
	}

	am.mu.Lock()
	defer am.mu.Unlock()

	key := fmt.Sprintf("%s:%s", username, protocol)
	now := time.Now()

	am.affinityMap[key] = &AffinityInfo{
		Backend:    newBackend,
		Protocol:   protocol,
		AssignedAt: now,
		ExpiresAt:  now.Add(am.defaultTTL),
		NodeID:     am.clusterManager.GetNodeID(),
	}

	logger.Infof("[AFFINITY] Updated affinity: %s from %s to %s", username, oldBackend, newBackend)

	// Broadcast to cluster
	am.queueEvent(AffinityEvent{
		Type:       AffinityEventUpdate,
		Username:   username,
		Backend:    newBackend,
		OldBackend: oldBackend,
		Protocol:   protocol,
		Timestamp:  now,
		NodeID:     am.clusterManager.GetNodeID(),
		TTL:        am.defaultTTL,
	})
}

// DeleteBackend removes a user's affinity
func (am *AffinityManager) DeleteBackend(username, protocol string) {
	if am == nil || !am.enabled {
		return
	}

	am.mu.Lock()
	defer am.mu.Unlock()

	key := fmt.Sprintf("%s:%s", username, protocol)

	// Remove from local map
	delete(am.affinityMap, key)

	logger.Debugf("[AFFINITY] Deleted affinity for %s:%s", username, protocol)

	// Broadcast deletion to cluster
	am.queueEvent(AffinityEvent{
		Type:      AffinityEventDelete,
		Username:  username,
		Protocol:  protocol,
		Timestamp: time.Now(),
		NodeID:    am.clusterManager.GetNodeID(),
	})
}

// queueEvent adds an event to the broadcast queue
func (am *AffinityManager) queueEvent(event AffinityEvent) {
	am.queueMu.Lock()
	defer am.queueMu.Unlock()

	am.broadcastQueue = append(am.broadcastQueue, event)
}

// GetBroadcasts returns events to broadcast (called by cluster manager)
func (am *AffinityManager) GetBroadcasts(overhead, limit int) [][]byte {
	am.queueMu.Lock()
	defer am.queueMu.Unlock()

	if len(am.broadcastQueue) == 0 {
		return nil
	}

	broadcasts := make([][]byte, 0, len(am.broadcastQueue))
	totalSize := 0

	for i := 0; i < len(am.broadcastQueue); i++ {
		encoded, err := encodeAffinityEvent(am.broadcastQueue[i])
		if err != nil {
			logger.Warnf("[AFFINITY] Failed to encode affinity event: %v", err)
			continue
		}

		// Check if adding this message would exceed the limit
		msgSize := overhead + len(encoded)
		if totalSize+msgSize > limit && len(broadcasts) > 0 {
			// Keep remaining events for next broadcast
			am.broadcastQueue = am.broadcastQueue[i:]
			return broadcasts
		}

		broadcasts = append(broadcasts, encoded)
		totalSize += msgSize
	}

	// All events broadcasted, clear queue
	am.broadcastQueue = am.broadcastQueue[:0]
	return broadcasts
}

// HandleClusterEvent processes an affinity event from another node
func (am *AffinityManager) HandleClusterEvent(data []byte) {
	event, err := decodeAffinityEvent(data)
	if err != nil {
		logger.Warnf("[AFFINITY] Failed to decode affinity event: %v", err)
		return
	}

	logger.Debugf("[AFFINITY] Received gossip event: type=%s user=%s backend=%s from=%s",
		event.Type, event.Username, event.Backend, event.NodeID)

	// Skip events from this node (we already applied them locally)
	if event.NodeID == am.clusterManager.GetNodeID() {
		logger.Debugf("[AFFINITY] Skipping own event from node %s", event.NodeID)
		return
	}

	// Check if event is too old (prevent replays after network partition)
	age := time.Since(event.Timestamp)
	if age > 5*time.Minute {
		logger.Debugf("[AFFINITY] Ignoring stale event from %s (age: %v)", event.NodeID, age)
		return
	}

	switch event.Type {
	case AffinityEventSet:
		am.handleAffinitySet(event)
	case AffinityEventUpdate:
		am.handleAffinityUpdate(event)
	case AffinityEventDelete:
		am.handleAffinityDelete(event)
	default:
		logger.Warnf("[AFFINITY] Unknown event type: %s", event.Type)
	}
}

// handleAffinitySet applies an affinity assignment from another node
func (am *AffinityManager) handleAffinitySet(event AffinityEvent) {
	am.mu.Lock()
	defer am.mu.Unlock()

	key := fmt.Sprintf("%s:%s", event.Username, event.Protocol)

	// Check if we already have affinity for this user
	existing, exists := am.affinityMap[key]
	if exists {
		// Only apply if event is newer than our local state
		if existing.AssignedAt.After(event.Timestamp) {
			logger.Infof("[AFFINITY] Ignoring older SET for %s from %s (existing: %s from %s, event: %s)",
				event.Username, event.NodeID, existing.Backend, existing.NodeID, event.Backend)
			return
		}
		logger.Infof("[AFFINITY] Overwriting existing affinity for %s: %s → %s (node %s → %s)",
			event.Username, existing.Backend, event.Backend, existing.NodeID, event.NodeID)
	}

	// Apply the affinity
	am.affinityMap[key] = &AffinityInfo{
		Backend:    event.Backend,
		Protocol:   event.Protocol,
		AssignedAt: event.Timestamp,
		ExpiresAt:  event.Timestamp.Add(event.TTL),
		NodeID:     event.NodeID,
	}

	logger.Infof("[AFFINITY] Applied cluster affinity: %s → %s (from node %s)",
		event.Username, event.Backend, event.NodeID)
}

// handleAffinityUpdate applies an affinity update from another node
func (am *AffinityManager) handleAffinityUpdate(event AffinityEvent) {
	am.mu.Lock()
	defer am.mu.Unlock()

	key := fmt.Sprintf("%s:%s", event.Username, event.Protocol)

	// Check if we have existing affinity
	existing, exists := am.affinityMap[key]
	if exists {
		// Only apply if event is newer than our local state (last-write-wins)
		if existing.AssignedAt.After(event.Timestamp) {
			logger.Debugf("[AFFINITY] Ignoring older UPDATE for %s from %s", event.Username, event.NodeID)
			return
		}

		logger.Infof("[AFFINITY] Received cluster update for %s: %s → %s (from node %s)",
			event.Username, existing.Backend, event.Backend, event.NodeID)
	} else {
		logger.Infof("[AFFINITY] Received cluster affinity for %s: → %s (from node %s)",
			event.Username, event.Backend, event.NodeID)
	}

	// Apply update
	am.affinityMap[key] = &AffinityInfo{
		Backend:    event.Backend,
		Protocol:   event.Protocol,
		AssignedAt: event.Timestamp,
		ExpiresAt:  event.Timestamp.Add(event.TTL),
		NodeID:     event.NodeID,
	}
}

// handleAffinityDelete removes an affinity from another node
func (am *AffinityManager) handleAffinityDelete(event AffinityEvent) {
	am.mu.Lock()
	defer am.mu.Unlock()

	key := fmt.Sprintf("%s:%s", event.Username, event.Protocol)

	if _, exists := am.affinityMap[key]; exists {
		delete(am.affinityMap, key)
		logger.Debugf("[AFFINITY] Applied cluster delete for %s:%s from node %s",
			event.Username, event.Protocol, event.NodeID)
	}
}

// cleanupRoutine periodically removes expired affinities
func (am *AffinityManager) cleanupRoutine() {
	ticker := time.NewTicker(am.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			am.cleanup()
		case <-am.stopCleanup:
			return
		}
	}
}

// cleanup removes expired affinities
func (am *AffinityManager) cleanup() {
	am.mu.Lock()
	defer am.mu.Unlock()

	now := time.Now()
	removed := 0

	for key, info := range am.affinityMap {
		if now.After(info.ExpiresAt) {
			delete(am.affinityMap, key)
			removed++
		}
	}

	if removed > 0 {
		logger.Debugf("[AFFINITY] Cleaned up %d expired affinities", removed)
	}
}

// broadcastRoutine periodically triggers broadcasts
func (am *AffinityManager) broadcastRoutine() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Trigger broadcast by checking queue
			am.queueMu.Lock()
			hasEvents := len(am.broadcastQueue) > 0
			am.queueMu.Unlock()

			if hasEvents {
				logger.Debugf("[AFFINITY] Triggering broadcast of %d queued events", len(am.broadcastQueue))
			}

		case <-am.stopBroadcast:
			return
		}
	}
}

// Stop stops the affinity manager
func (am *AffinityManager) Stop() {
	if am == nil {
		return
	}
	close(am.stopCleanup)
	close(am.stopBroadcast)
}

// GetStats returns affinity statistics
func (am *AffinityManager) GetStats(ctx context.Context) map[string]interface{} {
	if am == nil {
		return nil
	}

	am.mu.RLock()
	defer am.mu.RUnlock()

	stats := map[string]interface{}{
		"enabled":          am.enabled,
		"total_entries":    len(am.affinityMap),
		"ttl":              am.defaultTTL.String(),
		"cleanup_interval": am.cleanupInterval.String(),
	}

	// Count by protocol
	protocolCounts := make(map[string]int)
	for _, info := range am.affinityMap {
		protocolCounts[info.Protocol]++
	}
	stats["by_protocol"] = protocolCounts

	return stats
}

// encodeAffinityEvent encodes an event to bytes using gob
func encodeAffinityEvent(event AffinityEvent) ([]byte, error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	if err := encoder.Encode(event); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decodeAffinityEvent decodes an event from bytes using gob
func decodeAffinityEvent(data []byte) (AffinityEvent, error) {
	var event AffinityEvent
	decoder := gob.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&event); err != nil {
		return event, err
	}
	return event, nil
}
