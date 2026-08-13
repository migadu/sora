package server

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"sync"
	"time"

	"github.com/migadu/sora/affinitycache"
	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server/idgen"
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

// maxAffinityEventQueueSize bounds the outgoing gossip queue
const maxAffinityEventQueueSize = 5000

// AffinityEvent represents a cluster-wide affinity event
type AffinityEvent struct {
	Type       AffinityEventType `json:"type"`
	EventID    string            `json:"event_id"` // Unique per event, for duplicate suppression
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

// AffinityPersistStore defines the interface for persistent affinity storage.
// This is implemented by affinitycache.Store.
type AffinityPersistStore interface {
	LoadAll(ctx context.Context) ([]affinitycache.AffinityEntry, error)
	Set(ctx context.Context, entry affinitycache.AffinityEntry) error
	Delete(ctx context.Context, username, protocol string) error
	Cleanup(ctx context.Context) (int64, error)
	Close() error
}

// AffinityManager manages user-to-backend affinity mappings with cluster synchronization
type AffinityManager struct {
	affinityMap map[string]*AffinityInfo // key: "username:protocol" → backend
	mu          sync.RWMutex

	clusterManager *cluster.Manager
	persistStore   AffinityPersistStore // Optional SQLite persistence (nil = in-memory only)

	// Configuration
	enabled         bool
	defaultTTL      time.Duration
	cleanupInterval time.Duration

	// Outgoing gossip
	queue *gossipQueue

	// Duplicate suppression for received events
	dedup gossipDedup

	// When each key was last deleted, so that a SET delivered after the DELETE
	// that removes it is recognised as the older event. Affinity has no
	// push/pull provider, so a resurrected entry would never be repaired.
	tombstones gossipTombstones

	// Shutdown
	stopCleanup chan struct{}
	wg          sync.WaitGroup // Tracks pending async goroutines

	// Cleanup counter for periodic memory reporting
	cleanupCounter uint64
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
		queue:           newGossipQueue("affinity", clusterMgr, maxAffinityEventQueueSize),
		stopCleanup:     make(chan struct{}),
	}

	// Register with cluster manager
	clusterMgr.RegisterAffinityHandler(am.HandleClusterEvent)
	clusterMgr.RegisterAffinityBroadcaster(am.GetBroadcasts)

	// Start background routines
	go am.cleanupRoutine()

	logger.Debug("Affinity: Initialized gossip affinity", "ttl", ttl, "cleanup", cleanupInterval)

	return am
}

// SetPersistStore attaches a persistent storage backend to the affinity manager.
// If set, affinity mappings are written through to SQLite on every set/update/delete
// and loaded from disk on startup via LoadPersistedAffinities.
func (am *AffinityManager) SetPersistStore(store AffinityPersistStore) {
	if am == nil {
		return
	}
	am.persistStore = store
}

// LoadPersistedAffinities loads affinity entries from the persistent store into
// the in-memory map. Called once on startup, before gossip sync begins, to
// pre-populate the map so users are immediately routed to their previous backends.
func (am *AffinityManager) LoadPersistedAffinities(ctx context.Context) {
	if am == nil || am.persistStore == nil {
		return
	}

	entries, err := am.persistStore.LoadAll(ctx)
	if err != nil {
		logger.Error("Affinity: Failed to load persisted affinities", "error", err)
		return
	}

	am.mu.Lock()
	loaded := 0
	for _, e := range entries {
		key := fmt.Sprintf("%s:%s", e.Username, e.Protocol)
		// Only load if no existing entry (gossip may have already provided fresher data)
		if _, exists := am.affinityMap[key]; !exists {
			am.affinityMap[key] = &AffinityInfo{
				Backend:    e.Backend,
				Protocol:   e.Protocol,
				AssignedAt: e.AssignedAt,
				ExpiresAt:  e.ExpiresAt,
				NodeID:     e.NodeID,
			}
			loaded++
		}
	}
	am.mu.Unlock()

	logger.Info("Affinity: Loaded persisted affinities", "loaded", loaded, "total_on_disk", len(entries))
}

// persistSetAsync writes an affinity entry to the persistent store in a fire-and-forget goroutine.
func (am *AffinityManager) persistSetAsync(username, protocol, backend, nodeID string, assignedAt, expiresAt time.Time) {
	if am.persistStore == nil {
		return
	}
	am.wg.Add(1)
	go func() {
		defer am.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := am.persistStore.Set(ctx, affinitycache.AffinityEntry{
			Username:   username,
			Protocol:   protocol,
			Backend:    backend,
			AssignedAt: assignedAt,
			ExpiresAt:  expiresAt,
			NodeID:     nodeID,
		}); err != nil {
			logger.Warn("Affinity: Failed to persist set", "user", username, "error", err)
		}
	}()
}

// persistDeleteAsync removes an affinity entry from the persistent store in a fire-and-forget goroutine.
func (am *AffinityManager) persistDeleteAsync(username, protocol string) {
	if am.persistStore == nil {
		return
	}
	am.wg.Add(1)
	go func() {
		defer am.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := am.persistStore.Delete(ctx, username, protocol); err != nil {
			logger.Warn("Affinity: Failed to persist delete", "user", username, "error", err)
		}
	}()
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

// GetBackendAcrossProtocols returns the backend affinity for a user from any protocol
// This enables cache locality by routing all protocols (IMAP, POP3, LMTP) to the same backend
// Priority: same protocol > other protocols > none
func (am *AffinityManager) GetBackendAcrossProtocols(username, protocol string) (backend string, foundProtocol string, found bool) {
	if am == nil || !am.enabled {
		return "", "", false
	}

	am.mu.RLock()
	defer am.mu.RUnlock()

	now := time.Now()

	// First, check if there's affinity for this exact protocol
	key := fmt.Sprintf("%s:%s", username, protocol)
	if info, exists := am.affinityMap[key]; exists && now.Before(info.ExpiresAt) {
		return info.Backend, protocol, true
	}

	// Second, check if there's affinity for any other protocol
	// This ensures all protocols go to the same backend for cache locality
	// Check in priority order: IMAP > POP3 > LMTP > ManageSieve
	protocols := []string{"imap", "pop3", "lmtp", "managesieve"}
	for _, proto := range protocols {
		if proto == protocol {
			continue // Already checked above
		}
		key := fmt.Sprintf("%s:%s", username, proto)
		if info, exists := am.affinityMap[key]; exists && now.Before(info.ExpiresAt) {
			logger.Debug("Affinity: Found cross-protocol affinity for cache locality",
				"user", username, "requested_protocol", protocol, "found_protocol", proto, "backend", info.Backend)
			return info.Backend, proto, true
		}
	}

	return "", "", false
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

	logger.Debug("Affinity: Set - broadcasting to cluster", "user", username, "backend", backend)

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

	// Persist to disk (async, non-blocking)
	am.persistSetAsync(username, protocol, backend, am.clusterManager.GetNodeID(), now, now.Add(am.defaultTTL))
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

	logger.Debug("Affinity: Updated affinity", "user", username, "from", oldBackend, "to", newBackend)

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

	// Persist to disk (async, non-blocking)
	am.persistSetAsync(username, protocol, newBackend, am.clusterManager.GetNodeID(), now, now.Add(am.defaultTTL))
}

// DeleteBackend removes a user's affinity
func (am *AffinityManager) DeleteBackend(username, protocol string) {
	if am == nil || !am.enabled {
		return
	}

	am.mu.Lock()
	defer am.mu.Unlock()

	key := fmt.Sprintf("%s:%s", username, protocol)
	now := time.Now()

	// Remove from local map
	delete(am.affinityMap, key)
	am.tombstones.mark(key, now)

	logger.Debug("Affinity: Deleted affinity", "user", username, "protocol", protocol)

	// Broadcast deletion to cluster
	am.queueEvent(AffinityEvent{
		Type:      AffinityEventDelete,
		Username:  username,
		Protocol:  protocol,
		Timestamp: now,
		NodeID:    am.clusterManager.GetNodeID(),
	})

	// Persist deletion to disk (async, non-blocking)
	am.persistDeleteAsync(username, protocol)
}

// queueEvent encodes an event and hands it to the gossip queue
func (am *AffinityManager) queueEvent(event AffinityEvent) {
	if event.EventID == "" {
		event.EventID = idgen.New()
	}

	encoded, err := encodeAffinityEvent(event)
	if err != nil {
		logger.Warn("Affinity: Failed to encode affinity event", "type", event.Type, "error", err)
		return
	}

	am.queue.enqueue(encoded)
}

// GetBroadcasts returns events to broadcast (called by cluster manager).
// memberlist calls this once per gossip target, so an event stays queued until
// it has been transmitted often enough to have reached the cluster.
func (am *AffinityManager) GetBroadcasts(overhead, limit int) [][]byte {
	return am.queue.GetBroadcasts(overhead, limit)
}

// HandleClusterEvent processes an affinity event from another node
func (am *AffinityManager) HandleClusterEvent(data []byte) {
	event, err := decodeAffinityEvent(data)
	if err != nil {
		logger.Warn("Affinity: Failed to decode affinity event", "error", err)
		return
	}

	logger.Debug("Affinity: Received gossip event", "type", event.Type, "user", event.Username, "backend", event.Backend, "from_node", event.NodeID)

	// Skip events from this node (we already applied them locally)
	if event.NodeID == am.clusterManager.GetNodeID() {
		logger.Debug("Affinity: Skipping own event", "node_id", event.NodeID)
		return
	}

	// Check if event is too old (prevent replays after network partition)
	age := time.Since(event.Timestamp)
	if age > staleEventThreshold {
		logger.Debug("Affinity: Ignoring stale event", "node_id", event.NodeID, "age", age)
		return
	}

	// Gossip delivery is at-least-once: applying a retransmitted copy costs a
	// redundant write-through to the persistent store on every one.
	if am.dedup.seenBefore(event.EventID) {
		logger.Debug("Affinity: Ignoring duplicate event", "type", event.Type, "event_id", event.EventID)
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
		logger.Warn("Affinity: Unknown event type", "type", event.Type)
	}
}

// handleAffinitySet applies an affinity assignment from another node
func (am *AffinityManager) handleAffinitySet(event AffinityEvent) {
	am.mu.Lock()
	defer am.mu.Unlock()

	key := fmt.Sprintf("%s:%s", event.Username, event.Protocol)

	// A delete for this key may have been delivered first, in which case this
	// SET is the older event and applying it would resurrect the affinity.
	if am.tombstones.removedSince(key, event.Timestamp) {
		logger.Debug("Affinity: Ignoring SET superseded by a delete", "user", event.Username, "node", event.NodeID)
		return
	}

	// Check if we already have affinity for this user
	existing, exists := am.affinityMap[key]
	if exists {
		// Only apply if event is newer than our local state
		if existing.AssignedAt.After(event.Timestamp) {
			logger.Info("Affinity: Ignoring older SET", "user", event.Username, "node", event.NodeID,
				"existing_backend", existing.Backend, "existing_node", existing.NodeID, "event_backend", event.Backend)
			return
		}
		if existing.Backend == event.Backend && existing.AssignedAt.Equal(event.Timestamp) {
			return // Already applied; nothing to write through
		}
		logger.Info("Affinity: Overwriting existing affinity", "user", event.Username,
			"old_backend", existing.Backend, "new_backend", event.Backend,
			"old_node", existing.NodeID, "new_node", event.NodeID)
	}

	// Apply the affinity
	am.affinityMap[key] = &AffinityInfo{
		Backend:    event.Backend,
		Protocol:   event.Protocol,
		AssignedAt: event.Timestamp,
		ExpiresAt:  event.Timestamp.Add(event.TTL),
		NodeID:     event.NodeID,
	}

	logger.Info("Affinity: Applied cluster affinity", "user", event.Username,
		"backend", event.Backend, "node", event.NodeID)

	// Persist cluster event to disk
	am.persistSetAsync(event.Username, event.Protocol, event.Backend, event.NodeID, event.Timestamp, event.Timestamp.Add(event.TTL))
}

// handleAffinityUpdate applies an affinity update from another node
func (am *AffinityManager) handleAffinityUpdate(event AffinityEvent) {
	am.mu.Lock()
	defer am.mu.Unlock()

	key := fmt.Sprintf("%s:%s", event.Username, event.Protocol)

	// A delete for this key may have been delivered first, in which case this
	// UPDATE is the older event and applying it would resurrect the affinity.
	if am.tombstones.removedSince(key, event.Timestamp) {
		logger.Debug("Affinity: Ignoring UPDATE superseded by a delete", "user", event.Username, "from_node", event.NodeID)
		return
	}

	// Check if we have existing affinity
	existing, exists := am.affinityMap[key]
	if exists {
		// Only apply if event is newer than our local state (last-write-wins)
		if existing.AssignedAt.After(event.Timestamp) {
			logger.Debug("Affinity: Ignoring older UPDATE", "user", event.Username, "from_node", event.NodeID)
			return
		}
		if existing.Backend == event.Backend && existing.AssignedAt.Equal(event.Timestamp) {
			return // Already applied; nothing to write through
		}

		logger.Info("Affinity: Received cluster update", "user", event.Username,
			"old_backend", existing.Backend, "new_backend", event.Backend, "node", event.NodeID)
	} else {
		logger.Info("Affinity: Received cluster affinity", "user", event.Username,
			"backend", event.Backend, "node", event.NodeID)
	}

	// Apply update
	am.affinityMap[key] = &AffinityInfo{
		Backend:    event.Backend,
		Protocol:   event.Protocol,
		AssignedAt: event.Timestamp,
		ExpiresAt:  event.Timestamp.Add(event.TTL),
		NodeID:     event.NodeID,
	}

	// Persist cluster event to disk
	am.persistSetAsync(event.Username, event.Protocol, event.Backend, event.NodeID, event.Timestamp, event.Timestamp.Add(event.TTL))
}

// handleAffinityDelete removes an affinity from another node
func (am *AffinityManager) handleAffinityDelete(event AffinityEvent) {
	am.mu.Lock()
	defer am.mu.Unlock()

	key := fmt.Sprintf("%s:%s", event.Username, event.Protocol)

	// Record the removal before deciding whether it applies here: a SET for
	// this key delivered after this event is the older of the two, whether or
	// not we currently hold an entry to remove.
	am.tombstones.mark(key, event.Timestamp)

	existing, exists := am.affinityMap[key]
	if !exists {
		return
	}
	if existing.AssignedAt.After(event.Timestamp) {
		logger.Debug("Affinity: Ignoring delete older than the affinity it removes",
			"user", event.Username, "protocol", event.Protocol, "from_node", event.NodeID)
		return
	}

	delete(am.affinityMap, key)
	logger.Debug("Affinity: Applied cluster delete", "user", event.Username, "protocol", event.Protocol, "from_node", event.NodeID)

	// Persist deletion to disk
	am.persistDeleteAsync(event.Username, event.Protocol)
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
		logger.Debug("Affinity: Cleaned up expired affinities", "count", removed)
	}

	// Cleanup expired entries from persistent store
	if am.persistStore != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if cleaned, err := am.persistStore.Cleanup(ctx); err != nil {
				logger.Warn("Affinity: Failed to cleanup persistent store", "error", err)
			} else if cleaned > 0 {
				logger.Debug("Affinity: Cleaned up persisted expired entries", "count", cleaned)
			}
		}()
	}

	// Get broadcast queue size for memory reporting and metrics
	queueSize := am.queue.numQueued()

	// Update Prometheus metrics every cleanup cycle
	metrics.AffinityManagerEntries.Set(float64(len(am.affinityMap)))
	metrics.AffinityManagerBroadcastQueue.Set(float64(queueSize))

	// Log memory usage stats every 10 cleanup cycles (~10 hours with 1h cleanup interval)
	am.cleanupCounter++
	if am.cleanupCounter%10 == 0 {
		logger.Info("Affinity manager stats",
			"total_entries", len(am.affinityMap),
			"broadcast_queue_size", queueSize,
			"broadcast_queue_limit", maxAffinityEventQueueSize,
			"removed_this_cycle", removed)
	}
}

// GetAffinityCount returns the number of active affinities (for testing/monitoring)
func (am *AffinityManager) GetAffinityCount() int {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return len(am.affinityMap)
}

// Stop stops the affinity manager and closes the persistent store
func (am *AffinityManager) Stop() {
	if am == nil {
		return
	}
	close(am.stopCleanup)

	// Wait for any pending async writes to finish
	am.wg.Wait()

	if am.persistStore != nil {
		if err := am.persistStore.Close(); err != nil {
			logger.Warn("Affinity: Failed to close persist store", "error", err)
		}
	}
}

// GetStats returns affinity statistics
func (am *AffinityManager) GetStats(ctx context.Context) map[string]any {
	if am == nil {
		return nil
	}

	am.mu.RLock()
	totalEntries := len(am.affinityMap)

	// Count by protocol
	protocolCounts := make(map[string]int)
	for _, info := range am.affinityMap {
		protocolCounts[info.Protocol]++
	}
	am.mu.RUnlock()

	// Get broadcast queue size
	queueSize := am.queue.numQueued()

	stats := map[string]any{
		"enabled":          am.enabled,
		"total_entries":    totalEntries,
		"ttl":              am.defaultTTL.String(),
		"cleanup_interval": am.cleanupInterval.String(),
		"by_protocol":      protocolCounts,
		"memory_usage": map[string]any{
			"affinity_entries":    totalEntries,
			"broadcast_queue":     queueSize,
			"broadcast_queue_max": 5000,
			"queue_utilization":   float64(queueSize) / 5000.0 * 100,
		},
	}

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
