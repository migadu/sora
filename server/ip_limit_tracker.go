package server

import (
	"bytes"
	"encoding/gob"
	"sync"
	"time"

	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/logger"
)

// IPLimitEventType represents the type of IP limit event
type IPLimitEventType string

const (
	// IPLimitEventIncrement indicates an IP connection was added
	IPLimitEventIncrement IPLimitEventType = "IP_INCREMENT"

	// IPLimitEventDecrement indicates an IP connection was removed
	IPLimitEventDecrement IPLimitEventType = "IP_DECREMENT"

	// IPLimitEventStateSnapshot indicates a full state snapshot for reconciliation
	IPLimitEventStateSnapshot IPLimitEventType = "IP_STATE_SNAPSHOT"
)

const (
	// Default maximum size of IP event queue before we start dropping old events
	defaultMaxIPEventQueueSize = 10000

	// How often to broadcast full state snapshot for reconciliation
	ipStateSnapshotInterval = 60 * time.Second
)

// IPLimitEvent represents a cluster-wide per-IP connection event
type IPLimitEvent struct {
	Type       IPLimitEventType `json:"type"`
	IP         string           `json:"ip"`       // The IP address
	Protocol   string           `json:"protocol"` // "IMAP", "POP3", etc.
	Timestamp  time.Time        `json:"timestamp"`
	NodeID     string           `json:"node_id"`
	InstanceID string           `json:"instance_id"` // Unique instance identifier

	// For state snapshots
	StateSnapshot *IPLimitStateSnapshot `json:"state_snapshot,omitempty"`
}

// IPLimitStateSnapshot represents a full per-IP connection state for reconciliation
type IPLimitStateSnapshot struct {
	InstanceID  string                      `json:"instance_id"`
	Timestamp   time.Time                   `json:"timestamp"`
	Connections map[string]IPConnectionData `json:"connections"` // IP -> connection data
}

// IPConnectionData is the serializable version of IPConnectionInfo for gossip
type IPConnectionData struct {
	IP             string         `json:"ip"`
	LocalInstances map[string]int `json:"local_instances"` // instanceID -> count
	TotalCount     int            `json:"total_count"`     // Cluster-wide count
	LastUpdate     time.Time      `json:"last_update"`
}

// IPConnectionInfo tracks connection information for a specific IP
type IPConnectionInfo struct {
	IP             string
	TotalCount     int // Cluster-wide count (eventually consistent)
	LocalCount     int // This instance's count
	LastUpdate     time.Time
	LocalInstances map[string]int // instanceID -> count on that instance
}

// IPLimitTracker manages per-IP connection tracking using gossip protocol
type IPLimitTracker struct {
	protocol       string
	instanceID     string
	clusterManager *cluster.Manager

	// Connection tracking
	connections map[string]*IPConnectionInfo // IP -> info
	mu          sync.RWMutex

	// Configuration
	maxEventQueueSize int // Maximum events in broadcast queue

	// Broadcast queue for outgoing events
	broadcastQueue []IPLimitEvent
	queueMu        sync.Mutex

	// Cleanup counter for periodic memory reporting
	cleanupCounter uint64

	// Shutdown
	stopBroadcast     chan struct{}
	stopCleanup       chan struct{}
	stopStateSnapshot chan struct{}
	stopOnce          sync.Once
}

// NewIPLimitTracker creates a new IP limit tracker.
// If clusterMgr is provided, uses gossip protocol for cluster-wide tracking.
// If clusterMgr is nil, operates in local-only mode.
func NewIPLimitTracker(protocol string, instanceID string, clusterMgr *cluster.Manager, maxEventQueueSize int) *IPLimitTracker {
	// Use default if not specified
	if maxEventQueueSize <= 0 {
		maxEventQueueSize = defaultMaxIPEventQueueSize
	}

	tracker := &IPLimitTracker{
		protocol:          protocol,
		instanceID:        instanceID,
		clusterManager:    clusterMgr,
		connections:       make(map[string]*IPConnectionInfo),
		maxEventQueueSize: maxEventQueueSize,
		broadcastQueue:    make([]IPLimitEvent, 0, 100),
		stopBroadcast:     make(chan struct{}),
		stopCleanup:       make(chan struct{}),
		stopStateSnapshot: make(chan struct{}),
	}

	if clusterMgr != nil {
		// Cluster mode: register with cluster manager for gossip
		logger.Debug("IP limit tracker: Registering handlers with cluster manager", "protocol", protocol)
		clusterMgr.RegisterIPLimitHandler(tracker.HandleClusterEvent)
		clusterMgr.RegisterIPLimitBroadcaster(tracker.GetBroadcasts)
		logger.Debug("IP limit tracker: Handlers registered successfully", "protocol", protocol)

		// Start background routines
		go tracker.broadcastRoutine()
		go tracker.cleanupRoutine()
		go tracker.stateSnapshotRoutine()
	}

	return tracker
}

// IncrementIP increments the connection count for an IP
func (t *IPLimitTracker) IncrementIP(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	info, exists := t.connections[ip]
	if !exists {
		info = &IPConnectionInfo{
			IP:             ip,
			TotalCount:     0,
			LocalCount:     0,
			LastUpdate:     time.Now(),
			LocalInstances: make(map[string]int),
		}
		t.connections[ip] = info
	}

	// Increment counts
	info.LocalCount++
	info.TotalCount++
	info.LastUpdate = time.Now()
	info.LocalInstances[t.instanceID]++

	// Broadcast event (if in cluster mode)
	if t.clusterManager != nil {
		event := IPLimitEvent{
			Type:       IPLimitEventIncrement,
			IP:         ip,
			Protocol:   t.protocol,
			Timestamp:  time.Now(),
			NodeID:     t.clusterManager.GetNodeID(),
			InstanceID: t.instanceID,
		}
		t.queueEvent(event)
	}
}

// DecrementIP decrements the connection count for an IP
func (t *IPLimitTracker) DecrementIP(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	info, exists := t.connections[ip]
	if !exists {
		return // Nothing to decrement
	}

	// Only decrement if we actually own connections for this IP
	if info.LocalCount == 0 {
		return // Don't decrement connections we don't own
	}

	// Decrement local count
	info.LocalCount--

	// Decrement total count (we own this connection)
	if info.TotalCount > 0 {
		info.TotalCount--
	}
	info.LastUpdate = time.Now()

	// Decrement instance count
	if count := info.LocalInstances[t.instanceID]; count > 0 {
		info.LocalInstances[t.instanceID] = count - 1
		// Clean up zero counts
		if info.LocalInstances[t.instanceID] == 0 {
			delete(info.LocalInstances, t.instanceID)
		}
	}

	// Clean up IP entry if no connections remain
	if info.TotalCount == 0 && len(info.LocalInstances) == 0 {
		delete(t.connections, ip)
	}

	// Broadcast event (if in cluster mode)
	if t.clusterManager != nil {
		event := IPLimitEvent{
			Type:       IPLimitEventDecrement,
			IP:         ip,
			Protocol:   t.protocol,
			Timestamp:  time.Now(),
			NodeID:     t.clusterManager.GetNodeID(),
			InstanceID: t.instanceID,
		}
		t.queueEvent(event)
	}
}

// GetIPCount returns the cluster-wide connection count for an IP
func (t *IPLimitTracker) GetIPCount(ip string) int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if info, exists := t.connections[ip]; exists {
		return info.TotalCount
	}
	return 0
}

// queueEvent adds an event to the broadcast queue
func (t *IPLimitTracker) queueEvent(event IPLimitEvent) {
	t.queueMu.Lock()
	defer t.queueMu.Unlock()

	// Add event to queue
	t.broadcastQueue = append(t.broadcastQueue, event)

	// Limit queue size to prevent unbounded memory growth
	if len(t.broadcastQueue) > t.maxEventQueueSize {
		// Drop oldest events
		dropped := len(t.broadcastQueue) - t.maxEventQueueSize
		t.broadcastQueue = t.broadcastQueue[dropped:]
		logger.Warn("IP limit tracker: Dropped old events from broadcast queue", "protocol", t.protocol, "dropped", dropped)
	}
}

// GetBroadcasts returns pending broadcasts for gossip (called by cluster manager)
func (t *IPLimitTracker) GetBroadcasts(overhead, limit int) [][]byte {
	t.queueMu.Lock()
	defer t.queueMu.Unlock()

	var broadcasts [][]byte
	totalSize := 0

	// Process events from queue
	for len(t.broadcastQueue) > 0 {
		event := t.broadcastQueue[0]

		// Encode event
		var buf bytes.Buffer
		enc := gob.NewEncoder(&buf)
		if err := enc.Encode(event); err != nil {
			logger.Warn("IP limit tracker: Failed to encode event", "protocol", t.protocol, "error", err)
			t.broadcastQueue = t.broadcastQueue[1:] // Skip this event
			continue
		}

		msgSize := overhead + buf.Len()
		if totalSize+msgSize > limit && len(broadcasts) > 0 {
			// Reached size limit, keep remaining events for next broadcast
			break
		}

		broadcasts = append(broadcasts, buf.Bytes())
		totalSize += msgSize
		t.broadcastQueue = t.broadcastQueue[1:]
	}

	return broadcasts
}

// HandleClusterEvent processes incoming events from other cluster nodes
func (t *IPLimitTracker) HandleClusterEvent(data []byte) {
	var event IPLimitEvent
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	if err := dec.Decode(&event); err != nil {
		logger.Warn("IP limit tracker: Failed to decode cluster event", "protocol", t.protocol, "error", err)
		return
	}

	// Skip events from this instance (we already processed them locally)
	if event.InstanceID == t.instanceID {
		return
	}

	switch event.Type {
	case IPLimitEventIncrement:
		t.handleRemoteIncrement(&event)
	case IPLimitEventDecrement:
		t.handleRemoteDecrement(&event)
	case IPLimitEventStateSnapshot:
		t.handleStateSnapshot(&event)
	}
}

// handleRemoteIncrement processes an increment event from another node
func (t *IPLimitTracker) handleRemoteIncrement(event *IPLimitEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()

	info, exists := t.connections[event.IP]
	if !exists {
		info = &IPConnectionInfo{
			IP:             event.IP,
			TotalCount:     0,
			LocalCount:     0,
			LastUpdate:     time.Now(),
			LocalInstances: make(map[string]int),
		}
		t.connections[event.IP] = info
	}

	// Increment cluster-wide count
	info.TotalCount++
	info.LastUpdate = event.Timestamp
	info.LocalInstances[event.InstanceID]++
}

// handleRemoteDecrement processes a decrement event from another node
func (t *IPLimitTracker) handleRemoteDecrement(event *IPLimitEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()

	info, exists := t.connections[event.IP]
	if !exists {
		return // Nothing to decrement
	}

	// Decrement cluster-wide count
	if info.TotalCount > 0 {
		info.TotalCount--
	}
	info.LastUpdate = event.Timestamp

	if count := info.LocalInstances[event.InstanceID]; count > 0 {
		info.LocalInstances[event.InstanceID] = count - 1
		if info.LocalInstances[event.InstanceID] == 0 {
			delete(info.LocalInstances, event.InstanceID)
		}
	}

	// Clean up if no connections remain
	if info.TotalCount == 0 && len(info.LocalInstances) == 0 {
		delete(t.connections, event.IP)
	}
}

// handleStateSnapshot processes a full state snapshot from another node
func (t *IPLimitTracker) handleStateSnapshot(event *IPLimitEvent) {
	if event.StateSnapshot == nil {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	snapshot := event.StateSnapshot

	// Merge remote state
	for ip, remoteData := range snapshot.Connections {
		info, exists := t.connections[ip]
		if !exists {
			info = &IPConnectionInfo{
				IP:             ip,
				TotalCount:     0,
				LocalCount:     0,
				LastUpdate:     time.Now(),
				LocalInstances: make(map[string]int),
			}
			t.connections[ip] = info
		}

		// Merge instance counts from remote snapshot
		for instanceID, count := range remoteData.LocalInstances {
			if instanceID == t.instanceID {
				continue // Don't override our own count
			}
			info.LocalInstances[instanceID] = count
		}

		// Recalculate total from all instances
		total := 0
		for _, count := range info.LocalInstances {
			total += count
		}
		info.TotalCount = total
		info.LastUpdate = remoteData.LastUpdate
	}
}

// broadcastRoutine periodically processes the broadcast queue
func (t *IPLimitTracker) broadcastRoutine() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Queue is processed via GetBroadcasts callback from memberlist
		case <-t.stopBroadcast:
			return
		}
	}
}

// cleanupRoutine periodically cleans up stale connection data
func (t *IPLimitTracker) cleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			t.performCleanup()
		case <-t.stopCleanup:
			return
		}
	}
}

// performCleanup removes stale connection data
func (t *IPLimitTracker) performCleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()

	cleaned := 0
	for ip, info := range t.connections {
		// FIRST: Clean up zero-count instance entries
		// This must happen before checking if the IP should be removed
		for instanceID, count := range info.LocalInstances {
			if count <= 0 {
				delete(info.LocalInstances, instanceID)
			}
		}

		// SECOND: Clean up IPs with no connections
		// After removing zero-count instances, check if IP should be removed
		if info.TotalCount == 0 && len(info.LocalInstances) == 0 {
			delete(t.connections, ip)
			cleaned++
		}
	}

	if cleaned > 0 {
		logger.Debug("IP limit tracker: Cleaned up stale IPs", "protocol", t.protocol, "count", cleaned)
	}
}

// stateSnapshotRoutine periodically broadcasts full state snapshots
func (t *IPLimitTracker) stateSnapshotRoutine() {
	ticker := time.NewTicker(ipStateSnapshotInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			t.broadcastStateSnapshot()
		case <-t.stopStateSnapshot:
			return
		}
	}
}

// broadcastStateSnapshot sends a full state snapshot to the cluster
func (t *IPLimitTracker) broadcastStateSnapshot() {
	t.mu.RLock()

	// Build snapshot
	connections := make(map[string]IPConnectionData)
	for ip, info := range t.connections {
		if info.TotalCount == 0 {
			continue // Skip empty entries
		}

		// Copy instance counts
		localInstances := make(map[string]int)
		for instanceID, count := range info.LocalInstances {
			if count > 0 {
				localInstances[instanceID] = count
			}
		}

		connections[ip] = IPConnectionData{
			IP:             ip,
			LocalInstances: localInstances,
			TotalCount:     info.TotalCount,
			LastUpdate:     info.LastUpdate,
		}
	}
	t.mu.RUnlock()

	if len(connections) == 0 {
		return // Nothing to broadcast
	}

	snapshot := IPLimitStateSnapshot{
		InstanceID:  t.instanceID,
		Timestamp:   time.Now(),
		Connections: connections,
	}

	event := IPLimitEvent{
		Type:          IPLimitEventStateSnapshot,
		Timestamp:     time.Now(),
		NodeID:        t.clusterManager.GetNodeID(),
		InstanceID:    t.instanceID,
		StateSnapshot: &snapshot,
	}

	t.queueEvent(event)
	logger.Debug("IP limit tracker: Queued state snapshot", "protocol", t.protocol, "ips", len(connections))
}

// Stop shuts down the IP limit tracker
func (t *IPLimitTracker) Stop() {
	t.stopOnce.Do(func() {
		if t.clusterManager != nil {
			close(t.stopBroadcast)
			close(t.stopCleanup)
			close(t.stopStateSnapshot)
		}
	})
}
