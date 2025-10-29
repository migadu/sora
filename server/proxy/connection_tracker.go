package proxy

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

// ConnectionEventType represents the type of connection event
type ConnectionEventType string

const (
	// ConnectionEventRegister indicates a user connected
	ConnectionEventRegister ConnectionEventType = "CONN_REGISTER"

	// ConnectionEventUnregister indicates a user disconnected
	ConnectionEventUnregister ConnectionEventType = "CONN_UNREGISTER"

	// ConnectionEventKick indicates a user should be kicked
	ConnectionEventKick ConnectionEventType = "CONN_KICK"
)

// ConnectionEvent represents a cluster-wide connection event
type ConnectionEvent struct {
	Type       ConnectionEventType `json:"type"`
	AccountID  int64               `json:"account_id"`
	Username   string              `json:"username"`    // For debugging/logging
	Protocol   string              `json:"protocol"`    // "IMAP", "POP3", "ManageSieve"
	ClientAddr string              `json:"client_addr"` // For logging
	Timestamp  time.Time           `json:"timestamp"`
	NodeID     string              `json:"node_id"`
	InstanceID string              `json:"instance_id"` // Unique instance identifier
}

// UserConnectionInfo tracks connection information for a specific user
type UserConnectionInfo struct {
	AccountID      int64
	Username       string
	TotalCount     int // Cluster-wide count (eventually consistent)
	LocalCount     int // This instance's count
	LastUpdate     time.Time
	LocalInstances map[string]int // instanceID -> count on that instance
}

// ConnectionTracker manages connection tracking using gossip protocol
type ConnectionTracker struct {
	name           string
	instanceID     string
	clusterManager *cluster.Manager

	// Connection tracking
	connections map[int64]*UserConnectionInfo // accountID -> info
	mu          sync.RWMutex

	// Kick notifications
	kickSessions   map[int64][]chan struct{} // accountID -> channels to notify
	kickSessionsMu sync.RWMutex

	// Configuration
	maxConnectionsPerUser int // Cluster-wide limit per user (0 = unlimited)

	// Broadcast queue for outgoing events
	broadcastQueue []ConnectionEvent
	queueMu        sync.Mutex

	// Shutdown
	stopBroadcast chan struct{}
	stopCleanup   chan struct{}
	stopOnce      sync.Once
}

// NewConnectionTracker creates a new connection tracker.
// If clusterMgr is provided, uses gossip protocol for cluster-wide tracking (for proxies).
// If clusterMgr is nil, operates in local-only mode (for backend servers).
func NewConnectionTracker(name string, instanceID string, clusterMgr *cluster.Manager, maxConnectionsPerUser int) *ConnectionTracker {
	ct := &ConnectionTracker{
		name:                  name,
		instanceID:            instanceID,
		clusterManager:        clusterMgr,
		connections:           make(map[int64]*UserConnectionInfo),
		maxConnectionsPerUser: maxConnectionsPerUser,
		kickSessions:          make(map[int64][]chan struct{}),
		broadcastQueue:        make([]ConnectionEvent, 0, 100),
		stopBroadcast:         make(chan struct{}),
		stopCleanup:           make(chan struct{}),
	}

	if clusterMgr != nil {
		// Cluster mode: register with cluster manager for gossip
		logger.Debugf("[%s-GOSSIP-TRACKER] Registering handlers with cluster manager", name)
		clusterMgr.RegisterConnectionHandler(ct.HandleClusterEvent)
		clusterMgr.RegisterConnectionBroadcaster(ct.GetBroadcasts)
		logger.Debugf("[%s-GOSSIP-TRACKER] Handlers registered successfully", name)

		// Start background routines
		go ct.broadcastRoutine()
		go ct.cleanupRoutine()

		logger.Infof("[%s-GOSSIP-TRACKER] Initialized: instance=%s, max_per_user=%d (cluster mode)",
			name, instanceID, maxConnectionsPerUser)
	} else {
		// Local mode: no gossip, just track connections locally
		go ct.cleanupRoutine()

		logger.Infof("[%s-LOCAL-TRACKER] Initialized: instance=%s, max_per_user=%d (local mode)",
			name, instanceID, maxConnectionsPerUser)
	}

	return ct
}

// trackerType returns the name of the tracker for logging purposes.
func (ct *ConnectionTracker) trackerType() string {
	if ct.clusterManager == nil {
		return "LOCAL-TRACKER"
	}
	return "GOSSIP-TRACKER"
}

// RegisterConnection registers a new connection and broadcasts to cluster
func (ct *ConnectionTracker) RegisterConnection(ctx context.Context, accountID int64, username, protocol, clientAddr string) error {
	if ct == nil {
		return nil // Disabled
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()

	// Get or create user info
	info, exists := ct.connections[accountID]
	if !exists {
		info = &UserConnectionInfo{
			AccountID:      accountID,
			Username:       username,
			TotalCount:     0,
			LocalCount:     0,
			LastUpdate:     time.Now(),
			LocalInstances: make(map[string]int),
		}
		ct.connections[accountID] = info
	}

	// Check limit (if configured)
	// In cluster mode, check cluster-wide count. In local mode, check local count.
	checkCount := info.TotalCount // cluster mode
	if ct.clusterManager == nil {
		checkCount = info.LocalCount // local mode
	}

	if ct.maxConnectionsPerUser > 0 && checkCount >= ct.maxConnectionsPerUser {
		scope := "across cluster"
		if ct.clusterManager == nil {
			scope = "on this server"
		}
		return fmt.Errorf("user %s has reached maximum connections (%d/%d %s)",
			username, checkCount, ct.maxConnectionsPerUser, scope)
	}

	// Increment local count
	info.LocalCount++
	info.TotalCount++
	info.LastUpdate = time.Now()
	info.LocalInstances[ct.instanceID]++

	if ct.clusterManager == nil {
		info.TotalCount = info.LocalCount // In local mode, total = local
	}

	logger.Debugf("[%s-%s] Registered: user=%s, local=%d, total=%d", ct.name, ct.trackerType(), username, info.LocalCount, info.TotalCount)

	// Broadcast to cluster (only in cluster mode)
	if ct.clusterManager != nil {
		ct.queueEvent(ConnectionEvent{
			Type:       ConnectionEventRegister,
			AccountID:  accountID,
			Username:   username,
			Protocol:   protocol,
			ClientAddr: clientAddr,
			Timestamp:  time.Now(),
			NodeID:     ct.clusterManager.GetNodeID(),
			InstanceID: ct.instanceID,
		})
	}

	return nil
}

// UnregisterConnection unregisters a connection and broadcasts to cluster
func (ct *ConnectionTracker) UnregisterConnection(ctx context.Context, accountID int64, protocol, clientAddr string) error {
	if ct == nil {
		return nil // Disabled
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()

	info, exists := ct.connections[accountID]
	if !exists {
		logger.Debugf("[%s-%s] Unregister called for unknown accountID=%d", ct.name, ct.trackerType(), accountID)
		return nil
	}

	// Decrement local count
	if info.LocalCount > 0 {
		info.LocalCount--
	}
	if info.TotalCount > 0 {
		info.TotalCount--
	}
	if count := info.LocalInstances[ct.instanceID]; count > 0 {
		info.LocalInstances[ct.instanceID] = count - 1
	}

	// In local mode, keep total = local
	if ct.clusterManager == nil {
		info.TotalCount = info.LocalCount
	}

	info.LastUpdate = time.Now()

	logger.Debugf("[%s-%s] Unregistered: user=%s, local=%d, total=%d",
		ct.name, ct.trackerType(), info.Username, info.LocalCount, info.TotalCount)

	// Clean up if no local connections remain
	cleanupThreshold := info.TotalCount
	if ct.clusterManager == nil {
		cleanupThreshold = info.LocalCount // In local mode, clean up when no local connections
	}

	if cleanupThreshold <= 0 {
		delete(ct.connections, accountID)
	}

	// Broadcast to cluster (only in cluster mode)
	if ct.clusterManager != nil {
		ct.queueEvent(ConnectionEvent{
			Type:       ConnectionEventUnregister,
			AccountID:  accountID,
			Username:   info.Username,
			Protocol:   protocol,
			ClientAddr: clientAddr,
			Timestamp:  time.Now(),
			NodeID:     ct.clusterManager.GetNodeID(),
			InstanceID: ct.instanceID,
		})
	}

	return nil
}

// GetConnectionCount returns the cluster-wide connection count for a user
func (ct *ConnectionTracker) GetConnectionCount(accountID int64) int {
	if ct == nil {
		return 0
	}

	ct.mu.RLock()
	defer ct.mu.RUnlock()

	if info, exists := ct.connections[accountID]; exists {
		return info.TotalCount
	}
	return 0
}

// GetLocalConnectionCount returns the connection count for a user on this instance
func (ct *ConnectionTracker) GetLocalConnectionCount(accountID int64) int {
	if ct == nil {
		return 0
	}

	ct.mu.RLock()
	defer ct.mu.RUnlock()

	if info, exists := ct.connections[accountID]; exists {
		return info.LocalCount
	}
	return 0
}

// GetAllConnections returns all tracked connections (for admin tool)
func (ct *ConnectionTracker) GetAllConnections() []UserConnectionInfo {
	if ct == nil {
		return nil
	}

	ct.mu.RLock()
	defer ct.mu.RUnlock()

	result := make([]UserConnectionInfo, 0, len(ct.connections))
	for _, info := range ct.connections {
		var instancesCopy map[string]int
		if len(info.LocalInstances) > 0 {
			instancesCopy = make(map[string]int, len(info.LocalInstances))
			for k, v := range info.LocalInstances {
				instancesCopy[k] = v
			}
		}

		result = append(result, UserConnectionInfo{
			AccountID:      info.AccountID,
			Username:       info.Username,
			TotalCount:     info.TotalCount,
			LocalCount:     info.LocalCount,
			LastUpdate:     info.LastUpdate,
			LocalInstances: instancesCopy,
		})
	}
	return result
}

// KickUser kicks a user's connections.
// In cluster mode, broadcasts kick event via gossip.
// In local mode, directly closes all sessions for the user.
func (ct *ConnectionTracker) KickUser(accountID int64, protocol string) error {
	if ct == nil {
		return fmt.Errorf("connection tracker not initialized")
	}

	ct.mu.RLock()
	info, exists := ct.connections[accountID]
	username := ""
	if exists {
		username = info.Username
	}
	ct.mu.RUnlock()

	if ct.clusterManager != nil {
		// Cluster mode: broadcast kick event via gossip
		logger.Debugf("[%s-GOSSIP-TRACKER] Broadcasting kick for accountID=%d, protocol=%s",
			ct.name, accountID, protocol)

		ct.queueEvent(ConnectionEvent{
			Type:       ConnectionEventKick,
			AccountID:  accountID,
			Username:   username,
			Protocol:   protocol,
			Timestamp:  time.Now(),
			NodeID:     ct.clusterManager.GetNodeID(),
			InstanceID: ct.instanceID,
		})
	} else {
		// Local mode: directly kick sessions on this server
		logger.Infof("[%s-LOCAL-TRACKER] Kicking local sessions for accountID=%d, protocol=%s",
			ct.name, accountID, protocol)

		ct.kickSessionsMu.Lock()
		sessions := ct.kickSessions[accountID]
		if len(sessions) > 0 {
			// Close all kick channels for this user
			for _, ch := range sessions {
				select {
				case <-ch:
					// Already closed
				default:
					close(ch)
				}
			}
			delete(ct.kickSessions, accountID)
			logger.Infof("[%s-LOCAL-TRACKER] Kicked %d local sessions for accountID=%d",
				ct.name, len(sessions), accountID)
		} else {
			logger.Debugf("[%s-LOCAL-TRACKER] No active sessions to kick for accountID=%d",
				ct.name, accountID)
		}
		ct.kickSessionsMu.Unlock()
	}

	return nil
}

// RegisterSession registers a session for kick notifications
// Returns a channel that will be closed when the user should be kicked
func (ct *ConnectionTracker) RegisterSession(accountID int64) <-chan struct{} {
	if ct == nil {
		// Return a channel that never closes
		ch := make(chan struct{})
		return ch
	}

	ch := make(chan struct{})

	ct.kickSessionsMu.Lock()
	defer ct.kickSessionsMu.Unlock()

	ct.kickSessions[accountID] = append(ct.kickSessions[accountID], ch)

	logger.Debugf("[%s-GOSSIP-TRACKER] Registered session for accountID=%d", ct.name, accountID)

	return ch
}

// UnregisterSession removes a session's kick notification channel
func (ct *ConnectionTracker) UnregisterSession(accountID int64, ch <-chan struct{}) {
	if ct == nil {
		return
	}

	ct.kickSessionsMu.Lock()
	defer ct.kickSessionsMu.Unlock()

	sessions := ct.kickSessions[accountID]
	for i, session := range sessions {
		if session == ch {
			// Remove from slice
			ct.kickSessions[accountID] = append(sessions[:i], sessions[i+1:]...)
			break
		}
	}

	// Clean up if no more sessions
	if len(ct.kickSessions[accountID]) == 0 {
		delete(ct.kickSessions, accountID)
	}
}

// queueEvent adds an event to the broadcast queue
func (ct *ConnectionTracker) queueEvent(event ConnectionEvent) {
	ct.queueMu.Lock()
	defer ct.queueMu.Unlock()
	ct.broadcastQueue = append(ct.broadcastQueue, event)
}

// GetBroadcasts returns events to broadcast (called by cluster manager)
func (ct *ConnectionTracker) GetBroadcasts(overhead, limit int) [][]byte {
	ct.queueMu.Lock()
	defer ct.queueMu.Unlock()

	queueLen := len(ct.broadcastQueue)
	if queueLen == 0 {
		return nil
	}

	logger.Debugf("[%s-GOSSIP-TRACKER] GetBroadcasts called: queue_len=%d, overhead=%d, limit=%d",
		ct.name, queueLen, overhead, limit)

	broadcasts := make([][]byte, 0, len(ct.broadcastQueue))
	totalSize := 0

	for i := 0; i < len(ct.broadcastQueue); i++ {
		encoded, err := encodeConnectionEvent(ct.broadcastQueue[i])
		if err != nil {
			logger.Warnf("[%s-GOSSIP-TRACKER] Failed to encode event: %v", ct.name, err)
			continue
		}

		// Check if adding this message would exceed the limit
		msgSize := overhead + len(encoded)
		if totalSize+msgSize > limit && len(broadcasts) > 0 {
			// Keep remaining events for next broadcast
			ct.broadcastQueue = ct.broadcastQueue[i:]
			logger.Debugf("[%s-GOSSIP-TRACKER] GetBroadcasts returning %d messages (limit reached, %d remain queued)",
				ct.name, len(broadcasts), len(ct.broadcastQueue))
			return broadcasts
		}

		broadcasts = append(broadcasts, encoded)
		totalSize += msgSize
	}

	// All events broadcasted, clear queue
	ct.broadcastQueue = ct.broadcastQueue[:0]
	logger.Debugf("[%s-GOSSIP-TRACKER] GetBroadcasts returning %d messages (queue emptied)",
		ct.name, len(broadcasts))
	return broadcasts
}

// HandleClusterEvent processes a connection event from another node
func (ct *ConnectionTracker) HandleClusterEvent(data []byte) {
	logger.Debugf("[%s-GOSSIP-TRACKER] HandleClusterEvent called with data (len=%d)", ct.name, len(data))

	event, err := decodeConnectionEvent(data)
	if err != nil {
		logger.Warnf("[%s-GOSSIP-TRACKER] Failed to decode event: %v", ct.name, err)
		return
	}

	logger.Debugf("[%s-GOSSIP-TRACKER] Decoded event: type=%s, user=%s, instance=%s",
		ct.name, event.Type, event.Username, event.InstanceID)

	// Skip events from this instance (we already applied them locally)
	if event.InstanceID == ct.instanceID {
		logger.Debugf("[%s-GOSSIP-TRACKER] Skipping event from self (instance=%s)", ct.name, event.InstanceID)
		return
	}

	// Check if event is too old (prevent replays after network partition)
	age := time.Since(event.Timestamp)
	if age > 5*time.Minute {
		logger.Debugf("[%s-GOSSIP-TRACKER] Ignoring stale event from %s (age: %v)",
			ct.name, event.NodeID, age)
		return
	}

	switch event.Type {
	case ConnectionEventRegister:
		ct.handleRegister(event)
	case ConnectionEventUnregister:
		ct.handleUnregister(event)
	case ConnectionEventKick:
		ct.handleKick(event)
	default:
		logger.Warnf("[%s-GOSSIP-TRACKER] Unknown event type: %s", ct.name, event.Type)
	}
}

// handleRegister processes a register event from another node
func (ct *ConnectionTracker) handleRegister(event ConnectionEvent) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	info, exists := ct.connections[event.AccountID]
	if !exists {
		info = &UserConnectionInfo{
			AccountID:      event.AccountID,
			Username:       event.Username,
			TotalCount:     0,
			LocalCount:     0,
			LastUpdate:     time.Now(),
			LocalInstances: make(map[string]int),
		}
		ct.connections[event.AccountID] = info
	}

	// Increment cluster-wide count
	info.TotalCount++
	info.LastUpdate = time.Now()
	info.LocalInstances[event.InstanceID]++

	logger.Debugf("[%s-GOSSIP-TRACKER] Cluster register: user=%s, instance=%s, cluster_total=%d",
		ct.name, event.Username, event.InstanceID, info.TotalCount)
}

// handleUnregister processes an unregister event from another node
func (ct *ConnectionTracker) handleUnregister(event ConnectionEvent) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	info, exists := ct.connections[event.AccountID]
	if !exists {
		return // Unknown user, ignore
	}

	// Decrement cluster-wide count
	if info.TotalCount > 0 {
		info.TotalCount--
	}
	if count := info.LocalInstances[event.InstanceID]; count > 0 {
		info.LocalInstances[event.InstanceID] = count - 1
	}
	info.LastUpdate = time.Now()

	logger.Debugf("[%s-GOSSIP-TRACKER] Cluster unregister: user=%s, instance=%s, cluster_total=%d",
		ct.name, event.Username, event.InstanceID, info.TotalCount)

	// Clean up if no connections remain
	if info.TotalCount <= 0 {
		delete(ct.connections, event.AccountID)
	}
}

// handleKick processes a kick event from another node
func (ct *ConnectionTracker) handleKick(event ConnectionEvent) {
	logger.Debugf("[%s-GOSSIP-TRACKER] Received kick for accountID=%d, protocol=%s from node=%s",
		ct.name, event.AccountID, event.Protocol, event.NodeID)

	// Notify all sessions for this user
	ct.kickSessionsMu.Lock()
	defer ct.kickSessionsMu.Unlock()

	sessions := ct.kickSessions[event.AccountID]
	for _, ch := range sessions {
		select {
		case <-ch:
			// Already closed
		default:
			close(ch)
		}
	}

	// Clear the sessions list
	delete(ct.kickSessions, event.AccountID)

	logger.Debugf("[%s-GOSSIP-TRACKER] Notified %d sessions for accountID=%d",
		ct.name, len(sessions), event.AccountID)
}

// broadcastRoutine periodically triggers broadcasts
func (ct *ConnectionTracker) broadcastRoutine() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ct.queueMu.Lock()
			hasEvents := len(ct.broadcastQueue) > 0
			ct.queueMu.Unlock()

			if hasEvents {
				// Cluster manager will call GetBroadcasts()
				logger.Debugf("[%s-GOSSIP-TRACKER] Broadcasting %d queued events", ct.name, len(ct.broadcastQueue))
			}

		case <-ct.stopBroadcast:
			return
		}
	}
}

// cleanupRoutine periodically cleans up stale connection entries
func (ct *ConnectionTracker) cleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ct.cleanup()

		case <-ct.stopCleanup:
			return
		}
	}
}

// cleanup removes stale entries (not updated recently and zero connections)
func (ct *ConnectionTracker) cleanup() {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	cleaned := 0
	staleThreshold := time.Now().Add(-10 * time.Minute)

	for accountID, info := range ct.connections {
		if info.TotalCount <= 0 && info.LastUpdate.Before(staleThreshold) {
			delete(ct.connections, accountID)
			cleaned++
		}
	}

	if cleaned > 0 {
		logger.Debugf("[%s-GOSSIP-TRACKER] Cleaned up %d stale entries", ct.name, cleaned)
	}
}

// Stop stops the gossip tracker (idempotent)
func (ct *ConnectionTracker) Stop() {
	if ct == nil {
		return
	}

	ct.stopOnce.Do(func() {
		close(ct.stopBroadcast)
		close(ct.stopCleanup)
	})
}

// GetOperationTimeout returns a timeout for operations (for compatibility with old interface)
func (ct *ConnectionTracker) GetOperationTimeout() time.Duration {
	return 5 * time.Second // Gossip is fast, short timeout is fine
}

// IsEnabled returns whether connection tracking is enabled
func (ct *ConnectionTracker) IsEnabled() bool {
	return ct != nil
}

// Start is a no-op for gossip tracker (background routines started in constructor)
func (ct *ConnectionTracker) Start() {
	// Background routines already started in NewConnectionTracker
}

// UpdateActivity is a no-op for gossip tracker (no activity tracking needed)
func (ct *ConnectionTracker) UpdateActivity(ctx context.Context, accountID int64, protocol, clientAddr string) error {
	// Gossip tracker doesn't track activity timestamps
	return nil
}

// CheckTermination is deprecated - use RegisterSession instead
func (ct *ConnectionTracker) CheckTermination(ctx context.Context, accountID int64, protocol string) (bool, error) {
	return false, nil
}

// KickChannel is deprecated - use RegisterSession instead
func (ct *ConnectionTracker) KickChannel() <-chan struct{} {
	return nil
}

// encodeConnectionEvent encodes an event to bytes using gob
func encodeConnectionEvent(event ConnectionEvent) ([]byte, error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	if err := encoder.Encode(event); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decodeConnectionEvent decodes an event from bytes using gob
func decodeConnectionEvent(data []byte) (ConnectionEvent, error) {
	var event ConnectionEvent
	decoder := gob.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&event); err != nil {
		return event, err
	}
	return event, nil
}
