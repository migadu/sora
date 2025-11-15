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
	"github.com/migadu/sora/pkg/metrics"
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

	// ConnectionEventStateSnapshot indicates a full state snapshot for reconciliation
	ConnectionEventStateSnapshot ConnectionEventType = "CONN_STATE_SNAPSHOT"
)

const (
	// Default maximum size of event queue before we start dropping old events
	defaultMaxEventQueueSize = 50000

	// How often to broadcast full state snapshot for reconciliation
	stateSnapshotInterval = 60 * time.Second
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

	// For state snapshots
	StateSnapshot *ConnectionStateSnapshot `json:"state_snapshot,omitempty"`
}

// ConnectionStateSnapshot represents a full connection state for reconciliation
type ConnectionStateSnapshot struct {
	InstanceID  string                       `json:"instance_id"`
	Timestamp   time.Time                    `json:"timestamp"`
	Connections map[int64]UserConnectionData `json:"connections"` // accountID -> connection data
}

// UserConnectionData is the serializable version of UserConnectionInfo for gossip
type UserConnectionData struct {
	AccountID      int64          `json:"account_id"`
	Username       string         `json:"username"`
	LocalInstances map[string]int `json:"local_instances"` // instanceID -> count
	PerIPCount     map[string]int `json:"per_ip_count"`    // clientIP -> count (cluster-wide)
	LastUpdate     time.Time      `json:"last_update"`
}

// UserConnectionInfo tracks connection information for a specific user
type UserConnectionInfo struct {
	AccountID      int64
	Username       string
	TotalCount     int // Cluster-wide count (eventually consistent)
	LocalCount     int // This instance's count
	LastUpdate     time.Time
	LocalInstances map[string]int // instanceID -> count on that instance
	PerIPCount     map[string]int // clientIP -> count (cluster-wide via gossip, for per-user-per-IP limiting)
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
	maxConnectionsPerUser      int // Cluster-wide limit per user (0 = unlimited)
	maxConnectionsPerUserPerIP int // Local limit per user per IP (0 = unlimited)
	maxEventQueueSize          int // Maximum events in broadcast queue

	// Broadcast queue for outgoing events
	broadcastQueue []ConnectionEvent
	queueMu        sync.Mutex

	// Cleanup counter for periodic memory reporting
	cleanupCounter uint64

	// Shutdown
	stopBroadcast     chan struct{}
	stopCleanup       chan struct{}
	stopStateSnapshot chan struct{}
	stopOnce          sync.Once
}

// NewConnectionTracker creates a new connection tracker.
// If clusterMgr is provided, uses gossip protocol for cluster-wide tracking (for proxies).
// If clusterMgr is nil, operates in local-only mode (for backend servers).
func NewConnectionTracker(name string, instanceID string, clusterMgr *cluster.Manager, maxConnectionsPerUser int, maxConnectionsPerUserPerIP int, maxEventQueueSize int) *ConnectionTracker {
	// Use default if not specified
	if maxEventQueueSize <= 0 {
		maxEventQueueSize = defaultMaxEventQueueSize
	}

	ct := &ConnectionTracker{
		name:                       name,
		instanceID:                 instanceID,
		clusterManager:             clusterMgr,
		connections:                make(map[int64]*UserConnectionInfo),
		maxConnectionsPerUser:      maxConnectionsPerUser,
		maxConnectionsPerUserPerIP: maxConnectionsPerUserPerIP,
		maxEventQueueSize:          maxEventQueueSize,
		kickSessions:               make(map[int64][]chan struct{}),
		broadcastQueue:             make([]ConnectionEvent, 0, 100),
		stopBroadcast:              make(chan struct{}),
		stopCleanup:                make(chan struct{}),
		stopStateSnapshot:          make(chan struct{}),
	}

	if clusterMgr != nil {
		// Cluster mode: register with cluster manager for gossip
		logger.Debug("Gossip tracker: Registering handlers with cluster manager", "name", name)
		clusterMgr.RegisterConnectionHandler(ct.HandleClusterEvent)
		clusterMgr.RegisterConnectionBroadcaster(ct.GetBroadcasts)
		logger.Debug("Gossip tracker: Handlers registered successfully", "name", name)

		// Start background routines
		go ct.broadcastRoutine()
		go ct.cleanupRoutine()
		go ct.stateSnapshotRoutine()

		logger.Info("GossipTracker: Initialized (cluster mode)", "protocol", name,
			"instance", instanceID, "max_per_user", maxConnectionsPerUser, "queue_size", maxEventQueueSize)
	} else {
		// Local mode: no gossip, just track connections locally
		go ct.cleanupRoutine()

		logger.Info("LocalTracker: Initialized (local mode)", "protocol", name,
			"instance", instanceID, "max_per_user", maxConnectionsPerUser)
	}

	return ct
}

// trackerType returns the name of the tracker for logging purposes.
func (ct *ConnectionTracker) trackerType() string {
	if ct.clusterManager == nil {
		return "LocalTracker"
	}
	return "GossipTracker"
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
			PerIPCount:     make(map[string]int),
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
		logger.Info("Connection tracker: Maximum connections per user reached", "tracker", ct.trackerType(), "protocol", protocol, "username", username, "account_id", accountID, "current", checkCount, "max", ct.maxConnectionsPerUser, "scope", scope, "client_addr", clientAddr)
		return fmt.Errorf("user %s has reached maximum connections (%d/%d %s)",
			username, checkCount, ct.maxConnectionsPerUser, scope)
	}

	// Check per-user-per-IP limit (cluster-wide via gossip)
	if ct.maxConnectionsPerUserPerIP > 0 && clientAddr != "" {
		// Extract IP from clientAddr (format is usually "IP:port")
		clientIP := clientAddr
		if idx := len(clientAddr) - 1; idx >= 0 {
			for i := idx; i >= 0; i-- {
				if clientAddr[i] == ':' {
					clientIP = clientAddr[:i]
					break
				}
			}
		}

		ipCount := info.PerIPCount[clientIP]
		if ipCount >= ct.maxConnectionsPerUserPerIP {
			logger.Info("Connection tracker: Maximum connections per user per IP reached", "tracker", ct.trackerType(), "protocol", protocol, "username", username, "account_id", accountID, "ip", clientIP, "current", ipCount, "max", ct.maxConnectionsPerUserPerIP, "client_addr", clientAddr)
			return fmt.Errorf("user %s has reached maximum connections from IP %s (%d/%d)",
				username, clientIP, ipCount, ct.maxConnectionsPerUserPerIP)
		}
	}

	// Increment local count
	info.LocalCount++
	info.TotalCount++
	info.LastUpdate = time.Now()
	info.LocalInstances[ct.instanceID]++

	// Increment per-IP count (if tracking enabled)
	if ct.maxConnectionsPerUserPerIP > 0 && clientAddr != "" {
		// Extract IP from clientAddr
		clientIP := clientAddr
		if idx := len(clientAddr) - 1; idx >= 0 {
			for i := idx; i >= 0; i-- {
				if clientAddr[i] == ':' {
					clientIP = clientAddr[:i]
					break
				}
			}
		}
		info.PerIPCount[clientIP]++
	}

	if ct.clusterManager == nil {
		info.TotalCount = info.LocalCount // In local mode, total = local
	}

	logger.Debug("Connection tracker: Registered", "name", ct.name, "type", ct.trackerType(), "user", username, "local", info.LocalCount, "total", info.TotalCount)

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
		logger.Debug("Connection tracker: Unregister called for unknown account", "name", ct.name, "type", ct.trackerType(), "account_id", accountID)
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
		// Clean up zero counts immediately (consistent with PerIPCount cleanup)
		if info.LocalInstances[ct.instanceID] == 0 {
			delete(info.LocalInstances, ct.instanceID)
		}
	}

	// Decrement per-IP count (if tracking enabled)
	if ct.maxConnectionsPerUserPerIP > 0 && clientAddr != "" {
		// Extract IP from clientAddr
		clientIP := clientAddr
		if idx := len(clientAddr) - 1; idx >= 0 {
			for i := idx; i >= 0; i-- {
				if clientAddr[i] == ':' {
					clientIP = clientAddr[:i]
					break
				}
			}
		}
		if count := info.PerIPCount[clientIP]; count > 0 {
			info.PerIPCount[clientIP] = count - 1
			// Clean up zero counts
			if info.PerIPCount[clientIP] == 0 {
				delete(info.PerIPCount, clientIP)
			}
		}
	}

	// In local mode, keep total = local
	if ct.clusterManager == nil {
		info.TotalCount = info.LocalCount
	}

	info.LastUpdate = time.Now()

	logger.Debug("Connection tracker: Unregistered", "name", ct.name, "type", ct.trackerType(), "user", info.Username, "local", info.LocalCount, "total", info.TotalCount)

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

// GetUniqueUserCount returns the number of unique users with active connections (cluster-wide)
func (ct *ConnectionTracker) GetUniqueUserCount() int {
	if ct == nil {
		return 0
	}

	ct.mu.RLock()
	defer ct.mu.RUnlock()

	// Count unique users with at least one connection
	count := 0
	for _, info := range ct.connections {
		if info.TotalCount > 0 {
			count++
		}
	}
	return count
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
		logger.Debug("Gossip tracker: Broadcasting kick", "name", ct.name, "account_id", accountID, "protocol", protocol)

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
		logger.Info("LocalTracker: Kicking local sessions", "protocol", ct.name,
			"account_id", accountID, "target_protocol", protocol)

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
			logger.Info("LocalTracker: Kicked local sessions", "protocol", ct.name,
				"count", len(sessions), "account_id", accountID)
		} else {
			logger.Debug("Local tracker: No active sessions to kick", "name", ct.name, "account_id", accountID)
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

	logger.Debug("Gossip tracker: Registered session", "name", ct.name, "account_id", accountID)

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

// queueEvent adds an event to the broadcast queue with bounded size.
// Prioritizes kick events - they are never dropped to ensure security.
func (ct *ConnectionTracker) queueEvent(event ConnectionEvent) {
	ct.queueMu.Lock()
	defer ct.queueMu.Unlock()

	// If queue is full, drop oldest non-critical events
	if len(ct.broadcastQueue) >= ct.maxEventQueueSize {
		// Try to drop non-kick events (Register/Unregister/StateSnapshot)
		// Kick events are critical for security and must not be dropped
		dropCount := ct.maxEventQueueSize / 10
		droppedEvents := ct.dropNonCriticalEvents(dropCount)

		if droppedEvents > 0 {
			logger.Warn("Gossip tracker: Event queue overflow - dropped non-critical events",
				"name", ct.name, "current", len(ct.broadcastQueue),
				"max", ct.maxEventQueueSize, "dropped", droppedEvents)
		} else {
			// Queue is full of critical events (kicks) - cannot drop
			// This is a serious situation but we must preserve kick events
			logger.Error("Gossip tracker: Event queue overflow with critical events - cannot drop",
				"name", ct.name, "current", len(ct.broadcastQueue),
				"max", ct.maxEventQueueSize, "event_type", event.Type,
				"recommendation", "Increase maxEventQueueSize or investigate gossip performance")

			// For kick events, we MUST queue them even if over limit (security critical)
			// For other events when queue is all kicks, drop the new event
			if event.Type != ConnectionEventKick {
				logger.Warn("Gossip tracker: Dropping new non-critical event due to critical queue overflow",
					"name", ct.name, "event_type", event.Type)
				return // Don't queue this event
			}
			// Allow kick event to be queued even over limit
		}
	}

	ct.broadcastQueue = append(ct.broadcastQueue, event)
}

// dropNonCriticalEvents removes up to maxDrop non-critical events from the queue.
// Returns the number of events actually dropped.
// Critical events (ConnectionEventKick) are never dropped.
func (ct *ConnectionTracker) dropNonCriticalEvents(maxDrop int) int {
	dropped := 0
	writeIdx := 0

	// Single pass: iterate through queue, keep kicks, drop others until maxDrop reached
	for readIdx := 0; readIdx < len(ct.broadcastQueue); readIdx++ {
		event := ct.broadcastQueue[readIdx]

		// Always keep kick events (critical)
		if event.Type == ConnectionEventKick {
			if writeIdx != readIdx {
				ct.broadcastQueue[writeIdx] = event
			}
			writeIdx++
			continue
		}

		// For non-critical events: keep if we haven't dropped enough yet
		if dropped < maxDrop {
			// Drop this non-critical event
			dropped++
			switch event.Type {
			case ConnectionEventRegister:
				logger.Debug("Gossip tracker: Dropped register event", "name", ct.name, "user", event.Username)
			case ConnectionEventUnregister:
				logger.Debug("Gossip tracker: Dropped unregister event", "name", ct.name, "user", event.Username)
			case ConnectionEventStateSnapshot:
				logger.Debug("Gossip tracker: Dropped state snapshot", "name", ct.name)
			}
		} else {
			// Keep this event (already dropped enough)
			if writeIdx != readIdx {
				ct.broadcastQueue[writeIdx] = event
			}
			writeIdx++
		}
	}

	// Truncate queue to new size
	ct.broadcastQueue = ct.broadcastQueue[:writeIdx]
	return dropped
}

// GetBroadcasts returns events to broadcast (called by cluster manager)
func (ct *ConnectionTracker) GetBroadcasts(overhead, limit int) [][]byte {
	ct.queueMu.Lock()
	defer ct.queueMu.Unlock()

	queueLen := len(ct.broadcastQueue)
	if queueLen == 0 {
		return nil
	}

	logger.Debug("Gossip tracker: GetBroadcasts called", "name", ct.name, "queue_len", queueLen, "overhead", overhead, "limit", limit)

	broadcasts := make([][]byte, 0, len(ct.broadcastQueue))
	totalSize := 0

	for i := 0; i < len(ct.broadcastQueue); i++ {
		encoded, err := encodeConnectionEvent(ct.broadcastQueue[i])
		if err != nil {
			logger.Warn("Gossip tracker: Failed to encode event", "name", ct.name, "error", err)
			continue
		}

		// Check if adding this message would exceed the limit
		msgSize := overhead + len(encoded)
		if totalSize+msgSize > limit && len(broadcasts) > 0 {
			// Keep remaining events for next broadcast
			ct.broadcastQueue = ct.broadcastQueue[i:]
			logger.Debug("Gossip tracker: GetBroadcasts limit reached", "name", ct.name, "returned", len(broadcasts), "queued", len(ct.broadcastQueue))
			return broadcasts
		}

		broadcasts = append(broadcasts, encoded)
		totalSize += msgSize
	}

	// All events broadcasted, clear queue
	ct.broadcastQueue = ct.broadcastQueue[:0]
	logger.Debug("Gossip tracker: GetBroadcasts queue emptied", "name", ct.name, "messages", len(broadcasts))
	return broadcasts
}

// HandleClusterEvent processes a connection event from another node
func (ct *ConnectionTracker) HandleClusterEvent(data []byte) {
	logger.Debug("Gossip tracker: HandleClusterEvent called", "name", ct.name, "data_len", len(data))

	event, err := decodeConnectionEvent(data)
	if err != nil {
		logger.Warn("Gossip tracker: Failed to decode event", "name", ct.name, "error", err)
		return
	}

	logger.Debug("Gossip tracker: Decoded event", "name", ct.name, "type", event.Type, "user", event.Username, "instance", event.InstanceID)

	// Skip events from this instance (we already applied them locally)
	if event.InstanceID == ct.instanceID {
		logger.Debug("Gossip tracker: Skipping event from self", "name", ct.name, "instance", event.InstanceID)
		return
	}

	// Check if event is too old (prevent replays after network partition)
	age := time.Since(event.Timestamp)
	if age > 5*time.Minute {
		logger.Debug("Gossip tracker: Ignoring stale event", "name", ct.name, "node_id", event.NodeID, "age", age)
		return
	}

	// CRITICAL: Filter events by protocol to prevent cross-protocol contamination
	// All connection trackers receive all gossip events, but each should only process its own protocol
	// Without this check, IMAP events get counted in LMTP tracker, causing massive ghost connection leaks
	if event.Protocol != "" && event.Protocol != ct.name {
		logger.Debug("Gossip tracker: Ignoring event for different protocol", "tracker_protocol", ct.name, "event_protocol", event.Protocol, "event_type", event.Type)
		return
	}

	switch event.Type {
	case ConnectionEventRegister:
		ct.handleRegister(event)
	case ConnectionEventUnregister:
		ct.handleUnregister(event)
	case ConnectionEventKick:
		ct.handleKick(event)
	case ConnectionEventStateSnapshot:
		ct.reconcileState(event.StateSnapshot)
	default:
		logger.Warn("Gossip tracker: Unknown event type", "name", ct.name, "type", event.Type)
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
			PerIPCount:     make(map[string]int),
		}
		ct.connections[event.AccountID] = info
	}

	// Increment cluster-wide count
	info.TotalCount++
	info.LastUpdate = time.Now()
	info.LocalInstances[event.InstanceID]++

	// Increment per-IP count (cluster-wide tracking via gossip)
	if event.ClientAddr != "" {
		// Extract IP from clientAddr
		clientIP := event.ClientAddr
		if idx := len(event.ClientAddr) - 1; idx >= 0 {
			for i := idx; i >= 0; i-- {
				if event.ClientAddr[i] == ':' {
					clientIP = event.ClientAddr[:i]
					break
				}
			}
		}
		info.PerIPCount[clientIP]++
	}

	logger.Debug("Gossip tracker: Cluster register", "name", ct.name, "user", event.Username, "instance", event.InstanceID, "cluster_total", info.TotalCount)
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
		// Clean up zero counts immediately (consistent with PerIPCount cleanup)
		if info.LocalInstances[event.InstanceID] == 0 {
			delete(info.LocalInstances, event.InstanceID)
		}
	}

	// Decrement per-IP count (cluster-wide tracking via gossip)
	if event.ClientAddr != "" {
		// Extract IP from clientAddr
		clientIP := event.ClientAddr
		if idx := len(event.ClientAddr) - 1; idx >= 0 {
			for i := idx; i >= 0; i-- {
				if event.ClientAddr[i] == ':' {
					clientIP = event.ClientAddr[:i]
					break
				}
			}
		}
		if count := info.PerIPCount[clientIP]; count > 0 {
			info.PerIPCount[clientIP] = count - 1
			// Clean up zero counts
			if info.PerIPCount[clientIP] == 0 {
				delete(info.PerIPCount, clientIP)
			}
		}
	}

	info.LastUpdate = time.Now()

	logger.Debug("Gossip tracker: Cluster unregister", "name", ct.name, "user", event.Username, "instance", event.InstanceID, "cluster_total", info.TotalCount)

	// Clean up if no connections remain
	if info.TotalCount <= 0 {
		delete(ct.connections, event.AccountID)
	}
}

// handleKick processes a kick event from another node
func (ct *ConnectionTracker) handleKick(event ConnectionEvent) {
	logger.Debug("Gossip tracker: Received kick", "name", ct.name, "account_id", event.AccountID, "protocol", event.Protocol, "from_node", event.NodeID)

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

	logger.Debug("Gossip tracker: Notified sessions", "name", ct.name, "session_count", len(sessions), "account_id", event.AccountID)
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
				logger.Debug("Gossip tracker: Broadcasting queued events", "name", ct.name, "count", len(ct.broadcastQueue))
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
	cleanedInstances := 0
	cleanedIPs := 0
	staleThreshold := time.Now().Add(-10 * time.Minute)

	for accountID, info := range ct.connections {
		// Clean up zero-count entries in LocalInstances map
		for instanceID, count := range info.LocalInstances {
			if count <= 0 {
				delete(info.LocalInstances, instanceID)
				cleanedInstances++
			}
		}

		// Clean up zero-count entries in PerIPCount map
		for ip, count := range info.PerIPCount {
			if count <= 0 {
				delete(info.PerIPCount, ip)
				cleanedIPs++
			}
		}

		// Remove user entry if no connections and stale
		if info.TotalCount <= 0 && info.LastUpdate.Before(staleThreshold) {
			delete(ct.connections, accountID)
			cleaned++
		}
	}

	// Calculate total instance IDs and IPs across all users for memory reporting
	totalUsers := len(ct.connections)
	totalInstanceIDs := 0
	totalIPs := 0
	for _, info := range ct.connections {
		totalInstanceIDs += len(info.LocalInstances)
		totalIPs += len(info.PerIPCount)
	}

	if cleaned > 0 || cleanedInstances > 0 || cleanedIPs > 0 {
		logger.Debug("Gossip tracker: Cleaned up stale entries", "name", ct.name,
			"users", cleaned, "instance_ids", cleanedInstances, "ips", cleanedIPs)
	}

	// Update Prometheus metrics every cleanup cycle
	metrics.ConnectionTrackerUsers.WithLabelValues(ct.name).Set(float64(totalUsers))
	metrics.ConnectionTrackerInstanceIDs.WithLabelValues(ct.name).Set(float64(totalInstanceIDs))
	metrics.ConnectionTrackerIPs.WithLabelValues(ct.name).Set(float64(totalIPs))

	ct.queueMu.Lock()
	queueSize := len(ct.broadcastQueue)
	ct.queueMu.Unlock()
	metrics.ConnectionTrackerBroadcastQueue.WithLabelValues(ct.name).Set(float64(queueSize))

	// Log memory usage stats every 10 cleanup cycles (~50 minutes with 5min cleanup interval)
	// This helps monitor for memory leaks without flooding logs
	ct.cleanupCounter++
	if ct.cleanupCounter%10 == 0 {
		logger.Info("Connection tracker stats", "protocol", ct.name,
			"total_users", totalUsers,
			"total_instance_ids", totalInstanceIDs,
			"total_ips", totalIPs,
			"broadcast_queue", queueSize,
			"avg_instances_per_user", float64(totalInstanceIDs)/float64(max(totalUsers, 1)),
			"avg_ips_per_user", float64(totalIPs)/float64(max(totalUsers, 1)))
	}
}

// Helper function for division by zero protection
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// stateSnapshotRoutine periodically broadcasts full state for reconciliation
func (ct *ConnectionTracker) stateSnapshotRoutine() {
	ticker := time.NewTicker(stateSnapshotInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ct.broadcastStateSnapshot()

		case <-ct.stopStateSnapshot:
			return
		}
	}
}

// broadcastStateSnapshot creates and broadcasts a full state snapshot
func (ct *ConnectionTracker) broadcastStateSnapshot() {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	if len(ct.connections) == 0 {
		return // Nothing to broadcast
	}

	// Build snapshot of connections
	snapshot := &ConnectionStateSnapshot{
		InstanceID:  ct.instanceID,
		Timestamp:   time.Now(),
		Connections: make(map[int64]UserConnectionData, len(ct.connections)),
	}

	for accountID, info := range ct.connections {
		// Only include instances where we have actual connections
		localInstances := make(map[string]int)
		for instanceID, count := range info.LocalInstances {
			if count > 0 {
				localInstances[instanceID] = count
			}
		}

		if len(localInstances) == 0 {
			continue // Skip if no actual connections
		}

		// Copy PerIPCount for cluster-wide tracking
		perIPCount := make(map[string]int)
		for ip, count := range info.PerIPCount {
			if count > 0 {
				perIPCount[ip] = count
			}
		}

		snapshot.Connections[accountID] = UserConnectionData{
			AccountID:      accountID,
			Username:       info.Username,
			LocalInstances: localInstances,
			PerIPCount:     perIPCount,
			LastUpdate:     info.LastUpdate,
		}
	}

	if len(snapshot.Connections) == 0 {
		return // Nothing meaningful to broadcast
	}

	logger.Info("GossipTracker: Broadcasting state snapshot", "protocol", ct.name,
		"users", len(snapshot.Connections), "instance", ct.instanceID)

	// Queue the snapshot event
	ct.queueEvent(ConnectionEvent{
		Type:          ConnectionEventStateSnapshot,
		Protocol:      ct.name, // CRITICAL: Set protocol so receiving trackers can filter
		Timestamp:     snapshot.Timestamp,
		InstanceID:    ct.instanceID,
		StateSnapshot: snapshot,
	})
}

// reconcileState merges a remote state snapshot with local state
func (ct *ConnectionTracker) reconcileState(snapshot *ConnectionStateSnapshot) {
	if snapshot == nil {
		return
	}

	// Skip our own snapshots
	if snapshot.InstanceID == ct.instanceID {
		logger.Debug("Gossip tracker: Skipping own state snapshot", "name", ct.name)
		return
	}

	// Check if snapshot is too old (prevent stale reconciliation)
	age := time.Since(snapshot.Timestamp)
	if age > 5*time.Minute {
		logger.Debug("Gossip tracker: Ignoring stale state snapshot", "name", ct.name, "instance", snapshot.InstanceID, "age", age)
		return
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()

	reconciledCount := 0
	addedCount := 0

	for accountID, remoteData := range snapshot.Connections {
		info, exists := ct.connections[accountID]
		if !exists {
			// New user we didn't know about
			info = &UserConnectionInfo{
				AccountID:      accountID,
				Username:       remoteData.Username,
				TotalCount:     0,
				LocalCount:     0,
				LastUpdate:     time.Now(),
				LocalInstances: make(map[string]int),
				PerIPCount:     make(map[string]int),
			}
			ct.connections[accountID] = info
			addedCount++
		}

		// Merge remote instance counts
		for instanceID, count := range remoteData.LocalInstances {
			if instanceID == ct.instanceID {
				// Don't override our own local count
				continue
			}

			oldCount := info.LocalInstances[instanceID]
			if oldCount != count {
				info.LocalInstances[instanceID] = count
				reconciledCount++
			}
		}

		// Merge per-IP counts from remote snapshot (cluster-wide tracking)
		// We merge all IPs, not just from other instances, because per-IP is cluster-wide
		for ip, count := range remoteData.PerIPCount {
			oldCount := info.PerIPCount[ip]
			if oldCount != count {
				info.PerIPCount[ip] = count
				reconciledCount++
			}
		}

		// Recalculate total count
		info.TotalCount = info.LocalCount // Start with local
		for instanceID, count := range info.LocalInstances {
			if instanceID != ct.instanceID {
				info.TotalCount += count
			}
		}

		info.LastUpdate = time.Now()
	}

	logger.Info("GossipTracker: Reconciled state", "protocol", ct.name,
		"from_node", snapshot.InstanceID, "updated", reconciledCount, "added", addedCount)
}

// Stop stops the gossip tracker (idempotent)
func (ct *ConnectionTracker) Stop() {
	if ct == nil {
		return
	}

	ct.stopOnce.Do(func() {
		close(ct.stopBroadcast)
		close(ct.stopCleanup)
		if ct.clusterManager != nil {
			close(ct.stopStateSnapshot)
		}
	})
}

// GetStats returns connection tracker statistics
func (ct *ConnectionTracker) GetStats(ctx context.Context) map[string]any {
	if ct == nil {
		return nil
	}

	ct.mu.RLock()
	totalUsers := len(ct.connections)
	totalInstanceIDs := 0
	totalIPs := 0
	totalConnections := 0

	for _, info := range ct.connections {
		totalInstanceIDs += len(info.LocalInstances)
		totalIPs += len(info.PerIPCount)
		totalConnections += info.TotalCount
	}
	ct.mu.RUnlock()

	// Get broadcast queue size
	ct.queueMu.Lock()
	queueSize := len(ct.broadcastQueue)
	ct.queueMu.Unlock()

	stats := map[string]any{
		"protocol":          ct.name,
		"total_users":       totalUsers,
		"total_connections": totalConnections,
		"cluster_enabled":   ct.clusterManager != nil,
		"memory_usage": map[string]any{
			"tracked_users":       totalUsers,
			"instance_ids":        totalInstanceIDs,
			"tracked_ips":         totalIPs,
			"broadcast_queue":     queueSize,
			"broadcast_queue_max": 10000,
			"queue_utilization":   float64(queueSize) / 10000.0 * 100,
			"avg_instances_per_user": func() float64 {
				if totalUsers > 0 {
					return float64(totalInstanceIDs) / float64(totalUsers)
				}
				return 0
			}(),
			"avg_ips_per_user": func() float64 {
				if totalUsers > 0 {
					return float64(totalIPs) / float64(totalUsers)
				}
				return 0
			}(),
		},
	}

	return stats
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
