package server

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server/idgen"
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
)

// ConnectionEvent represents a cluster-wide connection event
type ConnectionEvent struct {
	Type       ConnectionEventType `json:"type"`
	EventID    string              `json:"event_id"` // Unique per event, for duplicate suppression
	AccountID  int64               `json:"account_id"`
	Username   string              `json:"username"`    // For debugging/logging
	Protocol   string              `json:"protocol"`    // "IMAP", "POP3", "ManageSieve"
	ClientAddr string              `json:"client_addr"` // For logging
	Timestamp  time.Time           `json:"timestamp"`
	NodeID     string              `json:"node_id"`
	InstanceID string              `json:"instance_id"` // Unique instance identifier

	// For state snapshots. A snapshot event without a payload is a liveness
	// heartbeat: full state travels over push/pull, and older builds decode the
	// empty payload as "nothing to reconcile".
	StateSnapshot *ConnectionStateSnapshot `json:"state_snapshot,omitempty"`
}

// ConnectionStateSnapshot represents a full connection state for reconciliation
type ConnectionStateSnapshot struct {
	InstanceID string    `json:"instance_id"`
	Protocol   string    `json:"protocol"` // Which tracker the state belongs to
	Timestamp  time.Time `json:"timestamp"`

	Connections map[int64]UserConnectionData `json:"connections"` // accountID -> connection data
}

// UserConnectionData is the serializable version of UserConnectionInfo for gossip
type UserConnectionData struct {
	AccountID  int64          `json:"account_id"`
	Username   string         `json:"username"`
	PerIPCount map[string]int `json:"per_ip_count"` // clientIP -> count (for THIS instance only)
	LastUpdate time.Time      `json:"last_update"`
}

// UserConnectionInfo tracks connection information for a specific user
type UserConnectionInfo struct {
	AccountID  int64
	Username   string
	LastUpdate time.Time
	FirstSeen  time.Time // When we first saw this connection (for cleanup, not updated by gossip)

	// PerIPCountByInstance tracks per-IP connection counts per instance (including local).
	// Structure: PerIPCountByInstance[instanceID][clientIP] = count
	//
	// - Local instance uses ct.instanceID as key
	// - Remote instances use their instanceID from gossip
	// - State snapshots replace entire map for the sending instance (authoritative)
	// - To get cluster-wide count for an IP: sum across all instances
	// - To get total connections: sum all counts across all instances and IPs
	PerIPCountByInstance map[string]map[string]int // instanceID -> (clientIP -> count)
}

// ConnectionTracker manages connection tracking using gossip protocol
type ConnectionTracker struct {
	name           string
	serverName     string
	hostname       string
	instanceID     string
	clusterManager *cluster.Manager

	// Connection tracking
	connections map[int64]*UserConnectionInfo // accountID -> info
	mu          sync.RWMutex

	// Kick notifications
	kickSessions   map[int64][]chan struct{} // accountID -> channels to notify
	kickSessionsMu sync.RWMutex

	// Cache invalidation (optional, for proxies)
	lookupCache LookupCacheInvalidator // Interface for invalidating auth/routing cache on kick

	// Configuration
	maxConnectionsPerUser      int  // Cluster-wide limit per user (0 = unlimited)
	maxConnectionsPerUserPerIP int  // Local limit per user per IP (0 = unlimited)
	maxEventQueueSize          int  // Maximum events in broadcast queue
	snapshotOnly               bool // If true, only broadcast state snapshots (no individual register/unregister)

	// Outgoing gossip, in three tiers drained in this order: the liveness
	// heartbeat, which peers purge this instance's counts without; kicks, which
	// nothing repairs once dropped; and ordinary register/unregister traffic,
	// which the next push/pull repairs.
	queue          *gossipQueue
	criticalQueue  *gossipQueue
	heartbeatQueue *gossipQueue

	// Instance tracking for stall detection
	instanceLastSeen map[string]time.Time

	// Duplicate suppression for received events
	dedup gossipDedup

	// Decrements delivered ahead of the increment they cancel (guarded by mu)
	deferred deferredDecrements

	// Cleanup counter for periodic memory reporting
	cleanupCounter uint64

	// Shutdown
	stopBroadcast chan struct{}
	stopCleanup   chan struct{}
	stopOnce      sync.Once
}

// LookupCacheInvalidator drops a proxy's cached auth and routing entry for one
// user. Entries are keyed by the name of the server the session is on, which
// the cache derives itself: a tracker that built the key would have to
// reproduce a format it does not own, and a key that does not match exactly
// invalidates nothing.
type LookupCacheInvalidator interface {
	InvalidateUser(serverName, username string)
}

// NewConnectionTracker creates a new connection tracker.
// If clusterMgr is provided, uses gossip protocol for cluster-wide tracking (for proxies).
// If clusterMgr is nil, operates in local-only mode (for backend servers).
// If snapshotOnly is true, only broadcasts periodic state snapshots (no individual register/unregister events).
func NewConnectionTracker(name, serverName, hostname string, instanceID string, clusterMgr *cluster.Manager, maxConnectionsPerUser int, maxConnectionsPerUserPerIP int, maxEventQueueSize int, snapshotOnly bool) *ConnectionTracker {
	// Use default if not specified
	if maxEventQueueSize <= 0 {
		maxEventQueueSize = defaultMaxEventQueueSize
	}

	ct := &ConnectionTracker{
		name:                       name,
		serverName:                 serverName,
		hostname:                   hostname,
		instanceID:                 instanceID,
		clusterManager:             clusterMgr,
		connections:                make(map[int64]*UserConnectionInfo),
		maxConnectionsPerUser:      maxConnectionsPerUser,
		maxConnectionsPerUserPerIP: maxConnectionsPerUserPerIP,
		maxEventQueueSize:          maxEventQueueSize,
		snapshotOnly:               snapshotOnly,
		kickSessions:               make(map[int64][]chan struct{}),
		queue:                      newGossipQueue("connection:"+name, clusterMgr, maxEventQueueSize),
		criticalQueue:              newCriticalGossipQueue("connection-kick:"+name, clusterMgr, maxCriticalQueued),
		heartbeatQueue:             newGossipQueue("connection-heartbeat:"+name, clusterMgr, maxHeartbeatQueued),
		deferred:                   deferredDecrements{kind: "connection:" + name},
		instanceLastSeen:           make(map[string]time.Time),
		stopBroadcast:              make(chan struct{}),
		stopCleanup:                make(chan struct{}),
	}

	if clusterMgr != nil {
		// Cluster mode: register with cluster manager for gossip
		logger.Debug("Gossip tracker: Registering handlers with cluster manager", "name", name)
		clusterMgr.RegisterConnectionHandler(ct.HandleClusterEvent)
		clusterMgr.RegisterConnectionBroadcaster(ct.GetBroadcasts)
		// The registration name only has to be unique on this node: push/pull
		// state is dispatched by kind and each tracker decides from the
		// protocol inside the payload whether the state is its own.
		clusterMgr.RegisterStateProvider(cluster.StateKindConnection, instanceID, ct.localState, ct.mergeRemoteState)
		logger.Debug("Gossip tracker: Handlers registered successfully", "name", name)

		// Start background routines
		go ct.heartbeatRoutine()
		go ct.cleanupRoutine()

		mode := "full"
		if snapshotOnly {
			mode = "snapshot-only"
		}
		logger.Info("GossipTracker: Initialized (cluster mode)", "protocol", name,
			"instance", instanceID, "max_per_user", maxConnectionsPerUser, "queue_size", maxEventQueueSize, "mode", mode)
	} else {
		// Local mode: no gossip, just track connections locally
		go ct.cleanupRoutine()

		logger.Info("LocalTracker: Initialized (local mode)", "protocol", name,
			"instance", instanceID, "max_per_user", maxConnectionsPerUser)
	}

	return ct
}

// SetLookupCache sets the lookup cache for cache invalidation on kick events.
// This should be called after creating the tracker to enable cache invalidation.
func (ct *ConnectionTracker) SetLookupCache(cache LookupCacheInvalidator) {
	ct.lookupCache = cache
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

	event, err := ct.registerLocked(accountID, username, protocol, clientAddr)
	if err != nil {
		return err
	}

	// Encoding happens outside the tracker lock: every accept on this listener
	// serialises on it, and gob encoding an event is orders of magnitude more
	// work than the bookkeeping it protects.
	if event != nil {
		ct.queueEvent(*event)
	}

	return nil
}

// registerLocked does the tracker's own bookkeeping for a new connection and
// returns the event to gossip, if any.
func (ct *ConnectionTracker) registerLocked(accountID int64, username, protocol, clientAddr string) (*ConnectionEvent, error) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	// Get or create user info
	info, exists := ct.connections[accountID]
	if !exists {
		now := time.Now()
		info = &UserConnectionInfo{
			AccountID:            accountID,
			Username:             username,
			LastUpdate:           now,
			FirstSeen:            now,
			PerIPCountByInstance: make(map[string]map[string]int),
		}
		ct.connections[accountID] = info
	}

	// Check limit (if configured)
	// In cluster mode, check cluster-wide count. In local mode, check local count.
	var checkCount int
	var scope string
	if ct.clusterManager == nil {
		// Local mode: check only this instance
		checkCount = info.GetLocalCount(ct.instanceID)
		scope = "on this server"
	} else {
		// Cluster mode: check cluster-wide
		checkCount = info.GetTotalCount()
		scope = "across cluster"
	}

	if ct.maxConnectionsPerUser > 0 && checkCount >= ct.maxConnectionsPerUser {
		logger.Info("Connection tracker: Maximum connections per user reached", "tracker", ct.trackerType(), "protocol", protocol, "username", username, "account_id", accountID, "current", checkCount, "max", ct.maxConnectionsPerUser, "scope", scope, "client_addr", clientAddr)
		return nil, fmt.Errorf("user %s has reached maximum connections (%d/%d %s)",
			username, checkCount, ct.maxConnectionsPerUser, scope)
	}

	// Check per-user-per-IP limit (cluster-wide via gossip)
	if ct.maxConnectionsPerUserPerIP > 0 && clientAddr != "" {
		clientIP := clientIPOf(clientAddr)

		// Get cluster-wide count for this IP by summing across all instances
		ipCount := info.GetClusterWideIPCount(clientIP)
		if ipCount >= ct.maxConnectionsPerUserPerIP {
			logger.Info("Connection tracker: Maximum connections per user per IP reached", "tracker", ct.trackerType(), "protocol", protocol, "username", username, "account_id", accountID, "ip", clientIP, "current", ipCount, "max", ct.maxConnectionsPerUserPerIP, "client_addr", clientAddr)
			return nil, fmt.Errorf("user %s has reached maximum connections from IP %s (%d/%d)",
				username, clientIP, ipCount, ct.maxConnectionsPerUserPerIP)
		}
	}

	// Increment connection count for this instance
	info.LastUpdate = time.Now()

	// We always track per-IP, even if limiting is disabled.
	clientIP := clientIPOf(clientAddr)

	// Initialize nested map if needed
	if info.PerIPCountByInstance[ct.instanceID] == nil {
		info.PerIPCountByInstance[ct.instanceID] = make(map[string]int)
	}
	info.PerIPCountByInstance[ct.instanceID][clientIP]++

	logger.Debug("Connection tracker: Registered", "name", ct.name, "type", ct.trackerType(), "user", username, "local", info.GetLocalCount(ct.instanceID), "total", info.GetTotalCount())

	// Broadcast to cluster (only in cluster mode and if not snapshot-only mode)
	if ct.clusterManager == nil || ct.snapshotOnly {
		return nil, nil
	}

	return &ConnectionEvent{
		Type:       ConnectionEventRegister,
		AccountID:  accountID,
		Username:   username,
		Protocol:   protocol,
		ClientAddr: clientAddr,
		Timestamp:  time.Now(),
		NodeID:     ct.clusterManager.GetNodeID(),
		InstanceID: ct.instanceID,
	}, nil
}

// UnregisterConnection unregisters a connection and broadcasts to cluster
func (ct *ConnectionTracker) UnregisterConnection(ctx context.Context, accountID int64, protocol, clientAddr string) error {
	if ct == nil {
		return nil // Disabled
	}

	// Encoding happens outside the tracker lock, as in RegisterConnection.
	if event := ct.unregisterLocked(accountID, protocol, clientAddr); event != nil {
		ct.queueEvent(*event)
	}

	return nil
}

// unregisterLocked does the tracker's own bookkeeping for a closed connection
// and returns the event to gossip, if any.
func (ct *ConnectionTracker) unregisterLocked(accountID int64, protocol, clientAddr string) *ConnectionEvent {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	info, exists := ct.connections[accountID]
	if !exists {
		logger.Debug("Connection tracker: Unregister called for unknown account", "name", ct.name, "type", ct.trackerType(), "account_id", accountID)
		return nil
	}

	// Decrement connection count for this instance
	clientIP := clientIPOf(clientAddr)

	if perIPMap := info.PerIPCountByInstance[ct.instanceID]; perIPMap != nil {
		if count := perIPMap[clientIP]; count > 0 {
			perIPMap[clientIP] = count - 1
			// Clean up zero counts
			if perIPMap[clientIP] == 0 {
				delete(perIPMap, clientIP)
			}
			// Clean up empty instance map
			if len(perIPMap) == 0 {
				delete(info.PerIPCountByInstance, ct.instanceID)
			}
		}
	}

	info.LastUpdate = time.Now()

	logger.Debug("Connection tracker: Unregistered", "name", ct.name, "type", ct.trackerType(), "user", info.Username, "local", info.GetLocalCount(ct.instanceID), "total", info.GetTotalCount())

	// Clean up if no connections remain
	var cleanupThreshold int
	if ct.clusterManager == nil || ct.snapshotOnly {
		// In local mode OR snapshot-only mode (backend servers), clean up when no local connections
		// Backend servers only track their own connections authoritatively, so should clean up
		// when local count hits 0, even if they've received gossip about other instances
		cleanupThreshold = info.GetLocalCount(ct.instanceID)
	} else {
		// In cluster proxy mode, clean up when no connections across cluster
		cleanupThreshold = info.GetTotalCount()
	}

	if cleanupThreshold <= 0 {
		delete(ct.connections, accountID)
	}

	// Broadcast to cluster (only in cluster mode and if not snapshot-only mode)
	if ct.clusterManager == nil || ct.snapshotOnly {
		return nil
	}

	return &ConnectionEvent{
		Type:       ConnectionEventUnregister,
		AccountID:  accountID,
		Username:   info.Username,
		Protocol:   protocol,
		ClientAddr: clientAddr,
		Timestamp:  time.Now(),
		NodeID:     ct.clusterManager.GetNodeID(),
		InstanceID: ct.instanceID,
	}
}

// clientIPOf strips the port from a "host:port" client address. An address
// without a port is already an IP.
func clientIPOf(clientAddr string) string {
	if idx := strings.LastIndexByte(clientAddr, ':'); idx >= 0 {
		return clientAddr[:idx]
	}
	return clientAddr
}

// getClusterWideIPCount calculates the cluster-wide connection count for a specific IP
// by summing counts across all instances in PerIPCountByInstance
func (info *UserConnectionInfo) GetClusterWideIPCount(clientIP string) int {
	total := 0
	for _, perIPMap := range info.PerIPCountByInstance {
		total += perIPMap[clientIP]
	}
	return total
}

// getTotalCount calculates the total cluster-wide connection count
// by summing all counts across all instances and IPs
func (info *UserConnectionInfo) GetTotalCount() int {
	total := 0
	for _, perIPMap := range info.PerIPCountByInstance {
		for _, count := range perIPMap {
			total += count
		}
	}
	return total
}

// getLocalCount returns the connection count for a specific instance
func (info *UserConnectionInfo) GetLocalCount(instanceID string) int {
	total := 0
	if perIPMap := info.PerIPCountByInstance[instanceID]; perIPMap != nil {
		for _, count := range perIPMap {
			total += count
		}
	}
	return total
}

// GetInstanceID returns the instance ID of this tracker
func (ct *ConnectionTracker) GetInstanceID() string {
	if ct == nil {
		return ""
	}
	return ct.instanceID
}

// GetConnectionCount returns the cluster-wide connection count for a user
func (ct *ConnectionTracker) GetConnectionCount(accountID int64) int {
	if ct == nil {
		return 0
	}

	ct.mu.RLock()
	defer ct.mu.RUnlock()

	if info, exists := ct.connections[accountID]; exists {
		return info.GetTotalCount()
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
		return info.GetLocalCount(ct.instanceID)
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
		// Deep copy PerIPCountByInstance
		perIPCopy := make(map[string]map[string]int, len(info.PerIPCountByInstance))
		for instanceID, perIPMap := range info.PerIPCountByInstance {
			perIPCopy[instanceID] = make(map[string]int, len(perIPMap))
			for ip, count := range perIPMap {
				perIPCopy[instanceID][ip] = count
			}
		}

		result = append(result, UserConnectionInfo{
			AccountID:            info.AccountID,
			Username:             info.Username,
			LastUpdate:           info.LastUpdate,
			FirstSeen:            info.FirstSeen,
			PerIPCountByInstance: perIPCopy,
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
		if info.GetTotalCount() > 0 {
			count++
		}
	}
	return count
}

// KickUser kicks a user's connections: the ones this node holds directly, and
// in cluster mode the ones its peers hold by broadcasting a kick event.
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
		logger.Info("Gossip tracker: Broadcasting kick", "name", ct.name, "account_id", accountID, "protocol", protocol)

		// The event is tagged with this tracker's own protocol, which is what
		// receivers filter on. Callers name the tracker however they index it -
		// the admin API passes "IMAP-host-listener" - and a name that is not
		// exactly ct.name would be discarded by every peer.
		encoded := ct.queueEvent(ConnectionEvent{
			Type:       ConnectionEventKick,
			AccountID:  accountID,
			Username:   username,
			Protocol:   ct.name,
			Timestamp:  time.Now(),
			NodeID:     ct.clusterManager.GetNodeID(),
			InstanceID: ct.instanceID,
		})

		// Gossip retires a broadcast after a bounded number of transmissions
		// with no acknowledgement, so a given peer can miss it. A kick is an
		// operator-rate event, so it is also sent to every current member over
		// TCP; the gossip copy remains as the backstop for peers that were
		// unreachable or that join while the send is in flight.
		if encoded != nil {
			go func() {
				delivered, failed := ct.clusterManager.SendConnectionEventReliable(encoded)
				logger.Info("Gossip tracker: Kick delivered to members", "name", ct.name,
					"account_id", accountID, "delivered", delivered, "failed", failed)
			}()
		}
	}

	// The kick is applied here whatever the mode. No path back into the cluster
	// reaches this node: the reliable fan-out skips self, gossip does not loop a
	// broadcast back, and HandleClusterEvent discards events from this instance -
	// so without this the node the operator issued the kick from is the one node
	// that never kicks.
	if kicked := ct.applyKick(accountID, username); kicked > 0 {
		logger.Info("Connection tracker: Kicked local sessions", "tracker", ct.trackerType(), "protocol", ct.name,
			"count", kicked, "account_id", accountID, "target_protocol", protocol)
	} else {
		logger.Debug("Connection tracker: No local sessions to kick", "tracker", ct.trackerType(), "name", ct.name, "account_id", accountID)
	}

	return nil
}

// applyKick closes every session this node holds for an account and drops the
// cached routing and auth entry held for the address the connection was
// registered under, so that a reconnect is looked up afresh. It reports how
// many sessions there were. Both steps are idempotent - a channel that is
// already closed is left alone - so a node may reach this both from the kick it
// issued and from a peer's copy of the same event.
func (ct *ConnectionTracker) applyKick(accountID int64, username string) int {
	if ct.lookupCache != nil && username != "" {
		ct.lookupCache.InvalidateUser(ct.serverName, username)
		logger.Debug("Connection tracker: Invalidated cache on kick", "name", ct.name, "server", ct.serverName, "user", username, "account_id", accountID)
	}

	ct.kickSessionsMu.Lock()
	defer ct.kickSessionsMu.Unlock()

	sessions := ct.kickSessions[accountID]
	for _, ch := range sessions {
		select {
		case <-ch:
			// Already closed
		default:
			close(ch)
		}
	}
	delete(ct.kickSessions, accountID)

	return len(sessions)
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

// queueEvent encodes an event, hands it to the tier it belongs to and returns
// the encoded message. Ordinary events can be resent or repaired by the next
// push/pull; a lost kick cannot; and a heartbeat is worth nothing if a backlog
// of either can keep it off the wire - it exists to keep peers from purging
// this instance precisely while that backlog is deep.
func (ct *ConnectionTracker) queueEvent(event ConnectionEvent) []byte {
	if event.EventID == "" {
		event.EventID = idgen.New()
	}

	encoded, err := encodeConnectionEvent(event)
	if err != nil {
		logger.Warn("Gossip tracker: Failed to encode event", "name", ct.name, "type", event.Type, "error", err)
		return nil
	}

	switch {
	case isHeartbeat(event):
		ct.heartbeatQueue.enqueue(encoded)
	case event.Type == ConnectionEventKick:
		ct.criticalQueue.enqueue(encoded)
	default:
		ct.queue.enqueue(encoded)
	}

	return encoded
}

// isHeartbeat reports whether an event is a bare liveness assertion rather than
// a snapshot carrying state.
func isHeartbeat(event ConnectionEvent) bool {
	return event.Type == ConnectionEventStateSnapshot && event.StateSnapshot == nil
}

// GetBroadcasts returns events to broadcast (called by cluster manager).
// memberlist calls this once per gossip target, so an event stays queued until
// it has been transmitted often enough to have reached the cluster.
func (ct *ConnectionTracker) GetBroadcasts(overhead, limit int) [][]byte {
	return drainTiers(ct.heartbeatQueue, ct.criticalQueue, ct.queue, overhead, limit)
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

	// CRITICAL: Filter events by protocol to prevent cross-protocol contamination
	// All connection trackers receive all gossip events, but each should only process its own protocol
	// Without this check, IMAP events get counted in LMTP tracker, causing massive ghost connection leaks
	if event.Protocol != "" && event.Protocol != ct.name {
		logger.Debug("Gossip tracker: Ignoring event for different protocol", "tracker_protocol", ct.name, "event_protocol", event.Protocol, "event_type", event.Type)
		return
	}

	// Update last seen time for this instance
	ct.mu.Lock()
	if ct.instanceLastSeen == nil {
		ct.instanceLastSeen = make(map[string]time.Time)
	}
	ct.instanceLastSeen[event.InstanceID] = time.Now()
	ct.mu.Unlock()

	// Check if event is too old (prevent replays after network partition)
	age := time.Since(event.Timestamp)
	if age > staleEventThreshold {
		logger.Debug("Gossip tracker: Ignoring stale event", "name", ct.name, "node_id", event.NodeID, "age", age)
		return
	}

	// Gossip delivery is at-least-once: register and unregister move a counter,
	// so a retransmitted copy must not be applied twice.
	if ct.dedup.seenBefore(event.EventID) {
		logger.Debug("Gossip tracker: Ignoring duplicate event", "name", ct.name, "type", event.Type, "event_id", event.EventID)
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
		// A payload-less snapshot is a heartbeat; recording the instance as
		// seen above is all it is for. Snapshots with a payload come from a
		// node that still gossips full state instead of using push/pull.
		if event.StateSnapshot != nil {
			ct.reconcileState(event.StateSnapshot)
		}
	default:
		logger.Warn("Gossip tracker: Unknown event type", "name", ct.name, "type", event.Type)
	}
}

// connectionCounterKey identifies the counter a register/unregister pair moves.
// Both events of a pair come from the same instance, so timestamps taken from
// this key's clock are comparable.
func connectionCounterKey(instanceID string, accountID int64, clientIP string) string {
	return fmt.Sprintf("%s|%d|%s", instanceID, accountID, clientIP)
}

// handleRegister processes a register event from another node
func (ct *ConnectionTracker) handleRegister(event ConnectionEvent) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	// An unregister for this connection may have been delivered first; the two
	// then cancel and neither is applied.
	if event.ClientAddr != "" {
		key := connectionCounterKey(event.InstanceID, event.AccountID, clientIPOf(event.ClientAddr))
		if ct.deferred.consume(key, event.Timestamp) {
			logger.Debug("Gossip tracker: Register cancelled by an earlier-delivered unregister",
				"name", ct.name, "user", event.Username, "instance", event.InstanceID)
			return
		}
	}

	info, exists := ct.connections[event.AccountID]
	if !exists {
		now := time.Now()
		info = &UserConnectionInfo{
			AccountID:            event.AccountID,
			Username:             event.Username,
			LastUpdate:           now,
			FirstSeen:            now,
			PerIPCountByInstance: make(map[string]map[string]int),
		}
		ct.connections[event.AccountID] = info
	}

	info.LastUpdate = time.Now()

	// Increment per-IP count for the remote instance (cluster-wide tracking via gossip)
	if event.ClientAddr != "" {
		clientIP := clientIPOf(event.ClientAddr)

		// Initialize nested map if needed
		if info.PerIPCountByInstance[event.InstanceID] == nil {
			info.PerIPCountByInstance[event.InstanceID] = make(map[string]int)
		}
		info.PerIPCountByInstance[event.InstanceID][clientIP]++
	}

	logger.Debug("Gossip tracker: Cluster register", "name", ct.name, "user", event.Username, "instance", event.InstanceID, "cluster_total", info.GetTotalCount())
}

// handleUnregister processes an unregister event from another node
func (ct *ConnectionTracker) handleUnregister(event ConnectionEvent) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	clientIP := clientIPOf(event.ClientAddr)
	info, exists := ct.connections[event.AccountID]

	// Nothing to subtract from: either the account is unknown here or this
	// instance holds no count for the IP. The register may simply be delivered
	// later, so the decrement is held until it shows up rather than dropped.
	if event.ClientAddr != "" && (!exists || info.PerIPCountByInstance[event.InstanceID][clientIP] <= 0) {
		ct.deferred.hold(connectionCounterKey(event.InstanceID, event.AccountID, clientIP), event.Timestamp)
		return
	}
	if !exists {
		return // Unknown user and no IP to attribute, ignore
	}

	// Decrement per-IP count for the remote instance (cluster-wide tracking via gossip)
	if event.ClientAddr != "" {
		perIPMap := info.PerIPCountByInstance[event.InstanceID]
		perIPMap[clientIP]--
		// Clean up zero counts
		if perIPMap[clientIP] == 0 {
			delete(perIPMap, clientIP)
		}
		// Clean up empty instance map
		if len(perIPMap) == 0 {
			delete(info.PerIPCountByInstance, event.InstanceID)
		}
	}

	info.LastUpdate = time.Now()

	logger.Debug("Gossip tracker: Cluster unregister", "name", ct.name, "user", event.Username, "instance", event.InstanceID, "cluster_total", info.GetTotalCount())

	// Clean up if no connections remain
	if info.GetTotalCount() <= 0 {
		delete(ct.connections, event.AccountID)
	}
}

// handleKick processes a kick event from another node
func (ct *ConnectionTracker) handleKick(event ConnectionEvent) {
	logger.Info("Gossip tracker: Received kick", "name", ct.name, "account_id", event.AccountID, "protocol", event.Protocol, "from_node", event.NodeID)

	kicked := ct.applyKick(event.AccountID, event.Username)

	logger.Info("Gossip tracker: Notified sessions", "name", ct.name, "session_count", kicked, "account_id", event.AccountID)
}

// heartbeatRoutine re-asserts that this instance is alive. Peers retire the
// counts of an instance they stop hearing from (see cleanup), and an instance
// holding only idle sessions produces no other gossip: push/pull would refresh
// it eventually, but it pairs with one random peer per round, so in a cluster
// of a dozen nodes a given peer is not reached reliably within the threshold.
func (ct *ConnectionTracker) heartbeatRoutine() {
	ticker := time.NewTicker(gossipHeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ct.queueHeartbeat()

		case <-ct.stopBroadcast:
			return
		}
	}
}

// queueHeartbeat gossips proof that this instance is alive. It is a state
// snapshot event with no state: the counts themselves travel over push/pull,
// and a build that predates that still decodes this as "nothing to reconcile".
func (ct *ConnectionTracker) queueHeartbeat() {
	ct.queueEvent(ConnectionEvent{
		Type:       ConnectionEventStateSnapshot,
		Protocol:   ct.name,
		Timestamp:  time.Now(),
		NodeID:     ct.clusterManager.GetNodeID(),
		InstanceID: ct.instanceID,
	})
}

// cleanupRoutine periodically cleans up stale connection entries
func (ct *ConnectionTracker) cleanupRoutine() {
	// Run cleanup every 1 minute to ensure timely cleanup of stale entries
	// (stale threshold is 3 minutes, so this ensures entries are cleaned within 4 minutes worst-case)
	ticker := time.NewTicker(1 * time.Minute)
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

// cleanup prunes invalid/expired bookkeeping data.
//
// Design goals:
//   - Never delete active local connections.
//   - In cluster mode, remote state is pruned based on *instance liveness*, not per-user age.
//     If an instance is still gossiping (instanceLastSeen is fresh), its state is authoritative.
//   - User entries are removed only when their total count reaches 0 after pruning.
func (ct *ConnectionTracker) cleanup() {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	cleanedUsers := 0
	cleanedInstances := 0
	cleanedIPs := 0

	now := time.Now()

	// 1) Purge instance maps for instances that appear offline/partitioned.
	//    This is the only place where we remove non-local connection counts.
	for instanceID, lastSeen := range ct.instanceLastSeen {
		if now.Sub(lastSeen) <= staleInstanceThreshold {
			continue
		}

		logger.Info("Gossip tracker: Purging stale instance data", "name", ct.name, "instance", instanceID, "age", now.Sub(lastSeen))
		for _, info := range ct.connections {
			if info.PerIPCountByInstance == nil {
				continue
			}
			if _, ok := info.PerIPCountByInstance[instanceID]; ok {
				delete(info.PerIPCountByInstance, instanceID)
				cleanedInstances++
			}
		}
		delete(ct.instanceLastSeen, instanceID)
	}

	// 2) Forget decrements whose register never arrived.
	ct.deferred.prune(gossipDedupWindow)

	// 3) Remove invalid counts and empty maps.
	for accountID, info := range ct.connections {
		if info.PerIPCountByInstance != nil {
			for instanceID, perIPMap := range info.PerIPCountByInstance {
				for ip, count := range perIPMap {
					if count <= 0 {
						delete(perIPMap, ip)
						cleanedIPs++
					}
				}
				if len(perIPMap) == 0 {
					delete(info.PerIPCountByInstance, instanceID)
					cleanedInstances++
				}
			}
		}

		// 4) Remove user entries if no counts remain.
		if info.GetTotalCount() <= 0 {
			delete(ct.connections, accountID)
			cleanedUsers++
		}
	}

	// 5) Metrics.
	totalUsers := len(ct.connections)
	totalInstanceIDs := 0
	totalIPs := 0
	for _, info := range ct.connections {
		totalInstanceIDs += len(info.PerIPCountByInstance)
		for _, perIPMap := range info.PerIPCountByInstance {
			totalIPs += len(perIPMap)
		}
	}

	if cleanedUsers > 0 || cleanedInstances > 0 || cleanedIPs > 0 {
		logger.Debug("Gossip tracker: Cleaned up stale entries", "name", ct.name,
			"users", cleanedUsers, "instance_ids", cleanedInstances, "ips", cleanedIPs)
	}

	metrics.ConnectionTrackerUsers.WithLabelValues(ct.name, ct.serverName, ct.hostname).Set(float64(totalUsers))
	metrics.ConnectionTrackerInstanceIDs.WithLabelValues(ct.name, ct.serverName, ct.hostname).Set(float64(totalInstanceIDs))
	metrics.ConnectionTrackerIPs.WithLabelValues(ct.name, ct.serverName, ct.hostname).Set(float64(totalIPs))

	queueSize := ct.queue.numQueued() + ct.criticalQueue.numQueued() + ct.heartbeatQueue.numQueued()
	metrics.ConnectionTrackerBroadcastQueue.WithLabelValues(ct.name, ct.serverName, ct.hostname).Set(float64(queueSize))

	// Log memory usage stats every 10 cleanup cycles (~10 minutes with 1m cleanup interval)
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

// stateSnapshot builds this instance's authoritative connection state.
// Only this instance's per-IP counts are included: every other instance is
// authoritative for its own.
func (ct *ConnectionTracker) stateSnapshot() *ConnectionStateSnapshot {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	// Build snapshot of connections
	snapshot := &ConnectionStateSnapshot{
		InstanceID:  ct.instanceID,
		Protocol:    ct.name,
		Timestamp:   time.Now(),
		Connections: make(map[int64]UserConnectionData, len(ct.connections)),
	}

	for accountID, info := range ct.connections {
		// Copy PerIPCount for THIS INSTANCE ONLY (authoritative for this instance)
		perIPCount := make(map[string]int)
		if perIPMap := info.PerIPCountByInstance[ct.instanceID]; perIPMap != nil {
			for ip, count := range perIPMap {
				if count > 0 {
					perIPCount[ip] = count
				}
			}
		}

		// Skip if no local connections
		if len(perIPCount) == 0 {
			continue
		}

		snapshot.Connections[accountID] = UserConnectionData{
			AccountID:  accountID,
			Username:   info.Username,
			PerIPCount: perIPCount, // Only this instance's per-IP counts
			LastUpdate: info.LastUpdate,
		}
	}

	return snapshot
}

// localState encodes this instance's connection state for a memberlist
// push/pull exchange. Full state is exchanged over push/pull rather than
// gossip because it outgrows the gossip datagram budget at a few dozen
// connections, while push/pull runs over TCP. An empty snapshot is still sent:
// it tells peers to retire the connections this instance no longer holds.
func (ct *ConnectionTracker) localState() []byte {
	snapshot := ct.stateSnapshot()

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(snapshot); err != nil {
		logger.Warn("Gossip tracker: Failed to encode state snapshot", "name", ct.name, "error", err)
		return nil
	}

	logger.Debug("GossipTracker: Sending state snapshot", "protocol", ct.name,
		"users", len(snapshot.Connections), "instance", ct.instanceID, "bytes", buf.Len())
	return buf.Bytes()
}

// mergeRemoteState applies a peer's connection state received over push/pull
func (ct *ConnectionTracker) mergeRemoteState(data []byte) {
	var snapshot ConnectionStateSnapshot
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&snapshot); err != nil {
		logger.Warn("Gossip tracker: Failed to decode remote state", "name", ct.name, "error", err)
		return
	}

	ct.reconcileState(&snapshot)
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

	// Push/pull hands every connection-state payload to every connection
	// tracker on this node, because the name it was registered under is only
	// unique on the node that produced it. The protocol inside the payload is
	// what says whose state it is; a snapshot that does not name one comes from
	// a build that predates the field and is taken as addressed to us.
	if snapshot.Protocol != "" && snapshot.Protocol != ct.name {
		return
	}

	// Check if snapshot is too old (prevent stale reconciliation)
	age := time.Since(snapshot.Timestamp)
	if age > staleEventThreshold {
		logger.Debug("Gossip tracker: Ignoring stale state snapshot", "name", ct.name, "instance", snapshot.InstanceID, "age", age)
		return
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()

	// Receiving a snapshot is proof the instance is alive, whether it arrived
	// over gossip or push/pull.
	if ct.instanceLastSeen == nil {
		ct.instanceLastSeen = make(map[string]time.Time)
	}
	ct.instanceLastSeen[snapshot.InstanceID] = time.Now()

	reconciledCount := 0
	addedCount := 0
	removedCount := 0

	// Build a map of accounts in the snapshot for fast lookup
	snapshotAccounts := make(map[int64]bool, len(snapshot.Connections))
	for accountID := range snapshot.Connections {
		snapshotAccounts[accountID] = true
	}

	// First pass: Remove stale entries for the snapshot's instance
	// If we have entries from snapshotInstanceID that are NOT in the snapshot, remove them
	for accountID, info := range ct.connections {
		// Check if this account has connections from the snapshot's instance
		if perIPMap := info.PerIPCountByInstance[snapshot.InstanceID]; len(perIPMap) > 0 {
			// If the snapshot doesn't include this account, the connection is stale
			if !snapshotAccounts[accountID] {
				// Remove the stale instance entry
				delete(info.PerIPCountByInstance, snapshot.InstanceID)
				removedCount++

				// Clean up the user entry if no connections remain
				if info.GetTotalCount() <= 0 {
					delete(ct.connections, accountID)
					logger.Debug("Gossip tracker: Removed user entry (no connections remain)", "name", ct.name,
						"account_id", accountID, "username", info.Username, "instance", snapshot.InstanceID)
				} else {
					logger.Debug("Gossip tracker: Removed stale entry for instance", "name", ct.name,
						"account_id", accountID, "username", info.Username,
						"instance", snapshot.InstanceID, "new_total", info.GetTotalCount())
				}
			}
		}
	}

	// Second pass: Add/update entries from the snapshot
	for accountID, remoteData := range snapshot.Connections {
		info, exists := ct.connections[accountID]
		if !exists {
			// New user we didn't know about
			now := time.Now()
			info = &UserConnectionInfo{
				AccountID:            accountID,
				Username:             remoteData.Username,
				LastUpdate:           now,
				FirstSeen:            now,
				PerIPCountByInstance: make(map[string]map[string]int),
			}
			ct.connections[accountID] = info
			addedCount++
		}

		// Replace per-IP counts for the snapshot's instance (authoritative)
		// The snapshot contains only the sending instance's per-IP counts
		if len(remoteData.PerIPCount) > 0 {
			// Replace entire map for this instance (authoritative)
			info.PerIPCountByInstance[snapshot.InstanceID] = remoteData.PerIPCount
			reconciledCount++
		} else {
			// Empty PerIPCount means no IP tracking for this instance - remove it
			if info.PerIPCountByInstance[snapshot.InstanceID] != nil {
				delete(info.PerIPCountByInstance, snapshot.InstanceID)
				reconciledCount++
			}
		}

		info.LastUpdate = time.Now()
	}

	logger.Info("GossipTracker: Reconciled state", "protocol", ct.name,
		"from_node", snapshot.InstanceID, "updated", reconciledCount, "added", addedCount, "removed", removedCount)
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
		totalInstanceIDs += len(info.PerIPCountByInstance)
		// Count total IP tracking entries across all instances
		for _, perIPMap := range info.PerIPCountByInstance {
			totalIPs += len(perIPMap)
		}
		totalConnections += info.GetTotalCount()
	}
	ct.mu.RUnlock()

	// Get broadcast queue size
	queueSize := ct.queue.numQueued() + ct.criticalQueue.numQueued() + ct.heartbeatQueue.numQueued()

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
			"broadcast_queue_max": ct.maxEventQueueSize,
			"queue_utilization":   float64(queueSize) / float64(ct.maxEventQueueSize) * 100,
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
