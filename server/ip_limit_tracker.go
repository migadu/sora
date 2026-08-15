package server

import (
	"bytes"
	"encoding/gob"
	"sync"
	"time"

	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/server/idgen"
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

// Default maximum size of IP event queue before we start dropping old events
const defaultMaxIPEventQueueSize = 10000

// IPLimitEvent represents a cluster-wide per-IP connection event
type IPLimitEvent struct {
	Type       IPLimitEventType `json:"type"`
	EventID    string           `json:"event_id"` // Unique per event, for duplicate suppression
	IP         string           `json:"ip"`       // The IP address
	Protocol   string           `json:"protocol"` // "IMAP", "POP3", etc.
	Timestamp  time.Time        `json:"timestamp"`
	NodeID     string           `json:"node_id"`
	InstanceID string           `json:"instance_id"` // Unique instance identifier

	// For state snapshots. This tracker only ever sends payload-less snapshots
	// as liveness heartbeats; full state travels over push/pull.
	StateSnapshot *IPLimitStateSnapshot `json:"state_snapshot,omitempty"`
}

// IPLimitStateSnapshot represents a full per-IP connection state for reconciliation
type IPLimitStateSnapshot struct {
	InstanceID string    `json:"instance_id"`
	Protocol   string    `json:"protocol"` // Which tracker the state belongs to
	Timestamp  time.Time `json:"timestamp"`

	Connections map[string]IPConnectionData `json:"connections"` // IP -> connection data
}

// IPConnectionData is the serializable version of IPConnectionInfo for gossip
type IPConnectionData struct {
	IP             string         `json:"ip"`
	LocalInstances map[string]int `json:"local_instances"` // instanceID -> count
	TotalCount     int            `json:"total_count"`     // Cluster-wide count
	LastUpdate     time.Time      `json:"last_update"`
}

// IPConnectionInfo tracks connection information for a specific IP.
// LocalInstances is the only authoritative state: TotalCount and LocalCount are
// derived from it by recalculate so the three can never drift apart.
type IPConnectionInfo struct {
	IP             string
	TotalCount     int // Cluster-wide count (eventually consistent)
	LocalCount     int // This instance's count
	LastUpdate     time.Time
	LocalInstances map[string]int // instanceID -> count on that instance
}

// recalculate derives the denormalized counters from the per-instance counts
// and drops instances that no longer hold connections.
func (info *IPConnectionInfo) recalculate(localInstanceID string) {
	total := 0
	for instanceID, count := range info.LocalInstances {
		if count <= 0 {
			delete(info.LocalInstances, instanceID)
			continue
		}
		total += count
	}

	info.TotalCount = total
	info.LocalCount = info.LocalInstances[localInstanceID]
}

// IPLimitTracker manages per-IP connection tracking using gossip protocol
type IPLimitTracker struct {
	protocol       string
	instanceID     string
	clusterManager *cluster.Manager

	// Connection tracking
	connections map[string]*IPConnectionInfo // IP -> info
	mu          sync.RWMutex

	// Instance tracking for liveness detection
	instanceLastSeen map[string]time.Time

	// Duplicate suppression for received events
	dedup gossipDedup

	// Decrements delivered ahead of the increment they cancel (guarded by mu)
	deferred deferredDecrements

	// Configuration
	maxEventQueueSize int // Maximum events in broadcast queue

	// Outgoing gossip. The liveness heartbeat uses a queue of its own that is
	// drained first: it is the smallest message the tracker produces, so under
	// msgLen-descending transmit order it would otherwise lose to every
	// ordinary event - exactly while a deep backlog is the reason peers most
	// need proof this instance is alive.
	queue          *gossipQueue
	heartbeatQueue *gossipQueue

	// Cleanup counter for periodic memory reporting
	cleanupCounter uint64

	// Shutdown
	stopBroadcast chan struct{}
	stopCleanup   chan struct{}
	stopOnce      sync.Once
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
		instanceLastSeen:  make(map[string]time.Time),
		maxEventQueueSize: maxEventQueueSize,
		queue:             newGossipQueue("ip-limit:"+protocol, clusterMgr, maxEventQueueSize),
		heartbeatQueue:    newGossipQueue("ip-limit-heartbeat:"+protocol, clusterMgr, maxHeartbeatQueued),
		deferred:          deferredDecrements{kind: "ip-limit:" + protocol},
		stopBroadcast:     make(chan struct{}),
		stopCleanup:       make(chan struct{}),
	}

	if clusterMgr != nil {
		// Cluster mode: register with cluster manager for gossip
		logger.Debug("IP limit tracker: Registering handlers with cluster manager", "protocol", protocol)
		clusterMgr.RegisterIPLimitHandler(tracker.HandleClusterEvent)
		clusterMgr.RegisterIPLimitBroadcaster(tracker.GetBroadcasts)
		// The registration name only has to be unique on this node: push/pull
		// state is dispatched by kind and each tracker decides from the
		// protocol inside the payload whether the state is its own.
		clusterMgr.RegisterStateProvider(cluster.StateKindIPLimit, instanceID, tracker.localState, tracker.mergeRemoteState)
		logger.Debug("IP limit tracker: Handlers registered successfully", "protocol", protocol)

		// Start background routines
		go tracker.heartbeatRoutine()
		go tracker.cleanupRoutine()
	}

	return tracker
}

// markInstanceSeen records that an instance is still gossiping. Callers must
// hold t.mu.
func (t *IPLimitTracker) markInstanceSeen(instanceID string) {
	if instanceID == "" || instanceID == t.instanceID {
		return
	}
	if t.instanceLastSeen == nil {
		t.instanceLastSeen = make(map[string]time.Time)
	}
	t.instanceLastSeen[instanceID] = time.Now()
}

// IncrementIP increments the connection count for an IP
func (t *IPLimitTracker) IncrementIP(ip string) {
	// Encoding happens outside the tracker lock: every accept on this listener
	// serialises on it, and gob encoding an event is orders of magnitude more
	// work than the bookkeeping it protects.
	if event := t.incrementLocked(ip); event != nil {
		t.queueEvent(*event)
	}
}

func (t *IPLimitTracker) incrementLocked(ip string) *IPLimitEvent {
	t.mu.Lock()
	defer t.mu.Unlock()

	info, exists := t.connections[ip]
	if !exists {
		info = &IPConnectionInfo{
			IP:             ip,
			LastUpdate:     time.Now(),
			LocalInstances: make(map[string]int),
		}
		t.connections[ip] = info
	}

	// Increment counts
	info.LocalInstances[t.instanceID]++
	info.LastUpdate = time.Now()
	info.recalculate(t.instanceID)

	// Broadcast event (if in cluster mode)
	if t.clusterManager == nil {
		return nil
	}

	return &IPLimitEvent{
		Type:       IPLimitEventIncrement,
		IP:         ip,
		Protocol:   t.protocol,
		Timestamp:  time.Now(),
		NodeID:     t.clusterManager.GetNodeID(),
		InstanceID: t.instanceID,
	}
}

// DecrementIP decrements the connection count for an IP
func (t *IPLimitTracker) DecrementIP(ip string) {
	// Encoding happens outside the tracker lock, as in IncrementIP.
	if event := t.decrementLocked(ip); event != nil {
		t.queueEvent(*event)
	}
}

func (t *IPLimitTracker) decrementLocked(ip string) *IPLimitEvent {
	t.mu.Lock()
	defer t.mu.Unlock()

	info, exists := t.connections[ip]
	if !exists {
		return nil // Nothing to decrement
	}

	// Only decrement if we actually own connections for this IP
	if info.LocalCount == 0 {
		return nil // Don't decrement connections we don't own
	}

	info.LocalInstances[t.instanceID]--
	info.LastUpdate = time.Now()
	info.recalculate(t.instanceID)

	// Clean up IP entry if no connections remain
	if info.TotalCount == 0 && len(info.LocalInstances) == 0 {
		delete(t.connections, ip)
	}

	// Broadcast event (if in cluster mode)
	if t.clusterManager == nil {
		return nil
	}

	return &IPLimitEvent{
		Type:       IPLimitEventDecrement,
		IP:         ip,
		Protocol:   t.protocol,
		Timestamp:  time.Now(),
		NodeID:     t.clusterManager.GetNodeID(),
		InstanceID: t.instanceID,
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

// queueEvent encodes an event and hands it to the right gossip queue. A
// payload-less snapshot is a liveness heartbeat and goes to the queue that is
// drained first; everything else is a counter delta that the next push/pull
// can repair.
func (t *IPLimitTracker) queueEvent(event IPLimitEvent) {
	if event.EventID == "" {
		event.EventID = idgen.New()
	}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(event); err != nil {
		logger.Warn("IP limit tracker: Failed to encode event", "protocol", t.protocol, "type", event.Type, "error", err)
		return
	}

	if event.Type == IPLimitEventStateSnapshot && event.StateSnapshot == nil {
		t.heartbeatQueue.enqueue(buf.Bytes())
		return
	}

	t.queue.enqueue(buf.Bytes())
}

// GetBroadcasts returns pending broadcasts for gossip (called by cluster
// manager). memberlist calls this once per gossip target, so an event stays
// queued until it has been transmitted often enough to have reached the cluster.
func (t *IPLimitTracker) GetBroadcasts(overhead, limit int) [][]byte {
	return drainTiers(t.heartbeatQueue, nil, t.queue, overhead, limit)
}

// decodeIPLimitEvent decodes an event from bytes using gob
func decodeIPLimitEvent(data []byte) (IPLimitEvent, error) {
	var event IPLimitEvent
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&event); err != nil {
		return event, err
	}
	return event, nil
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

	// Every tracker receives every per-IP event, but counts are per protocol:
	// without this filter an IMAP connection would be counted against the POP3
	// limit and never retired by the POP3 owner's state.
	if event.Protocol != "" && event.Protocol != t.protocol {
		return
	}

	// Gossip delivery is at-least-once: increment and decrement move a counter,
	// so a retransmitted copy must not be applied twice.
	if t.dedup.seenBefore(event.EventID) {
		return
	}

	switch event.Type {
	case IPLimitEventIncrement:
		t.handleRemoteIncrement(&event)
	case IPLimitEventDecrement:
		t.handleRemoteDecrement(&event)
	case IPLimitEventStateSnapshot:
		// A payload-less snapshot is a liveness heartbeat. A snapshot that does
		// carry state comes from a node old enough to still gossip full state,
		// and those events have no Protocol, so they reach every protocol's
		// tracker and cannot be attributed to one: applying them would let one
		// protocol's counts overwrite another's. Liveness is all we take.
		t.handleHeartbeat(&event)
	}
}

// handleHeartbeat records that the sending instance is still alive
func (t *IPLimitTracker) handleHeartbeat(event *IPLimitEvent) {
	if event.StateSnapshot != nil {
		logger.Debug("IP limit tracker: Ignoring gossiped full state (pre-push/pull node)",
			"protocol", t.protocol, "instance", event.InstanceID)
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	t.markInstanceSeen(event.InstanceID)
}

// ipCounterKey identifies the counter an increment/decrement pair moves. Both
// events of a pair come from the same instance, so timestamps taken from this
// key's clock are comparable.
func ipCounterKey(instanceID, ip string) string {
	return instanceID + "|" + ip
}

// handleRemoteIncrement processes an increment event from another node
func (t *IPLimitTracker) handleRemoteIncrement(event *IPLimitEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.markInstanceSeen(event.InstanceID)

	// A decrement for this connection may have been delivered first; the two
	// then cancel and neither is applied.
	if t.deferred.consume(ipCounterKey(event.InstanceID, event.IP), event.Timestamp) {
		return
	}

	info, exists := t.connections[event.IP]
	if !exists {
		info = &IPConnectionInfo{
			IP:             event.IP,
			LastUpdate:     time.Now(),
			LocalInstances: make(map[string]int),
		}
		t.connections[event.IP] = info
	}

	info.LocalInstances[event.InstanceID]++
	info.LastUpdate = event.Timestamp
	info.recalculate(t.instanceID)
}

// handleRemoteDecrement processes a decrement event from another node
func (t *IPLimitTracker) handleRemoteDecrement(event *IPLimitEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.markInstanceSeen(event.InstanceID)

	// Nothing to subtract from: the increment may simply be delivered later, so
	// the decrement is held until it shows up rather than dropped, which would
	// leave the increment as a phantom connection against the per-IP limit.
	info, exists := t.connections[event.IP]
	if !exists || info.LocalInstances[event.InstanceID] <= 0 {
		t.deferred.hold(ipCounterKey(event.InstanceID, event.IP), event.Timestamp)
		return
	}

	info.LocalInstances[event.InstanceID]--
	info.LastUpdate = event.Timestamp
	info.recalculate(t.instanceID)

	// Clean up if no connections remain
	if info.TotalCount == 0 && len(info.LocalInstances) == 0 {
		delete(t.connections, event.IP)
	}
}

// reconcileState applies a peer's authoritative per-IP state. A snapshot only
// carries the counts the sending instance owns: every other instance is
// authoritative for its own, and an IP the snapshot does not mention is one the
// sender no longer holds connections from.
func (t *IPLimitTracker) reconcileState(snapshot *IPLimitStateSnapshot) {
	if snapshot == nil || snapshot.InstanceID == "" || snapshot.InstanceID == t.instanceID {
		return
	}

	// Push/pull hands every per-IP payload to every IP tracker on this node,
	// because the name it was registered under is only unique on the node that
	// produced it. The protocol inside the payload is what says whose state it
	// is; a snapshot that does not name one comes from a build that predates
	// the field and is taken as addressed to us.
	if snapshot.Protocol != "" && snapshot.Protocol != t.protocol {
		return
	}

	if age := time.Since(snapshot.Timestamp); age > staleEventThreshold {
		logger.Debug("IP limit tracker: Ignoring stale state snapshot", "protocol", t.protocol,
			"instance", snapshot.InstanceID, "age", age)
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	t.markInstanceSeen(snapshot.InstanceID)

	removed := 0
	updated := 0

	// Retire counts the sender no longer reports.
	for ip, info := range t.connections {
		if _, stillHeld := snapshot.Connections[ip]; stillHeld {
			continue
		}
		if _, attributed := info.LocalInstances[snapshot.InstanceID]; !attributed {
			continue
		}

		delete(info.LocalInstances, snapshot.InstanceID)
		info.recalculate(t.instanceID)
		removed++

		if info.TotalCount == 0 && len(info.LocalInstances) == 0 {
			delete(t.connections, ip)
		}
	}

	// Replace the sender's counts with the authoritative ones.
	for ip, remoteData := range snapshot.Connections {
		count := remoteData.LocalInstances[snapshot.InstanceID]

		info, exists := t.connections[ip]
		if !exists {
			if count <= 0 {
				continue
			}
			info = &IPConnectionInfo{
				IP:             ip,
				LastUpdate:     remoteData.LastUpdate,
				LocalInstances: make(map[string]int),
			}
			t.connections[ip] = info
		}

		info.LocalInstances[snapshot.InstanceID] = count
		if remoteData.LastUpdate.After(info.LastUpdate) {
			info.LastUpdate = remoteData.LastUpdate
		}
		info.recalculate(t.instanceID)
		updated++

		if info.TotalCount == 0 && len(info.LocalInstances) == 0 {
			delete(t.connections, ip)
		}
	}

	if removed > 0 || updated > 0 {
		logger.Debug("IP limit tracker: Reconciled state", "protocol", t.protocol,
			"instance", snapshot.InstanceID, "updated", updated, "removed", removed)
	}
}

// stateSnapshot builds this instance's authoritative per-IP state
func (t *IPLimitTracker) stateSnapshot() *IPLimitStateSnapshot {
	t.mu.RLock()
	defer t.mu.RUnlock()

	now := time.Now()
	connections := make(map[string]IPConnectionData, len(t.connections))
	for ip, info := range t.connections {
		count := info.LocalInstances[t.instanceID]
		if count <= 0 {
			continue
		}

		connections[ip] = IPConnectionData{
			IP:             ip,
			LocalInstances: map[string]int{t.instanceID: count},
			TotalCount:     count,
			LastUpdate:     now,
		}
	}

	return &IPLimitStateSnapshot{
		InstanceID:  t.instanceID,
		Protocol:    t.protocol,
		Timestamp:   now,
		Connections: connections,
	}
}

// localState encodes this instance's per-IP state for a memberlist push/pull
// exchange. Full state is exchanged over push/pull rather than gossip because
// it outgrows the gossip datagram budget, while push/pull runs over TCP.
// An empty snapshot is still sent: it tells peers to retire our old counts.
func (t *IPLimitTracker) localState() []byte {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(t.stateSnapshot()); err != nil {
		logger.Warn("IP limit tracker: Failed to encode state snapshot", "protocol", t.protocol, "error", err)
		return nil
	}
	return buf.Bytes()
}

// mergeRemoteState applies a peer's per-IP state received over push/pull
func (t *IPLimitTracker) mergeRemoteState(data []byte) {
	var snapshot IPLimitStateSnapshot
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&snapshot); err != nil {
		logger.Warn("IP limit tracker: Failed to decode remote state", "protocol", t.protocol, "error", err)
		return
	}

	t.reconcileState(&snapshot)
}

// heartbeatRoutine re-asserts that this instance is alive. Peers retire the
// counts of an instance they stop hearing from (see performCleanup), and an
// instance whose connections are all idle produces no other gossip: push/pull
// would refresh it eventually, but it pairs with one random peer per round, so
// in a cluster of a dozen nodes a given peer is not reached reliably within the
// staleness threshold.
func (t *IPLimitTracker) heartbeatRoutine() {
	ticker := time.NewTicker(gossipHeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			t.queueHeartbeat()
		case <-t.stopBroadcast:
			return
		}
	}
}

// queueHeartbeat gossips proof that this instance is alive. It is a state
// snapshot event with no state: the counts themselves travel over push/pull.
func (t *IPLimitTracker) queueHeartbeat() {
	t.queueEvent(IPLimitEvent{
		Type:       IPLimitEventStateSnapshot,
		Protocol:   t.protocol,
		Timestamp:  time.Now(),
		NodeID:     t.clusterManager.GetNodeID(),
		InstanceID: t.instanceID,
	})
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

	now := time.Now()
	cleaned := 0
	purged := 0

	// Counts are only ever retired by their owner, so an owner that stopped
	// heartbeating takes its counts with it: its connections died with the
	// instance and nothing else will retire them. Counts this instance owns are
	// authoritative for as long as the connection is open and never age out.
	alive := func(instanceID string) bool {
		if instanceID == t.instanceID {
			return true
		}
		lastSeen, known := t.instanceLastSeen[instanceID]
		return known && now.Sub(lastSeen) <= staleInstanceThreshold
	}

	// Forget decrements whose increment never arrived.
	t.deferred.prune(gossipDedupWindow)

	for ip, info := range t.connections {
		for instanceID := range info.LocalInstances {
			if alive(instanceID) {
				continue
			}
			delete(info.LocalInstances, instanceID)
			purged++
		}

		// Drop zero counts, then IPs with nothing left.
		info.recalculate(t.instanceID)
		if info.TotalCount == 0 && len(info.LocalInstances) == 0 {
			delete(t.connections, ip)
			cleaned++
		}
	}

	for instanceID, lastSeen := range t.instanceLastSeen {
		if now.Sub(lastSeen) > staleInstanceThreshold {
			logger.Info("IP limit tracker: Purging stale instance data", "protocol", t.protocol,
				"instance", instanceID, "age", now.Sub(lastSeen))
			delete(t.instanceLastSeen, instanceID)
		}
	}

	if cleaned > 0 || purged > 0 {
		logger.Debug("IP limit tracker: Cleaned up stale IPs", "protocol", t.protocol, "ips", cleaned, "instances", purged)
	}

	// Log memory usage stats every 10 cleanup cycles (~50 minutes with 5min cleanup interval)
	// This helps monitor for memory leaks without flooding logs
	t.cleanupCounter++
	if t.cleanupCounter%10 == 0 {
		totalIPs := len(t.connections)
		totalInstances := 0
		for _, info := range t.connections {
			totalInstances += len(info.LocalInstances)
		}

		logger.Info("IP limit tracker stats", "protocol", t.protocol,
			"total_ips", totalIPs,
			"total_instances", totalInstances,
			"cleanup_cycles", t.cleanupCounter)
	}
}

// Stop shuts down the IP limit tracker
func (t *IPLimitTracker) Stop() {
	t.stopOnce.Do(func() {
		if t.clusterManager != nil {
			close(t.stopBroadcast)
			close(t.stopCleanup)
		}
	})
}
