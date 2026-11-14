package server

import (
	"bytes"
	"encoding/gob"
	"time"

	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/server/idgen"
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

// maxRateLimitEventQueueSize bounds the outgoing gossip queue
const maxRateLimitEventQueueSize = 10000

// RateLimitEvent represents a cluster-wide rate limiting event
type RateLimitEvent struct {
	Type      RateLimitEventType `json:"type"`
	EventID   string             `json:"event_id"` // Unique per event, for duplicate suppression
	IP        string             `json:"ip"`
	Timestamp time.Time          `json:"timestamp"`
	NodeID    string             `json:"node_id"`

	// Protocol is the protocol of the limiter that produced the event; only
	// limiters of the same protocol apply it.
	Protocol string `json:"protocol,omitempty"`

	// For BLOCK_IP events
	BlockedUntil time.Time `json:"blocked_until,omitempty"`
	FailureCount int       `json:"failure_count,omitempty"`
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

	// Outgoing gossip. IP blocks and unblocks have a tier of their own that is
	// drained first: every failed login queues a username failure and, past
	// the delay threshold, a failure count, and within a transmit tier
	// memberlist hands out the largest message first, so during an attack -
	// when a block matters most - username failures for long addresses would
	// otherwise hold the block off the wire until it went stale.
	blocks *gossipQueue
	queue  *gossipQueue

	// Duplicate suppression for received events
	dedup gossipDedup

	// When each IP was last unblocked and each username last succeeded, so that
	// a BLOCK_IP or USERNAME_FAILURE delivered after the event that clears it is
	// recognised as the older of the pair. USERNAME_FAILURE and USERNAME_SUCCESS
	// encode to the same length, so the transmit queue orders them arbitrarily.
	unblocked gossipTombstones
	succeeded gossipTombstones

	// Configuration
	syncBlocks        bool
	syncFailureCounts bool
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
		blocks:            newGossipQueue("rate-limit-blocks:"+limiter.protocol, clusterMgr, maxRateLimitEventQueueSize),
		queue:             newGossipQueue("rate-limit:"+limiter.protocol, clusterMgr, maxRateLimitEventQueueSize),
	}

	// A tombstone is marked for every event of its kind, whether or not this
	// node holds anything to clear, so each map is bounded like the map it
	// shadows. Successful authentication is the hot path here: without a cap,
	// ordinary logins alone would grow the success tombstones without limit.
	crl.succeeded.maxEntries = limiter.config.MaxUsernameEntries
	crl.unblocked.maxEntries = limiter.config.MaxIPEntries

	// Register with cluster manager to receive rate limit events
	clusterMgr.RegisterRateLimitHandler(crl.HandleClusterEvent)

	// Register as broadcaster for outgoing events
	clusterMgr.RegisterRateLimitBroadcaster(crl.GetBroadcasts)

	logger.Info("CLUSTER-LIMITER: initialized cluster rate limiting", "protocol", limiter.protocol,
		"sync_blocks", syncBlocks, "sync_failure_counts", syncFailureCounts)

	return crl
}

// JoinCluster makes the limiter share its IP blocks, progressive-delay failure
// counts and username failures with the limiters of the same protocol on the
// other cluster nodes, as [cluster.rate_limit_sync] configures. It does nothing
// on a disabled (nil) limiter, without a cluster manager, or with sync disabled.
// Call it before the limiter records its first attempt.
func (a *AuthRateLimiter) JoinCluster(clusterMgr *cluster.Manager, sync config.ClusterRateLimitSyncConfig) {
	if a == nil || clusterMgr == nil || !sync.Enabled {
		return
	}
	a.SetClusterLimiter(NewClusterRateLimiter(a, clusterMgr, sync.SyncBlocks, sync.SyncFailureCounts))
}

// BroadcastBlockIP broadcasts an IP block event to the cluster
func (crl *ClusterRateLimiter) BroadcastBlockIP(ip string, blockedUntil time.Time, failureCount int, firstFailure time.Time) {
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

// queueEvent encodes an event and hands it to the gossip queue
func (crl *ClusterRateLimiter) queueEvent(event RateLimitEvent) {
	if event.EventID == "" {
		event.EventID = idgen.New()
	}
	event.Protocol = crl.limiter.protocol

	encoded, err := encodeRateLimitEvent(event)
	if err != nil {
		logger.Warn("Cluster limiter: Failed to encode rate limit event", "type", event.Type, "error", err)
		return
	}

	switch event.Type {
	case RateLimitEventBlockIP, RateLimitEventUnblockIP:
		crl.blocks.enqueue(encoded)
	default:
		crl.queue.enqueue(encoded)
	}
}

// GetBroadcasts returns events to broadcast (called by cluster manager).
// memberlist calls this once per gossip target, so an event stays queued until
// it has been transmitted often enough to have reached the cluster. Blocks go
// first, within half of the datagram so a burst of them cannot stall the
// failure counts behind it.
func (crl *ClusterRateLimiter) GetBroadcasts(overhead, limit int) [][]byte {
	return drainTiers(nil, crl.blocks, crl.queue, overhead, limit)
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

	// Every limiter on this node receives every rate-limit event of the cluster.
	// The limiters of one node are independent of each other - an IMAP failure
	// does not count against POP3 - so a peer's event belongs only to the limiter
	// of the protocol that produced it.
	if event.Protocol != crl.limiter.protocol {
		return
	}

	// Check if event is too old (prevent replays after network partition)
	age := time.Since(event.Timestamp)
	if age > staleEventThreshold {
		logger.Debug("Cluster limiter: Ignoring stale rate limit event", "node_id", event.NodeID, "age", age)
		return
	}

	// Gossip delivery is at-least-once: a username failure increments a counter,
	// so a retransmitted copy must not be applied twice.
	if crl.dedup.seenBefore(event.EventID) {
		logger.Debug("Cluster limiter: Ignoring duplicate rate limit event", "type", event.Type, "event_id", event.EventID)
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

// handleBlockIP applies an IP block from another node.
//
// A block of an address this node exempts from rate limiting is not held, as
// the local path never blocks it: no check here would refuse the address, so
// the entry would only list it as blocked (GetBlockedEntries, blocked_ips)
// while this node lets it through.
func (crl *ClusterRateLimiter) handleBlockIP(event RateLimitEvent) {
	if !crl.syncBlocks || crl.limiter.isRateLimitExempt(event.IP) {
		return
	}

	// Check if block is still valid (not expired)
	if time.Now().After(event.BlockedUntil) {
		logger.Debug("Cluster limiter: Ignoring expired block", "ip", event.IP, "from_node", event.NodeID)
		return
	}

	// An unblock for this IP may have been delivered first, in which case this
	// block is the older event and applying it would re-block a cleared IP.
	if crl.unblocked.removedSince(event.IP, event.Timestamp) {
		logger.Debug("Cluster limiter: Ignoring block superseded by an unblock", "ip", event.IP, "from_node", event.NodeID)
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

	// Record the unblock before deciding whether it applies here: a block for
	// this IP delivered after this event is the older of the two, whether or
	// not we currently hold a block to lift.
	crl.unblocked.mark(event.IP, event.Timestamp)

	crl.limiter.ipMu.Lock()
	defer crl.limiter.ipMu.Unlock()

	existing, exists := crl.limiter.blockedIPs[event.IP]
	if !exists {
		return
	}
	if existing.LastFailure.After(event.Timestamp) {
		logger.Debug("Cluster limiter: Ignoring unblock older than the block it lifts",
			"protocol", crl.limiter.protocol, "ip", event.IP, "from_node", event.NodeID)
		return
	}

	delete(crl.limiter.blockedIPs, event.IP)
	logger.Debug("Cluster limiter: Applied cluster unblock", "protocol", crl.limiter.protocol, "ip", event.IP, "from_node", event.NodeID)
}

// handleFailureCount merges progressive delay tracking from another node.
//
// Both nodes count failures of the same address, so a peer's count says the
// address failed at least that often: it raises this node's count and never
// lowers it. Taking the newest count instead let a peer that had seen fewer
// failures reset the count of a node close to blocking the address, so an
// attack spread over two nodes could stay under max_attempts_per_ip on both.
//
// An address this node exempts from rate limiting is not tracked, as the local
// path never tracks it: peers of one protocol may exempt other networks (a
// rolling change of exempt_networks, or two [[server]] entries of the same
// protocol), and their delay must not apply here.
func (crl *ClusterRateLimiter) handleFailureCount(event RateLimitEvent) {
	if !crl.syncFailureCounts || crl.limiter.isRateLimitExempt(event.IP) {
		return
	}

	crl.limiter.ipMu.Lock()
	defer crl.limiter.ipMu.Unlock()

	info, exists := crl.limiter.ipFailureCounts[event.IP]
	if !exists {
		// The cap bounds the map however its entries arrive, as in
		// updateFailureTracking: every node would otherwise hold the union of
		// the whole cluster's attack traffic for the length of the window.
		if maxIPs := crl.limiter.config.MaxIPEntries; maxIPs > 0 && len(crl.limiter.ipFailureCounts) >= maxIPs {
			crl.limiter.evictOldestIP()
		}
		info = &IPFailureInfo{FirstFailure: event.FirstFailure}
		crl.limiter.addIPCounter(event.IP, info)
	}

	info.FailureCount = max(info.FailureCount, event.FailureCount)
	// A peer's delay is capped by this node's max_delay, as every local step
	// is in updateFailureTracking. Peers of one protocol may run with other
	// limits (a rolling change of max_delay, or two [[server]] entries of the
	// same protocol), and a longer delay of theirs must not apply here.
	if delay := min(event.LastDelay, crl.limiter.config.MaxDelay); delay > info.LastDelay {
		info.LastDelay = delay
	}
	if !event.FirstFailure.IsZero() && event.FirstFailure.Before(info.FirstFailure) {
		info.FirstFailure = event.FirstFailure
		crl.limiter.ipQueue.fix(info) // a parked counter is ordered by its block instead
	}
	if event.Timestamp.After(info.LastFailure) {
		info.LastFailure = event.Timestamp
	}

	logger.Debug("Cluster limiter: Merged failure count", "protocol", crl.limiter.protocol, "ip", event.IP, "from_node", event.NodeID,
		"peer_failures", event.FailureCount, "failures", info.FailureCount, "delay", info.LastDelay)
}

// handleUsernameFailure applies a username failure from another node
func (crl *ClusterRateLimiter) handleUsernameFailure(event RateLimitEvent) {
	if event.Username == "" {
		return
	}

	// A success for this username may have been delivered first, in which case
	// this failure predates it and is already accounted for by the success.
	if crl.succeeded.removedSince(event.Username, event.Timestamp) {
		logger.Debug("CLUSTER-LIMITER: Ignoring username failure superseded by a success",
			"protocol", crl.limiter.protocol, "username", event.Username, "from_node", event.NodeID)
		return
	}

	crl.limiter.usernameMu.Lock()
	defer crl.limiter.usernameMu.Unlock()

	info, exists := crl.limiter.usernameFailureCounts[event.Username]
	if !exists {
		// Bounded however entries arrive, as in updateUsernameFailure.
		if maxUsernames := crl.limiter.config.MaxUsernameEntries; maxUsernames > 0 && len(crl.limiter.usernameFailureCounts) >= maxUsernames {
			crl.limiter.evictOldestUsername()
		}
		info = &UsernameFailureInfo{FirstFailure: event.Timestamp}
		crl.limiter.addUsernameCounter(event.Username, info)
	}

	// Increment failure count (each node broadcasts its local failure).
	// LastFailure only moves forward: a failure delivered out of order that
	// rewound it would let a success older than the newest failure pass the
	// guard in handleUsernameSuccess and wipe a count that is still current.
	// The count itself cannot be split - the older failure stays counted even
	// though the success supersedes it - which errs towards blocking, the safe
	// direction for a rate limiter.
	info.FailureCount++
	if event.Timestamp.After(info.LastFailure) {
		info.LastFailure = event.Timestamp
	}

	logger.Debug("CLUSTER-LIMITER: Applied username failure from cluster", "protocol", crl.limiter.protocol,
		"username", event.Username, "from_node", event.NodeID, "total_failures", info.FailureCount)
}

// handleUsernameSuccess clears username failures (successful auth)
func (crl *ClusterRateLimiter) handleUsernameSuccess(event RateLimitEvent) {
	if event.Username == "" {
		return
	}

	// Record the success before deciding whether it clears anything here: a
	// failure for this username delivered after this event is the older of the
	// two, whether or not we currently hold a count to clear.
	crl.succeeded.mark(event.Username, event.Timestamp)

	crl.limiter.usernameMu.Lock()
	defer crl.limiter.usernameMu.Unlock()

	info, exists := crl.limiter.usernameFailureCounts[event.Username]
	if !exists {
		return
	}
	if info.LastFailure.After(event.Timestamp) {
		logger.Debug("CLUSTER-LIMITER: Ignoring success older than the failures it clears",
			"protocol", crl.limiter.protocol, "username", event.Username, "from_node", event.NodeID)
		return
	}

	crl.limiter.dropUsernameCounter(event.Username)

	logger.Debug("CLUSTER-LIMITER: Cleared username failures from cluster", "protocol", crl.limiter.protocol,
		"username", event.Username, "from_node", event.NodeID)
}

// Stop releases the cluster rate limiter. It owns no goroutine - memberlist
// drives the queue - but callers shut it down alongside the other components.
func (crl *ClusterRateLimiter) Stop() {}

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
