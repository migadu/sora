// Package cluster provides distributed coordination using HashiCorp memberlist
// for leader election and cluster membership.
package cluster

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
)

const (
	// defaultRetransmitMult and defaultUDPBufferSize mirror
	// memberlist.DefaultLANConfig() and are used when no memberlist instance is
	// attached yet.
	defaultRetransmitMult = 4
	defaultUDPBufferSize  = 1400

	// broadcastFrameOverhead is everything memberlist wraps around one user
	// broadcast inside a datagram: compound header (2), AES encryption (29),
	// compound message length prefix plus user-message type byte (3), and this
	// package's own subsystem marker (2).
	broadcastFrameOverhead = 2 + 29 + 3 + 2

	// pushPullInterval is how often memberlist runs a full-state exchange with
	// one random peer. Subsystems repair missed events over that exchange, so
	// the value is pinned here rather than inherited from memberlist's defaults.
	pushPullInterval = 30 * time.Second

	// handlerQueueDepth is how many gossip payloads may wait for one handler.
	// A payload never exceeds a datagram, so a full queue costs well under a
	// megabyte.
	handlerQueueDepth = 256

	// dropLogInterval bounds how often a saturated handler queue logs, so a
	// burst that overruns a handler does not also flood the log.
	dropLogInterval = 10 * time.Second
)

// Message type markers prefixed to every gossip broadcast.
var (
	markerRateLimit  = [2]byte{'R', 'L'}
	markerAffinity   = [2]byte{'A', 'F'}
	markerConnection = [2]byte{'C', 'N'}
	markerIPLimit    = [2]byte{'I', 'P'}
)

// Manager handles cluster coordination and leader election
type Manager struct {
	config                config.ClusterConfig
	memberlist            *memberlist.Memberlist
	delegate              *clusterDelegate
	nodeID                string
	isLeader              bool
	leaderID              string
	retransmitMult        int
	udpBufferSize         int
	mu                    sync.RWMutex
	ctx                   context.Context
	cancel                context.CancelFunc
	leaderChangeCallbacks []func(isLeader bool, newLeaderID string)
	callbackMu            sync.RWMutex

	// Full-state exchange over push/pull
	stateProviders map[string]stateProvider
	stateMu        sync.RWMutex

	// Rate limit event handling
	rateLimitHandlers   []*handlerQueue
	rateLimitMu         sync.RWMutex
	rateLimitBroadcasts []func(int, int) [][]byte
	broadcastMu         sync.RWMutex

	// Affinity event handling
	affinityHandlers    []*handlerQueue
	affinityMu          sync.RWMutex
	affinityBroadcasts  []func(int, int) [][]byte
	affinityBroadcastMu sync.RWMutex

	// Connection tracking event handling
	connectionHandlers    []*handlerQueue
	connectionMu          sync.RWMutex
	connectionBroadcasts  []func(int, int) [][]byte
	connectionBroadcastMu sync.RWMutex

	// Per-IP connection limit event handling
	ipLimitHandlers    []*handlerQueue
	ipLimitMu          sync.RWMutex
	ipLimitBroadcasts  []func(int, int) [][]byte
	ipLimitBroadcastMu sync.RWMutex
}

// handlerQueue delivers gossip payloads to one registered handler from a single
// worker goroutine. memberlist calls NotifyMsg on its packet receive loop, and
// the connection and IP handlers serialize on a tracker mutex that the accept
// path also takes, so delivery must neither block the caller nor spawn per
// message - gossip volume would otherwise turn handler contention into
// unbounded goroutine and buffer growth. Events that arrive with the queue full
// are dropped and counted.
type handlerQueue struct {
	kind        string
	handler     func([]byte)
	events      chan []byte
	dropped     atomic.Uint64
	lastDropLog atomic.Int64
}

func newHandlerQueue(ctx context.Context, kind string, handler func([]byte)) *handlerQueue {
	q := &handlerQueue{
		kind:    kind,
		handler: handler,
		events:  make(chan []byte, handlerQueueDepth),
	}
	go q.run(ctx)
	return q
}

func (q *handlerQueue) run(ctx context.Context) {
	var done <-chan struct{}
	if ctx != nil {
		done = ctx.Done()
	}

	for {
		select {
		case data := <-q.events:
			q.invoke(data)
		case <-done:
			return
		}
	}
}

func (q *handlerQueue) invoke(data []byte) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Panic in gossip handler", "kind", q.kind, "error", fmt.Errorf("%v", r))
		}
	}()
	q.handler(data)
}

// deliver queues one payload, or drops it if the handler has fallen behind
func (q *handlerQueue) deliver(data []byte) {
	select {
	case q.events <- data:
	default:
		q.recordDrop()
	}
}

func (q *handlerQueue) recordDrop() {
	total := q.dropped.Add(1)

	now := time.Now().UnixNano()
	last := q.lastDropLog.Load()
	if now-last < int64(dropLogInterval) || !q.lastDropLog.CompareAndSwap(last, now) {
		return
	}

	logger.Warn("Cluster: Gossip handler queue full, dropping events", "kind", q.kind, "capacity", cap(q.events), "dropped_total", total)
}

// deliverGossip hands one received payload to every handler of a subsystem
func deliverGossip(queues []*handlerQueue, data []byte) {
	if len(queues) == 0 {
		return
	}

	// memberlist reuses the receive buffer once NotifyMsg returns, and a queued
	// event outlives that call.
	payload := make([]byte, len(data))
	copy(payload, data)

	for _, q := range queues {
		q.deliver(payload)
	}
}

// clusterDelegate implements memberlist.Delegate for custom cluster behavior
type clusterDelegate struct {
	meta          []byte
	manager       *Manager
	metaLock      sync.RWMutex
	broadcastTurn atomic.Uint64
}

// Kinds of subsystem state exchanged over push/pull. A kind groups the
// providers that speak the same payload format, whatever the node they run on.
const (
	StateKindConnection = "connection"
	StateKindIPLimit    = "ip-limit"
)

// stateProvider exchanges one subsystem's full state during a push/pull round
type stateProvider struct {
	kind  string
	local func() []byte
	merge func([]byte)
}

// stateEntry is one provider's full state on the push/pull wire. The name it
// travels under is only unique on the node that produced it - two nodes name
// their listeners differently - so the receiver dispatches on Kind and each
// subsystem decides from the payload whether the state is addressed to it.
type stateEntry struct {
	Kind string
	Data []byte
}

// New creates a new cluster manager
func New(cfg config.ClusterConfig) (*Manager, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("cluster mode is not enabled")
	}

	// Use hostname as default node ID
	nodeID := cfg.NodeID
	if nodeID == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("failed to get hostname for node ID: %w", err)
		}
		nodeID = hostname
	}

	ctx, cancel := context.WithCancel(context.Background())

	m := &Manager{
		config:   cfg,
		nodeID:   nodeID,
		isLeader: false,
		leaderID: "",
		ctx:      ctx,
		cancel:   cancel,
	}

	// Create delegate
	m.delegate = &clusterDelegate{
		meta:    []byte(nodeID),
		manager: m,
	}
	logger.Info("Cluster delegate created", "delegate", fmt.Sprintf("%p", m.delegate))

	// Configure memberlist
	mlConfig := memberlist.DefaultLANConfig()
	mlConfig.Name = nodeID
	mlConfig.PushPullInterval = pushPullInterval
	m.retransmitMult = mlConfig.RetransmitMult
	m.udpBufferSize = mlConfig.UDPBufferSize

	bindAddr := cfg.GetBindAddr()
	bindPort := cfg.GetBindPort()

	mlConfig.BindAddr = bindAddr
	mlConfig.BindPort = bindPort
	mlConfig.Delegate = m.delegate

	// Warn if both addr contains port AND port field is set (port field will be ignored)
	if cfg.Addr != "" && strings.Contains(cfg.Addr, ":") && cfg.Port > 0 {
		logger.Warn("Cluster configuration: 'addr' contains port and 'port' field is also set", "addr", cfg.Addr, "port", cfg.Port)
		logger.Warn("The port from 'addr' will be used - 'port' field will be ignored", "addr_port", bindPort, "port_field", cfg.Port)
		logger.Warn("To avoid confusion, remove either the port from 'addr' or remove the 'port' field")
	}

	// Validate bind address - must be a specific IP, not 0.0.0.0 or localhost hostname
	if bindAddr == "" || bindAddr == "0.0.0.0" || bindAddr == "::" || bindAddr == "localhost" {
		logger.Error("Cluster mode ERROR: 'addr' must be a specific IP address reachable from other nodes")
		logger.Error("Current value is not valid for cluster gossip", "addr", bindAddr)
		logger.Error("The gossip protocol requires advertising a real IP address that other nodes can reach")
		logger.Error("Example: addr = \"10.10.10.40:7946\" or addr = \"10.10.10.40\" with port = 7946")
		logger.Error("Cannot use: 0.0.0.0, localhost, or ::")
		cancel()
		return nil, fmt.Errorf("cluster addr '%s' must be a specific IP address reachable from other nodes", bindAddr)
	}

	// Warn about loopback addresses (allowed for testing but not recommended for production)
	if bindAddr == "127.0.0.1" || bindAddr == "::1" {
		logger.Warn("Cluster mode: Using loopback address - this only works for single-machine testing", "addr", bindAddr)
		logger.Warn("For production clusters across multiple machines, use a real network IP address")
	}

	// Use bind address as advertise address (they should be the same)
	mlConfig.AdvertiseAddr = bindAddr
	mlConfig.AdvertisePort = bindPort

	// Log memberlist configuration
	logger.Info("Memberlist config", "name", mlConfig.Name, "bind_addr", mlConfig.BindAddr, "bind_port", mlConfig.BindPort, "advertise_addr", mlConfig.AdvertiseAddr, "advertise_port", mlConfig.AdvertisePort, "gossip_interval", mlConfig.GossipInterval, "gossip_nodes", mlConfig.GossipNodes)
	logger.Info("Cluster delegate attached to memberlist config", "delegate", fmt.Sprintf("%p", mlConfig.Delegate))

	// Enable more verbose memberlist logging to debug gossip
	mlConfig.LogOutput = &memberlistLogger{prefix: "[Memberlist] "}

	// Set up encryption if secret key is provided
	if cfg.SecretKey != "" {
		keyBytes, err := base64.StdEncoding.DecodeString(cfg.SecretKey)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to decode cluster secret_key: %w", err)
		}
		if len(keyBytes) != 32 {
			cancel()
			return nil, fmt.Errorf("cluster secret_key must be 32 bytes (got %d bytes)", len(keyBytes))
		}
		mlConfig.SecretKey = keyBytes
		logger.Info("Cluster encryption enabled with secret key")
	} else {
		// secret_key is mandatory when cluster mode is enabled. Gossip carries
		// security-sensitive state (auth-failure counts, IP blocks, connection-kick
		// commands); without encryption any host able to reach the gossip port can
		// forge these messages. Fail closed rather than running unauthenticated.
		logger.Error("Cluster mode ERROR: 'secret_key' is required when cluster mode is enabled")
		logger.Error("Gossip carries auth-failure state, IP blocks, and connection-kick commands")
		logger.Error("Without encryption, any host able to reach the gossip port can forge them")
		logger.Error("Generate a key with: openssl rand -base64 32")
		cancel()
		return nil, fmt.Errorf("cluster secret_key is required when cluster mode is enabled (generate one with: openssl rand -base64 32)")
	}

	// Create memberlist
	logger.Info("Creating memberlist with config", "node", mlConfig.Name, "bind_addr", mlConfig.BindAddr, "bind_port", mlConfig.BindPort, "delegate", fmt.Sprintf("%p", mlConfig.Delegate))
	ml, err := memberlist.Create(mlConfig)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create memberlist: %w", err)
	}

	m.memberlist = ml
	logger.Info("Memberlist created successfully", "instance", fmt.Sprintf("%p", ml))

	// Filter out self-references from peers list
	// A node should never list itself in the peers array as this causes gossip issues
	logger.Info("Filtering peers", "node_id", nodeID, "configured_peers", cfg.Peers)
	filteredPeers := make([]string, 0, len(cfg.Peers))
	selfReferenceFound := false
	for _, peer := range cfg.Peers {
		logger.Info("Checking peer against nodeID", "peer", peer, "node_id", nodeID)
		if peer == nodeID {
			selfReferenceFound = true
			logger.Warn("Cluster configuration: node_id found in peers list - ignoring self-reference", "node_id", nodeID)
			logger.Warn("The peers list should only contain OTHER nodes in the cluster, not this node itself")
		} else {
			logger.Info("Peer accepted (not self)", "peer", peer)
			filteredPeers = append(filteredPeers, peer)
		}
	}
	logger.Info("Peer filtering complete", "count", len(filteredPeers), "peers", filteredPeers)

	// Join cluster if peers are specified (after filtering)
	if len(filteredPeers) > 0 {
		logger.Info("Attempting to join cluster with peers", "peers", filteredPeers)
		n, err := ml.Join(filteredPeers)
		if err != nil {
			logger.Warn("Failed to join cluster peers (will retry in background)", "peers", filteredPeers, "error", err)
		} else {
			logger.Info("Join returned - contacted peers", "count", n, "peers", filteredPeers)
			// Check actual member count after join
			actualMembers := ml.NumMembers()
			logger.Info("Cluster members after join (expected 2+)", "members", actualMembers)
			if actualMembers < 2 {
				logger.Warn("Join succeeded but cluster only has few members - peer may have rejected us", "members", actualMembers)
				logger.Warn("Common causes: encryption key mismatch, network issues, or peer not running")
			}
		}
	} else {
		logger.Warn("No peers to join - running as standalone single-node cluster")
	}

	// Start leader election loop
	go m.leaderElectionLoop()

	// Start retry loop for cluster membership
	if len(filteredPeers) > 0 {
		go m.joinRetryLoop(filteredPeers)
	}

	if selfReferenceFound {
		logger.Info("Cluster manager started", "node_id", nodeID, "addr", cfg.Addr, "original_peers", cfg.Peers, "filtered_peers", filteredPeers)
	} else {
		logger.Info("Cluster manager started", "node_id", nodeID, "addr", cfg.Addr, "peers", filteredPeers)
	}

	return m, nil
}

// joinRetryLoop periodically retries joining the cluster if we haven't joined all peers
func (m *Manager) joinRetryLoop(peers []string) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	expectedMembers := len(peers) + 1 // peers + ourselves

	for {
		select {
		case <-m.ctx.Done():
			logger.Info("Cluster join retry loop stopping")
			return
		case <-ticker.C:
			currentMembers := m.memberlist.NumMembers()
			if currentMembers < expectedMembers {
				logger.Info("Cluster: Retry join - attempting to rejoin", "current", currentMembers, "expected", expectedMembers, "peers", peers)
				n, err := m.memberlist.Join(peers)
				if err != nil {
					logger.Warn("Cluster: Retry join failed", "peers", peers, "error", err)
				} else {
					newMembers := m.memberlist.NumMembers()
					logger.Info("Cluster: Retry join contacted peers", "contacted", n, "members", newMembers)
					if newMembers >= expectedMembers {
						logger.Info("Cluster: Successfully joined all peers - stopping retry loop")
						return
					}
				}
			} else {
				// We have all expected members, stop retrying
				logger.Debug("Cluster: Join retry - cluster complete", "current", currentMembers, "expected", expectedMembers)
				return
			}
		}
	}
}

// leaderElectionLoop continuously monitors cluster membership and determines leader
func (m *Manager) leaderElectionLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Run immediately on startup
	m.electLeader()

	for {
		select {
		case <-m.ctx.Done():
			logger.Info("Cluster leader election loop stopping")
			return
		case <-ticker.C:
			m.electLeader()
		}
	}
}

// electLeader performs leader election based on lexicographically smallest node ID
// This is a simple, deterministic leader election that all nodes agree on
func (m *Manager) electLeader() {
	members := m.memberlist.Members()
	if len(members) == 0 {
		// No members (shouldn't happen, but handle gracefully)
		m.mu.Lock()
		m.isLeader = true
		m.leaderID = m.nodeID
		m.mu.Unlock()
		return
	}

	// Find the lexicographically smallest node ID (deterministic leader selection)
	var leaderNode *memberlist.Node
	for _, member := range members {
		if leaderNode == nil || member.Name < leaderNode.Name {
			leaderNode = member
		}
	}

	m.mu.Lock()
	oldLeader := m.leaderID
	oldIsLeader := m.isLeader
	m.leaderID = leaderNode.Name
	m.isLeader = (leaderNode.Name == m.nodeID)
	newIsLeader := m.isLeader
	newLeaderID := m.leaderID
	m.mu.Unlock()

	// Check if leadership changed
	leadershipChanged := (oldIsLeader != newIsLeader) || (oldLeader != newLeaderID)

	// Log leadership changes
	if oldLeader != newLeaderID {
		logger.Info("Cluster leader changed", "old", oldLeader, "new", newLeaderID, "is_leader", newIsLeader)
	} else if !oldIsLeader && newIsLeader {
		logger.Info("This node became the cluster leader", "node_id", m.nodeID)
	} else if oldIsLeader && !newIsLeader {
		logger.Info("This node is no longer the cluster leader", "new_leader", newLeaderID)
	}

	// Notify callbacks if leadership changed
	if leadershipChanged {
		m.notifyLeaderChange(newIsLeader, newLeaderID)
	}
}

// OnLeaderChange registers a callback to be called when leadership changes
// The callback receives: isLeader (whether this node is now the leader), newLeaderID (the new leader's node ID)
func (m *Manager) OnLeaderChange(callback func(isLeader bool, newLeaderID string)) {
	m.callbackMu.Lock()
	defer m.callbackMu.Unlock()
	m.leaderChangeCallbacks = append(m.leaderChangeCallbacks, callback)
}

// RegisterRateLimitHandler registers a callback to handle rate limit events from the cluster
func (m *Manager) RegisterRateLimitHandler(handler func([]byte)) {
	m.rateLimitMu.Lock()
	defer m.rateLimitMu.Unlock()
	m.rateLimitHandlers = append(m.rateLimitHandlers, newHandlerQueue(m.ctx, "rate-limit", handler))
}

// notifyRateLimitHandlers queues an event for all registered rate limit handlers
func (m *Manager) notifyRateLimitHandlers(data []byte) {
	m.rateLimitMu.RLock()
	queues := m.rateLimitHandlers
	m.rateLimitMu.RUnlock()

	deliverGossip(queues, data)
}

// RegisterRateLimitBroadcaster registers a callback to generate rate limit broadcasts
func (m *Manager) RegisterRateLimitBroadcaster(broadcaster func(int, int) [][]byte) {
	m.broadcastMu.Lock()
	defer m.broadcastMu.Unlock()
	m.rateLimitBroadcasts = append(m.rateLimitBroadcasts, broadcaster)
}

// RegisterAffinityHandler registers a callback to handle affinity events from the cluster
func (m *Manager) RegisterAffinityHandler(handler func([]byte)) {
	m.affinityMu.Lock()
	defer m.affinityMu.Unlock()
	m.affinityHandlers = append(m.affinityHandlers, newHandlerQueue(m.ctx, "affinity", handler))
}

// notifyAffinityHandlers queues an event for all registered affinity handlers
func (m *Manager) notifyAffinityHandlers(data []byte) {
	m.affinityMu.RLock()
	queues := m.affinityHandlers
	m.affinityMu.RUnlock()

	deliverGossip(queues, data)
}

// RegisterAffinityBroadcaster registers a callback to generate affinity broadcasts
func (m *Manager) RegisterAffinityBroadcaster(broadcaster func(int, int) [][]byte) {
	m.affinityBroadcastMu.Lock()
	defer m.affinityBroadcastMu.Unlock()
	m.affinityBroadcasts = append(m.affinityBroadcasts, broadcaster)
}

// RegisterConnectionHandler registers a callback to handle connection events from the cluster
func (m *Manager) RegisterConnectionHandler(handler func([]byte)) {
	m.connectionMu.Lock()
	defer m.connectionMu.Unlock()
	m.connectionHandlers = append(m.connectionHandlers, newHandlerQueue(m.ctx, "connection", handler))
	logger.Info("Cluster: RegisterConnectionHandler", "handlers", len(m.connectionHandlers))
}

// notifyConnectionHandlers queues an event for all registered connection handlers
func (m *Manager) notifyConnectionHandlers(data []byte) {
	m.connectionMu.RLock()
	queues := m.connectionHandlers
	m.connectionMu.RUnlock()

	logger.Debug("Cluster: Notifying connection handlers", "handlers", len(queues), "data_len", len(data))

	deliverGossip(queues, data)
}

// RegisterConnectionBroadcaster registers a callback to generate connection broadcasts
func (m *Manager) RegisterConnectionBroadcaster(broadcaster func(int, int) [][]byte) {
	m.connectionBroadcastMu.Lock()
	defer m.connectionBroadcastMu.Unlock()
	m.connectionBroadcasts = append(m.connectionBroadcasts, broadcaster)
	logger.Debug("Cluster: RegisterConnectionBroadcaster", "count", len(m.connectionBroadcasts))
}

// collectBroadcasts gathers messages from the given broadcast sources, tags each
// with its subsystem marker and enforces the byte budget memberlist handed us.
// memberlist does not re-check what a delegate returns, so a message that cannot
// fit the budget is dropped here rather than handed to the UDP transport.
func collectBroadcasts(kind string, marker [2]byte, broadcasters []func(int, int) [][]byte, overhead, limit int) [][]byte {
	var allBroadcasts [][]byte
	totalSize := 0

	for _, broadcaster := range broadcasters {
		// Sources budget for the marker prepended below.
		for _, msg := range broadcaster(overhead+len(marker), limit-totalSize) {
			marked := make([]byte, 0, len(marker)+len(msg))
			marked = append(marked, marker[:]...)
			marked = append(marked, msg...)

			msgSize := overhead + len(marked)
			if msgSize > limit {
				logger.Warn("Cluster: Dropping oversized gossip message", "kind", kind, "size", msgSize, "limit", limit)
				continue
			}
			if totalSize+msgSize > limit {
				continue
			}

			allBroadcasts = append(allBroadcasts, marked)
			totalSize += msgSize
		}
	}

	if len(allBroadcasts) > 0 {
		logger.Debug("Cluster: Collected gossip broadcasts", "kind", kind, "messages", len(allBroadcasts), "bytes", totalSize)
	}
	return allBroadcasts
}

// getConnectionBroadcasts collects broadcasts from all registered connection broadcasters
func (m *Manager) getConnectionBroadcasts(overhead, limit int) [][]byte {
	m.connectionBroadcastMu.RLock()
	broadcasters := make([]func(int, int) [][]byte, len(m.connectionBroadcasts))
	copy(broadcasters, m.connectionBroadcasts)
	m.connectionBroadcastMu.RUnlock()

	return collectBroadcasts("connection", markerConnection, broadcasters, overhead, limit)
}

// getAffinityBroadcasts collects broadcasts from all registered affinity broadcasters
func (m *Manager) getAffinityBroadcasts(overhead, limit int) [][]byte {
	m.affinityBroadcastMu.RLock()
	broadcasters := make([]func(int, int) [][]byte, len(m.affinityBroadcasts))
	copy(broadcasters, m.affinityBroadcasts)
	m.affinityBroadcastMu.RUnlock()

	return collectBroadcasts("affinity", markerAffinity, broadcasters, overhead, limit)
}

// getRateLimitBroadcasts collects broadcasts from all registered broadcasters
func (m *Manager) getRateLimitBroadcasts(overhead, limit int) [][]byte {
	m.broadcastMu.RLock()
	broadcasters := make([]func(int, int) [][]byte, len(m.rateLimitBroadcasts))
	copy(broadcasters, m.rateLimitBroadcasts)
	m.broadcastMu.RUnlock()

	return collectBroadcasts("rate-limit", markerRateLimit, broadcasters, overhead, limit)
}

// notifyLeaderChange calls all registered callbacks when leadership changes
func (m *Manager) notifyLeaderChange(isLeader bool, newLeaderID string) {
	m.callbackMu.RLock()
	callbacks := make([]func(bool, string), len(m.leaderChangeCallbacks))
	copy(callbacks, m.leaderChangeCallbacks)
	m.callbackMu.RUnlock()

	for _, callback := range callbacks {
		// Call callbacks in goroutines to avoid blocking election loop
		// Use timeout to prevent goroutine leaks from blocked callbacks
		go func(cb func(bool, string)) {
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() {
					if r := recover(); r != nil {
						logger.Error("Panic in leader change callback", "error", fmt.Errorf("%v", r))
					}
				}()
				cb(isLeader, newLeaderID)
			}()

			select {
			case <-done:
				// Callback completed successfully
			case <-time.After(30 * time.Second):
				logger.Warn("Cluster: Leader change callback timed out after 30s", "is_leader", isLeader, "leader_id", newLeaderID)
			case <-m.ctx.Done():
				// Manager shutting down
			}
		}(callback)
	}
}

// IsLeader returns true if this node is the current cluster leader
func (m *Manager) IsLeader() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isLeader
}

// GetLeaderID returns the node ID of the current cluster leader
func (m *Manager) GetLeaderID() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.leaderID
}

// GetNodeID returns this node's ID
func (m *Manager) GetNodeID() string {
	if m == nil {
		return ""
	}
	return m.nodeID
}

// GetMemberCount returns the number of nodes in the cluster
func (m *Manager) GetMemberCount() int {
	if m == nil || m.memberlist == nil {
		return 1
	}
	return m.memberlist.NumMembers()
}

// RetransmitMult returns the multiplier memberlist uses to decide how often a
// broadcast is retransmitted. Broadcast sources feed it to their own
// memberlist.TransmitLimitedQueue so that retransmission is counted by
// memberlist's formula rather than a copy of it.
func (m *Manager) RetransmitMult() int {
	if m == nil || m.retransmitMult <= 0 {
		return defaultRetransmitMult
	}
	return m.retransmitMult
}

// MaxBroadcastSize returns the largest message a broadcast source may queue. A
// message that never fits a datagram is never transmitted, and a broadcast is
// only retired once it has been transmitted, so an oversized message would sit
// in the queue forever. Sources reject it at the point where it is produced.
func (m *Manager) MaxBroadcastSize() int {
	size := defaultUDPBufferSize
	if m != nil && m.udpBufferSize > 0 {
		size = m.udpBufferSize
	}
	return size - broadcastFrameOverhead
}

// GetMembers returns information about all cluster members
func (m *Manager) GetMembers() []MemberInfo {
	members := m.memberlist.Members()
	result := make([]MemberInfo, len(members))
	for i, member := range members {
		result[i] = MemberInfo{
			Name: member.Name,
			Addr: member.Addr.String(),
			Port: member.Port,
		}
	}
	return result
}

// SendConnectionEventReliable delivers one connection event to every other
// member over TCP, outside the gossip epidemic, and reports how many peers took
// it. Gossip retires a broadcast after a bounded number of transmissions with
// no acknowledgement, which is the right trade for per-connection traffic but
// not for a kick: an operator issues those one at a time, so a connection per
// peer is affordable, and a peer that misses a kick keeps a session alive that
// was supposed to be closed cluster-wide.
func (m *Manager) SendConnectionEventReliable(msg []byte) (delivered, failed int) {
	if m == nil || m.memberlist == nil {
		return 0, 0
	}

	framed := make([]byte, 0, len(markerConnection)+len(msg))
	framed = append(framed, markerConnection[:]...)
	framed = append(framed, msg...)

	return fanOutReliable(m.memberlist.Members(), m.nodeID, m.memberlist.SendReliable, framed)
}

// fanOutReliable sends msg to every member but self, in parallel, and counts
// the outcomes. A failure is logged and reported rather than retried: the
// caller keeps the message queued for gossip as a backstop.
func fanOutReliable(members []*memberlist.Node, self string, send func(*memberlist.Node, []byte) error, msg []byte) (delivered, failed int) {
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, member := range members {
		if member.Name == self {
			continue
		}

		wg.Add(1)
		go func(node *memberlist.Node) {
			defer wg.Done()

			err := send(node, msg)

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed++
				logger.Warn("Cluster: Reliable send to member failed", "node", node.Name, "error", err)
				return
			}
			delivered++
		}(member)
	}

	wg.Wait()
	return delivered, failed
}

// RegisterIPLimitHandler registers a callback to handle per-IP limit events from the cluster
func (m *Manager) RegisterIPLimitHandler(handler func([]byte)) {
	m.ipLimitMu.Lock()
	defer m.ipLimitMu.Unlock()
	m.ipLimitHandlers = append(m.ipLimitHandlers, newHandlerQueue(m.ctx, "ip-limit", handler))
	logger.Info("Cluster: RegisterIPLimitHandler", "handlers", len(m.ipLimitHandlers))
}

// notifyIPLimitHandlers queues an event for all registered IP limit handlers
func (m *Manager) notifyIPLimitHandlers(data []byte) {
	m.ipLimitMu.RLock()
	queues := m.ipLimitHandlers
	m.ipLimitMu.RUnlock()

	logger.Debug("Cluster: Notifying IP limit handlers", "handlers", len(queues), "data_len", len(data))

	deliverGossip(queues, data)
}

// RegisterIPLimitBroadcaster registers a callback to generate per-IP limit broadcasts
func (m *Manager) RegisterIPLimitBroadcaster(broadcaster func(int, int) [][]byte) {
	m.ipLimitBroadcastMu.Lock()
	defer m.ipLimitBroadcastMu.Unlock()
	m.ipLimitBroadcasts = append(m.ipLimitBroadcasts, broadcaster)
	logger.Debug("Cluster: RegisterIPLimitBroadcaster", "count", len(m.ipLimitBroadcasts))
}

// getIPLimitBroadcasts collects broadcasts from all registered per-IP limit broadcasters
func (m *Manager) getIPLimitBroadcasts(overhead, limit int) [][]byte {
	m.ipLimitBroadcastMu.RLock()
	broadcasters := make([]func(int, int) [][]byte, len(m.ipLimitBroadcasts))
	copy(broadcasters, m.ipLimitBroadcasts)
	m.ipLimitBroadcastMu.RUnlock()

	return collectBroadcasts("ip-limit", markerIPLimit, broadcasters, overhead, limit)
}

// RegisterStateProvider registers a subsystem's full-state exchange with
// memberlist push/pull. Unlike gossip broadcasts, push/pull runs over TCP, so
// the payload is not bound by the UDP datagram budget.
//
// kind says which providers can merge this payload and must be the same on
// every node. name only distinguishes the providers of one kind within this
// node - the instance ID of the listener is the natural choice - and never has
// to agree with anything a peer chose, because the receiver dispatches on kind
// and the payload itself identifies whose state it carries.
func (m *Manager) RegisterStateProvider(kind, name string, local func() []byte, merge func([]byte)) {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()

	if m.stateProviders == nil {
		m.stateProviders = make(map[string]stateProvider)
	}

	registered := kind + ":" + name
	for i := 2; ; i++ {
		if _, taken := m.stateProviders[registered]; !taken {
			break
		}
		registered = fmt.Sprintf("%s:%s#%d", kind, name, i)
	}

	m.stateProviders[registered] = stateProvider{kind: kind, local: local, merge: merge}
	logger.Debug("Cluster: RegisterStateProvider", "kind", kind, "name", registered, "count", len(m.stateProviders))
}

// snapshotStateProviders returns a copy of the registered providers
func (m *Manager) snapshotStateProviders() map[string]stateProvider {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()

	providers := make(map[string]stateProvider, len(m.stateProviders))
	for name, provider := range m.stateProviders {
		providers[name] = provider
	}
	return providers
}

// localState collects the full state of every registered subsystem for a
// push/pull exchange with a peer
func (m *Manager) localState() []byte {
	providers := m.snapshotStateProviders()
	if len(providers) == 0 {
		return nil
	}

	state := make(map[string]stateEntry, len(providers))
	for name, provider := range providers {
		if data := provider.local(); len(data) > 0 {
			state[name] = stateEntry{Kind: provider.kind, Data: data}
		}
	}
	if len(state) == 0 {
		return nil
	}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(state); err != nil {
		logger.Warn("Cluster: Failed to encode local state", "error", err)
		return nil
	}

	logger.Debug("Cluster: Sending local state", "subsystems", len(state), "bytes", buf.Len())
	return buf.Bytes()
}

// mergeRemoteState hands a peer's push/pull state to the matching subsystems
func (m *Manager) mergeRemoteState(buf []byte) {
	if len(buf) == 0 {
		return
	}

	var state map[string]stateEntry
	if err := gob.NewDecoder(bytes.NewReader(buf)).Decode(&state); err != nil {
		logger.Warn("Cluster: Failed to decode remote state", "error", err, "len", len(buf))
		return
	}

	providers := m.snapshotStateProviders()
	for remoteName, entry := range state {
		merged := 0
		for name, provider := range providers {
			if provider.kind != entry.Kind {
				continue
			}
			merged++

			func() {
				defer func() {
					if r := recover(); r != nil {
						logger.Error("Panic in state merge", "name", name, "error", fmt.Errorf("%v", r))
					}
				}()
				provider.merge(entry.Data)
			}()
		}

		if merged == 0 {
			logger.Debug("Cluster: No state provider registered for remote state", "kind", entry.Kind, "remote_name", remoteName)
		}
	}
}

// MemberInfo holds information about a cluster member
type MemberInfo struct {
	Name string
	Addr string
	Port uint16
}

// memberlistLogger adapts memberlist's log output to our logger
type memberlistLogger struct {
	prefix string
}

func (m *memberlistLogger) Write(p []byte) (n int, err error) {
	msg := string(p)
	// Memberlist logs are very verbose, only log important ones
	if bytes.Contains(p, []byte("broadcasting")) ||
		bytes.Contains(p, []byte("GetBroadcasts")) ||
		bytes.Contains(p, []byte("gossip")) {
		logger.Debug("Cluster", "prefix", m.prefix, "msg", msg)
	}
	return len(p), nil
}

// Shutdown gracefully shuts down the cluster manager
func (m *Manager) Shutdown() error {
	logger.Info("Shutting down cluster manager")
	m.cancel()

	if m.memberlist != nil {
		// Leave the cluster gracefully
		if err := m.memberlist.Leave(time.Second * 5); err != nil {
			logger.Warn("Error leaving cluster", "error", err)
		}
		if err := m.memberlist.Shutdown(); err != nil {
			return fmt.Errorf("failed to shutdown memberlist: %w", err)
		}
	}

	logger.Info("Cluster manager shutdown complete")
	return nil
}

// memberlist.Delegate implementation

func (d *clusterDelegate) NodeMeta(limit int) []byte {
	d.metaLock.RLock()
	defer d.metaLock.RUnlock()
	return d.meta
}

func (d *clusterDelegate) NotifyMsg(msg []byte) {
	logger.Debug("Cluster: NotifyMsg called", "len", len(msg))

	if len(msg) < 2 {
		logger.Warn("Cluster: Received invalid message", "len", len(msg))
		return // Invalid message
	}

	// Check message type by magic marker
	if msg[0] == 0x52 && msg[1] == 0x4C { // 'R' 'L' - Rate Limit
		logger.Debug("Cluster: Received rate limit message", "len", len(msg))
		// Strip marker and forward to rate limit handlers
		d.manager.notifyRateLimitHandlers(msg[2:])
	} else if msg[0] == 0x41 && msg[1] == 0x46 { // 'A' 'F' - Affinity
		logger.Debug("Cluster: Received affinity message", "len", len(msg))
		// Strip marker and forward to affinity handlers
		d.manager.notifyAffinityHandlers(msg[2:])
	} else if msg[0] == 0x43 && msg[1] == 0x4E { // 'C' 'N' - Connection
		logger.Debug("Cluster: Received connection tracking message", "len", len(msg))
		// Strip marker and forward to connection handlers
		d.manager.notifyConnectionHandlers(msg[2:])
	} else if msg[0] == 0x49 && msg[1] == 0x50 { // 'I' 'P' - IP Limit
		logger.Debug("Cluster: Received per-IP limit message", "len", len(msg))
		// Strip marker and forward to IP limit handlers
		d.manager.notifyIPLimitHandlers(msg[2:])
	} else {
		logger.Warn("Cluster: Received unknown message type", "type", fmt.Sprintf("0x%02x%02x", msg[0], msg[1]), "len", len(msg))
	}
}

func (d *clusterDelegate) GetBroadcasts(overhead, limit int) [][]byte {
	logger.Debug("Cluster: GetBroadcasts called by memberlist", "overhead", overhead, "limit", limit)

	collectors := []func(int, int) [][]byte{
		d.manager.getRateLimitBroadcasts,
		d.manager.getAffinityBroadcasts,
		d.manager.getConnectionBroadcasts,
		d.manager.getIPLimitBroadcasts,
	}

	// A datagram holds only a couple of events, so with a fixed collector order
	// a busy subsystem would take the whole budget on every call and the others
	// would never gossip at all. Rotating which one is asked first gives each
	// the full budget on every fourth call.
	first := int(d.broadcastTurn.Add(1) % uint64(len(collectors)))

	var allBroadcasts [][]byte
	totalSize := 0

	for i := range collectors {
		// Each collector already enforces the budget it is given; this only
		// keeps the running total across subsystems.
		for _, msg := range collectors[(first+i)%len(collectors)](overhead, limit-totalSize) {
			msgSize := overhead + len(msg)
			if totalSize+msgSize > limit {
				continue
			}
			allBroadcasts = append(allBroadcasts, msg)
			totalSize += msgSize
		}
	}

	return allBroadcasts
}

func (d *clusterDelegate) LocalState(join bool) []byte {
	return d.manager.localState()
}

func (d *clusterDelegate) MergeRemoteState(buf []byte, join bool) {
	d.manager.mergeRemoteState(buf)
}
