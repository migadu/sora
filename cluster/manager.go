// Package cluster provides distributed coordination using HashiCorp memberlist
// for leader election and cluster membership.
package cluster

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
)

// Manager handles cluster coordination and leader election
type Manager struct {
	config                config.ClusterConfig
	memberlist            *memberlist.Memberlist
	delegate              *clusterDelegate
	nodeID                string
	isLeader              bool
	leaderID              string
	mu                    sync.RWMutex
	ctx                   context.Context
	cancel                context.CancelFunc
	leaderChangeCallbacks []func(isLeader bool, newLeaderID string)
	callbackMu            sync.RWMutex

	// Rate limit event handling
	rateLimitHandlers   []func([]byte)
	rateLimitMu         sync.RWMutex
	rateLimitBroadcasts []func(int, int) [][]byte
	broadcastMu         sync.RWMutex

	// Affinity event handling
	affinityHandlers    []func([]byte)
	affinityMu          sync.RWMutex
	affinityBroadcasts  []func(int, int) [][]byte
	affinityBroadcastMu sync.RWMutex

	// Connection tracking event handling
	connectionHandlers    []func([]byte)
	connectionMu          sync.RWMutex
	connectionBroadcasts  []func(int, int) [][]byte
	connectionBroadcastMu sync.RWMutex
}

// clusterDelegate implements memberlist.Delegate for custom cluster behavior
type clusterDelegate struct {
	meta     []byte
	manager  *Manager
	metaLock sync.RWMutex
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

	// Configure memberlist
	mlConfig := memberlist.DefaultLANConfig()
	mlConfig.Name = nodeID
	mlConfig.BindAddr = cfg.BindAddr
	mlConfig.BindPort = cfg.BindPort
	mlConfig.Delegate = m.delegate

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
		logger.Infof("Cluster encryption enabled with secret key")
	} else {
		logger.Warn("Cluster encryption disabled - secret_key not configured (NOT recommended for production)")
	}

	// Create memberlist
	ml, err := memberlist.Create(mlConfig)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create memberlist: %w", err)
	}

	m.memberlist = ml

	// Filter out self-references from peers list
	// A node should never list itself in the peers array as this causes gossip issues
	filteredPeers := make([]string, 0, len(cfg.Peers))
	selfReferenceFound := false
	for _, peer := range cfg.Peers {
		if peer == nodeID {
			selfReferenceFound = true
			logger.Warnf("Cluster configuration WARNING: node_id '%s' found in peers list - ignoring self-reference", nodeID)
			logger.Warnf("The peers list should only contain OTHER nodes in the cluster, not this node itself")
		} else {
			filteredPeers = append(filteredPeers, peer)
		}
	}

	// Join cluster if peers are specified (after filtering)
	if len(filteredPeers) > 0 {
		n, err := ml.Join(filteredPeers)
		if err != nil {
			logger.Warn("Failed to join cluster peers: %v (will retry in background)", err)
		} else {
			logger.Infof("Successfully joined cluster with %d peers", n)
		}
	}

	// Start leader election loop
	go m.leaderElectionLoop()

	if selfReferenceFound {
		logger.Infof("Cluster manager started: node_id=%s, bind=%s:%d, original_peers=%v, filtered_peers=%v",
			nodeID, cfg.BindAddr, cfg.BindPort, cfg.Peers, filteredPeers)
	} else {
		logger.Infof("Cluster manager started: node_id=%s, bind=%s:%d, peers=%v",
			nodeID, cfg.BindAddr, cfg.BindPort, filteredPeers)
	}

	return m, nil
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
		logger.Infof("Cluster leader changed: %s -> %s (this node is leader: %v)",
			oldLeader, newLeaderID, newIsLeader)
	} else if !oldIsLeader && newIsLeader {
		logger.Infof("This node became the cluster leader: %s", m.nodeID)
	} else if oldIsLeader && !newIsLeader {
		logger.Infof("This node is no longer the cluster leader (new leader: %s)", newLeaderID)
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
	m.rateLimitHandlers = append(m.rateLimitHandlers, handler)
}

// notifyRateLimitHandlers calls all registered rate limit handlers
func (m *Manager) notifyRateLimitHandlers(data []byte) {
	m.rateLimitMu.RLock()
	handlers := make([]func([]byte), len(m.rateLimitHandlers))
	copy(handlers, m.rateLimitHandlers)
	m.rateLimitMu.RUnlock()

	// Call handlers asynchronously to avoid blocking gossip receive
	for _, handler := range handlers {
		go handler(data)
	}
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
	m.affinityHandlers = append(m.affinityHandlers, handler)
}

// notifyAffinityHandlers calls all registered affinity handlers
func (m *Manager) notifyAffinityHandlers(data []byte) {
	m.affinityMu.RLock()
	handlers := make([]func([]byte), len(m.affinityHandlers))
	copy(handlers, m.affinityHandlers)
	m.affinityMu.RUnlock()

	// Call handlers asynchronously to avoid blocking gossip receive
	for _, handler := range handlers {
		go handler(data)
	}
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
	m.connectionHandlers = append(m.connectionHandlers, handler)
}

// notifyConnectionHandlers calls all registered connection handlers
func (m *Manager) notifyConnectionHandlers(data []byte) {
	m.connectionMu.RLock()
	handlers := make([]func([]byte), len(m.connectionHandlers))
	copy(handlers, m.connectionHandlers)
	handlerCount := len(m.connectionHandlers)
	m.connectionMu.RUnlock()

	logger.Debugf("[Cluster] Notifying %d connection handlers with data (len=%d)", handlerCount, len(data))

	// Call handlers asynchronously to avoid blocking gossip receive
	for _, handler := range handlers {
		go handler(data)
	}
}

// RegisterConnectionBroadcaster registers a callback to generate connection broadcasts
func (m *Manager) RegisterConnectionBroadcaster(broadcaster func(int, int) [][]byte) {
	m.connectionBroadcastMu.Lock()
	defer m.connectionBroadcastMu.Unlock()
	m.connectionBroadcasts = append(m.connectionBroadcasts, broadcaster)
}

// getConnectionBroadcasts collects broadcasts from all registered connection broadcasters
func (m *Manager) getConnectionBroadcasts(overhead, limit int) [][]byte {
	m.connectionBroadcastMu.RLock()
	broadcasters := make([]func(int, int) [][]byte, len(m.connectionBroadcasts))
	copy(broadcasters, m.connectionBroadcasts)
	broadcasterCount := len(m.connectionBroadcasts)
	m.connectionBroadcastMu.RUnlock()

	logger.Debugf("[Cluster] getConnectionBroadcasts called: %d broadcasters registered", broadcasterCount)

	var allBroadcasts [][]byte
	totalSize := 0

	for idx, broadcaster := range broadcasters {
		broadcasts := broadcaster(overhead, limit-totalSize)
		logger.Debugf("[Cluster] Broadcaster %d returned %d messages", idx, len(broadcasts))
		for _, msg := range broadcasts {
			// Add 'CN' magic marker to identify connection messages
			marked := make([]byte, len(msg)+2)
			marked[0] = 0x43 // 'C'
			marked[1] = 0x4E // 'N'
			copy(marked[2:], msg)

			msgSize := overhead + len(marked)
			if totalSize+msgSize > limit && len(allBroadcasts) > 0 {
				logger.Debugf("[Cluster] Connection broadcast limit reached: returning %d messages", len(allBroadcasts))
				return allBroadcasts
			}

			allBroadcasts = append(allBroadcasts, marked)
			totalSize += msgSize
		}
	}

	logger.Debugf("[Cluster] getConnectionBroadcasts returning %d total messages", len(allBroadcasts))
	return allBroadcasts
}

// getAffinityBroadcasts collects broadcasts from all registered affinity broadcasters
func (m *Manager) getAffinityBroadcasts(overhead, limit int) [][]byte {
	m.affinityBroadcastMu.RLock()
	broadcasters := make([]func(int, int) [][]byte, len(m.affinityBroadcasts))
	copy(broadcasters, m.affinityBroadcasts)
	m.affinityBroadcastMu.RUnlock()

	var allBroadcasts [][]byte
	totalSize := 0

	for _, broadcaster := range broadcasters {
		broadcasts := broadcaster(overhead, limit-totalSize)
		for _, msg := range broadcasts {
			// Add 'AF' magic marker to identify affinity messages
			marked := make([]byte, len(msg)+2)
			marked[0] = 0x41 // 'A'
			marked[1] = 0x46 // 'F'
			copy(marked[2:], msg)

			msgSize := overhead + len(marked)
			if totalSize+msgSize > limit && len(allBroadcasts) > 0 {
				return allBroadcasts
			}

			allBroadcasts = append(allBroadcasts, marked)
			totalSize += msgSize
		}
	}

	return allBroadcasts
}

// getRateLimitBroadcasts collects broadcasts from all registered broadcasters
func (m *Manager) getRateLimitBroadcasts(overhead, limit int) [][]byte {
	m.broadcastMu.RLock()
	broadcasters := make([]func(int, int) [][]byte, len(m.rateLimitBroadcasts))
	copy(broadcasters, m.rateLimitBroadcasts)
	m.broadcastMu.RUnlock()

	var allBroadcasts [][]byte
	totalSize := 0

	for _, broadcaster := range broadcasters {
		broadcasts := broadcaster(overhead, limit-totalSize)
		for _, msg := range broadcasts {
			// Add 'RL' magic marker to identify rate limit messages
			marked := make([]byte, len(msg)+2)
			marked[0] = 0x52 // 'R'
			marked[1] = 0x4C // 'L'
			copy(marked[2:], msg)

			msgSize := overhead + len(marked)
			if totalSize+msgSize > limit && len(allBroadcasts) > 0 {
				return allBroadcasts
			}

			allBroadcasts = append(allBroadcasts, marked)
			totalSize += msgSize
		}
	}

	return allBroadcasts
}

// notifyLeaderChange calls all registered callbacks when leadership changes
func (m *Manager) notifyLeaderChange(isLeader bool, newLeaderID string) {
	m.callbackMu.RLock()
	callbacks := make([]func(bool, string), len(m.leaderChangeCallbacks))
	copy(callbacks, m.leaderChangeCallbacks)
	m.callbackMu.RUnlock()

	for _, callback := range callbacks {
		// Call callbacks in goroutines to avoid blocking election loop
		go func(cb func(bool, string)) {
			defer func() {
				if r := recover(); r != nil {
					logger.Error("Panic in leader change callback", fmt.Errorf("%v", r))
				}
			}()
			cb(isLeader, newLeaderID)
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
	return m.nodeID
}

// GetMemberCount returns the number of nodes in the cluster
func (m *Manager) GetMemberCount() int {
	return m.memberlist.NumMembers()
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

// MemberInfo holds information about a cluster member
type MemberInfo struct {
	Name string
	Addr string
	Port uint16
}

// Shutdown gracefully shuts down the cluster manager
func (m *Manager) Shutdown() error {
	logger.Info("Shutting down cluster manager")
	m.cancel()

	if m.memberlist != nil {
		// Leave the cluster gracefully
		if err := m.memberlist.Leave(time.Second * 5); err != nil {
			logger.Warn("Error leaving cluster: %v", err)
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
	if len(msg) < 2 {
		logger.Debugf("[Cluster] Received invalid message (len=%d)", len(msg))
		return // Invalid message
	}

	// Check message type by magic marker
	if msg[0] == 0x52 && msg[1] == 0x4C { // 'R' 'L' - Rate Limit
		logger.Debugf("[Cluster] Received rate limit message (len=%d)", len(msg))
		// Strip marker and forward to rate limit handlers
		d.manager.notifyRateLimitHandlers(msg[2:])
	} else if msg[0] == 0x41 && msg[1] == 0x46 { // 'A' 'F' - Affinity
		logger.Debugf("[Cluster] Received affinity message (len=%d)", len(msg))
		// Strip marker and forward to affinity handlers
		d.manager.notifyAffinityHandlers(msg[2:])
	} else if msg[0] == 0x43 && msg[1] == 0x4E { // 'C' 'N' - Connection
		logger.Debugf("[Cluster] Received connection tracking message (len=%d)", len(msg))
		// Strip marker and forward to connection handlers
		d.manager.notifyConnectionHandlers(msg[2:])
	} else {
		logger.Debugf("[Cluster] Received unknown message type: 0x%02x%02x (len=%d)", msg[0], msg[1], len(msg))
	}
}

func (d *clusterDelegate) GetBroadcasts(overhead, limit int) [][]byte {
	// Collect broadcasts from all registered broadcasters
	var allBroadcasts [][]byte
	totalSize := 0

	// Get rate limit broadcasts
	rateLimitBroadcasts := d.manager.getRateLimitBroadcasts(overhead, limit-totalSize)
	for _, msg := range rateLimitBroadcasts {
		msgSize := overhead + len(msg)
		if totalSize+msgSize > limit && len(allBroadcasts) > 0 {
			return allBroadcasts
		}
		allBroadcasts = append(allBroadcasts, msg)
		totalSize += msgSize
	}

	// Get affinity broadcasts
	affinityBroadcasts := d.manager.getAffinityBroadcasts(overhead, limit-totalSize)
	for _, msg := range affinityBroadcasts {
		msgSize := overhead + len(msg)
		if totalSize+msgSize > limit && len(allBroadcasts) > 0 {
			return allBroadcasts
		}
		allBroadcasts = append(allBroadcasts, msg)
		totalSize += msgSize
	}

	// Get connection broadcasts
	connectionBroadcasts := d.manager.getConnectionBroadcasts(overhead, limit-totalSize)
	for _, msg := range connectionBroadcasts {
		msgSize := overhead + len(msg)
		if totalSize+msgSize > limit && len(allBroadcasts) > 0 {
			return allBroadcasts
		}
		allBroadcasts = append(allBroadcasts, msg)
		totalSize += msgSize
	}

	return allBroadcasts
}

func (d *clusterDelegate) LocalState(join bool) []byte {
	// Return local state (not used for basic leader election)
	return nil
}

func (d *clusterDelegate) MergeRemoteState(buf []byte, join bool) {
	// Merge remote state (not used for basic leader election)
}
