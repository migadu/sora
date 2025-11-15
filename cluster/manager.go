// Package cluster provides distributed coordination using HashiCorp memberlist
// for leader election and cluster membership.
package cluster

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
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

	// Per-IP connection limit event handling
	ipLimitHandlers    []func([]byte)
	ipLimitMu          sync.RWMutex
	ipLimitBroadcasts  []func(int, int) [][]byte
	ipLimitBroadcastMu sync.RWMutex
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
	logger.Info("Cluster delegate created", "delegate", fmt.Sprintf("%p", m.delegate))

	// Configure memberlist
	mlConfig := memberlist.DefaultLANConfig()
	mlConfig.Name = nodeID

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
		logger.Warn("Cluster encryption disabled - secret_key not configured (NOT recommended for production)")
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
	m.rateLimitHandlers = append(m.rateLimitHandlers, handler)
}

// notifyRateLimitHandlers calls all registered rate limit handlers
func (m *Manager) notifyRateLimitHandlers(data []byte) {
	m.rateLimitMu.RLock()
	handlers := make([]func([]byte), len(m.rateLimitHandlers))
	copy(handlers, m.rateLimitHandlers)
	m.rateLimitMu.RUnlock()

	// Call handlers asynchronously to avoid blocking gossip receive
	// Use timeout to prevent goroutine leaks from blocked handlers
	for _, handler := range handlers {
		go func(h func([]byte)) {
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() {
					if r := recover(); r != nil {
						logger.Error("Panic in rate limit handler", "error", fmt.Errorf("%v", r))
					}
				}()
				h(data)
			}()

			select {
			case <-done:
				// Handler completed successfully
			case <-time.After(5 * time.Second):
				logger.Warn("Cluster: Rate limit handler timed out after 5s")
			case <-m.ctx.Done():
				// Manager shutting down
			}
		}(handler)
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
	// Use timeout to prevent goroutine leaks from blocked handlers
	for _, handler := range handlers {
		go func(h func([]byte)) {
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() {
					if r := recover(); r != nil {
						logger.Error("Panic in affinity handler", "error", fmt.Errorf("%v", r))
					}
				}()
				h(data)
			}()

			select {
			case <-done:
				// Handler completed successfully
			case <-time.After(5 * time.Second):
				logger.Warn("Cluster: Affinity handler timed out after 5s")
			case <-m.ctx.Done():
				// Manager shutting down
			}
		}(handler)
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
	logger.Info("Cluster: RegisterConnectionHandler", "handlers", len(m.connectionHandlers))
}

// notifyConnectionHandlers calls all registered connection handlers
func (m *Manager) notifyConnectionHandlers(data []byte) {
	m.connectionMu.RLock()
	handlers := make([]func([]byte), len(m.connectionHandlers))
	copy(handlers, m.connectionHandlers)
	handlerCount := len(m.connectionHandlers)
	m.connectionMu.RUnlock()

	logger.Debug("Cluster: Notifying connection handlers", "handlers", handlerCount, "data_len", len(data))

	// Call handlers asynchronously to avoid blocking gossip receive
	// Use timeout to prevent goroutine leaks from blocked handlers
	for _, handler := range handlers {
		go func(h func([]byte)) {
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() {
					if r := recover(); r != nil {
						logger.Error("Panic in connection handler", "error", fmt.Errorf("%v", r))
					}
				}()
				h(data)
			}()

			select {
			case <-done:
				// Handler completed successfully
			case <-time.After(5 * time.Second):
				logger.Warn("Cluster: Connection handler timed out after 5s")
			case <-m.ctx.Done():
				// Manager shutting down
			}
		}(handler)
	}
}

// RegisterConnectionBroadcaster registers a callback to generate connection broadcasts
func (m *Manager) RegisterConnectionBroadcaster(broadcaster func(int, int) [][]byte) {
	m.connectionBroadcastMu.Lock()
	defer m.connectionBroadcastMu.Unlock()
	m.connectionBroadcasts = append(m.connectionBroadcasts, broadcaster)
	logger.Debug("Cluster: RegisterConnectionBroadcaster", "count", len(m.connectionBroadcasts))
}

// getConnectionBroadcasts collects broadcasts from all registered connection broadcasters
func (m *Manager) getConnectionBroadcasts(overhead, limit int) [][]byte {
	m.connectionBroadcastMu.RLock()
	broadcasters := make([]func(int, int) [][]byte, len(m.connectionBroadcasts))
	copy(broadcasters, m.connectionBroadcasts)
	broadcasterCount := len(m.connectionBroadcasts)
	m.connectionBroadcastMu.RUnlock()

	logger.Debug("Cluster: getConnectionBroadcasts called", "broadcasters", broadcasterCount)

	var allBroadcasts [][]byte
	totalSize := 0

	for idx, broadcaster := range broadcasters {
		broadcasts := broadcaster(overhead, limit-totalSize)
		logger.Debug("Cluster: Broadcaster returned messages", "idx", idx, "count", len(broadcasts))
		for _, msg := range broadcasts {
			// Add 'CN' magic marker to identify connection messages
			marked := make([]byte, len(msg)+2)
			marked[0] = 0x43 // 'C'
			marked[1] = 0x4E // 'N'
			copy(marked[2:], msg)

			msgSize := overhead + len(marked)
			if totalSize+msgSize > limit && len(allBroadcasts) > 0 {
				logger.Debug("Cluster: Connection broadcast limit reached", "count", len(allBroadcasts))
				return allBroadcasts
			}

			allBroadcasts = append(allBroadcasts, marked)
			totalSize += msgSize
		}
	}

	logger.Debug("Cluster: getConnectionBroadcasts returning messages", "total", len(allBroadcasts))
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

// RegisterIPLimitHandler registers a callback to handle per-IP limit events from the cluster
func (m *Manager) RegisterIPLimitHandler(handler func([]byte)) {
	m.ipLimitMu.Lock()
	defer m.ipLimitMu.Unlock()
	m.ipLimitHandlers = append(m.ipLimitHandlers, handler)
	logger.Info("Cluster: RegisterIPLimitHandler", "handlers", len(m.ipLimitHandlers))
}

// notifyIPLimitHandlers calls all registered IP limit handlers
func (m *Manager) notifyIPLimitHandlers(data []byte) {
	m.ipLimitMu.RLock()
	handlers := make([]func([]byte), len(m.ipLimitHandlers))
	copy(handlers, m.ipLimitHandlers)
	handlerCount := len(m.ipLimitHandlers)
	m.ipLimitMu.RUnlock()

	logger.Debug("Cluster: Notifying IP limit handlers", "handlers", handlerCount, "data_len", len(data))

	// Call handlers asynchronously to avoid blocking gossip receive
	// Use timeout to prevent goroutine leaks from blocked handlers
	for _, handler := range handlers {
		go func(h func([]byte)) {
			done := make(chan struct{})
			go func() {
				defer close(done)
				h(data)
			}()

			select {
			case <-done:
				// Handler completed successfully
			case <-time.After(5 * time.Second):
				logger.Warn("Cluster: IP limit handler timed out after 5s")
			case <-m.ctx.Done():
				// Manager shutting down
			}
		}(handler)
	}
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
	broadcasterCount := len(m.ipLimitBroadcasts)
	m.ipLimitBroadcastMu.RUnlock()

	logger.Debug("Cluster: getIPLimitBroadcasts called", "broadcasters", broadcasterCount)

	var allBroadcasts [][]byte
	totalSize := 0

	for idx, broadcaster := range broadcasters {
		broadcasts := broadcaster(overhead, limit-totalSize)
		logger.Debug("Cluster: IP limit broadcaster returned messages", "idx", idx, "count", len(broadcasts))
		for _, msg := range broadcasts {
			// Add 'IP' magic marker to identify per-IP limit messages
			marked := make([]byte, len(msg)+2)
			marked[0] = 0x49 // 'I'
			marked[1] = 0x50 // 'P'
			copy(marked[2:], msg)

			msgSize := overhead + len(marked)
			if totalSize+msgSize > limit && len(allBroadcasts) > 0 {
				logger.Debug("Cluster: IP limit broadcast limit reached", "count", len(allBroadcasts))
				return allBroadcasts
			}

			allBroadcasts = append(allBroadcasts, marked)
			totalSize += msgSize
		}
	}

	logger.Debug("Cluster: getIPLimitBroadcasts returning messages", "total", len(allBroadcasts))
	return allBroadcasts
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

	// Get per-IP limit broadcasts
	ipLimitBroadcasts := d.manager.getIPLimitBroadcasts(overhead, limit-totalSize)
	for _, msg := range ipLimitBroadcasts {
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
