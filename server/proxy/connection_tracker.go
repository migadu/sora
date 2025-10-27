package proxy

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
)

// ConnectionInfo represents an active connection in memory
type ConnectionInfo struct {
	AccountID       int64
	Protocol        string
	ClientAddr      string
	ServerAddr      string
	Email           string
	InstanceID      string
	ConnectedAt     time.Time
	LastActivity    time.Time
	ShouldTerminate bool
	IsProxy         bool // Whether this is a proxy connection
	// Fields for tracking changes
	isNew      bool
	isModified bool
}

// ConnectionTracker manages connection tracking with in-memory caching
type ConnectionTracker struct {
	rdb                     *resilient.ResilientDatabase
	name                    string // e.g. "IMAP", "POP3"
	instanceID              string
	connections             map[string]*ConnectionInfo // key: "accountID:protocol:clientAddr"
	mu                      sync.RWMutex
	updateInterval          time.Duration
	terminationPollInterval time.Duration
	operationTimeout        time.Duration // Timeout for individual operations (register/unregister)
	batchFlushTimeout       time.Duration // Timeout for batch flush operations
	persistToDB             bool
	batchUpdates            bool
	enabled                 bool
	kickCh                  chan struct{}
	stopCh                  chan struct{}
	wg                      sync.WaitGroup
	stopped                 bool
}

// NewConnectionTracker creates a new connection tracker
func NewConnectionTracker(name string, rdb *resilient.ResilientDatabase, instanceID string, updateInterval, terminationPollInterval, operationTimeout, batchFlushTimeout time.Duration, persistToDB, batchUpdates, enabled bool) *ConnectionTracker {
	tracker := &ConnectionTracker{
		rdb:                     rdb,
		name:                    name,
		instanceID:              instanceID,
		connections:             make(map[string]*ConnectionInfo),
		updateInterval:          updateInterval,
		terminationPollInterval: terminationPollInterval,
		operationTimeout:        operationTimeout,
		batchFlushTimeout:       batchFlushTimeout,
		persistToDB:             persistToDB,
		batchUpdates:            batchUpdates,
		enabled:                 enabled,
		kickCh:                  make(chan struct{}),
		stopCh:                  make(chan struct{}),
	}

	if enabled && persistToDB {
		if batchUpdates {
			tracker.startBatchUpdater()
		}
		// Start poller for immediate kick notifications
		tracker.startTerminationPoller()
	}

	return tracker
}

// Start starts the connection tracker
func (ct *ConnectionTracker) Start() {
	if !ct.enabled {
		return
	}

	// Load existing connections from database if persisting
	if ct.persistToDB {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Cleanup stale connections for this instance on startup
		removed, err := ct.rdb.CleanupConnectionsByInstanceIDWithRetry(ctx, ct.instanceID)
		if err != nil {
			log.Printf("[ConnectionTracker:%s] WARNING: Failed to cleanup stale connections for instance %s: %v", ct.name, ct.instanceID, err)
		} else if removed > 0 {
			log.Printf("[ConnectionTracker:%s] Cleaned up %d stale connections for instance %s", ct.name, removed, ct.instanceID)
		}
	}
}

// IsEnabled returns true if the connection tracker is enabled.
func (ct *ConnectionTracker) IsEnabled() bool {
	return ct.enabled
}

// GetOperationTimeout returns the configured timeout for individual operations
func (ct *ConnectionTracker) GetOperationTimeout() time.Duration {
	return ct.operationTimeout
}

// Stop stops the connection tracker
func (ct *ConnectionTracker) Stop() {
	ct.mu.Lock()
	if ct.stopped {
		ct.mu.Unlock()
		return
	}
	ct.stopped = true
	ct.mu.Unlock()

	close(ct.stopCh)
	ct.wg.Wait()

	// Flush any remaining changes
	if ct.enabled && ct.persistToDB {
		ct.flushChanges()
	}
}

// RegisterConnection registers a new connection
func (ct *ConnectionTracker) RegisterConnection(ctx context.Context, accountID int64, protocol, clientAddr, serverAddr, email string, isProxy bool) error {
	if !ct.enabled {
		return nil
	}

	key := ct.makeKey(accountID, protocol, clientAddr)

	ct.mu.Lock()
	ct.connections[key] = &ConnectionInfo{
		AccountID:    accountID,
		Protocol:     protocol,
		ClientAddr:   clientAddr,
		ServerAddr:   serverAddr,
		Email:        email,
		InstanceID:   ct.instanceID,
		ConnectedAt:  time.Now(),
		LastActivity: time.Now(),
		IsProxy:      isProxy,
		isNew:        true,
	}
	ct.mu.Unlock()

	// If not batching, write immediately
	if ct.persistToDB && !ct.batchUpdates {
		return ct.rdb.RegisterConnectionWithRetry(ctx, accountID, protocol, clientAddr, serverAddr, ct.instanceID, email, isProxy)
	}

	return nil
}

// UpdateActivity updates the last activity time for a connection
func (ct *ConnectionTracker) UpdateActivity(ctx context.Context, accountID int64, protocol, clientAddr string) error {
	if !ct.enabled {
		return nil
	}

	key := ct.makeKey(accountID, protocol, clientAddr)

	ct.mu.Lock()
	if conn, exists := ct.connections[key]; exists {
		conn.LastActivity = time.Now()
		if !conn.isNew {
			conn.isModified = true
		}
	}
	ct.mu.Unlock()

	// If not batching, write immediately
	if ct.persistToDB && !ct.batchUpdates {
		return ct.rdb.UpdateConnectionActivityWithRetry(ctx, accountID, protocol, clientAddr)
	}

	return nil
}

// UnregisterConnection removes a connection
func (ct *ConnectionTracker) UnregisterConnection(ctx context.Context, accountID int64, protocol, clientAddr string) error {
	if !ct.enabled {
		return nil
	}

	key := ct.makeKey(accountID, protocol, clientAddr)

	ct.mu.Lock()
	_, exists := ct.connections[key]
	if exists {
		delete(ct.connections, key)
	}
	ct.mu.Unlock()

	// If persistence is enabled and the connection was tracked in memory,
	// always attempt to unregister from the DB.
	// The DB call is idempotent for non-existent rows.
	if ct.persistToDB && exists {
		return ct.rdb.UnregisterConnectionWithRetry(ctx, accountID, protocol, clientAddr)
	}

	return nil
}

// CheckTermination checks if a connection should be terminated
func (ct *ConnectionTracker) CheckTermination(ctx context.Context, accountID int64, protocol, clientAddr string) (bool, error) {
	if !ct.enabled {
		return false, nil
	}

	key := ct.makeKey(accountID, protocol, clientAddr)

	ct.mu.RLock()
	conn, exists := ct.connections[key]
	if exists {
		shouldTerminate := conn.ShouldTerminate
		ct.mu.RUnlock()
		return shouldTerminate, nil
	}
	ct.mu.RUnlock()

	// If not in memory and we're persisting, check database
	if ct.persistToDB {
		return ct.rdb.CheckConnectionTerminationWithRetry(ctx, accountID, protocol, clientAddr)
	}

	return false, nil
}

// GetActiveConnections returns all active connections
func (ct *ConnectionTracker) GetActiveConnections(ctx context.Context) ([]db.ConnectionInfo, error) {
	if !ct.enabled {
		return []db.ConnectionInfo{}, nil
	}

	ct.mu.RLock()
	defer ct.mu.RUnlock()

	var connections []db.ConnectionInfo
	for _, conn := range ct.connections {
		connections = append(connections, db.ConnectionInfo{
			AccountID:       conn.AccountID,
			Protocol:        conn.Protocol,
			ClientAddr:      conn.ClientAddr,
			ServerAddr:      conn.ServerAddr,
			InstanceID:      conn.InstanceID,
			ConnectedAt:     conn.ConnectedAt,
			LastActivity:    conn.LastActivity,
			ShouldTerminate: conn.ShouldTerminate,
		})
	}

	return connections, nil
}

// GetConnectionStats returns connection statistics
func (ct *ConnectionTracker) GetConnectionStats(ctx context.Context) (*db.ConnectionStats, error) {
	if !ct.enabled {
		return &db.ConnectionStats{
			ConnectionsByProtocol: make(map[string]int64),
			ConnectionsByServer:   make(map[string]int64),
			Users:                 []db.ConnectionInfo{},
		}, nil
	}

	connections, err := ct.GetActiveConnections(ctx)
	if err != nil {
		return nil, err
	}

	stats := &db.ConnectionStats{
		TotalConnections:      int64(len(connections)),
		ConnectionsByProtocol: make(map[string]int64),
		ConnectionsByServer:   make(map[string]int64),
		Users:                 connections,
	}

	for _, conn := range connections {
		stats.ConnectionsByProtocol[conn.Protocol]++
		stats.ConnectionsByServer[conn.ServerAddr]++
	}

	return stats, nil
}

// MarkConnectionsForTermination marks connections for termination
func (ct *ConnectionTracker) MarkConnectionsForTermination(ctx context.Context, criteria db.TerminationCriteria) (int64, error) {
	if !ct.enabled {
		return 0, nil
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()

	var marked int64
	for _, conn := range ct.connections {
		shouldMark := true

		// Apply criteria
		if criteria.Protocol != "" && conn.Protocol != criteria.Protocol {
			shouldMark = false
		}
		if criteria.ServerAddr != "" && conn.ServerAddr != criteria.ServerAddr {
			shouldMark = false
		}
		if criteria.ClientAddr != "" && conn.ClientAddr != criteria.ClientAddr {
			shouldMark = false
		}

		// For email criteria, we'd need to look up in database
		// For now, we'll mark in memory and let batch update handle it

		if shouldMark {
			conn.ShouldTerminate = true
			conn.isModified = true
			marked++
		}
	}

	return marked, nil
}

// KickChannel returns a channel that is closed when a kick notification is received.
func (ct *ConnectionTracker) KickChannel() <-chan struct{} {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return ct.kickCh
}

// startTerminationPoller periodically checks the database for connections that have been marked for termination.
func (ct *ConnectionTracker) startTerminationPoller() {
	ct.wg.Add(1)
	go func() {
		defer ct.wg.Done()
		// This is more reliable than LISTEN/NOTIFY in a replicated DB environment.
		ticker := time.NewTicker(ct.terminationPollInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				reloaded, err := ct.reloadTerminatedConnections(context.Background())
				if err != nil {
					log.Printf("[ConnectionTracker:%s] Error polling for terminations: %v", ct.name, err)
					continue
				}

				if reloaded > 0 {
					log.Printf("[ConnectionTracker:%s] Found %d newly terminated connections, broadcasting kick.", ct.name, reloaded)
					ct.mu.Lock()
					close(ct.kickCh)
					ct.kickCh = make(chan struct{})
					ct.mu.Unlock()
				}
			case <-ct.stopCh:
				return
			}
		}
	}()
}

// startBatchUpdater starts the background batch updater
func (ct *ConnectionTracker) startBatchUpdater() {
	ct.wg.Add(1)
	go func() {
		defer ct.wg.Done()

		ticker := time.NewTicker(ct.updateInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				ct.flushChanges()
			case <-ct.stopCh:
				return
			}
		}
	}()
}

// flushChanges writes pending changes to the database
func (ct *ConnectionTracker) flushChanges() {
	if !ct.persistToDB {
		return
	}

	ct.mu.Lock()

	var (
		toInsert []db.ConnectionInfo
		toUpdate []db.ConnectionInfo
	)

	// Collect changes
	for _, conn := range ct.connections {
		if conn.isNew {
			toInsert = append(toInsert, db.ConnectionInfo{
				AccountID:  conn.AccountID,
				Protocol:   conn.Protocol,
				ClientAddr: conn.ClientAddr,
				ServerAddr: conn.ServerAddr,
				InstanceID: conn.InstanceID,
				Email:      conn.Email,
				IsProxy:    conn.IsProxy,
			})
			conn.isNew = false
		} else if conn.isModified {
			toUpdate = append(toUpdate, db.ConnectionInfo{
				AccountID:       conn.AccountID,
				Protocol:        conn.Protocol,
				ClientAddr:      conn.ClientAddr,
				LastActivity:    conn.LastActivity,
				ShouldTerminate: conn.ShouldTerminate,
			})
			conn.isModified = false
		}
	}
	ct.mu.Unlock() // Release lock before making DB calls

	if len(toInsert) == 0 && len(toUpdate) == 0 {
		return
	}

	// Use configurable timeout for batch operations - connection tracking is not time-critical
	ctx, cancel := context.WithTimeout(context.Background(), ct.batchFlushTimeout)
	defer cancel()

	// Apply changes to database in real batches
	// Connection tracking is non-critical monitoring data, so we tolerate failures gracefully
	if len(toInsert) > 0 {
		if err := ct.rdb.BatchRegisterConnectionsWithRetry(ctx, toInsert); err != nil {
			log.Printf("[ConnectionTracker:%s] Failed to batch insert %d connections (non-critical, will retry on next flush): %v", ct.name, len(toInsert), err)
			// Mark connections as new again so they'll be retried on next flush
			ct.mu.Lock()
			for _, connInfo := range toInsert {
				key := ct.makeKey(connInfo.AccountID, connInfo.Protocol, connInfo.ClientAddr)
				if conn, exists := ct.connections[key]; exists {
					conn.isNew = true
				}
			}
			ct.mu.Unlock()
		}
	}
	if len(toUpdate) > 0 {
		if err := ct.rdb.BatchUpdateConnectionsWithRetry(ctx, toUpdate); err != nil {
			log.Printf("[ConnectionTracker:%s] Failed to batch update %d connections (non-critical, will retry on next flush): %v", ct.name, len(toUpdate), err)
			// Mark connections as modified again so they'll be retried on next flush
			ct.mu.Lock()
			for _, connInfo := range toUpdate {
				key := ct.makeKey(connInfo.AccountID, connInfo.Protocol, connInfo.ClientAddr)
				if conn, exists := ct.connections[key]; exists {
					conn.isModified = true
				}
			}
			ct.mu.Unlock()
		}
	}
}

// reloadTerminatedConnections reloads connections that may have been marked for termination in the database
func (ct *ConnectionTracker) reloadTerminatedConnections(ctx context.Context) (int, error) {
	// Get all connections for this instance that have been marked for termination
	terminatedConns, err := ct.rdb.GetTerminatedConnectionsByInstanceWithRetry(ctx, ct.instanceID)
	if err != nil {
		log.Printf("[ConnectionTracker:%s] Failed to get terminated connections: %v", ct.name, err)
		return 0, err
	}

	if len(terminatedConns) == 0 {
		return 0, nil
	}

	var reloadedCount int
	ct.mu.Lock()
	defer ct.mu.Unlock()
	for _, dbConn := range terminatedConns {
		key := ct.makeKey(dbConn.AccountID, dbConn.Protocol, dbConn.ClientAddr)
		if conn, exists := ct.connections[key]; exists {
			// Only update and count if the state changes from not-terminated to terminated.
			if dbConn.ShouldTerminate && !conn.ShouldTerminate {
				conn.ShouldTerminate = true
				reloadedCount++
			}
		}
	}
	return reloadedCount, nil
}

// makeKey creates a unique key for a connection
func (ct *ConnectionTracker) makeKey(accountID int64, protocol, clientAddr string) string {
	return fmt.Sprintf("%d:%s:%s", accountID, protocol, clientAddr)
}
