package proxy

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/migadu/sora/db"
)

// ConnectionInfo represents an active connection in memory
type ConnectionInfo struct {
	AccountID       int64
	Protocol        string
	ClientAddr      string
	ServerAddr      string
	InstanceID      string
	ConnectedAt     time.Time
	LastActivity    time.Time
	ShouldTerminate bool
	// Fields for tracking changes
	isNew      bool
	isModified bool
}

// ConnectionTracker manages connection tracking with in-memory caching
type ConnectionTracker struct {
	db             *db.Database
	name           string // e.g. "IMAP", "POP3"
	instanceID     string
	connections    map[string]*ConnectionInfo // key: "accountID:protocol:clientAddr"
	mu             sync.RWMutex
	updateInterval time.Duration
	persistToDB    bool
	batchUpdates   bool
	enabled        bool
	kickCh         chan struct{}
	stopCh         chan struct{}
	wg             sync.WaitGroup
}

// NewConnectionTracker creates a new connection tracker
func NewConnectionTracker(name string, database *db.Database, instanceID string, updateInterval time.Duration, persistToDB, batchUpdates, enabled bool) *ConnectionTracker {
	tracker := &ConnectionTracker{
		db:             database,
		name:           name,
		instanceID:     instanceID,
		connections:    make(map[string]*ConnectionInfo),
		updateInterval: updateInterval,
		persistToDB:    persistToDB,
		batchUpdates:   batchUpdates,
		enabled:        enabled,
		kickCh:         make(chan struct{}),
		stopCh:         make(chan struct{}),
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
		removed, err := ct.db.CleanupConnectionsByInstanceID(ctx, ct.instanceID)
		if err != nil {
			log.Printf("[ConnectionTracker:%s] WARNING: Failed to cleanup stale connections for instance %s: %v", ct.name, ct.instanceID, err)
		} else if removed > 0 {
			log.Printf("[ConnectionTracker:%s] Cleaned up %d stale connections for instance %s", ct.name, removed, ct.instanceID)
		}

		connections, err := ct.db.GetActiveConnections(ctx)
		if err != nil {
			log.Printf("[ConnectionTracker:%s] Failed to load existing connections: %v", ct.name, err)
		} else {
			ct.mu.Lock()
			for _, conn := range connections {
				key := ct.makeKey(conn.AccountID, conn.Protocol, conn.ClientAddr)
				ct.connections[key] = &ConnectionInfo{
					AccountID:       conn.AccountID,
					Protocol:        conn.Protocol,
					ClientAddr:      conn.ClientAddr,
					ServerAddr:      conn.ServerAddr,
					InstanceID:      conn.InstanceID,
					ConnectedAt:     conn.ConnectedAt,
					LastActivity:    conn.LastActivity,
					ShouldTerminate: conn.ShouldTerminate,
				}
			}
			ct.mu.Unlock()
			log.Printf("[ConnectionTracker:%s] Loaded %d existing connections from other instances", ct.name, len(connections))
		}
	}
}

// IsEnabled returns true if the connection tracker is enabled.
func (ct *ConnectionTracker) IsEnabled() bool {
	return ct.enabled
}

// Stop stops the connection tracker
func (ct *ConnectionTracker) Stop() {
	close(ct.stopCh)
	ct.wg.Wait()

	// Flush any remaining changes
	if ct.enabled && ct.persistToDB {
		ct.flushChanges()
	}
}

// RegisterConnection registers a new connection
func (ct *ConnectionTracker) RegisterConnection(ctx context.Context, accountID int64, protocol, clientAddr, serverAddr string) error {
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
		InstanceID:   ct.instanceID,
		ConnectedAt:  time.Now(),
		LastActivity: time.Now(),
		isNew:        true,
	}
	ct.mu.Unlock()

	// If not batching, write immediately
	if ct.persistToDB && !ct.batchUpdates {
		return ct.db.RegisterConnection(ctx, accountID, protocol, clientAddr, serverAddr, ct.instanceID)
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
		return ct.db.UpdateConnectionActivity(ctx, accountID, protocol, clientAddr)
	}

	return nil
}

// UnregisterConnection removes a connection
func (ct *ConnectionTracker) UnregisterConnection(ctx context.Context, accountID int64, protocol, clientAddr string) error {
	if !ct.enabled {
		return nil
	}

	key := ct.makeKey(accountID, protocol, clientAddr)

	var wasPersisted bool
	ct.mu.Lock()
	if conn, exists := ct.connections[key]; exists {
		// If the connection was never persisted (isNew=true), we don't need to touch the DB.
		wasPersisted = !conn.isNew
		delete(ct.connections, key)
	}
	ct.mu.Unlock()

	// If not batching, write immediately
	// If the connection existed in our tracker and was already persisted to the DB,
	// unregister it from the DB immediately. This ensures external tools see the change right away.
	if ct.persistToDB && wasPersisted {
		return ct.db.UnregisterConnection(ctx, accountID, protocol, clientAddr)
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
		return ct.db.CheckConnectionTermination(ctx, accountID, protocol, clientAddr)
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

	// If email criteria is specified and we're persisting, also update database
	if criteria.Email != "" && ct.persistToDB {
		dbMarked, err := ct.db.MarkConnectionsForTermination(ctx, criteria)
		if err != nil {
			return marked, err
		}
		// Reload affected connections
		ct.reloadTerminatedConnections(ctx)
		return dbMarked, nil
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
		ticker := time.NewTicker(2 * time.Second) // Poll every 2 seconds.
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ct.mu.Lock()
	defer ct.mu.Unlock()

	var (
		toInsert []ConnectionInfo
		toUpdate []ConnectionInfo
	)

	// Collect changes
	for _, conn := range ct.connections {
		if conn.isNew {
			toInsert = append(toInsert, *conn)
			conn.isNew = false
		} else if conn.isModified {
			toUpdate = append(toUpdate, *conn)
			conn.isModified = false
		}
	}

	// Apply changes to database
	for _, conn := range toInsert {
		if err := ct.db.RegisterConnection(ctx, conn.AccountID, conn.Protocol, conn.ClientAddr, conn.ServerAddr, conn.InstanceID); err != nil {
			log.Printf("[ConnectionTracker:%s] Failed to insert connection: %v", ct.name, err)
		}
	}

	for _, conn := range toUpdate {
		if err := ct.db.UpdateConnectionActivity(ctx, conn.AccountID, conn.Protocol, conn.ClientAddr); err != nil {
			log.Printf("[ConnectionTracker:%s] Failed to update connection: %v", ct.name, err)
		}
	}

	if len(toInsert) > 0 || len(toUpdate) > 0 {
		log.Printf("[ConnectionTracker:%s] Batch update: %d inserts, %d updates",
			ct.name, len(toInsert), len(toUpdate))
	}
}

// reloadTerminatedConnections reloads connections that may have been marked for termination in the database
func (ct *ConnectionTracker) reloadTerminatedConnections(ctx context.Context) (int, error) {
	// Get all connections for this instance that have been marked for termination
	terminatedConns, err := ct.db.GetTerminatedConnectionsByInstance(ctx, ct.instanceID)
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
