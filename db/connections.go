package db

import (
	"context"
	"fmt"
	"time"
)

// ConnectionInfo represents an active connection
type ConnectionInfo struct {
	ID              int64
	AccountID       int64
	Protocol        string
	ClientAddr      string
	ServerAddr      string
	InstanceID      string
	ConnectedAt     time.Time
	LastActivity    time.Time
	ShouldTerminate bool
	Email           string // Primary email for display
	IsProxy         bool   // Whether this is a proxy connection
}

// ConnectionStats represents aggregated connection statistics
type ConnectionStats struct {
	TotalConnections      int64
	ConnectionsByProtocol map[string]int64
	ConnectionsByServer   map[string]int64
	Users                 []ConnectionInfo
}

// NOTE: Connection tracking has been migrated to gossip-based system.
// The following write functions have been removed as they are no longer used:
// - RegisterConnection
// - UpdateConnectionActivity
// - UnregisterConnection
// - BatchRegisterConnections
// - BatchUpdateConnections
// - CleanupConnectionsByInstanceID
//
// See server/proxy/connection_tracker.go for the new gossip-based implementation.
// Read-only functions (GetActiveConnections, GetConnectionStats, GetUserConnections)
// are kept for admin API and CLI tool usage.

// GetActiveConnections retrieves all active connections
func (db *Database) GetActiveConnections(ctx context.Context) ([]ConnectionInfo, error) {
	query := `
		SELECT
			id,
			account_id,
			protocol,
			client_addr,
			server_addr,
			instance_id,
			connected_at,
			last_activity,
			should_terminate,
			email,
			is_proxy
		FROM active_connections
		ORDER BY server_addr, protocol, email`

	rows, err := db.GetReadPool().Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get active connections: %w", err)
	}
	defer rows.Close()

	var connections []ConnectionInfo
	for rows.Next() {
		var conn ConnectionInfo
		err := rows.Scan(&conn.ID, &conn.AccountID, &conn.Protocol, &conn.ClientAddr,
			&conn.ServerAddr, &conn.InstanceID, &conn.ConnectedAt, &conn.LastActivity, &conn.ShouldTerminate, &conn.Email, &conn.IsProxy)
		if err != nil {
			return nil, fmt.Errorf("failed to scan connection: %w", err)
		}
		connections = append(connections, conn)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating connections: %w", err)
	}

	return connections, nil
}

// GetConnectionStats retrieves aggregated connection statistics
func (db *Database) GetConnectionStats(ctx context.Context) (*ConnectionStats, error) {
	// Get all connection details
	connections, err := db.GetActiveConnections(ctx)
	if err != nil {
		return nil, err
	}

	// Derive all stats from the single list of connections.
	// This is more efficient than running multiple separate aggregate queries.
	protocolMap := make(map[string]int64)
	serverMap := make(map[string]int64)

	for _, conn := range connections {
		protocolMap[conn.Protocol]++
		serverMap[conn.ServerAddr]++
	}

	stats := &ConnectionStats{
		TotalConnections:      int64(len(connections)),
		ConnectionsByProtocol: protocolMap,
		ConnectionsByServer:   serverMap,
		Users:                 connections,
	}

	return stats, nil
}

// GetUserConnections retrieves active connections for a specific user
func (db *Database) GetUserConnections(ctx context.Context, email string) ([]ConnectionInfo, error) {
	query := `
		SELECT 
			ac.id,
			ac.account_id,
			ac.protocol,
			ac.client_addr,
			ac.server_addr,
			ac.instance_id,
			ac.connected_at,
			ac.last_activity,
			ac.should_terminate,
			c.address as email
		FROM active_connections ac
		INNER JOIN credentials c ON ac.account_id = c.account_id
		WHERE LOWER(c.address) = LOWER($1)		ORDER BY ac.protocol, ac.connected_at`

	rows, err := db.GetReadPool().Query(ctx, query, email)
	if err != nil {
		return nil, fmt.Errorf("failed to get user connections: %w", err)
	}
	defer rows.Close()

	var connections []ConnectionInfo
	for rows.Next() {
		var conn ConnectionInfo
		err := rows.Scan(&conn.ID, &conn.AccountID, &conn.Protocol, &conn.ClientAddr,
			&conn.ServerAddr, &conn.InstanceID, &conn.ConnectedAt, &conn.LastActivity, &conn.ShouldTerminate, &conn.Email)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user connection: %w", err)
		}
		connections = append(connections, conn)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating user connections: %w", err)
	}

	return connections, nil
}

// GetTerminatedConnectionsByInstance was removed - it was only used with the old
// database-based kick mechanism. The new gossip-based system doesn't use this.
