package db

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
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
}

// ConnectionStats represents aggregated connection statistics
type ConnectionStats struct {
	TotalConnections      int64
	ConnectionsByProtocol map[string]int64
	ConnectionsByServer   map[string]int64
	Users                 []ConnectionInfo
}

// RegisterConnection registers a new active connection
func (db *Database) RegisterConnection(ctx context.Context, accountID int64, protocol, clientAddr, serverAddr, instanceID string) error {
	query := `
		INSERT INTO active_connections (account_id, protocol, client_addr, server_addr, instance_id)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (account_id, protocol, client_addr)
		DO UPDATE SET server_addr = EXCLUDED.server_addr,
		              instance_id = EXCLUDED.instance_id,
		              last_activity = now()
		RETURNING id`

	var id int64
	err := db.GetWritePool().QueryRow(ctx, query, accountID, protocol, clientAddr, serverAddr, instanceID).Scan(&id)
	if err != nil {
		return fmt.Errorf("failed to register connection: %w", err)
	}

	return nil
}

// UpdateConnectionActivity updates the last activity time for a connection
func (db *Database) UpdateConnectionActivity(ctx context.Context, accountID int64, protocol, clientAddr string) error {
	query := `
		UPDATE active_connections
		SET last_activity = now()
		WHERE account_id = $1 AND protocol = $2 AND client_addr = $3`

	result, err := db.GetWritePool().Exec(ctx, query, accountID, protocol, clientAddr)
	if err != nil {
		return fmt.Errorf("failed to update connection activity: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("connection not found")
	}

	return nil
}

// UnregisterConnection removes an active connection
func (db *Database) UnregisterConnection(ctx context.Context, accountID int64, protocol, clientAddr string) error {
	query := `
		DELETE FROM active_connections
		WHERE account_id = $1 AND protocol = $2 AND client_addr = $3`

	_, err := db.GetWritePool().Exec(ctx, query, accountID, protocol, clientAddr)
	if err != nil {
		return fmt.Errorf("failed to unregister connection: %w", err)
	}

	return nil
}

// BatchRegisterConnections registers multiple new active connections in a single batch.
func (db *Database) BatchRegisterConnections(ctx context.Context, connections []ConnectionInfo) error {
	if len(connections) == 0 {
		return nil
	}

	batch := &pgx.Batch{}
	query := `
		INSERT INTO active_connections (account_id, protocol, client_addr, server_addr, instance_id)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (account_id, protocol, client_addr)
		DO UPDATE SET server_addr = EXCLUDED.server_addr,
		              instance_id = EXCLUDED.instance_id,
		              last_activity = now()`

	for _, conn := range connections {
		batch.Queue(query, conn.AccountID, conn.Protocol, conn.ClientAddr, conn.ServerAddr, conn.InstanceID)
	}

	br := db.GetWritePool().SendBatch(ctx, batch)
	defer br.Close()

	// We need to check the result of each queued command.
	for i := 0; i < len(connections); i++ {
		_, err := br.Exec()
		if err != nil {
			// Log the error for the specific failed insert/update but continue.
			// A single failure shouldn't stop the whole batch.
			log.Printf("[DB] BatchRegisterConnections: error processing item %d: %v", i, err)
		}
	}

	return br.Close() // br.Close() will return the first error encountered if any.
}

// BatchUpdateConnections updates multiple connections in a single batch.
func (db *Database) BatchUpdateConnections(ctx context.Context, connections []ConnectionInfo) error {
	if len(connections) == 0 {
		return nil
	}

	batch := &pgx.Batch{}
	query := `
		UPDATE active_connections
		SET last_activity = now(), should_terminate = $4
		WHERE account_id = $1 AND protocol = $2 AND client_addr = $3`

	for _, conn := range connections {
		batch.Queue(query, conn.AccountID, conn.Protocol, conn.ClientAddr, conn.ShouldTerminate)
	}

	br := db.GetWritePool().SendBatch(ctx, batch)
	defer br.Close()

	for i := 0; i < len(connections); i++ {
		if _, err := br.Exec(); err != nil {
			log.Printf("[DB] BatchUpdateConnections: error processing item %d: %v", i, err)
		}
	}

	return br.Close()
}

// CleanupStaleConnections removes connections that haven't been active for the specified duration
func (db *Database) CleanupStaleConnections(ctx context.Context, staleAfter time.Duration) (int64, error) {
	query := `
		DELETE FROM active_connections
		WHERE last_activity < $1`

	cutoff := time.Now().Add(-staleAfter)
	result, err := db.GetWritePool().Exec(ctx, query, cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup stale connections: %w", err)
	}

	return result.RowsAffected(), nil
}

// CleanupConnectionsByInstanceID removes all connections for a specific instance ID.
// This is useful to call on server startup to clear stale connections from a previous run.
func (db *Database) CleanupConnectionsByInstanceID(ctx context.Context, instanceID string) (int64, error) {
	query := `
		DELETE FROM active_connections
		WHERE instance_id = $1`

	result, err := db.GetWritePool().Exec(ctx, query, instanceID)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup connections for instance %s: %w", instanceID, err)
	}

	return result.RowsAffected(), nil
}

// GetActiveConnections retrieves all active connections
func (db *Database) GetActiveConnections(ctx context.Context) ([]ConnectionInfo, error) {
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
			COALESCE(c.address, '') as email
		FROM active_connections ac
		LEFT JOIN credentials c ON ac.account_id = c.account_id AND c.primary_identity = true		ORDER BY ac.server_addr, ac.protocol, c.address`

	rows, err := db.GetReadPool().Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get active connections: %w", err)
	}
	defer rows.Close()

	var connections []ConnectionInfo
	for rows.Next() {
		var conn ConnectionInfo
		err := rows.Scan(&conn.ID, &conn.AccountID, &conn.Protocol, &conn.ClientAddr,
			&conn.ServerAddr, &conn.InstanceID, &conn.ConnectedAt, &conn.LastActivity, &conn.ShouldTerminate, &conn.Email)
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
	// Get total count
	var totalCount int64
	countQuery := `SELECT COUNT(*) FROM active_connections`
	err := db.GetReadPool().QueryRow(ctx, countQuery).Scan(&totalCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get total connection count: %w", err)
	}

	// Get counts by protocol
	protocolQuery := `
		SELECT protocol, COUNT(*) as count
		FROM active_connections
		GROUP BY protocol`

	protocolRows, err := db.GetReadPool().Query(ctx, protocolQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to get protocol counts: %w", err)
	}
	defer protocolRows.Close()

	protocolMap := make(map[string]int64)
	for protocolRows.Next() {
		var protocol string
		var count int64
		err := protocolRows.Scan(&protocol, &count)
		if err != nil {
			return nil, fmt.Errorf("failed to scan protocol count: %w", err)
		}
		protocolMap[protocol] = count
	}

	// Get counts by server
	serverQuery := `
		SELECT server_addr, COUNT(*) as count
		FROM active_connections
		GROUP BY server_addr`

	serverRows, err := db.GetReadPool().Query(ctx, serverQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to get server counts: %w", err)
	}
	defer serverRows.Close()

	serverMap := make(map[string]int64)
	for serverRows.Next() {
		var serverAddr string
		var count int64
		err := serverRows.Scan(&serverAddr, &count)
		if err != nil {
			return nil, fmt.Errorf("failed to scan server count: %w", err)
		}
		serverMap[serverAddr] = count
	}

	// Get all connection details
	connections, err := db.GetActiveConnections(ctx)
	if err != nil {
		return nil, err
	}

	stats := &ConnectionStats{
		TotalConnections:      totalCount,
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

// MarkConnectionsForTermination marks connections for termination based on various criteria
func (db *Database) MarkConnectionsForTermination(ctx context.Context, criteria TerminationCriteria) (int64, error) {
	query := `
		UPDATE active_connections
		SET should_terminate = true
		WHERE 1=1`

	var args []interface{}
	argCount := 0

	if criteria.Email != "" {
		argCount++
		query += fmt.Sprintf(" AND account_id IN (SELECT account_id FROM credentials WHERE LOWER(address) = LOWER($%d) AND deleted_at IS NULL)", argCount)
		args = append(args, criteria.Email)
	}

	if criteria.Protocol != "" {
		argCount++
		query += fmt.Sprintf(" AND protocol = $%d", argCount)
		args = append(args, criteria.Protocol)
	}

	if criteria.ServerAddr != "" {
		argCount++
		query += fmt.Sprintf(" AND server_addr = $%d", argCount)
		args = append(args, criteria.ServerAddr)
	}

	if criteria.ClientAddr != "" {
		argCount++
		query += fmt.Sprintf(" AND client_addr = $%d", argCount)
		args = append(args, criteria.ClientAddr)
	}

	result, err := db.GetWritePool().Exec(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("failed to mark connections for termination: %w", err)
	}

	return result.RowsAffected(), nil
}

// CheckConnectionTermination checks if a specific connection should be terminated
func (db *Database) CheckConnectionTermination(ctx context.Context, accountID int64, protocol, clientAddr string) (bool, error) {
	query := `
		SELECT should_terminate
		FROM active_connections
		WHERE account_id = $1 AND protocol = $2 AND client_addr = $3`

	var shouldTerminate bool
	err := db.GetReadPool().QueryRow(ctx, query, accountID, protocol, clientAddr).Scan(&shouldTerminate)
	if err != nil {
		// If no rows found, connection doesn't exist, so consider it terminated
		return false, nil
	}

	return shouldTerminate, nil
}

// TerminationCriteria represents criteria for marking connections for termination
type TerminationCriteria struct {
	Email      string // Terminate all connections for this email
	Protocol   string // Terminate connections using this protocol
	ServerAddr string // Terminate connections to this server
	ClientAddr string // Terminate connections from this client
}

// GetTerminatedConnectionsByInstance retrieves connections for a specific instance that are marked for termination.
func (db *Database) GetTerminatedConnectionsByInstance(ctx context.Context, instanceID string) ([]ConnectionInfo, error) {
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
			COALESCE(c.address, '') as email
		FROM active_connections ac
		LEFT JOIN credentials c ON ac.account_id = c.account_id AND c.primary_identity = true		WHERE ac.instance_id = $1 AND ac.should_terminate = true`

	rows, err := db.GetReadPool().Query(ctx, query, instanceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get terminated connections for instance %s: %w", instanceID, err)
	}
	defer rows.Close()

	var connections []ConnectionInfo
	for rows.Next() {
		var conn ConnectionInfo
		err := rows.Scan(&conn.ID, &conn.AccountID, &conn.Protocol, &conn.ClientAddr,
			&conn.ServerAddr, &conn.InstanceID, &conn.ConnectedAt, &conn.LastActivity, &conn.ShouldTerminate, &conn.Email)
		if err != nil {
			return nil, fmt.Errorf("failed to scan terminated connection: %w", err)
		}
		connections = append(connections, conn)
	}

	return connections, rows.Err()
}
