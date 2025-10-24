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
func (db *Database) RegisterConnection(ctx context.Context, tx pgx.Tx, accountID int64, protocol, clientAddr, serverAddr, instanceID, email string) error {
	query := `
		INSERT INTO active_connections (account_id, is_prelookup_account, protocol, client_addr, server_addr, instance_id, email)
		VALUES ($1, false, $2, $3, $4, $5, $6)
		ON CONFLICT (account_id, is_prelookup_account, protocol, client_addr)
		DO UPDATE SET server_addr = EXCLUDED.server_addr,
		              instance_id = EXCLUDED.instance_id,
		              email = EXCLUDED.email,
		              last_activity = now()
		RETURNING id`

	var id int64
	err := tx.QueryRow(ctx, query, accountID, protocol, clientAddr, serverAddr, instanceID, email).Scan(&id)
	if err != nil {
		return fmt.Errorf("failed to register connection: %w", err)
	}

	return nil
}

// UpdateConnectionActivity updates the last activity time for a connection
func (db *Database) UpdateConnectionActivity(ctx context.Context, tx pgx.Tx, accountID int64, protocol, clientAddr string) error {
	query := `
		UPDATE active_connections
		SET last_activity = now()
		WHERE account_id = $1 AND protocol = $2 AND client_addr = $3 AND is_prelookup_account = false`

	result, err := tx.Exec(ctx, query, accountID, protocol, clientAddr)
	if err != nil {
		return fmt.Errorf("failed to update connection activity: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("connection not found")
	}

	return nil
}

// UnregisterConnection removes an active connection
func (db *Database) UnregisterConnection(ctx context.Context, tx pgx.Tx, accountID int64, protocol, clientAddr string) error {
	query := `
		DELETE FROM active_connections
		WHERE account_id = $1 AND protocol = $2 AND client_addr = $3 AND is_prelookup_account = false`

	_, err := tx.Exec(ctx, query, accountID, protocol, clientAddr)
	if err != nil {
		return fmt.Errorf("failed to unregister connection: %w", err)
	}

	return nil
}

// BatchRegisterConnections registers multiple new active connections in a single batch.
func (db *Database) BatchRegisterConnections(ctx context.Context, tx pgx.Tx, connections []ConnectionInfo) error {
	if len(connections) == 0 {
		return nil
	}

	query := `
		INSERT INTO active_connections (account_id, is_prelookup_account, protocol, client_addr, server_addr, instance_id)
		VALUES ($1, false, $2, $3, $4, $5)
		ON CONFLICT (account_id, is_prelookup_account, protocol, client_addr)
		DO UPDATE SET server_addr = EXCLUDED.server_addr,
		              instance_id = EXCLUDED.instance_id,
		              last_activity = now()`

	for _, conn := range connections {
		_, err := tx.Exec(ctx, query, conn.AccountID, conn.Protocol, conn.ClientAddr, conn.ServerAddr, conn.InstanceID)
		if err != nil {
			// Log the error for the specific failed insert/update but continue.
			// A single failure shouldn't stop the whole batch.
			log.Printf("[DB] BatchRegisterConnections: error processing item for account %d: %v", conn.AccountID, err)
			return fmt.Errorf("failed to register connection for account %d: %w", conn.AccountID, err)
		}
	}

	return nil
}

// BatchUpdateConnections updates multiple connections in a single batch.
func (db *Database) BatchUpdateConnections(ctx context.Context, tx pgx.Tx, connections []ConnectionInfo) error {
	if len(connections) == 0 {
		return nil
	}

	query := `
		UPDATE active_connections
		SET last_activity = now(), should_terminate = $4
		WHERE account_id = $1 AND protocol = $2 AND client_addr = $3 AND is_prelookup_account = false`

	for _, conn := range connections {
		if _, err := tx.Exec(ctx, query, conn.AccountID, conn.Protocol, conn.ClientAddr, conn.ShouldTerminate); err != nil {
			log.Printf("[DB] BatchUpdateConnections: error processing item for account %d: %v", conn.AccountID, err)
			return fmt.Errorf("failed to update connection for account %d: %w", conn.AccountID, err)
		}
	}

	return nil
}

// CleanupStaleConnections removes connections that haven't been active for the specified duration
func (db *Database) CleanupStaleConnections(ctx context.Context, tx pgx.Tx, staleAfter time.Duration) (int64, error) {
	query := `
		DELETE FROM active_connections
		WHERE last_activity < $1`

	cutoff := time.Now().Add(-staleAfter)
	result, err := tx.Exec(ctx, query, cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup stale connections: %w", err)
	}

	return result.RowsAffected(), nil
}

// CleanupConnectionsByInstanceID removes all connections for a specific instance ID.
// This is useful to call on server startup to clear stale connections from a previous run.
func (db *Database) CleanupConnectionsByInstanceID(ctx context.Context, tx pgx.Tx, instanceID string) (int64, error) {
	query := `
		DELETE FROM active_connections
		WHERE instance_id = $1`

	result, err := tx.Exec(ctx, query, instanceID)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup connections for instance %s: %w", instanceID, err)
	}

	return result.RowsAffected(), nil
}

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
			email
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

// MarkConnectionsForTermination marks connections for termination based on various criteria
func (db *Database) MarkConnectionsForTermination(ctx context.Context, tx pgx.Tx, criteria TerminationCriteria) (int64, error) {
	query := `
		UPDATE active_connections
		SET should_terminate = true
		WHERE 1=1`

	var args []interface{}
	argCount := 0

	if criteria.Email != "" {
		argCount++
		query += fmt.Sprintf(" AND account_id IN (SELECT c.account_id FROM credentials c JOIN accounts a ON c.account_id = a.id WHERE LOWER(c.address) = LOWER($%d) AND a.deleted_at IS NULL)", argCount)
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

	result, err := tx.Exec(ctx, query, args...)
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
		WHERE account_id = $1 AND protocol = $2 AND client_addr = $3 AND is_prelookup_account = false`

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
