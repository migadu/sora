package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type ComponentStatus string

const (
	StatusHealthy     ComponentStatus = "healthy"
	StatusDegraded    ComponentStatus = "degraded"
	StatusUnhealthy   ComponentStatus = "unhealthy"
	StatusUnreachable ComponentStatus = "unreachable"
)

type HealthStatus struct {
	ComponentName  string          `json:"component_name"`
	Status         ComponentStatus `json:"status"`
	LastCheck      time.Time       `json:"last_check"`
	LastError      *string         `json:"last_error,omitempty"`
	CheckCount     int             `json:"check_count"`
	FailCount      int             `json:"fail_count"`
	Metadata       map[string]any  `json:"metadata,omitempty"`
	ServerHostname string          `json:"server_hostname"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

type SystemHealthOverview struct {
	OverallStatus    ComponentStatus `json:"overall_status"`
	ComponentCount   int             `json:"component_count"`
	HealthyCount     int             `json:"healthy_count"`
	DegradedCount    int             `json:"degraded_count"`
	UnhealthyCount   int             `json:"unhealthy_count"`
	UnreachableCount int             `json:"unreachable_count"`
	LastUpdated      time.Time       `json:"last_updated"`
}

// StoreHealthStatus stores or updates the health status for a component
func (db *Database) StoreHealthStatus(ctx context.Context, tx pgx.Tx, hostname string, componentName string, status ComponentStatus, lastError error, checkCount, failCount int, metadata map[string]any) error {
	var errorStr *string
	if lastError != nil {
		errStr := lastError.Error()
		errorStr = &errStr
	}

	var metadataJSON []byte
	if metadata != nil {
		var err error
		metadataJSON, err = json.Marshal(metadata)
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}
	}

	query := `
		INSERT INTO health_status (
			component_name, server_hostname, status, last_check, last_error, 
			check_count, fail_count, metadata, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (component_name, server_hostname) 
		DO UPDATE SET 
			status = EXCLUDED.status,
			last_check = EXCLUDED.last_check,
			last_error = EXCLUDED.last_error,
			check_count = EXCLUDED.check_count,
			fail_count = EXCLUDED.fail_count,
			metadata = EXCLUDED.metadata,
			updated_at = EXCLUDED.updated_at
	`

	_, err := tx.Exec(ctx, query,
		componentName,
		hostname,
		string(status),
		time.Now(),
		errorStr,
		checkCount,
		failCount,
		metadataJSON,
		time.Now(),
	)

	return err
}

// GetHealthStatus retrieves the health status for a specific component on a server
func (db *Database) GetHealthStatus(ctx context.Context, hostname, componentName string) (*HealthStatus, error) {
	query := `
		SELECT component_name, server_hostname, status, last_check, last_error, 
			   check_count, fail_count, metadata, updated_at
		FROM health_status 
		WHERE component_name = $1 AND server_hostname = $2
	`

	var h HealthStatus
	var statusStr string
	var metadataJSON []byte

	err := db.ReadPool.QueryRow(ctx, query, componentName, hostname).Scan(
		&h.ComponentName,
		&h.ServerHostname,
		&statusStr,
		&h.LastCheck,
		&h.LastError,
		&h.CheckCount,
		&h.FailCount,
		&metadataJSON,
		&h.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil // Component not found
		}
		return nil, err
	}

	h.Status = ComponentStatus(statusStr)

	if len(metadataJSON) > 0 {
		err = json.Unmarshal(metadataJSON, &h.Metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return &h, nil
}

// GetAllHealthStatuses retrieves health status for all components
func (db *Database) GetAllHealthStatuses(ctx context.Context, hostname string) ([]*HealthStatus, error) {
	var query string
	var args []any

	if hostname != "" {
		query = `
			SELECT component_name, server_hostname, status, last_check, last_error, 
				   check_count, fail_count, metadata, updated_at
			FROM health_status 
			WHERE server_hostname = $1
			ORDER BY component_name
		`
		args = append(args, hostname)
	} else {
		query = `
			SELECT component_name, server_hostname, status, last_check, last_error, 
				   check_count, fail_count, metadata, updated_at
			FROM health_status 
			ORDER BY server_hostname, component_name
		`
	}

	rows, err := db.ReadPool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var statuses []*HealthStatus
	for rows.Next() {
		var h HealthStatus
		var statusStr string
		var metadataJSON []byte

		err := rows.Scan(
			&h.ComponentName,
			&h.ServerHostname,
			&statusStr,
			&h.LastCheck,
			&h.LastError,
			&h.CheckCount,
			&h.FailCount,
			&metadataJSON,
			&h.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		h.Status = ComponentStatus(statusStr)

		if len(metadataJSON) > 0 {
			err = json.Unmarshal(metadataJSON, &h.Metadata)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal metadata for %s: %w", h.ComponentName, err)
			}
		}

		statuses = append(statuses, &h)
	}

	return statuses, rows.Err()
}

// GetSystemHealthOverview provides a high-level overview of system health
func (db *Database) GetSystemHealthOverview(ctx context.Context, hostname string) (*SystemHealthOverview, error) {
	var query string
	var args []any

	if hostname != "" {
		query = `
			SELECT 
				COUNT(*) as total,
				COALESCE(SUM(CASE WHEN status = 'healthy' THEN 1 ELSE 0 END), 0) as healthy,
				COALESCE(SUM(CASE WHEN status = 'degraded' THEN 1 ELSE 0 END), 0) as degraded,
				COALESCE(SUM(CASE WHEN status = 'unhealthy' THEN 1 ELSE 0 END), 0) as unhealthy,
				COALESCE(SUM(CASE WHEN status = 'unreachable' THEN 1 ELSE 0 END), 0) as unreachable,
				COALESCE(MAX(updated_at), NOW()) as last_updated
			FROM health_status 
			WHERE server_hostname = $1
		`
		args = append(args, hostname)
	} else {
		query = `
			SELECT 
				COUNT(*) as total,
				COALESCE(SUM(CASE WHEN status = 'healthy' THEN 1 ELSE 0 END), 0) as healthy,
				COALESCE(SUM(CASE WHEN status = 'degraded' THEN 1 ELSE 0 END), 0) as degraded,
				COALESCE(SUM(CASE WHEN status = 'unhealthy' THEN 1 ELSE 0 END), 0) as unhealthy,
				COALESCE(SUM(CASE WHEN status = 'unreachable' THEN 1 ELSE 0 END), 0) as unreachable,
				COALESCE(MAX(updated_at), NOW()) as last_updated
			FROM health_status
		`
	}

	var overview SystemHealthOverview
	err := db.ReadPool.QueryRow(ctx, query, args...).Scan(
		&overview.ComponentCount,
		&overview.HealthyCount,
		&overview.DegradedCount,
		&overview.UnhealthyCount,
		&overview.UnreachableCount,
		&overview.LastUpdated,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return &SystemHealthOverview{
				OverallStatus:  StatusUnreachable,
				ComponentCount: 0,
				LastUpdated:    time.Now(),
			}, nil
		}
		return nil, err
	}

	// Determine overall status based on component statuses
	if overview.ComponentCount == 0 {
		overview.OverallStatus = StatusUnreachable
	} else if overview.UnhealthyCount > 0 || overview.UnreachableCount > 0 {
		overview.OverallStatus = StatusUnhealthy
	} else if overview.DegradedCount > 0 {
		overview.OverallStatus = StatusDegraded
	} else {
		overview.OverallStatus = StatusHealthy
	}

	return &overview, nil
}

// GetHealthHistory gets health status changes over time for a component
func (db *Database) GetHealthHistory(ctx context.Context, hostname, componentName string, since time.Time, limit int) ([]*HealthStatus, error) {
	query := `
		SELECT component_name, server_hostname, status, last_check, last_error, 
			   check_count, fail_count, metadata, updated_at
		FROM health_status 
		WHERE component_name = $1 AND server_hostname = $2 AND updated_at >= $3
		ORDER BY updated_at DESC
		LIMIT $4
	`

	rows, err := db.ReadPool.Query(ctx, query, componentName, hostname, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []*HealthStatus
	for rows.Next() {
		var h HealthStatus
		var statusStr string
		var metadataJSON []byte

		err := rows.Scan(
			&h.ComponentName,
			&h.ServerHostname,
			&statusStr,
			&h.LastCheck,
			&h.LastError,
			&h.CheckCount,
			&h.FailCount,
			&metadataJSON,
			&h.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		h.Status = ComponentStatus(statusStr)

		if len(metadataJSON) > 0 {
			err = json.Unmarshal(metadataJSON, &h.Metadata)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
			}
		}

		history = append(history, &h)
	}

	return history, rows.Err()
}
