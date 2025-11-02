package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// RecordAuthAttempt records an authentication attempt in the database
func (d *Database) RecordAuthAttempt(ctx context.Context, tx pgx.Tx, ipAddress, username, protocol string, success bool) error {
	query := `
		INSERT INTO auth_attempts (ip_address, username, protocol, success, attempted_at)
		VALUES ($1, $2, $3, $4, now())`

	var usernameParam any
	if username == "" {
		usernameParam = nil
	} else {
		usernameParam = username
	}

	_, err := tx.Exec(ctx, query, ipAddress, usernameParam, protocol, success)
	if err != nil {
		return fmt.Errorf("failed to record auth attempt: %w", err)
	}

	return nil
}

// GetFailedAttemptsCount counts failed authentication attempts within a time window
func (d *Database) GetFailedAttemptsCount(ctx context.Context, ipAddress, username string, windowDuration time.Duration) (ipCount, usernameCount int, err error) {
	cutoffTime := time.Now().Add(-windowDuration)

	// Count IP-based failed attempts
	ipQuery := `
		SELECT COUNT(*) 
		FROM auth_attempts 
		WHERE ip_address = $1 AND success = false AND attempted_at > $2`

	err = d.GetReadPool().QueryRow(ctx, ipQuery, ipAddress, cutoffTime).Scan(&ipCount)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to count IP-based failed attempts: %w", err)
	}

	// Count username-based failed attempts (if username provided)
	if username != "" {
		usernameQuery := `
			SELECT COUNT(*) 
			FROM auth_attempts
			WHERE LOWER(username) = LOWER($1) AND success = false AND attempted_at > $2`

		err = d.GetReadPool().QueryRow(ctx, usernameQuery, username, cutoffTime).Scan(&usernameCount)
		if err != nil {
			return 0, 0, fmt.Errorf("failed to count username-based failed attempts: %w", err)
		}
	}

	return ipCount, usernameCount, nil
}

// GetFailedAttemptsCountSeparateWindows counts failed authentication attempts with separate time windows for IP and username
func (d *Database) GetFailedAttemptsCountSeparateWindows(ctx context.Context, ipAddress, username string, ipWindowDuration, usernameWindowDuration time.Duration) (ipCount, usernameCount int, err error) {
	ipCutoffTime := time.Now().Add(-ipWindowDuration)

	// Count IP-based failed attempts
	ipQuery := `
		SELECT COUNT(*) 
		FROM auth_attempts 
		WHERE ip_address = $1 AND success = false AND attempted_at > $2`

	err = d.GetReadPool().QueryRow(ctx, ipQuery, ipAddress, ipCutoffTime).Scan(&ipCount)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to count IP-based failed attempts: %w", err)
	}

	// Count username-based failed attempts (if username provided)
	if username != "" {
		usernameCutoffTime := time.Now().Add(-usernameWindowDuration)
		usernameQuery := `
			SELECT COUNT(*) 
			FROM auth_attempts
			WHERE LOWER(username) = LOWER($1) AND success = false AND attempted_at > $2`

		err = d.GetReadPool().QueryRow(ctx, usernameQuery, username, usernameCutoffTime).Scan(&usernameCount)
		if err != nil {
			return 0, 0, fmt.Errorf("failed to count username-based failed attempts: %w", err)
		}
	}

	return ipCount, usernameCount, nil
}

// GetAuthAttemptsStats returns statistics about authentication attempts
func (d *Database) GetAuthAttemptsStats(ctx context.Context, windowDuration time.Duration) (map[string]any, error) {
	cutoffTime := time.Now().Add(-windowDuration)

	query := `
		SELECT 
			COUNT(*) as total_attempts,
			COUNT(*) FILTER (WHERE success = true) as successful_attempts,
			COUNT(*) FILTER (WHERE success = false) as failed_attempts,
			COUNT(DISTINCT ip_address) as unique_ips,
			COUNT(DISTINCT username) FILTER (WHERE username IS NOT NULL) as unique_usernames,
			COUNT(DISTINCT protocol) as unique_protocols
		FROM auth_attempts 
		WHERE attempted_at > $1`

	var stats struct {
		TotalAttempts      int64
		SuccessfulAttempts int64
		FailedAttempts     int64
		UniqueIPs          int64
		UniqueUsernames    int64
		UniqueProtocols    int64
	}

	err := d.GetReadPool().QueryRow(ctx, query, cutoffTime).Scan(
		&stats.TotalAttempts,
		&stats.SuccessfulAttempts,
		&stats.FailedAttempts,
		&stats.UniqueIPs,
		&stats.UniqueUsernames,
		&stats.UniqueProtocols,
	)
	if err != nil && err != pgx.ErrNoRows {
		return nil, fmt.Errorf("failed to get auth attempts stats: %w", err)
	}

	return map[string]any{
		"total_attempts":      stats.TotalAttempts,
		"successful_attempts": stats.SuccessfulAttempts,
		"failed_attempts":     stats.FailedAttempts,
		"unique_ips":          stats.UniqueIPs,
		"unique_usernames":    stats.UniqueUsernames,
		"unique_protocols":    stats.UniqueProtocols,
		"window_duration":     windowDuration.String(),
	}, nil
}

// GetBlockedIPs returns IPs that are currently blocked based on rate limiting
func (d *Database) GetBlockedIPs(ctx context.Context, ipWindowDuration, usernameWindowDuration time.Duration, maxAttemptsPerIP, maxAttemptsPerUsername int) ([]map[string]any, error) {
	query := `
		WITH ip_failures AS (
			SELECT 
				ip_address,
				COUNT(*) as failure_count,
				MAX(attempted_at) as last_failure,
				MIN(attempted_at) as first_failure
			FROM auth_attempts 
			WHERE 
				success = false 
				AND attempted_at >= NOW() - $1::interval
			GROUP BY ip_address
			HAVING COUNT(*) >= $2
		),
		username_failures AS (
			SELECT 
				LOWER(username) as lower_username,
				COUNT(*) as failure_count,
				MAX(attempted_at) as last_failure,
				MIN(attempted_at) as first_failure
			FROM auth_attempts 
			WHERE 
				success = false
				AND attempted_at >= NOW() - $3::interval
				AND username IS NOT NULL 
				AND username != ''
			GROUP BY lower_username
			HAVING COUNT(*) >= $4
		)
		SELECT 
			'ip' as block_type,
			ip_address as identifier,
			failure_count,
			first_failure,
			last_failure,
			NULL as username
		FROM ip_failures
		UNION ALL
		SELECT 
			'username' as block_type,
			lower_username as identifier,
			failure_count,
			first_failure,
			last_failure,
			lower_username as username
		FROM username_failures
		ORDER BY last_failure DESC
	`

	rows, err := d.GetReadPool().Query(ctx, query, ipWindowDuration, maxAttemptsPerIP, usernameWindowDuration, maxAttemptsPerUsername)
	if err != nil {
		return nil, fmt.Errorf("failed to get blocked IPs: %w", err)
	}
	defer rows.Close()

	var results []map[string]any
	for rows.Next() {
		var blockType, identifier string
		var username *string
		var failureCount int
		var firstFailure, lastFailure time.Time

		err := rows.Scan(&blockType, &identifier, &failureCount, &firstFailure, &lastFailure, &username)
		if err != nil {
			return nil, fmt.Errorf("failed to scan blocked IP row: %w", err)
		}

		result := map[string]any{
			"block_type":    blockType,
			"identifier":    identifier,
			"failure_count": failureCount,
			"first_failure": firstFailure,
			"last_failure":  lastFailure,
		}

		if username != nil {
			result["username"] = *username
		}

		results = append(results, result)
	}

	return results, rows.Err()
}
