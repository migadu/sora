package db

import (
	"context"
	"fmt"
	"log"
	"time"
)

func (d *Database) FindExistingContentHashes(ctx context.Context, ids []string) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	rows, err := d.GetReadPool().Query(ctx, `SELECT content_hash FROM messages WHERE content_hash = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []string
	for rows.Next() {
		var chash string
		if err := rows.Scan(&chash); err != nil {
			continue // log or ignore individual scan errors
		}
		result = append(result, chash)
	}

	return result, nil
}

// CacheMetricsRecord represents a cache metrics entry in the database
type CacheMetricsRecord struct {
	InstanceID      string    `json:"instance_id"`
	ServerHostname  string    `json:"server_hostname"`
	Hits            int64     `json:"hits"`
	Misses          int64     `json:"misses"`
	HitRate         float64   `json:"hit_rate"`
	TotalOperations int64     `json:"total_operations"`
	UptimeSeconds   int64     `json:"uptime_seconds"`
	RecordedAt      time.Time `json:"recorded_at"`
}

// StoreCacheMetrics stores cache metrics in the database
func (d *Database) StoreCacheMetrics(ctx context.Context, instanceID, serverHostname string, hits, misses int64, uptimeSeconds int64) error {
	totalOps := hits + misses
	var hitRate float64
	if totalOps > 0 {
		hitRate = float64(hits) / float64(totalOps) * 100
	}

	_, err := d.GetWritePool().Exec(ctx, `
		INSERT INTO cache_metrics (instance_id, server_hostname, hits, misses, hit_rate, total_operations, uptime_seconds)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		instanceID, serverHostname, hits, misses, hitRate, totalOps, uptimeSeconds)

	return err
}

// GetCacheMetrics retrieves cache metrics for a specific time range
func (d *Database) GetCacheMetrics(ctx context.Context, instanceID string, since time.Time, limit int) ([]*CacheMetricsRecord, error) {
	query := `
		SELECT instance_id, server_hostname, hits, misses, hit_rate, total_operations, uptime_seconds, recorded_at
		FROM cache_metrics
		WHERE recorded_at >= $1`

	args := []interface{}{since}
	argIndex := 2

	if instanceID != "" {
		query += fmt.Sprintf(" AND instance_id = $%d", argIndex)
		args = append(args, instanceID)
		argIndex++
	}

	query += " ORDER BY recorded_at DESC"

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIndex)
		args = append(args, limit)
	}

	rows, err := d.GetReadPool().Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var metrics []*CacheMetricsRecord
	for rows.Next() {
		var m CacheMetricsRecord
		if err := rows.Scan(&m.InstanceID, &m.ServerHostname, &m.Hits, &m.Misses,
			&m.HitRate, &m.TotalOperations, &m.UptimeSeconds, &m.RecordedAt); err != nil {
			log.Printf("WARNING: failed to scan cache metrics record: %v", err)
			continue
		}
		metrics = append(metrics, &m)
	}

	return metrics, nil
}

// GetLatestCacheMetrics retrieves the latest cache metrics for all instances
func (d *Database) GetLatestCacheMetrics(ctx context.Context) ([]*CacheMetricsRecord, error) {
	query := `
		WITH latest_metrics AS (
			SELECT DISTINCT ON (instance_id, server_hostname) 
				instance_id, server_hostname, hits, misses, hit_rate, total_operations, uptime_seconds, recorded_at
			FROM cache_metrics
			ORDER BY instance_id, server_hostname, recorded_at DESC
		)
		SELECT * FROM latest_metrics ORDER BY recorded_at DESC`

	rows, err := d.GetReadPool().Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var metrics []*CacheMetricsRecord
	for rows.Next() {
		var m CacheMetricsRecord
		if err := rows.Scan(&m.InstanceID, &m.ServerHostname, &m.Hits, &m.Misses,
			&m.HitRate, &m.TotalOperations, &m.UptimeSeconds, &m.RecordedAt); err != nil {
			log.Printf("WARNING: failed to scan latest cache metrics record: %v", err)
			continue
		}
		metrics = append(metrics, &m)
	}

	return metrics, nil
}

// CleanupOldCacheMetrics removes cache metrics older than the specified duration
func (d *Database) CleanupOldCacheMetrics(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan)

	result, err := d.GetWritePool().Exec(ctx, `
		DELETE FROM cache_metrics WHERE recorded_at < $1`, cutoff)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected(), nil
}
