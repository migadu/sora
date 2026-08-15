package db

import (
	"context"
	"encoding/json"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

// growingRelations are tables whose row count grows with the size of the
// installation, so scanning them costs more on every node as tenants are added.
var growingRelations = map[string]bool{
	"accounts":         true,
	"credentials":      true,
	"mailboxes":        true,
	"mailbox_stats":    true,
	"messages":         true,
	"message_contents": true,
}

// TestMetricsStatsQueriesDoNotScanGrowingTables ensures the gauges the metrics
// collector refreshes every 60 seconds on every database-connected node cost the
// same on a large installation as on a small one.
//
// The message aggregate is deliberately not covered: it sums pre-aggregated
// mailbox_stats rows and has no bounded substitute.
func TestMetricsStatsQueriesDoNotScanGrowingTables(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database := setupTestDatabase(t)
	defer database.Close()

	ctx := context.Background()

	for name, query := range map[string]string{
		"accounts":  accountsRowEstimateQuery,
		"mailboxes": mailboxesRowEstimateQuery,
	} {
		t.Run(name, func(t *testing.T) {
			for _, relation := range explainRelations(t, ctx, database, query) {
				if growingRelations[relation] {
					t.Errorf("the %s gauge query reads relation %q, whose size grows with the installation", name, relation)
				}
			}
		})
	}
}

// TestGetMetricsStatsTracksTableSize pins down what the gauges report: once the
// tables have been analyzed, the totals track every row of the table, soft-deleted
// rows included.
func TestGetMetricsStatsTracksTableSize(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database := setupTestDatabase(t)
	defer database.Close()

	ctx := context.Background()

	_, err := database.GetWritePool().Exec(ctx, "ANALYZE accounts, mailboxes")
	require.NoError(t, err)

	stats, err := database.GetMetricsStats(ctx)
	require.NoError(t, err)

	for _, tc := range []struct {
		table    string
		reported int64
	}{
		{"accounts", stats.TotalAccounts},
		{"mailboxes", stats.TotalMailboxes},
	} {
		var rows int64
		require.NoError(t, database.GetReadPool().QueryRow(ctx, "SELECT COUNT(*) FROM "+tc.table).Scan(&rows))

		// The estimate is a snapshot of the last ANALYZE and the test database is
		// shared, so rows may appear in between.
		tolerance := math.Max(50, float64(rows)*0.1)
		require.InDelta(t, float64(rows), float64(tc.reported), tolerance, "reported %s total", tc.table)
	}
}

// TestRowCountFallsBackWhenEstimateMissing ensures a table awaiting its first
// analyze is counted exactly rather than reported as empty.
func TestRowCountFallsBackWhenEstimateMissing(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database := setupTestDatabase(t)
	defer database.Close()

	ctx := context.Background()

	count, err := rowCount(ctx, database.GetReadPool(), `SELECT 3::bigint`, `SELECT 7::bigint`)
	require.NoError(t, err)
	require.Equal(t, int64(3), count, "an available estimate must be used")

	count, err = rowCount(ctx, database.GetReadPool(), `SELECT (-1)::bigint`, `SELECT 7::bigint`)
	require.NoError(t, err)
	require.Equal(t, int64(7), count, "a missing estimate must fall back to the exact count")
}

// explainRelations returns the relations PostgreSQL reads to answer query.
func explainRelations(t *testing.T, ctx context.Context, database *Database, query string) []string {
	t.Helper()

	var raw []byte
	err := database.GetReadPool().QueryRow(ctx, "EXPLAIN (FORMAT JSON) "+query).Scan(&raw)
	require.NoError(t, err)

	var plan any
	require.NoError(t, json.Unmarshal(raw, &plan))

	var relations []string
	var walk func(node any)
	walk = func(node any) {
		switch typed := node.(type) {
		case map[string]any:
			if name, ok := typed["Relation Name"].(string); ok {
				relations = append(relations, name)
			}
			for _, child := range typed {
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(plan)

	return relations
}
