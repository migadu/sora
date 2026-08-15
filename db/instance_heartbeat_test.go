package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRecordInstanceHeartbeat verifies the liveness signal itself: the first beat
// registers the instance, every later beat refreshes it. Without the refresh a
// long-lived instance would eventually be mistaken for a decommissioned one and its
// unuploaded mail reaped.
func TestRecordInstanceHeartbeat(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	instanceID := fmt.Sprintf("heartbeat_test_%d", time.Now().UnixNano())

	beat := func() {
		t.Helper()
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		require.NoError(t, db.RecordInstanceHeartbeat(ctx, tx, instanceID))
		require.NoError(t, tx.Commit(ctx))
	}

	beat()

	var first time.Time
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		`SELECT last_seen FROM instance_heartbeats WHERE instance_id = $1`, instanceID).Scan(&first),
		"the first heartbeat must register the instance")

	// Backdate, then beat again: the second beat must refresh the same row.
	_, err := db.GetWritePool().Exec(ctx,
		`UPDATE instance_heartbeats SET last_seen = now() - interval '1 day' WHERE instance_id = $1`, instanceID)
	require.NoError(t, err)

	beat()

	var second time.Time
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		`SELECT last_seen FROM instance_heartbeats WHERE instance_id = $1`, instanceID).Scan(&second))
	assert.True(t, second.After(first.Add(-time.Second)),
		"a later heartbeat must refresh last_seen, got %s after backdating (first beat %s)", second, first)

	var rows int
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		`SELECT COUNT(*) FROM instance_heartbeats WHERE instance_id = $1`, instanceID).Scan(&rows))
	assert.Equal(t, 1, rows, "heartbeats must upsert, not accumulate one row per beat")
}

// TestGetStrandedUploadInstances covers the visibility gap: the existing alerting
// only counts uploads with attempts >= max_attempts, so a backlog owned by an
// instance that stopped retrying entirely is invisible today — both when it is dead
// (mail is about to be dropped) and when its liveness is unknown (the backlog can
// never be reaped and grows forever).
func TestGetStrandedUploadInstances(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _, accountID, _ := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	ts := time.Now().UnixNano()

	const maxAttempts = 5
	const liveness = time.Hour

	goneID := fmt.Sprintf("stranded_gone_%d", ts)
	unknownID := fmt.Sprintf("stranded_unknown_%d", ts)
	aliveID := fmt.Sprintf("stranded_alive_%d", ts)
	exhaustedID := fmt.Sprintf("stranded_exhausted_%d", ts)

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	addUpload := func(instanceID, hash string, attempts int, size int64) {
		t.Helper()
		_, err := tx.Exec(ctx, `
			INSERT INTO pending_uploads (account_id, content_hash, size, instance_id, attempts, created_at)
			VALUES ($1, $2, $3, $4, $5, now() - interval '10 days')
		`, accountID, hash, size, instanceID, attempts)
		require.NoError(t, err)
	}
	addHeartbeat := func(instanceID string, lastSeen time.Time) {
		t.Helper()
		_, err := tx.Exec(ctx,
			`INSERT INTO instance_heartbeats (instance_id, last_seen) VALUES ($1, $2)`, instanceID, lastSeen)
		require.NoError(t, err)
	}

	addUpload(goneID, fmt.Sprintf("stranded_gone_a_%d", ts), 0, 100)
	addUpload(goneID, fmt.Sprintf("stranded_gone_b_%d", ts), 1, 200)
	addHeartbeat(goneID, time.Now().Add(-3*time.Hour))

	addUpload(unknownID, fmt.Sprintf("stranded_unknown_a_%d", ts), 0, 50)

	addUpload(aliveID, fmt.Sprintf("stranded_alive_a_%d", ts), 0, 100)
	addHeartbeat(aliveID, time.Now())

	addUpload(exhaustedID, fmt.Sprintf("stranded_exhausted_a_%d", ts), maxAttempts, 100)
	addHeartbeat(exhaustedID, time.Now().Add(-3*time.Hour))

	require.NoError(t, tx.Commit(ctx))

	stranded, err := db.GetStrandedUploadInstances(ctx, maxAttempts, liveness)
	require.NoError(t, err)

	byID := make(map[string]StrandedUploadInstance, len(stranded))
	for _, s := range stranded {
		byID[s.InstanceID] = s
	}

	gone, ok := byID[goneID]
	require.True(t, ok, "an instance that stopped heartbeating while holding retryable uploads must be reported")
	assert.Equal(t, int64(2), gone.PendingCount)
	assert.Equal(t, int64(300), gone.PendingBytes)
	assert.True(t, gone.LastSeen.Valid, "a dead instance is reported with the heartbeat that proves it is dead")

	unknown, ok := byID[unknownID]
	require.True(t, ok, "an instance whose liveness cannot be determined must be reported: its backlog is never reaped")
	assert.Equal(t, int64(1), unknown.PendingCount)
	assert.False(t, unknown.LastSeen.Valid, "an instance that never registered has no heartbeat to report")

	assert.NotContains(t, byID, aliveID, "an instance that is still beating is not stranded")
	assert.NotContains(t, byID, exhaustedID,
		"uploads at max_attempts are already covered by the failed-upload alerting")
}
