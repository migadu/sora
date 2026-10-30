package db

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// Backend maintenance marks (SetBackendMaintenance, ClearBackendMaintenance,
// ListBackendMaintenance) and the upload backlog that decides when a host in maintenance
// may be stopped (GetInstanceUploadBacklog).
//
// The test database is shared with packages running concurrently: every host and
// instance id here is unique to its test, assertions look only at those, and each test
// removes what it wrote.

// maintenanceHost returns a host name no other test uses, normalized as callers store it.
func maintenanceHost(t *testing.T, label string) string {
	t.Helper()
	return strings.ToLower(fmt.Sprintf("%s-%s-%d.example.com", label, t.Name(), time.Now().UnixNano()))
}

// setMaintenance marks a host and removes the mark when the test ends.
func setMaintenance(t *testing.T, db *Database, m BackendMaintenance) BackendMaintenance {
	t.Helper()
	var stored BackendMaintenance
	inTx(t, db, func(tx pgx.Tx) {
		var err error
		stored, err = db.SetBackendMaintenance(context.Background(), tx, m)
		require.NoError(t, err)
	})
	t.Cleanup(func() {
		if _, err := db.GetWritePool().Exec(context.Background(),
			`DELETE FROM backend_maintenance WHERE host = $1`, m.Host); err != nil {
			t.Errorf("cleanup of maintenance mark %s: %v", m.Host, err)
		}
	})
	return stored
}

func listedMaintenance(t *testing.T, db *Database, host string) (BackendMaintenance, bool) {
	t.Helper()
	all, err := db.ListBackendMaintenance(context.Background())
	require.NoError(t, err)
	for _, m := range all {
		if m.Host == host {
			return m, true
		}
	}
	return BackendMaintenance{}, false
}

// Marking a host that is already in maintenance updates who marked it, why, and which
// instance must drain, but keeps when maintenance began.
func TestBackendMaintenance_RepeatKeepsCreatedAt(t *testing.T) {
	if testing.Short() {
		t.Skip("database test")
	}
	db := setupTestDatabase(t)
	t.Cleanup(db.Close)
	ctx := context.Background()

	host := maintenanceHost(t, "upsert")
	first := setMaintenance(t, db, BackendMaintenance{
		Host: host, InstanceID: "instance-a", Reason: "disk swap", CreatedBy: "alice",
	})
	require.Equal(t, host, first.Host)
	require.Equal(t, "instance-a", first.InstanceID)
	require.Equal(t, "disk swap", first.Reason)
	require.Equal(t, "alice", first.CreatedBy)
	require.False(t, first.CreatedAt.IsZero())

	// Backdate the start so a reset to now() could not pass for the original by luck.
	began := time.Now().Add(-2 * time.Hour).Truncate(time.Microsecond)
	_, err := db.GetWritePool().Exec(ctx, `UPDATE backend_maintenance SET created_at = $2 WHERE host = $1`, host, began)
	require.NoError(t, err)

	var second BackendMaintenance
	inTx(t, db, func(tx pgx.Tx) {
		second, err = db.SetBackendMaintenance(ctx, tx, BackendMaintenance{
			Host: host, InstanceID: "instance-b", Reason: "kernel upgrade", CreatedBy: "bob",
		})
		require.NoError(t, err)
	})
	require.Equal(t, "instance-b", second.InstanceID)
	require.Equal(t, "kernel upgrade", second.Reason)
	require.Equal(t, "bob", second.CreatedBy)
	require.True(t, second.CreatedAt.Equal(began), "a repeated mark keeps when maintenance began: got %v, want %v", second.CreatedAt, began)

	stored, ok := listedMaintenance(t, db, host)
	require.True(t, ok)
	require.Equal(t, second.InstanceID, stored.InstanceID)
	require.True(t, stored.CreatedAt.Equal(began))
}

// An instance id is what the safe-to-stop check reads; without one the backlog would
// always look drained.
func TestBackendMaintenance_RefusesMissingHostOrInstance(t *testing.T) {
	if testing.Short() {
		t.Skip("database test")
	}
	db := setupTestDatabase(t)
	t.Cleanup(db.Close)
	ctx := context.Background()

	host := maintenanceHost(t, "refuse")
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	_, err = db.SetBackendMaintenance(ctx, tx, BackendMaintenance{Host: host})
	require.Error(t, err)
	_, err = db.SetBackendMaintenance(ctx, tx, BackendMaintenance{InstanceID: "instance-a"})
	require.Error(t, err)
}

func TestBackendMaintenance_ClearReportsWhetherMarked(t *testing.T) {
	if testing.Short() {
		t.Skip("database test")
	}
	db := setupTestDatabase(t)
	t.Cleanup(db.Close)
	ctx := context.Background()

	host := maintenanceHost(t, "clear")
	setMaintenance(t, db, BackendMaintenance{Host: host, InstanceID: "instance-a"})
	_, ok := listedMaintenance(t, db, host)
	require.True(t, ok)

	clearMark := func() bool {
		var existed bool
		inTx(t, db, func(tx pgx.Tx) {
			var err error
			existed, err = db.ClearBackendMaintenance(ctx, tx, host)
			require.NoError(t, err)
		})
		return existed
	}
	require.True(t, clearMark(), "the first clear removes the mark")
	_, ok = listedMaintenance(t, db, host)
	require.False(t, ok)
	require.False(t, clearMark(), "a second clear finds nothing")
}

func TestBackendMaintenance_ListReturnsMarksByHost(t *testing.T) {
	if testing.Short() {
		t.Skip("database test")
	}
	db := setupTestDatabase(t)
	t.Cleanup(db.Close)

	// The same suffix for both, so their order is decided by the label alone.
	suffix := strings.ToLower(fmt.Sprintf("%s-%d.example.com", t.Name(), time.Now().UnixNano()))
	later := setMaintenance(t, db, BackendMaintenance{
		Host: "zz-" + suffix, InstanceID: "instance-z", Reason: "rack move", CreatedBy: "carol",
	})
	earlier := setMaintenance(t, db, BackendMaintenance{
		Host: "aa-" + suffix, InstanceID: "instance-a", Reason: "disk swap", CreatedBy: "dave",
	})

	all, err := db.ListBackendMaintenance(context.Background())
	require.NoError(t, err)
	var ours []BackendMaintenance
	for _, m := range all {
		if strings.HasSuffix(m.Host, suffix) {
			ours = append(ours, m)
		}
	}
	require.Len(t, ours, 2)
	for i, want := range []BackendMaintenance{earlier, later} {
		got := ours[i]
		require.Equal(t, want.Host, got.Host)
		require.Equal(t, want.InstanceID, got.InstanceID)
		require.Equal(t, want.Reason, got.Reason)
		require.Equal(t, want.CreatedBy, got.CreatedBy)
		require.True(t, want.CreatedAt.Equal(got.CreatedAt))
	}
}

// backlogAccount creates an account to own pending uploads (pending_uploads.account_id
// references accounts) and removes it, and every pending upload it owns, when the test
// ends.
func backlogAccount(t *testing.T, db *Database) int64 {
	t.Helper()
	ctx := context.Background()
	var accountID int64
	inTx(t, db, func(tx pgx.Tx) {
		var err error
		accountID, err = db.CreateAccount(ctx, tx, CreateAccountRequest{
			Email:     fmt.Sprintf("backlog_%d@example.com", time.Now().UnixNano()),
			Password:  "password123",
			IsPrimary: true,
			HashType:  "bcrypt",
		})
		require.NoError(t, err)
	})
	t.Cleanup(func() {
		ctx := context.Background()
		for _, stmt := range []string{
			`DELETE FROM pending_uploads WHERE account_id = $1`,
			`DELETE FROM credentials WHERE account_id = $1`,
			`DELETE FROM accounts WHERE id = $1`,
		} {
			if _, err := db.GetWritePool().Exec(ctx, stmt, accountID); err != nil {
				t.Errorf("cleanup of account %d: %s: %v", accountID, stmt, err)
				return
			}
		}
	})
	return accountID
}

func insertPendingUpload(t *testing.T, db *Database, accountID int64, instanceID, hash string, attempts int, createdAt time.Time) {
	t.Helper()
	_, err := db.GetWritePool().Exec(context.Background(), `
		INSERT INTO pending_uploads (account_id, content_hash, size, instance_id, attempts, created_at)
		VALUES ($1, $2, 100, $3, $4, $5)
	`, accountID, hash, instanceID, attempts, createdAt)
	require.NoError(t, err)
}

// The backlog is one instance's: every pending upload it owns counts, parked ones
// included (still mail only that node holds), and parked are those at or past
// maxAttempts. Another instance's uploads are not its backlog.
func TestInstanceUploadBacklog_CountsPendingAndParkedOfOneInstance(t *testing.T) {
	if testing.Short() {
		t.Skip("database test")
	}
	db := setupTestDatabase(t)
	t.Cleanup(db.Close)
	ctx := context.Background()

	const maxAttempts = 5
	ts := time.Now().UnixNano()
	accountID := backlogAccount(t, db)
	draining := fmt.Sprintf("backlog-draining-%d", ts)
	other := fmt.Sprintf("backlog-other-%d", ts)
	now := time.Now().Truncate(time.Microsecond)
	oldest := now.Add(-3 * time.Hour)

	insertPendingUpload(t, db, accountID, draining, fmt.Sprintf("bl_fresh_%d", ts), 0, now.Add(-time.Minute))
	insertPendingUpload(t, db, accountID, draining, fmt.Sprintf("bl_retrying_%d", ts), maxAttempts-1, now.Add(-time.Hour))
	insertPendingUpload(t, db, accountID, draining, fmt.Sprintf("bl_parked_%d", ts), maxAttempts, oldest)
	insertPendingUpload(t, db, accountID, draining, fmt.Sprintf("bl_parked_past_%d", ts), maxAttempts+3, now.Add(-2*time.Hour))
	// Older and more numerous on another node: none of it is the draining host's backlog.
	insertPendingUpload(t, db, accountID, other, fmt.Sprintf("bl_other_1_%d", ts), 0, now.Add(-48*time.Hour))
	insertPendingUpload(t, db, accountID, other, fmt.Sprintf("bl_other_2_%d", ts), maxAttempts, now.Add(-48*time.Hour))

	backlog, err := db.GetInstanceUploadBacklog(ctx, draining, maxAttempts)
	require.NoError(t, err)
	require.Equal(t, int64(4), backlog.Pending, "every upload the instance owns, parked included")
	require.Equal(t, int64(2), backlog.Parked, "attempts at or past maxAttempts")
	require.NotNil(t, backlog.Oldest)
	require.True(t, backlog.Oldest.Equal(oldest), "oldest of this instance only: got %v, want %v", *backlog.Oldest, oldest)

	otherBacklog, err := db.GetInstanceUploadBacklog(ctx, other, maxAttempts)
	require.NoError(t, err)
	require.Equal(t, int64(2), otherBacklog.Pending)
	require.Equal(t, int64(1), otherBacklog.Parked)
}

func TestInstanceUploadBacklog_EmptyWhenNothingPending(t *testing.T) {
	if testing.Short() {
		t.Skip("database test")
	}
	db := setupTestDatabase(t)
	t.Cleanup(db.Close)

	backlog, err := db.GetInstanceUploadBacklog(context.Background(), fmt.Sprintf("backlog-idle-%d", time.Now().UnixNano()), 5)
	require.NoError(t, err)
	require.Equal(t, int64(0), backlog.Pending)
	require.Equal(t, int64(0), backlog.Parked)
	require.Nil(t, backlog.Oldest)
}
