//go:build integration

package main

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/resilient"
)

// The admin test database is shared by the sora-admin tests, so every test uses its own
// hosts and instance ids and removes what it wrote.

func backendsTestDB(t *testing.T) *resilient.ResilientDatabase {
	t.Helper()
	rdb := openAdminTestDatabase(t)
	t.Cleanup(func() { rdb.Close() })

	saved := globalConfig
	globalConfig.Uploader.MaxAttempts = 5
	t.Cleanup(func() { globalConfig = saved })
	return rdb
}

func backendsTestHost(t *testing.T, rdb *resilient.ResilientDatabase) string {
	t.Helper()
	host := fmt.Sprintf("storage-%d.maintenance.example.com", time.Now().UnixNano())
	t.Cleanup(func() { _, _ = rdb.ClearBackendMaintenanceWithRetry(context.Background(), host) })
	return host
}

// shortDrainTimings makes --wait confirm a zero backlog for 300ms, polling every 20ms.
func shortDrainTimings(t *testing.T) {
	t.Helper()
	quiet, poll := drainQuietPeriod, drainPollInterval
	drainQuietPeriod, drainPollInterval = 300*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { drainQuietPeriod, drainPollInterval = quiet, poll })
}

// pendingUpload queues an upload for instanceID (no account: pending_uploads.account_id is
// nullable) and returns a func that removes it.
func pendingUpload(t *testing.T, rdb *resilient.ResilientDatabase, instanceID string, attempts int) func() {
	t.Helper()
	pool := rdb.GetOperationalDatabase().GetWritePool()
	var id int64
	err := pool.QueryRow(context.Background(), `
		INSERT INTO pending_uploads (account_id, content_hash, size, instance_id, attempts)
		VALUES (NULL, $1, 100, $2, $3) RETURNING id
	`, fmt.Sprintf("%064x", time.Now().UnixNano()), instanceID, attempts).Scan(&id)
	if err != nil {
		t.Fatalf("queue pending upload: %v", err)
	}
	remove := func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM pending_uploads WHERE id = $1`, id); err != nil {
			t.Errorf("remove pending upload %d: %v", id, err)
		}
	}
	t.Cleanup(remove)
	return remove
}

// waitAsync runs waitUntilSafeToStop and reports when it returns. A wait still running when
// the test ends is cancelled and joined first: cleanups run last-registered first, so this
// happens before shortDrainTimings restores the timings the wait reads.
func waitAsync(t *testing.T, rdb *resilient.ResilientDatabase, host string) <-chan error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		done <- waitUntilSafeToStop(ctx, rdb, host, "")
	}()
	t.Cleanup(func() {
		cancel()
		<-finished
	})
	return done
}

func TestBackendsMaintenanceOnAndOff(t *testing.T) {
	rdb := backendsTestDB(t)
	ctx := context.Background()
	host := backendsTestHost(t, rdb)

	if err := maintenanceOn(ctx, rdb, host, "", "disk swap", false); err != nil {
		t.Fatalf("on: %v", err)
	}
	row, found, err := findMaintenance(masterContext(ctx), rdb, host)
	if err != nil || !found {
		t.Fatalf("after on: found=%v err=%v", found, err)
	}
	if row.InstanceID != host {
		t.Errorf("instance id = %q, want the host when --instance is omitted", row.InstanceID)
	}
	if row.Reason != "disk swap" || row.CreatedBy == "" {
		t.Errorf("row = %+v, want the reason and an operator", row)
	}
	if err := showBackendsStatus(ctx, rdb, host); err != nil {
		t.Errorf("status of a backend in maintenance: %v", err)
	}

	// on again names the real instance; the backend stays in maintenance since the start.
	if err := maintenanceOn(ctx, rdb, host, "node-7", "disk swap", false); err != nil {
		t.Fatalf("on again: %v", err)
	}
	again, _, _ := findMaintenance(masterContext(ctx), rdb, host)
	if again.InstanceID != "node-7" || !again.CreatedAt.Equal(row.CreatedAt) {
		t.Errorf("after on again: %+v, want instance node-7 and the original start %v", again, row.CreatedAt)
	}

	if err := maintenanceOff(ctx, rdb, host); err != nil {
		t.Fatalf("off: %v", err)
	}
	if _, found, _ := findMaintenance(masterContext(ctx), rdb, host); found {
		t.Fatal("still in maintenance after off")
	}
	if err := maintenanceOff(ctx, rdb, host); err != nil {
		t.Fatalf("off again must be harmless: %v", err)
	}
	if err := showBackendsStatus(ctx, rdb, host); !errors.Is(err, errNotInMaintenance) {
		t.Errorf("status of a backend not in maintenance: %v, want errNotInMaintenance", err)
	}
}

// --wait reports safe to stop only after the backlog has stayed at zero for the quiet
// period, and starts over when an upload appears inside it.
func TestWaitUntilSafeToStop_NeedsASustainedZero(t *testing.T) {
	rdb := backendsTestDB(t)
	shortDrainTimings(t)
	ctx := context.Background()
	host := backendsTestHost(t, rdb)
	if err := maintenanceOn(ctx, rdb, host, "", "", false); err != nil {
		t.Fatalf("on: %v", err)
	}

	removeFirst := pendingUpload(t, rdb, host, 0)
	done := waitAsync(t, rdb, host)

	time.Sleep(150 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("returned with an upload pending: %v", err)
	default:
	}

	removeFirst()
	time.Sleep(150 * time.Millisecond) // inside the quiet period
	removeSecond := pendingUpload(t, rdb, host, 0)
	time.Sleep(drainQuietPeriod + 100*time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("returned although an upload appeared inside the quiet period: %v", err)
	default:
	}

	removeSecond()
	lastZero := time.Now()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("wait: %v", err)
		}
		if waited := time.Since(lastZero); waited < drainQuietPeriod {
			t.Fatalf("safe to stop after %v of zero backlog, want at least %v", waited, drainQuietPeriod)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("never reported safe to stop after the backlog drained")
	}
}

// Parked uploads (out of attempts) are still mail only that node holds: they keep --wait
// waiting.
func TestWaitUntilSafeToStop_ParkedUploadsKeepItWaiting(t *testing.T) {
	rdb := backendsTestDB(t)
	shortDrainTimings(t)
	ctx := context.Background()
	host := backendsTestHost(t, rdb)
	if err := maintenanceOn(ctx, rdb, host, "", "", false); err != nil {
		t.Fatalf("on: %v", err)
	}
	pendingUpload(t, rdb, host, globalConfig.Uploader.MaxAttempts)

	select {
	case err := <-waitAsync(t, rdb, host):
		t.Fatalf("returned with a parked upload: %v", err)
	case <-time.After(drainQuietPeriod * 3):
	}
}

// Turning maintenance off ends a --wait: there is nothing to wait for any more.
func TestWaitUntilSafeToStop_EndsWhenMaintenanceIsTurnedOff(t *testing.T) {
	rdb := backendsTestDB(t)
	shortDrainTimings(t)
	ctx := context.Background()
	host := backendsTestHost(t, rdb)
	if err := maintenanceOn(ctx, rdb, host, "", "", false); err != nil {
		t.Fatalf("on: %v", err)
	}
	pendingUpload(t, rdb, host, 0)
	done := waitAsync(t, rdb, host)

	if err := maintenanceOff(ctx, rdb, host); err != nil {
		t.Fatalf("off: %v", err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("reported safe to stop after maintenance was turned off")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("kept waiting after maintenance was turned off")
	}
}
