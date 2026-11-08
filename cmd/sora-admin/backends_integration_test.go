//go:build integration

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/db"
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

// shortDrainTimings makes --wait poll every 20ms and count a sessions report older than
// 200ms as stale (fakeNode reports every 20ms).
func shortDrainTimings(t *testing.T) {
	t.Helper()
	poll, maxAge := drainPollInterval, sessionsReportMaxAge
	drainPollInterval, sessionsReportMaxAge = 20*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { drainPollInterval, sessionsReportMaxAge = poll, maxAge })
}

// forgetInstance removes, when the test ends, what was recorded under an instance id.
func forgetInstance(t *testing.T, rdb *resilient.ResilientDatabase, instanceID string) {
	t.Helper()
	t.Cleanup(func() {
		pool := rdb.GetOperationalDatabase().GetWritePool()
		for _, stmt := range []string{
			`DELETE FROM instance_heartbeats WHERE instance_id = $1`,
			`DELETE FROM instance_sessions WHERE instance_id = $1`,
		} {
			if _, err := pool.Exec(context.Background(), stmt, instanceID); err != nil {
				t.Errorf("forget instance %s: %v", instanceID, err)
			}
		}
	})
}

// fakeNode stands in for a backend reporting its sessions (cmd/sora's sessionsReporter):
// it reports once before returning, then every 20ms until silenced or the test ends. Like
// the real node it looks up its own maintenance before each report and, once in it,
// reports refusing new sessions for it (refuse_after 0), unless told it still accepts them.
type fakeNode struct {
	t        *testing.T
	rdb      *resilient.ResilientDatabase
	instance string

	mu        sync.Mutex
	open      int64
	accepting bool // refuse_after has not passed yet

	silenced chan struct{}
	done     chan struct{}
	once     sync.Once
}

func startFakeNode(t *testing.T, rdb *resilient.ResilientDatabase, instance string) *fakeNode {
	t.Helper()
	forgetInstance(t, rdb, instance)
	n := &fakeNode{t: t, rdb: rdb, instance: instance, silenced: make(chan struct{}), done: make(chan struct{})}
	n.report()
	go func() {
		defer close(n.done)
		for {
			select {
			case <-n.silenced:
				return
			case <-time.After(20 * time.Millisecond):
			}
			n.report()
		}
	}()
	t.Cleanup(n.silence)
	return n
}

func (n *fakeNode) report() {
	n.mu.Lock()
	s := db.InstanceSessions{InstanceID: n.instance, Open: n.open}
	accepting := n.accepting
	n.mu.Unlock()
	if !accepting {
		since, err := n.rdb.GetMaintenanceRefusalWithRetry(context.Background(), n.instance, 0)
		if err != nil {
			n.t.Errorf("maintenance of %s: %v", n.instance, err)
			return
		}
		s.RefusingSince = since
	}
	if err := n.rdb.ReportInstanceSessionsWithRetry(context.Background(), s); err != nil {
		n.t.Errorf("report sessions of %s: %v", n.instance, err)
	}
}

// sessions sets how many sessions are open.
func (n *fakeNode) sessions(open int64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.open = open
}

// accept makes the node accept new sessions in maintenance (true), as it does until
// refuse_after has passed, or refuse them (false).
func (n *fakeNode) accept(accepting bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.accepting = accepting
}

// silence stops the reports, as from a node that stopped.
func (n *fakeNode) silence() {
	n.once.Do(func() { close(n.silenced) })
	<-n.done
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
	var once sync.Once
	remove := func() {
		once.Do(func() {
			if _, err := pool.Exec(context.Background(), `DELETE FROM pending_uploads WHERE id = $1`, id); err != nil {
				t.Errorf("remove pending upload %d: %v", id, err)
			}
		})
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
		done <- waitUntilSafeToStop(ctx, rdb, host)
	}()
	t.Cleanup(func() {
		cancel()
		<-finished
	})
	return done
}

// stillWaiting fails the test if the wait returned within d.
func stillWaiting(t *testing.T, done <-chan error, d time.Duration, why string) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("returned %s: %v", why, err)
	case <-time.After(d):
	}
}

// safeWithin fails the test unless the wait reports safe to stop within d, and returns
// how long that took.
func safeWithin(t *testing.T, done <-chan error, d time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("wait: %v", err)
		}
		return time.Since(start)
	case <-time.After(d):
		t.Fatal("never reported safe to stop")
		return 0
	}
}

// inMaintenance puts host in maintenance under instance, which must be known.
func inMaintenance(t *testing.T, rdb *resilient.ResilientDatabase, host, instance string) {
	t.Helper()
	if err := maintenanceOn(context.Background(), rdb, host, instance, "", false); err != nil {
		t.Fatalf("on: %v", err)
	}
}

func TestBackendsMaintenanceOnAndOff(t *testing.T) {
	rdb := backendsTestDB(t)
	ctx := context.Background()
	host := backendsTestHost(t, rdb)
	startFakeNode(t, rdb, host)

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
	node7 := fmt.Sprintf("node-7-%d", time.Now().UnixNano())
	startFakeNode(t, rdb, node7)
	if err := maintenanceOn(ctx, rdb, host, node7, "disk swap", false); err != nil {
		t.Fatalf("on again: %v", err)
	}
	again, _, _ := findMaintenance(masterContext(ctx), rdb, host)
	if again.InstanceID != node7 || !again.CreatedAt.Equal(row.CreatedAt) {
		t.Errorf("after on again: %+v, want instance %s and the original start %v", again, node7, row.CreatedAt)
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

// An instance id no node ever reported under (here: the host's IP while the node reports
// under its hostname) would read as drained from the start. on refuses it, writes nothing,
// and names the ids that do report.
func TestBackendsMaintenanceOn_RefusesUnknownInstance(t *testing.T) {
	rdb := backendsTestDB(t)
	ctx := context.Background()
	host := backendsTestHost(t, rdb)
	reporting := fmt.Sprintf("storage-reporting-%d", time.Now().UnixNano())
	startFakeNode(t, rdb, reporting)

	for _, instance := range []string{"", "192.0.2.10"} {
		err := maintenanceOn(ctx, rdb, host, instance, "", false)
		if err == nil {
			t.Fatalf("on with unknown instance %q succeeded", instance)
		}
		for _, want := range []string{"--instance", reporting} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not mention %q", err, want)
			}
		}
		if _, found, _ := findMaintenance(masterContext(ctx), rdb, host); found {
			t.Fatalf("on with unknown instance %q put the host in maintenance", instance)
		}
	}

	if err := maintenanceOn(ctx, rdb, host, reporting, "", false); err != nil {
		t.Fatalf("on with the reporting instance: %v", err)
	}
}

// --wait reports safe to stop once nothing is pending, and not before.
func TestWaitUntilSafeToStop_WaitsForPendingUploads(t *testing.T) {
	rdb := backendsTestDB(t)
	shortDrainTimings(t)
	host := backendsTestHost(t, rdb)
	startFakeNode(t, rdb, host)
	inMaintenance(t, rdb, host, "")

	removeUpload := pendingUpload(t, rdb, host, 0)
	done := waitAsync(t, rdb, host)
	stillWaiting(t, done, 300*time.Millisecond, "with an upload pending")

	removeUpload()
	safeWithin(t, done, 5*time.Second)
}

// Until the node refuses new sessions, none open proves nothing: the next one could start
// right after the report. --wait waits for the node to refuse them.
func TestWaitUntilSafeToStop_WaitsUntilTheNodeRefusesNewSessions(t *testing.T) {
	rdb := backendsTestDB(t)
	shortDrainTimings(t)
	host := backendsTestHost(t, rdb)
	node := startFakeNode(t, rdb, host)
	node.accept(true)
	inMaintenance(t, rdb, host, "")

	done := waitAsync(t, rdb, host)
	stillWaiting(t, done, 300*time.Millisecond, "while the node still accepts new sessions")

	node.accept(false)
	safeWithin(t, done, 5*time.Second)
}

// An empty queue is not enough while the node still has sessions that can add uploads
// (the proxies close IMAP sessions gradually, and one still open can APPEND): --wait
// waits for the node to report none.
func TestWaitUntilSafeToStop_WaitsForOpenSessions(t *testing.T) {
	rdb := backendsTestDB(t)
	shortDrainTimings(t)
	host := backendsTestHost(t, rdb)
	node := startFakeNode(t, rdb, host)
	node.sessions(1300)
	inMaintenance(t, rdb, host, "")

	done := waitAsync(t, rdb, host)
	stillWaiting(t, done, 300*time.Millisecond, "with sessions open and nothing pending")

	node.sessions(1)
	stillWaiting(t, done, 300*time.Millisecond, "with one session open")

	node.sessions(0)
	safeWithin(t, done, 5*time.Second)
}

// A node's report of refusing new sessions holds only for the maintenance it refused for.
// Maintenance turned off and on again while the node restarts: its last report (refusing,
// none open) is still current, but the new process accepted sessions until it looked.
func TestWaitUntilSafeToStop_NotOnARefusalForAnEarlierMaintenance(t *testing.T) {
	rdb := backendsTestDB(t)
	shortDrainTimings(t)
	sessionsReportMaxAge = time.Minute // the old process's last report stays current
	ctx := context.Background()
	host := backendsTestHost(t, rdb)
	node := startFakeNode(t, rdb, host)
	inMaintenance(t, rdb, host, "")
	time.Sleep(60 * time.Millisecond) // a report refusing for this maintenance
	node.silence()

	if err := maintenanceOff(ctx, rdb, host); err != nil {
		t.Fatalf("off: %v", err)
	}
	inMaintenance(t, rdb, host, "")
	done := waitAsync(t, rdb, host)
	stillWaiting(t, done, 300*time.Millisecond, "on a report refusing for the earlier maintenance")

	startFakeNode(t, rdb, host) // the new process reports, refusing for the current one
	safeWithin(t, done, 5*time.Second)
}

// Without a current report the sessions are unknown, which is never safe: neither a
// node that does not report (an older build: heartbeat only) nor one that stopped reporting.
func TestWaitUntilSafeToStop_NeverWithoutACurrentReport(t *testing.T) {
	rdb := backendsTestDB(t)
	shortDrainTimings(t)

	t.Run("heartbeat only", func(t *testing.T) {
		host := backendsTestHost(t, rdb)
		forgetInstance(t, rdb, host)
		if _, err := rdb.GetOperationalDatabase().GetWritePool().Exec(context.Background(),
			`INSERT INTO instance_heartbeats (instance_id, last_seen) VALUES ($1, now())`, host); err != nil {
			t.Fatalf("heartbeat: %v", err)
		}
		inMaintenance(t, rdb, host, "")
		stillWaiting(t, waitAsync(t, rdb, host), 300*time.Millisecond, "for a node that does not report its sessions")
	})

	t.Run("stopped reporting", func(t *testing.T) {
		host := backendsTestHost(t, rdb)
		node := startFakeNode(t, rdb, host)
		inMaintenance(t, rdb, host, "")
		node.silence()
		stillWaiting(t, waitAsync(t, rdb, host), 300*time.Millisecond, "on a report that stopped advancing")
	})
}

// Correcting the instance id while a wait runs: the wait follows the corrected one instead
// of staying on the old one.
func TestWaitUntilSafeToStop_FollowsInstanceCorrection(t *testing.T) {
	rdb := backendsTestDB(t)
	shortDrainTimings(t)
	host := backendsTestHost(t, rdb)
	wrong := startFakeNode(t, rdb, host) // reports, but is not the node in maintenance
	wrong.sessions(1)
	real := fmt.Sprintf("node-real-%d", time.Now().UnixNano())
	startFakeNode(t, rdb, real)
	inMaintenance(t, rdb, host, "")
	done := waitAsync(t, rdb, host)
	stillWaiting(t, done, 100*time.Millisecond, "on the wrong instance with a session open")

	removePending := pendingUpload(t, rdb, real, 0)
	inMaintenance(t, rdb, host, real)
	stillWaiting(t, done, 300*time.Millisecond, "on the corrected instance with an upload pending")

	removePending()
	safeWithin(t, done, 5*time.Second)
}

// Parked uploads (out of attempts) are still mail only that node holds: they keep --wait
// waiting.
func TestWaitUntilSafeToStop_ParkedUploadsKeepItWaiting(t *testing.T) {
	rdb := backendsTestDB(t)
	shortDrainTimings(t)
	host := backendsTestHost(t, rdb)
	startFakeNode(t, rdb, host)
	inMaintenance(t, rdb, host, "")
	pendingUpload(t, rdb, host, globalConfig.Uploader.MaxAttempts)

	stillWaiting(t, waitAsync(t, rdb, host), 300*time.Millisecond, "with a parked upload")
}

// Turning maintenance off ends a --wait: there is nothing to wait for any more.
func TestWaitUntilSafeToStop_EndsWhenMaintenanceIsTurnedOff(t *testing.T) {
	rdb := backendsTestDB(t)
	shortDrainTimings(t)
	ctx := context.Background()
	host := backendsTestHost(t, rdb)
	startFakeNode(t, rdb, host)
	inMaintenance(t, rdb, host, "")
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
