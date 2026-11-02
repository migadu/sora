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

// shortDrainTimings makes --wait require 300ms of quiet, polling every 20ms, and count a
// sessions report older than 200ms as stale (fakeNode reports every 20ms).
func shortDrainTimings(t *testing.T) {
	t.Helper()
	quiet, poll, maxAge := drainQuietPeriod, drainPollInterval, sessionsReportMaxAge
	drainQuietPeriod, drainPollInterval, sessionsReportMaxAge = 300*time.Millisecond, 20*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { drainQuietPeriod, drainPollInterval, sessionsReportMaxAge = quiet, poll, maxAge })
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

// fakeNode stands in for a backend reporting its sessions (cmd/sora's
// runSessionsReport): it reports once before returning, then every 20ms until silenced or
// the test ends.
type fakeNode struct {
	t        *testing.T
	rdb      *resilient.ResilientDatabase
	instance string

	mu      sync.Mutex
	open    int64
	started int64
	since   time.Time

	silenced chan struct{}
	done     chan struct{}
	once     sync.Once
}

func startFakeNode(t *testing.T, rdb *resilient.ResilientDatabase, instance string) *fakeNode {
	t.Helper()
	forgetInstance(t, rdb, instance)
	n := &fakeNode{t: t, rdb: rdb, instance: instance, since: time.Now(), silenced: make(chan struct{}), done: make(chan struct{})}
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
	s := db.InstanceSessions{InstanceID: n.instance, Open: n.open, Started: n.started, Since: n.since}
	n.mu.Unlock()
	if err := n.rdb.ReportInstanceSessionsWithRetry(context.Background(), s); err != nil {
		n.t.Errorf("report sessions of %s: %v", n.instance, err)
	}
}

// sessions sets how many sessions are open; each one opened also counts as started.
func (n *fakeNode) sessions(open int64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if open > n.open {
		n.started += open - n.open
	}
	n.open = open
}

// sessionCameAndWent counts a session that started and ended between two reports.
func (n *fakeNode) sessionCameAndWent() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.started++
}

// restart is the node's process restarting: a new count from zero.
func (n *fakeNode) restart() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.since, n.started = time.Now(), n.open
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

// --wait reports safe to stop only after the backend has been quiet for the quiet period,
// and starts over when an upload appears inside it.
func TestWaitUntilSafeToStop_NeedsASustainedZero(t *testing.T) {
	rdb := backendsTestDB(t)
	shortDrainTimings(t)
	host := backendsTestHost(t, rdb)
	startFakeNode(t, rdb, host)
	inMaintenance(t, rdb, host, "")

	removeFirst := pendingUpload(t, rdb, host, 0)
	done := waitAsync(t, rdb, host)
	stillWaiting(t, done, 150*time.Millisecond, "with an upload pending")

	removeFirst()
	time.Sleep(150 * time.Millisecond) // inside the quiet period
	removeSecond := pendingUpload(t, rdb, host, 0)
	stillWaiting(t, done, drainQuietPeriod+100*time.Millisecond, "although an upload appeared inside the quiet period")

	removeSecond()
	if waited := safeWithin(t, done, 5*time.Second); waited < drainQuietPeriod {
		t.Fatalf("safe to stop after %v of quiet, want at least %v", waited, drainQuietPeriod)
	}
}

// An empty queue is not enough while the node still has sessions that can add uploads
// (the proxies close IMAP sessions gradually, and one still open can APPEND): --wait
// waits for the node to report none, then for the quiet period.
func TestWaitUntilSafeToStop_WaitsForOpenSessions(t *testing.T) {
	rdb := backendsTestDB(t)
	shortDrainTimings(t)
	host := backendsTestHost(t, rdb)
	node := startFakeNode(t, rdb, host)
	node.sessions(1300)
	inMaintenance(t, rdb, host, "")

	done := waitAsync(t, rdb, host)
	stillWaiting(t, done, 3*drainQuietPeriod, "with sessions open and nothing pending")

	node.sessions(1)
	stillWaiting(t, done, 3*drainQuietPeriod, "with one session open")

	node.sessions(0)
	if waited := safeWithin(t, done, 5*time.Second); waited < drainQuietPeriod {
		t.Fatalf("safe to stop %v after the last session ended, want at least %v", waited, drainQuietPeriod)
	}
}

// A session that started and ended between two reports leaves no open count, only a
// higher started count: it restarts the quiet period.
func TestWaitUntilSafeToStop_SessionsThatCameAndWentRestartIt(t *testing.T) {
	rdb := backendsTestDB(t)
	shortDrainTimings(t)
	host := backendsTestHost(t, rdb)
	node := startFakeNode(t, rdb, host)
	inMaintenance(t, rdb, host, "")
	done := waitAsync(t, rdb, host)

	var last time.Time
	deadline := time.Now().Add(3 * drainQuietPeriod)
	for time.Now().Before(deadline) {
		node.sessionCameAndWent()
		last = time.Now()
		stillWaiting(t, done, drainQuietPeriod/3, "while sessions kept coming")
	}
	safeWithin(t, done, 5*time.Second)
	if since := time.Since(last); since < drainQuietPeriod {
		t.Fatalf("safe to stop %v after the last session, want at least %v", since, drainQuietPeriod)
	}
}

// A restart of the node restarts the quiet period, even when its new count happens to
// match the old one: what the node saw before it restarted says nothing about after.
func TestWaitUntilSafeToStop_NodeRestartRestartsIt(t *testing.T) {
	rdb := backendsTestDB(t)
	shortDrainTimings(t)
	host := backendsTestHost(t, rdb)
	node := startFakeNode(t, rdb, host)
	inMaintenance(t, rdb, host, "")
	done := waitAsync(t, rdb, host)

	time.Sleep(drainQuietPeriod / 2)
	node.restart() // nothing started before or after: the count stays 0
	restarted := time.Now()
	waited := safeWithin(t, done, 5*time.Second)
	if since := time.Since(restarted); since < drainQuietPeriod {
		t.Fatalf("safe to stop %v after the node restarted (%v into the wait), want at least %v", since, waited, drainQuietPeriod)
	}
}

// Without a current report the sessions are unknown, which never counts as quiet: neither a
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
		stillWaiting(t, waitAsync(t, rdb, host), 3*drainQuietPeriod, "for a node that does not report its sessions")
	})

	t.Run("stopped reporting", func(t *testing.T) {
		host := backendsTestHost(t, rdb)
		node := startFakeNode(t, rdb, host)
		inMaintenance(t, rdb, host, "")
		node.silence()
		stillWaiting(t, waitAsync(t, rdb, host), 3*drainQuietPeriod, "on a report that stopped advancing")
	})
}

// Correcting the instance id while a wait runs: the wait follows the corrected one, from
// scratch, instead of finishing on the old (empty) one.
func TestWaitUntilSafeToStop_FollowsInstanceCorrection(t *testing.T) {
	rdb := backendsTestDB(t)
	shortDrainTimings(t)
	drainQuietPeriod = time.Second // room to correct the id while the wait is on the old one
	host := backendsTestHost(t, rdb)
	startFakeNode(t, rdb, host) // reports, but is not where the uploads are
	real := fmt.Sprintf("node-real-%d", time.Now().UnixNano())
	startFakeNode(t, rdb, real)
	inMaintenance(t, rdb, host, "")
	done := waitAsync(t, rdb, host)

	time.Sleep(drainQuietPeriod / 3)
	removePending := pendingUpload(t, rdb, real, 0)
	inMaintenance(t, rdb, host, real)
	stillWaiting(t, done, 3*drainQuietPeriod, "on the old instance after the correction")

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

	stillWaiting(t, waitAsync(t, rdb, host), 3*drainQuietPeriod, "with a parked upload")
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
