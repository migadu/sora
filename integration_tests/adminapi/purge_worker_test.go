//go:build integration

package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/server/cleaner"
)

// The purge worker runs on nodes that have object storage. It polls for accounts marked
// for purging, claims each with an advisory lock so that only one node works on it, runs
// the purge, and records a backoff when the purge fails. These tests drive one worker
// cycle at a time against the same database the Admin API marked accounts in.

// runWorker runs purge worker cycles on the stack's S3 until a cycle purges nothing, and
// returns how many accounts went. The test database is shared, and other tests (the
// request tests here, the db package's) leave marked accounts behind that the worker
// rightly drains too, so a test asserts on its own account's state, never on the count.
func (s *purgeStack) runWorker(t *testing.T) int {
	t.Helper()
	w := cleaner.NewPurgeWorker(s.rdb, s.st, time.Minute)
	total := 0
	for i := 0; i < 50; i++ {
		purged, err := w.RunOnce(context.Background())
		if err != nil {
			t.Fatalf("purge worker cycle: %v", err)
		}
		total += purged
		if purged == 0 {
			return total
		}
	}
	t.Fatal("the worker kept purging accounts")
	return total
}

// requireStillThere asserts that the account row survived a worker cycle.
func (s *purgeStack) requireStillThere(t *testing.T, accountID int64) {
	t.Helper()
	if n := s.count(t, "accounts", accountID); n != 1 {
		t.Fatalf("the account row is gone")
	}
}

// requestPurge marks the account through the Admin API.
func (s *purgeStack) requestPurge(t *testing.T, email string) {
	t.Helper()
	s.request(t, "DELETE", "/admin/accounts/"+email+"?purge=true", nil, http.StatusAccepted)
}

// backoff reads the account's purge backoff: attempts so far, and when the next one may run.
func (s *purgeStack) backoff(t *testing.T, accountID int64) (int, *time.Time) {
	t.Helper()
	var attempts int
	var next *time.Time
	if err := s.rdb.QueryRowWithRetry(context.Background(),
		`SELECT purge_attempts, purge_next_attempt_at FROM accounts WHERE id = $1`, accountID).Scan(&attempts, &next); err != nil {
		t.Fatalf("read purge backoff: %v", err)
	}
	return attempts, next
}

func TestPurgeWorker_DrainsMarkedAccount(t *testing.T) {
	s := setupPurgeStack(t)
	email, accountID := s.newMailAccount(t, "worker-drain", "worker-pass-1")
	for i := 0; i < 3; i++ {
		s.addMessage(t, accountID, email, fmt.Sprintf("up%d", i), true)
	}
	s.addMessage(t, accountID, email, "queued", false)
	s.requestPurge(t, email)

	if purged := s.runWorker(t); purged < 1 {
		t.Fatalf("worker purged %d accounts, want at least 1", purged)
	}
	s.requireGone(t, accountID, email)
	if resp, _ := s.api.makeRequest(t, "POST", "/admin/accounts/"+email+"/restore", nil); resp.StatusCode == http.StatusOK {
		t.Error("a purged account was restored")
	}
}

// Two accounts marked in sequence are purged oldest request first, both in one cycle.
func TestPurgeWorker_DrainsSeveral(t *testing.T) {
	s := setupPurgeStack(t)
	emailA, idA := s.newMailAccount(t, "worker-a", "worker-pass-2")
	emailB, idB := s.newMailAccount(t, "worker-b", "worker-pass-2")
	s.addMessage(t, idA, emailA, "a", true)
	s.addMessage(t, idB, emailB, "b", true)
	s.requestPurge(t, emailA)
	s.requestPurge(t, emailB)

	s.runWorker(t)
	s.requireGone(t, idA, emailA)
	s.requireGone(t, idB, emailB)
}

// A restored account is not purged even though it was marked: restore clears the mark,
// and the worker never touches an account that is in service.
func TestPurgeWorker_SkipsRestoredAccount(t *testing.T) {
	s := setupPurgeStack(t)
	email, accountID := s.newMailAccount(t, "worker-restored", "worker-pass-3")
	key := s.addMessage(t, accountID, email, "kept", true)
	s.requestPurge(t, email)
	s.request(t, "POST", "/admin/accounts/"+email+"/restore", nil, http.StatusOK)

	s.runWorker(t)
	s.requireStillThere(t, accountID)
	if n := s.count(t, "messages", accountID); n != 1 {
		t.Errorf("a restored account lost messages: %d left, want 1", n)
	}
	if len(s.s3.Keys(key)) != 1 {
		t.Error("a restored account's body was deleted from S3")
	}
}

// When S3 refuses the deletes, the account stays marked and out of service, a backoff is
// recorded so the worker does not hammer it every cycle, and the next request from the
// operator (or the backoff expiring) lets a later cycle finish it.
func TestPurgeWorker_FailureBacksOffThenRetries(t *testing.T) {
	s := setupPurgeStack(t)
	email, accountID := s.newMailAccount(t, "worker-s3fail", "worker-pass-4")
	keys := []string{s.addMessage(t, accountID, email, "a", true), s.addMessage(t, accountID, email, "b", true)}
	s.requestPurge(t, email)

	s.s3.FailDeletes(true)
	s.runWorker(t)
	s.requireRetryable(t, accountID, email)
	if s.purgeMark(t, accountID) == nil {
		t.Fatal("a failed purge dropped the mark")
	}
	attempts, next := s.backoff(t, accountID)
	if attempts != 1 || next == nil || !next.After(time.Now()) {
		t.Fatalf("after one failed purge: attempts=%d next=%v, want 1 and a time in the future", attempts, next)
	}
	local, domain, _ := strings.Cut(email, "@")
	if left := s.s3.Keys(domain + "/" + local + "/"); len(left) != len(keys) {
		t.Fatalf("S3 refused every delete, yet objects changed: %v", left)
	}

	// Still backed off: a cycle in the meantime leaves it alone.
	s.s3.FailDeletes(false)
	s.runWorker(t)
	s.requireStillThere(t, accountID)

	// A new request from the operator clears the backoff.
	s.requestPurge(t, email)
	if attempts, next := s.backoff(t, accountID); attempts != 0 || next != nil {
		t.Fatalf("a new request did not clear the backoff: attempts=%d next=%v", attempts, next)
	}
	s.runWorker(t)
	s.requireGone(t, accountID, email)
}

// An account another node is purging (its advisory lock is held) is skipped, not purged
// twice at once, and picked up again once the lock is gone.
func TestPurgeWorker_SkipsAccountClaimedElsewhere(t *testing.T) {
	s := setupPurgeStack(t)
	email, accountID := s.newMailAccount(t, "worker-claimed", "worker-pass-5")
	s.addMessage(t, accountID, email, "m", true)
	s.requestPurge(t, email)

	ctx := context.Background()
	tx, err := s.rdb.BeginTxWithRetry(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, db.AccountPurgeLockID(accountID)); err != nil {
		t.Fatal(err)
	}
	s.runWorker(t)
	if n := s.count(t, "accounts", accountID); n != 1 {
		_ = tx.Rollback(ctx)
		t.Fatal("the account row went while another node held it")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	s.runWorker(t)
	s.requireGone(t, accountID, email)
}

// An upload in flight holds the body's lock, so the purge leaves that body, fails the
// pass and backs off; once the upload is done the next attempt finishes.
func TestPurgeWorker_UploadInFlightIsRetried(t *testing.T) {
	s := setupPurgeStack(t)
	email, accountID := s.newMailAccount(t, "worker-upload", "worker-pass-6")
	s.addMessage(t, accountID, email, "free", true)
	lockedKey := s.addMessage(t, accountID, email, "busy", true)
	hash := lockedKey[strings.LastIndex(lockedKey, "/")+1:]
	s.requestPurge(t, email)

	ctx := context.Background()
	tx, err := s.rdb.BeginTxWithRetry(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, db.GetS3ObjectLockID(accountID, hash)); err != nil {
		t.Fatal(err)
	}
	s.runWorker(t)
	if len(s.s3.Keys(lockedKey)) != 1 {
		t.Error("the purge deleted a body while its upload held the lock")
	}
	s.requireRetryable(t, accountID, email)
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	s.requestPurge(t, email) // clears the backoff
	s.runWorker(t)
	s.requireGone(t, accountID, email)
}

// A message that lands while the purge runs is purged too; a steady stream of them makes
// the purge give up for this cycle, without deleting any live body, and the account
// stays marked for the next one.
func TestPurgeWorker_MessagesArrivingMidPurge(t *testing.T) {
	s := setupPurgeStack(t)
	email, accountID := s.newMailAccount(t, "worker-late", "worker-pass-7")
	s.addMessage(t, accountID, email, "early", true)
	s.requestPurge(t, email)

	arrived := false
	s.s3.OnDelete(func([]string) {
		if !arrived {
			arrived = true
			s.addLiveDetachedMessage(t, accountID, email, "late")
		}
	})
	s.runWorker(t)
	s.s3.OnDelete(nil)
	if !arrived {
		t.Fatal("test bug: the late message was never added")
	}
	s.requireGone(t, accountID, email)

	email2, accountID2 := s.newMailAccount(t, "worker-stream", "worker-pass-7")
	s.addMessage(t, accountID2, email2, "first", true)
	s.requestPurge(t, email2)
	n := 0
	s.s3.OnDelete(func([]string) {
		n++
		s.addLiveDetachedMessage(t, accountID2, email2, fmt.Sprintf("stream%d", n))
	})
	s.runWorker(t)
	s.s3.OnDelete(nil)
	s.requireRetryable(t, accountID2, email2)
	if s.purgeMark(t, accountID2) == nil {
		t.Error("the account lost its mark after a failed cycle")
	}
	rows, err := s.rdb.QueryWithRetry(context.Background(),
		`SELECT s3_domain || '/' || s3_localpart || '/' || content_hash FROM messages WHERE account_id = $1 AND expunged_at IS NULL AND uploaded`, accountID2)
	if err != nil {
		t.Fatal(err)
	}
	var live []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			t.Fatal(err)
		}
		live = append(live, key)
	}
	rows.Close()
	if len(live) == 0 {
		t.Fatal("test bug: no live message left to check")
	}
	for _, key := range live {
		if len(s.s3.Keys(key)) != 1 {
			t.Errorf("the purge deleted the body of live message %s", key)
		}
	}
}

// Pending purges are visible as a count and the age of the oldest, so an operator can
// alert on a purge that nothing picks up.
func TestPurgeWorker_ReportsPending(t *testing.T) {
	s := setupPurgeStack(t)
	ctx := context.Background()
	before, _, err := s.rdb.PendingAccountPurgesWithRetry(ctx)
	if err != nil {
		t.Fatal(err)
	}
	email, _ := s.newMailAccount(t, "worker-pending", "worker-pass-8")
	s.requestPurge(t, email)

	count, oldest, err := s.rdb.PendingAccountPurgesWithRetry(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count < before+1 {
		t.Errorf("pending purges = %d, want at least %d", count, before+1)
	}
	// Other tests leave marked accounts behind (some backed off), so the oldest age is
	// only known to be non-negative.
	if oldest < 0 {
		t.Errorf("oldest pending purge age = %v, want non-negative", oldest)
	}
	s.runWorker(t)
	after, _, err := s.rdb.PendingAccountPurgesWithRetry(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after >= count {
		t.Errorf("pending purges = %d after the cycle, want fewer than %d", after, count)
	}
}
