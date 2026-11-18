//go:build integration

package resilient

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/go-imap"
	"github.com/migadu/sora/db"
)

// crossAccountBodyCap is the most distinct bodies one COPY or MOVE may re-key into another
// account's mailbox.
const crossAccountBodyCap = db.MaxCrossAccountBodies

// heldAdvisoryLocks returns how many advisory locks are held by the backend that holds
// accountID's S3 object lock on hash in shared mode, as a cross-account COPY or MOVE does
// during its S3 phase; 0 when no backend holds it.
func heldAdvisoryLocks(t *testing.T, pool *pgxpool.Pool, accountID int64, hash string) int {
	t.Helper()
	id := uint64(db.GetS3ObjectLockID(accountID, hash))
	var n int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM pg_locks l
		WHERE l.locktype = 'advisory' AND l.granted AND l.pid = (
			SELECT h.pid FROM pg_locks h
			WHERE h.locktype = 'advisory' AND h.mode = 'ShareLock' AND h.granted
			  AND h.database = (SELECT oid FROM pg_database WHERE datname = current_database())
			  AND h.classid = $1::bigint::oid AND h.objid = $2::bigint::oid AND h.objsubid = 1
			LIMIT 1)`,
		int64(id>>32), int64(id&0xffffffff)).Scan(&n); err != nil {
		t.Fatalf("count the advisory locks of the session: %v", err)
	}
	return n
}

// A cross-account COPY or MOVE holds two advisory locks per distinct body until it
// commits: the destination object's S3 lock and the FTS orphan-sweep lock (restageFTS).
// PostgreSQL keeps every one of them in its shared lock table, max_locks_per_transaction x
// (max_connections + max_prepared_transactions) entries for the whole server, so one command
// over tens of thousands of messages fails every session with "out of shared memory". One
// over the cap is refused before any body lock or storage callback, changing no
// rows. A fresh check may hold account-rekey guards until rollback.
func TestCrossAccountCopyMoveOverTheBodyCapTakeNoBodyLocks(t *testing.T) {
	ctx := context.Background()
	cfg := testDatabaseConfig()
	plain := newTestPool(t, cfg, nil)
	rdb := newTestResilientDatabase(cfg, plain)
	const bodies = crossAccountBodyCap + 1

	for _, command := range []string{"COPY", "MOVE"} {
		t.Run(command, func(t *testing.T) {
			f := newCrossAccountMoveFixture(t, plain, bodies)
			uids := make([]imap.UID, bodies)
			for i := range uids {
				uids[i] = imap.UID(i + 1)
			}
			checks, held := 0, 0
			ensure := func(_ context.Context, hash string) error {
				if checks++; checks == 1 {
					held = heldAdvisoryLocks(t, plain, f.ownerID, hash)
				}
				return nil
			}
			var err error
			if command == "COPY" {
				_, _, err = rdb.CopyMessagesWithRetry(ctx, &uids, f.srcID, f.destID, f.ownerID,
					"example.net", "owner", "test-instance", f.sourceHashes(), f.hashes, ensure)
			} else {
				_, err = rdb.MoveMessagesWithRetry(ctx, &uids, f.srcID, f.destID, f.ownerID,
					"example.net", "owner", "test-instance", f.sourceHashes(), f.hashes, ensure)
			}
			if !errors.Is(err, db.ErrCrossAccountBodyLimit) || checks != 0 {
				t.Errorf("%s of %d distinct bodies into another account: err = %v, made %d S3 checks while its session held %d advisory locks; want it refused before taking any",
					command, bodies, err, checks, held)
			}
			if n := countLiveMessages(t, plain, f.destID); n != 0 {
				t.Errorf("%s over the cap left %d messages in DEST, want 0", command, n)
			}
			if n := countLiveMessages(t, plain, f.srcID); n != bodies {
				t.Errorf("%s over the cap left %d messages in SRC, want %d", command, n, bodies)
			}
		})
	}
}

// A cross-account COPY at the cap still runs, holding its destination objects' locks until
// its rows commit: the cleaner's deleter, which takes the same lock before its orphan
// re-check, cannot delete a body the copy has made exist under the owner's key and whose
// rows it cannot see yet. The cap counts bodies, not messages: two copies of one body are
// one. The session holds at most two advisory locks per body.
func TestCrossAccountCopyAtTheBodyCapHoldsTheCleanerOff(t *testing.T) {
	ctx := context.Background()
	cfg := testDatabaseConfig()
	plain := newTestPool(t, cfg, nil)
	rdb := newTestResilientDatabase(cfg, plain)
	const messages = crossAccountBodyCap + 1
	f := newCrossAccountMoveFixture(t, plain, messages)
	// The last message carries the body of the one before it.
	f.hashes[messages-1] = f.hashes[messages-2]
	if _, err := plain.Exec(ctx, `UPDATE messages SET content_hash = $3 WHERE mailbox_id = $1 AND uid = $2`,
		f.srcID, messages, f.hashes[messages-1]); err != nil {
		t.Fatalf("share a body: %v", err)
	}
	bodies := f.hashes[:crossAccountBodyCap]

	candidate := func(hash string) []db.UserScopedObjectForCleanup {
		return []db.UserScopedObjectForCleanup{{AccountID: f.ownerID, ContentHash: hash, S3Domain: "example.net", S3Localpart: "owner"}}
	}
	// confirmedOrphans runs the cleaner's lock and orphan re-check over hash under the
	// owner's key and returns what it would delete.
	confirmedOrphans := func(hash string) []db.UserScopedObjectForCleanup {
		var confirmed []db.UserScopedObjectForCleanup
		if err := rdb.ExecuteWithLockedS3Orphans(ctx, candidate(hash), time.Minute,
			func(_ context.Context, orphans []db.UserScopedObjectForCleanup) error {
				confirmed = orphans
				return nil
			}); err != nil {
			t.Fatalf("cleaner batch: %v", err)
		}
		return confirmed
	}
	last := bodies[len(bodies)-1]
	if len(confirmedOrphans(last)) != 1 {
		t.Fatal("precondition: with nothing in flight the cleaner deletes the owner's object")
	}

	uids := make([]imap.UID, messages)
	for i := range uids {
		uids[i] = imap.UID(i + 1)
	}
	checks := 0
	ensure := func(_ context.Context, hash string) error {
		checks++
		if hash != last {
			return nil
		}
		if held := heldAdvisoryLocks(t, plain, f.ownerID, hash); held == 0 || held > 2*crossAccountBodyCap {
			t.Errorf("COPY of %d bodies holds %d advisory locks during its S3 phase, want 1..%d", crossAccountBodyCap, held, 2*crossAccountBodyCap)
		}
		if orphans := confirmedOrphans(hash); len(orphans) != 0 {
			t.Errorf("the cleaner confirmed %v as an orphan while COPY held it", orphans)
		}
		return nil
	}
	uidMap, _, err := rdb.CopyMessagesWithRetry(ctx, &uids, f.srcID, f.destID, f.ownerID,
		"example.net", "owner", "test-instance", f.sourceHashes(), bodies, ensure)
	if err != nil {
		t.Fatalf("COPY of %d messages with %d distinct bodies into another account: %v", messages, len(bodies), err)
	}
	if len(uidMap) != messages || checks != len(bodies) {
		t.Fatalf("COPY copied %d messages and made %d S3 checks, want %d and %d", len(uidMap), checks, messages, len(bodies))
	}
	if orphans := confirmedOrphans(last); len(orphans) != 0 {
		t.Errorf("the cleaner confirmed %v as an orphan after COPY committed rows for it", orphans)
	}
}

// Same-mailbox CopyMessagesWithRetry must fail immediately before taking
// destination S3 locks or invoking ensureDestObject, and same-mailbox
// MoveMessagesWithRetry must succeed with nil sourceHashes while skipping
// destination S3 locks and ensureDestObject even on > MaxCrossAccountBodies
// legacy contributor rows.
func TestSameMailboxCopyMoveWithRetrySkipsDestObjectsAndSourceHashes(t *testing.T) {
	ctx := context.Background()
	cfg := testDatabaseConfig()
	plain := newTestPool(t, cfg, nil)
	rdb := newTestResilientDatabase(cfg, plain)
	const bodies = crossAccountBodyCap + 1

	t.Run("COPY", func(t *testing.T) {
		f := newCrossAccountMoveFixture(t, plain, bodies)
		if _, err := plain.Exec(ctx, `UPDATE messages SET mailbox_id = $2 WHERE mailbox_id = $1`, f.srcID, f.destID); err != nil {
			t.Fatalf("place legacy contributor rows in shared mailbox: %v", err)
		}
		if _, err := plain.Exec(ctx, `UPDATE mailboxes SET highest_uid = $2 WHERE id = $1`, f.destID, bodies); err != nil {
			t.Fatalf("update highest_uid: %v", err)
		}
		uids := make([]imap.UID, bodies)
		for i := range uids {
			uids[i] = imap.UID(i + 1)
		}
		checks, held := 0, 0
		ensure := func(_ context.Context, hash string) error {
			if checks++; checks == 1 {
				held = heldAdvisoryLocks(t, plain, f.ownerID, hash)
			}
			return nil
		}
		_, _, err := rdb.CopyMessagesWithRetry(ctx, &uids, f.destID, f.destID, f.ownerID,
			"example.net", "owner", "test-instance", f.sourceHashes(), f.hashes, ensure)
		if err == nil || !strings.Contains(err.Error(), "source and destination mailboxes cannot be the same") {
			t.Fatalf("same-mailbox CopyMessagesWithRetry err = %v, want same-mailbox error", err)
		}
		if checks != 0 || held != 0 {
			t.Errorf("same-mailbox CopyMessagesWithRetry made %d S3 checks and held %d advisory locks, want 0 and 0", checks, held)
		}
	})

	t.Run("MOVE", func(t *testing.T) {
		f := newCrossAccountMoveFixture(t, plain, bodies)
		if _, err := plain.Exec(ctx, `UPDATE messages SET mailbox_id = $2 WHERE mailbox_id = $1`, f.srcID, f.destID); err != nil {
			t.Fatalf("place legacy contributor rows in shared mailbox: %v", err)
		}
		if _, err := plain.Exec(ctx, `UPDATE mailboxes SET highest_uid = $2 WHERE id = $1`, f.destID, bodies); err != nil {
			t.Fatalf("update highest_uid: %v", err)
		}
		uids := make([]imap.UID, bodies)
		for i := range uids {
			uids[i] = imap.UID(i + 1)
		}
		checks, held := 0, 0
		ensure := func(_ context.Context, hash string) error {
			if checks++; checks == 1 {
				held = heldAdvisoryLocks(t, plain, f.ownerID, hash)
			}
			return nil
		}
		uidMap, err := rdb.MoveMessagesWithRetry(ctx, &uids, f.destID, f.destID, f.ownerID,
			"example.net", "owner", "test-instance", nil, f.hashes, ensure)
		if err != nil {
			t.Fatalf("same-mailbox MoveMessagesWithRetry failed: %v", err)
		}
		if len(uidMap) != bodies {
			t.Errorf("same-mailbox MoveMessagesWithRetry moved %d rows, want %d", len(uidMap), bodies)
		}
		if checks != 0 || held != 0 {
			t.Errorf("same-mailbox MoveMessagesWithRetry made %d S3 checks and held %d advisory locks, want 0 and 0", checks, held)
		}
		if n := countLiveMessages(t, plain, f.destID); n != bodies {
			t.Errorf("same-mailbox MoveMessagesWithRetry left %d live messages, want %d", n, bodies)
		}
	})
}

// When cross-account source rows are concurrently expunged before the write
// transaction reads them (so cross == false), oversized destObjects must still be
// refused with ErrCrossAccountBodyLimit before locking or copying destObjects.
func TestCrossAccountCopyMoveOversizedDestObjectsWithNoCrossRowsRefusedBeforeLocks(t *testing.T) {
	ctx := context.Background()
	cfg := testDatabaseConfig()
	plain := newTestPool(t, cfg, nil)
	rdb := newTestResilientDatabase(cfg, plain)
	const bodies = crossAccountBodyCap + 1

	for _, command := range []string{"COPY", "MOVE"} {
		t.Run(command, func(t *testing.T) {
			f := newCrossAccountMoveFixture(t, plain, bodies)
			if _, err := plain.Exec(ctx, `UPDATE messages SET expunged_at = now(), expunged_modseq = nextval('messages_modseq') WHERE mailbox_id = $1`, f.srcID); err != nil {
				t.Fatalf("expunge source rows: %v", err)
			}
			uids := make([]imap.UID, bodies)
			for i := range uids {
				uids[i] = imap.UID(i + 1)
			}
			checks, held := 0, 0
			ensure := func(_ context.Context, hash string) error {
				if checks++; checks == 1 {
					held = heldAdvisoryLocks(t, plain, f.ownerID, hash)
				}
				return nil
			}
			var err error
			if command == "COPY" {
				_, _, err = rdb.CopyMessagesWithRetry(ctx, &uids, f.srcID, f.destID, f.ownerID,
					"example.net", "owner", "test-instance", f.sourceHashes(), f.hashes, ensure)
			} else {
				_, err = rdb.MoveMessagesWithRetry(ctx, &uids, f.srcID, f.destID, f.ownerID,
					"example.net", "owner", "test-instance", f.sourceHashes(), f.hashes, ensure)
			}
			if !errors.Is(err, db.ErrCrossAccountBodyLimit) || checks != 0 || held != 0 {
				t.Errorf("%s with %d destObjects and 0 live cross rows: err = %v, checks = %d, held = %d; want ErrCrossAccountBodyLimit, 0, 0",
					command, bodies, err, checks, held)
			}
		})
	}
}
