//go:build integration

package imap

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// moveObjectLockFixture is a cross-account MOVE about to land on a destination object
// the cleaner may delete: the owner's only row for the body was expunged longer ago
// than the grace period, so the object under the owner's key is an orphan to the
// cleaner until a moved row commits.
type moveObjectLockFixture struct {
	server     *common.TestServer
	fake       *common.FakeS3
	s3         *resilient.ResilientS3Storage
	cc         *imapclient.Client // the contributor, INBOX selected
	ownerEmail string
	shared     string
	candidate  db.UserScopedObjectForCleanup
	destKey    string
	marker     string
}

const moveObjectLockGrace = time.Minute

func newMoveObjectLockFixture(t *testing.T) *moveObjectLockFixture {
	t.Helper()
	server, contributor, fake := common.SetupIMAPServerWithRealS3(t)
	t.Cleanup(server.Close)
	ctx := context.Background()
	rdb := server.ResilientDB

	ownerEmail, ownerID, shared := createOwnerWithSharedMailbox(t, server, contributor.Email, "lrswi")
	contributorID, err := rdb.GetAccountIDByAddressWithRetry(ctx, contributor.Email)
	require.NoError(t, err)

	cc, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.Logout() })
	require.NoError(t, cc.Login(contributor.Email, contributor.Password).Wait())

	const marker = "cross-account move object lock marker"
	appendTo(t, cc, "INBOX", "Move object lock", marker)
	var hash string
	require.NoError(t, rdb.QueryRowWithRetry(ctx,
		`SELECT content_hash FROM messages WHERE account_id = $1 AND uploaded AND expunged_at IS NULL`,
		contributorID).Scan(&hash))

	// The owner gets the body under its own key through a COPY, then expunges that
	// row; backdating the expunge puts it past the grace period. The contributor keeps
	// the message in INBOX, which is what the tests move.
	_, err = cc.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	_, err = cc.Copy(imap.SeqSetNum(1), shared).Wait()
	require.NoError(t, err, "cross-account COPY")

	oc, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	require.NoError(t, oc.Login(ownerEmail, "owner-pass-123").Wait())
	_, err = oc.Select(shared, nil).Wait()
	require.NoError(t, err)
	require.NoError(t, oc.Store(imap.SeqSetNum(1), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagDeleted}, Silent: true}, nil).Close())
	require.NoError(t, oc.Expunge().Close())
	_ = oc.Logout()
	_, err = rdb.ExecWithRetry(ctx,
		`UPDATE messages SET expunged_at = now() - interval '1 hour' WHERE account_id = $1 AND content_hash = $2`,
		ownerID, hash)
	require.NoError(t, err)

	ownerLocal, ownerDomain, _ := strings.Cut(ownerEmail, "@")
	f := &moveObjectLockFixture{
		server:     server,
		fake:       fake,
		cc:         cc,
		ownerEmail: ownerEmail,
		shared:     shared,
		candidate:  db.UserScopedObjectForCleanup{AccountID: ownerID, ContentHash: hash, S3Domain: ownerDomain, S3Localpart: ownerLocal},
		destKey:    helpers.NewS3Key(ownerDomain, ownerLocal, hash),
		marker:     marker,
	}
	require.NotEmpty(t, fake.Keys(f.destKey), "precondition: the owner's object exists")

	// Control: with nothing in flight, this object is exactly what the cleaner deletes.
	tx, err := rdb.GetDatabase().GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	orphan, err := rdb.GetDatabase().IsS3ObjectOrphan(ctx, tx, ownerID, hash, moveObjectLockGrace)
	require.NoError(t, err)
	require.True(t, orphan, "precondition: the owner's object is an orphan to the cleaner")

	s3storage, err := storage.New(fake.Endpoint(), "test-access-key", "test-secret-key", "test-bucket", false, false, 10*time.Second)
	require.NoError(t, err)
	f.s3 = resilient.NewResilientS3Storage(s3storage)
	return f
}

// reap runs one batch of the cleaner's S3 phase (server/cleaner reapS3Objects) over the
// fixture's object: under the object's lock, re-check that it is an orphan, delete it
// from S3 and delete its expunged rows. during, when set, runs while the lock is held,
// before the deletion. It returns the objects the re-check confirmed as orphans.
func (f *moveObjectLockFixture) reap(t *testing.T, during func()) []db.UserScopedObjectForCleanup {
	t.Helper()
	rdb := f.server.ResilientDB
	var confirmed []db.UserScopedObjectForCleanup
	err := rdb.ExecuteWithLockedS3Orphans(context.Background(), []db.UserScopedObjectForCleanup{f.candidate}, moveObjectLockGrace,
		func(ctx context.Context, orphans []db.UserScopedObjectForCleanup) error {
			confirmed = orphans
			if during != nil {
				during()
			}
			if len(orphans) == 0 {
				return nil
			}
			keys := make([]string, len(orphans))
			for i, o := range orphans {
				keys[i] = helpers.NewS3Key(o.S3Domain, o.S3Localpart, o.ContentHash)
			}
			for key, err := range f.s3.DeleteBulkWithRetry(ctx, keys) {
				t.Errorf("delete %s: %v", key, err)
			}
			_, err := rdb.DeleteExpungedMessagesByS3KeyPartsBatchWithRetry(ctx, orphans)
			return err
		})
	require.NoError(t, err)
	return confirmed
}

// assertOwnerReadsMove checks that the moved message is the shared mailbox's only live
// message and that the owner reads its body from S3.
func (f *moveObjectLockFixture) assertOwnerReadsMove(t *testing.T) {
	t.Helper()
	require.NotEmpty(t, f.fake.Keys(f.destKey), "the moved row's object must exist")
	oc, err := imapclient.DialInsecure(f.server.Address, nil)
	require.NoError(t, err)
	defer oc.Logout()
	require.NoError(t, oc.Login(f.ownerEmail, "owner-pass-123").Wait())
	mbox, err := oc.Select(f.shared, nil).Wait()
	require.NoError(t, err)
	require.Equal(t, uint32(1), mbox.NumMessages)
	assert.Contains(t, string(fetchFullBody(t, oc, 1)), f.marker, "owner FETCHes the moved body from S3")
}

// startMove starts a MOVE of the selected mailbox's first message into mailbox and
// returns the channel its result arrives on.
func startMove(c *imapclient.Client, mailbox string) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := c.Move(imap.SeqSetNum(1), mailbox).Wait()
		done <- err
	}()
	return done
}

// moveDestRowHold is a transaction holding a mailbox row, so that a MOVE into the
// mailbox stops at its mailbox locks (lockMailboxStatsPair), the first thing its
// database transaction writes, before it moves any row.
type moveDestRowHold struct {
	server *common.TestServer
	tx     pgx.Tx
	pid    int
}

func holdMoveDestRow(t *testing.T, server *common.TestServer, accountID int64, mailbox string) *moveDestRowHold {
	t.Helper()
	ctx := context.Background()
	tx, err := server.ResilientDB.GetDatabase().GetWritePool().Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	h := &moveDestRowHold{server: server, tx: tx}
	require.NoError(t, tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&h.pid))
	_, err = tx.Exec(ctx, `SELECT 1 FROM mailboxes WHERE account_id = $1 AND name = $2 FOR UPDATE`, accountID, mailbox)
	require.NoError(t, err)
	return h
}

// waitBlocked waits until a statement waits for the held row.
func (h *moveDestRowHold) waitBlocked(t *testing.T) {
	t.Helper()
	pool := h.server.ResilientDB.GetDatabase().GetWritePool()
	waitForMoveState(t, "a statement waits for the held mailbox row", func() bool {
		var waiting bool
		_ = pool.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))`, h.pid).Scan(&waiting)
		return waiting
	})
}

func (h *moveDestRowHold) release(t *testing.T) {
	t.Helper()
	require.NoError(t, h.tx.Rollback(context.Background()))
}

// waitForMoveState polls cond until it holds, failing the test after ten seconds.
func waitForMoveState(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestCrossAccountMoveHoldsDestObjectLockUntilCommit interleaves the cleaner with a
// cross-account MOVE whose destination object already exists (#744). The MOVE has
// found the object and is about to commit its rows; the cleaner, which cannot see
// uncommitted rows, must not be able to confirm the object as an orphan and delete it.
func TestCrossAccountMoveHoldsDestObjectLockUntilCommit(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	f := newMoveObjectLockFixture(t)

	// The MOVE stops at its mailbox locks: after it has checked the destination
	// object, before its rows commit.
	hold := holdMoveDestRow(t, f.server, f.candidate.AccountID, f.shared)
	moveDone := startMove(f.cc, f.shared)
	hold.waitBlocked(t)

	confirmed := f.reap(t, nil)
	assert.Empty(t, confirmed, "the cleaner confirmed the destination object of an uncommitted MOVE as an orphan")
	assert.NotEmpty(t, f.fake.Keys(f.destKey), "the cleaner deleted the destination object while the MOVE was in flight")

	hold.release(t)
	require.NoError(t, <-moveDone, "cross-account MOVE")
	f.assertOwnerReadsMove(t)
}

// TestCrossAccountMoveWaitsForCleanerBeforeCheckingDestObject is the other order: the
// cleaner has confirmed the destination object as an orphan and holds its lock when
// the MOVE arrives. The MOVE must check the object only after the cleaner is done, find
// it gone and copy it again, rather than trust a check made before the deletion.
func TestCrossAccountMoveWaitsForCleanerBeforeCheckingDestObject(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	f := newMoveObjectLockFixture(t)
	ctx := context.Background()
	pool := f.server.ResilientDB.GetDatabase().GetWritePool()

	lockID := uint64(db.GetS3ObjectLockID(f.candidate.AccountID, f.candidate.ContentHash))
	var moveDone <-chan error
	var moveErr error
	movedUnderCleaner := false
	confirmed := f.reap(t, func() {
		moveDone = startMove(f.cc, f.shared)
		waitForMoveState(t, "the MOVE waits for the object lock the cleaner holds, or is done", func() bool {
			select {
			case moveErr = <-moveDone:
				movedUnderCleaner = true
				return true
			default:
			}
			var waiting bool
			_ = pool.QueryRow(ctx, `
				SELECT EXISTS (SELECT 1 FROM pg_locks
				               WHERE locktype = 'advisory' AND NOT granted
				                 AND classid = $1::bigint::oid AND objid = $2::bigint::oid AND objsubid = 1)`,
				int64(lockID>>32), int64(lockID&0xffffffff)).Scan(&waiting)
			return waiting
		})
	})
	require.Len(t, confirmed, 1, "the cleaner confirmed the object before the MOVE arrived")
	assert.False(t, movedUnderCleaner, "the MOVE committed while the cleaner held the destination object's lock")
	if !movedUnderCleaner {
		moveErr = <-moveDone
	}
	require.NoError(t, moveErr, "cross-account MOVE")
	f.assertOwnerReadsMove(t)
}

// TestCrossAccountMoveOfBodyUploadedDuringMove covers the source's upload finishing while
// a cross-account MOVE of the body is in flight. The MOVE read the body as not uploaded
// and staged it for an upload under the owner's key; the source's upload writes only the
// source's key. The moved row must stay not uploaded until its own upload writes the
// owner's key, not claim an object under the owner's key that nothing wrote.
func TestCrossAccountMoveOfBodyUploadedDuringMove(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, contributor, fake := common.SetupIMAPServerWithRealS3(t)
	defer server.Close()
	ctx := context.Background()
	pool := server.ResilientDB.GetDatabase().GetWritePool()

	ownerEmail, ownerID, shared := createOwnerWithSharedMailbox(t, server, contributor.Email, "lrswi")
	contributorID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(ctx, contributor.Email)
	require.NoError(t, err)

	cc, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer cc.Logout()
	require.NoError(t, cc.Login(contributor.Email, contributor.Password).Wait())

	fake.FailPuts(true) // the contributor's upload stalls, so the body stays staged
	const marker = "uploaded during move marker"
	appendTo(t, cc, "INBOX", "Uploaded during move", marker)
	require.Zero(t, fake.ObjectCount(), "precondition: the upload is pending")
	_, err = cc.Select("INBOX", nil).Wait()
	require.NoError(t, err)

	hold := holdMoveDestRow(t, server, ownerID, shared)
	moveDone := startMove(cc, shared)
	hold.waitBlocked(t)

	// The contributor's upload finishes now, after the MOVE read the message.
	fake.FailPuts(false)
	uploaded := func(accountID int64, live bool) (hash string, done bool) {
		server.WaitForUploads(t)
		_ = pool.QueryRow(ctx, `
			SELECT content_hash, uploaded FROM messages
			WHERE account_id = $1 AND (expunged_at IS NULL) = $2`, accountID, live).Scan(&hash, &done)
		return hash, done
	}
	waitForMoveState(t, "the contributor's upload finishes", func() bool { _, done := uploaded(contributorID, true); return done })

	hold.release(t)
	require.NoError(t, <-moveDone, "cross-account MOVE")

	var hash string
	waitForMoveState(t, "the owner's moved row is uploaded", func() bool {
		var done bool
		hash, done = uploaded(ownerID, true)
		return done
	})
	ownerLocal, ownerDomain, _ := strings.Cut(ownerEmail, "@")
	require.NotEmpty(t, fake.Keys(helpers.NewS3Key(ownerDomain, ownerLocal, hash)),
		"the owner's moved row says uploaded, but nothing wrote its object under the owner's key")

	oc, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer oc.Logout()
	require.NoError(t, oc.Login(ownerEmail, "owner-pass-123").Wait())
	_, err = oc.Select(shared, nil).Wait()
	require.NoError(t, err)
	assert.Contains(t, string(fetchFullBody(t, oc, 1)), marker, "owner FETCHes the moved body from S3")
}
