//go:build integration

package imap

import (
	"context"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// contributorLiveRows returns how many live rows the contributor has.
func (f *sourceRekeyFixture) contributorLiveRows(t *testing.T) int {
	t.Helper()
	var n int
	require.NoError(t, f.server.ResilientDB.GetDatabase().GetWritePool().QueryRow(context.Background(),
		`SELECT COUNT(*) FROM messages WHERE account_id = $1 AND expunged_at IS NULL`, f.contributorID).Scan(&n))
	return n
}

// checkOwnerMove checks what a MOVE that raced with the rekey left behind
// (checkOwnerResult). A refused MOVE must also leave its source in place, and the MOVE
// that lands takes it out of the contributor's mailbox.
func (f *sourceRekeyFixture) checkOwnerMove(t *testing.T, moveErr error) {
	t.Helper()
	f.checkOwnerResult(t, "MOVE", moveErr, func() error {
		require.Equal(t, 1, f.contributorLiveRows(t), "a refused MOVE must leave its source in place")
		_, err := f.cc.Move(imap.SeqSetNum(1), f.shared).Wait()
		return err
	})
	assert.Zero(t, f.contributorLiveRows(t), "the MOVE expunged its source")
}

// TestCrossAccountMoveOfSourceRekeyedBeforeRowLock requests a rekey after a
// cross-account MOVE made it exist under the owner's key for the old hash and before the
// MOVE locks the source rows (#784). Current admission holds the rekey off until
// MOVE ends. The MOVE must not commit a row under a new hash,
// whose object under the owner's key nothing wrote.
func TestCrossAccountMoveOfSourceRekeyedBeforeRowLock(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	f := newSourceRekeyFixture(t)

	// The MOVE stops at its mailbox locks: after it copied the body under the owner's key,
	// before it locks and reads the source rows.
	barrier := newCopyBarrier(t, f.server,
		`SELECT 1 FROM mailboxes WHERE account_id = $1 AND name = $2 FOR UPDATE`, f.ownerID, f.shared)
	moveDone := startMove(f.cc, f.shared)
	barrier.waitBlocked(t)
	require.NotEmpty(t, f.fake.Keys(f.ownerKey(f.legacy.ContentHash)), "the MOVE copied the body under the owner's key for the old hash")

	rekeyDone := f.startBlockedRekey(t)
	barrier.release(t)
	moveErr := <-moveDone
	require.NoError(t, <-rekeyDone)
	f.checkOwnerMove(t, moveErr)
}

// TestCrossAccountMoveOfSourceRekeyedBeforeObjectCheck requests a rekey after a
// cross-account MOVE read it and before the MOVE checks the owner's object, i.e. before
// the move's transaction first reads the source rows. The MOVE makes the object exist for
// the hash it read, so it must not commit a row under the new one.
func TestCrossAccountMoveOfSourceRekeyedBeforeObjectCheck(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	f := newSourceRekeyFixture(t)

	// The cleaner's lock of the owner's object for the old hash stops the MOVE before it
	// checks that object.
	barrier := newCopyBarrier(t, f.server, `SELECT pg_advisory_xact_lock($1)`,
		db.GetS3ObjectLockID(f.ownerID, f.legacy.ContentHash))
	moveDone := startMove(f.cc, f.shared)
	barrier.waitBlocked(t)

	rekeyDone := f.startBlockedRekey(t)
	barrier.release(t)
	moveErr := <-moveDone
	require.NoError(t, <-rekeyDone)
	f.checkOwnerMove(t, moveErr)
}
