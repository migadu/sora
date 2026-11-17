//go:build integration

package resilient

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/circuitbreaker"
	"github.com/stretchr/testify/require"
)

// The caller's rekey-only map cannot bound the shared body locks of legacy rows
// already owned by the destination. Read the whole selected source in the actual
// write transaction before the first destination lock or storage callback.
func TestCrossAccountBodyBudgetIncludesAlreadyOwnedSources(t *testing.T) {
	ctx := context.Background()
	cfg := testDatabaseConfig()
	plain := newTestPool(t, cfg, nil)
	rdb := newTestResilientDatabase(cfg, plain)
	settings := circuitbreaker.DefaultSettings("complete-source-budget")
	settings.IsSuccessful = isBreakerSuccess // match the production database breaker
	rdb.writeBreaker = circuitbreaker.NewCircuitBreaker(settings)
	for _, mode := range []string{"COPY", "MOVE"} {
		for _, shape := range []string{"mixed over cap", "same body repeats", "all already owned"} {
			t.Run(mode+"/"+shape, func(t *testing.T) {
				const n = db.MaxCrossAccountBodies + 1
				f := newCrossAccountMoveFixture(t, plain, n)
				_, err := plain.Exec(ctx, `UPDATE messages SET account_id=$2 WHERE mailbox_id=$1 AND uid>1`, f.srcID, f.ownerID)
				require.NoError(t, err)
				if shape == "same body repeats" {
					_, err = plain.Exec(ctx, `UPDATE messages SET content_hash=$2 WHERE mailbox_id=$1`, f.srcID, f.hashes[0])
					require.NoError(t, err)
				}
				source := map[imap.UID]string{1: f.hashes[0]}
				objects := []string{f.hashes[0]}
				if shape == "all already owned" {
					_, err = plain.Exec(ctx, `UPDATE messages SET account_id=$2 WHERE mailbox_id=$1`, f.srcID, f.ownerID)
					require.NoError(t, err)
					source = nil
					objects = nil
				}
				uids := make([]imap.UID, n)
				for i := range uids {
					uids[i] = imap.UID(i + 1)
				}
				calls := 0
				ensure := func(context.Context, string) error { calls++; return nil }
				before := rdb.writeBreaker.Counts()
				var mapped map[imap.UID]imap.UID
				if mode == "COPY" {
					mapped, _, err = rdb.CopyMessagesWithRetry(ctx, &uids, f.srcID, f.destID, f.ownerID, "example.net", "owner", "budget", source, objects, ensure)
				} else {
					mapped, err = rdb.MoveMessagesWithRetry(ctx, &uids, f.srcID, f.destID, f.ownerID, "example.net", "owner", "budget", source, objects, ensure)
				}
				after := rdb.writeBreaker.Counts()
				require.Equal(t, before.TotalFailures, after.TotalFailures, "an implementation limit must not charge the database breaker")
				if shape == "mixed over cap" {
					require.ErrorIs(t, err, db.ErrCrossAccountBodyLimit)
					require.Zero(t, calls, "complete-source refusal must precede storage callbacks")
					require.Empty(t, mapped)
					require.Equal(t, 0, countLiveMessages(t, plain, f.destID))
					require.Equal(t, n, countLiveMessages(t, plain, f.srcID))
					require.Equal(t, before.Requests+2, after.Requests, "one begin and one refused operation; no transaction retry")
				} else {
					require.NoError(t, err)
					require.Len(t, mapped, n)
					require.Equal(t, n, countLiveMessages(t, plain, f.destID))
				}
			})
		}
	}
}

// A source change committed while the account guard is queued is read afterwards,
// before any storage callback. No stale pre-lock cardinality decides the command.
func TestCrossAccountBodyBudgetReadsFreshAfterAccountGuard(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cfg := testDatabaseConfig()
	plain := newTestPool(t, cfg, nil)
	rdb := newTestResilientDatabase(cfg, plain)
	const n = db.MaxCrossAccountBodies + 1
	f := newCrossAccountMoveFixture(t, plain, n)
	_, err := plain.Exec(ctx, `UPDATE messages SET account_id=$2 WHERE mailbox_id=$1 AND uid>1`, f.srcID, f.ownerID)
	require.NoError(t, err)
	guard, err := plain.Begin(ctx)
	require.NoError(t, err)
	defer guard.Rollback(context.Background())
	_, err = guard.Exec(ctx, `SELECT pg_advisory_xact_lock($1::int4,hashint8($2::bigint))`, consts.SoraContentRekeyLockClassID, f.accountID)
	require.NoError(t, err)
	uids := make([]imap.UID, n)
	for i := range uids {
		uids[i] = imap.UID(i + 1)
	}
	var calls atomic.Int64
	type outcome struct {
		uids map[imap.UID]imap.UID
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		m, _, err := rdb.CopyMessagesWithRetry(ctx, &uids, f.srcID, f.destID, f.ownerID, "example.net", "owner", "fresh-budget", map[imap.UID]string{1: f.hashes[0]}, []string{f.hashes[0]}, func(context.Context, string) error { calls.Add(1); return nil })
		done <- outcome{m, err}
	}()
	require.Eventually(t, func() bool {
		var waiting bool
		err := plain.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted AND mode='ShareLock' AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND classid=$1::bigint::oid AND objid=hashint8($2::bigint)::oid AND objsubid=2)`, int64(consts.SoraContentRekeyLockClassID), f.accountID).Scan(&waiting)
		return err == nil && waiting
	}, 3*time.Second, 10*time.Millisecond)
	require.Zero(t, calls.Load(), "budget/account admission must precede storage")
	_, err = guard.Exec(ctx, `UPDATE messages SET expunged_at=now(),expunged_modseq=nextval('messages_modseq') WHERE mailbox_id=$1 AND uid>1`, f.srcID)
	require.NoError(t, err)
	require.NoError(t, guard.Commit(ctx))
	got := <-done
	require.NoError(t, got.err)
	require.Len(t, got.uids, 1, "the fresh source now has only one live selected body")
	require.Equal(t, int64(1), calls.Load())
	require.Equal(t, 1, countLiveMessages(t, plain, f.destID))
}
