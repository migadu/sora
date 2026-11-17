package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/require"
)

func TestMailboxMutationResults(t *testing.T) {
	d, accountID := setupMailboxTestDatabase(t)
	defer d.Close()
	ctx := context.Background()

	create := func(name string, parent *int64) *CreatedMailbox {
		tx, err := d.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		state, err := d.CreateMailboxReturningState(ctx, tx, accountID, accountID, name, parent, "")
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		return state
	}
	changeSub := func(name string, subscribed bool) SubscriptionMutation {
		tx, err := d.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		state, err := d.UpdateSubscriptionReturningState(ctx, tx, accountID, name, subscribed)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		return state
	}

	t.Run("ghost subscription mutations carry database name keys", func(t *testing.T) {
		const name = "Absent/Key"
		var key string
		require.NoError(t, d.GetWritePool().QueryRow(ctx, "SELECT LOWER($1::text)", name).Scan(&key))
		sub := changeSub(name, true)
		require.True(t, sub.Changed)
		require.Zero(t, sub.Mailbox.ID)
		require.Equal(t, key, sub.NameKey)
		noop := changeSub(name, true)
		require.False(t, noop.Changed)
		require.Equal(t, key, noop.NameKey)
		unsub := changeSub(name, false)
		require.True(t, unsub.Changed)
		require.Zero(t, unsub.Mailbox.ID)
		require.Equal(t, key, unsub.NameKey)
	})
	t.Run("creation identity and initial state do not adopt later subscription", func(t *testing.T) {
		created := create("Original", nil)
		require.True(t, created.Visible)
		require.Positive(t, created.ID)
		require.Equal(t, "original", created.NameKey)
		require.False(t, created.Subscribed)
		sub := changeSub("ORIGINAL", true)
		require.True(t, sub.Changed)
		require.Equal(t, created.ID, sub.Mailbox.ID)
		require.False(t, created.Subscribed, "the creation value is immutable")
		require.False(t, changeSub("Original", true).Changed, "an idempotent own SUBSCRIBE cannot absorb a foreign one")
	})
	t.Run("preexisting ghost subscription is initial state", func(t *testing.T) {
		require.True(t, changeSub("Ghost", true).Changed)
		created := create("Ghost", nil)
		require.True(t, created.Subscribed)
	})
	t.Run("creation records subscription at the insert snapshot", func(t *testing.T) {
		const key = int64(1577000001)
		blocker, err := d.GetWritePool().Acquire(ctx)
		require.NoError(t, err)
		defer blocker.Release()
		_, err = blocker.Exec(ctx, "SELECT pg_advisory_lock($1)", key)
		require.NoError(t, err)
		defer blocker.Exec(ctx, "SELECT pg_advisory_unlock($1)", key)
		_, err = d.GetWritePool().Exec(ctx, fmt.Sprintf(`
			CREATE FUNCTION test_initial_subscription_barrier() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN PERFORM pg_advisory_xact_lock(%d::bigint); RETURN NEW; END $$;
			CREATE TRIGGER test_initial_subscription_barrier AFTER INSERT ON mailboxes
			FOR EACH ROW WHEN (NEW.name='StatementSnapshot') EXECUTE FUNCTION test_initial_subscription_barrier();`, key))
		require.NoError(t, err)
		defer d.GetWritePool().Exec(ctx, "DROP TRIGGER test_initial_subscription_barrier ON mailboxes; DROP FUNCTION test_initial_subscription_barrier()")
		limited, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		tx, err := d.GetWritePool().Begin(limited)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		var pid int
		require.NoError(t, tx.QueryRow(limited, "SELECT pg_backend_pid()").Scan(&pid))
		type result struct {
			state *CreatedMailbox
			err   error
		}
		done := make(chan result, 1)
		go func() {
			state, err := d.CreateMailboxReturningState(limited, tx, accountID, accountID, "StatementSnapshot", nil, "")
			done <- result{state, err}
		}()
		require.Eventually(t, func() bool {
			var waiting bool
			err := d.GetWritePool().QueryRow(ctx, "SELECT COALESCE(bool_or(wait_event_type='Lock'),false) FROM pg_stat_activity WHERE pid=$1", pid).Scan(&waiting)
			return err == nil && waiting
		}, 5*time.Second, 5*time.Millisecond)
		// The INSERT is still executing, so this subscription commits after its
		// statement snapshot but before the later path/visibility statements.
		subTx, err := d.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer subTx.Rollback(ctx)
		require.NoError(t, d.Subscribe(ctx, subTx, accountID, "StatementSnapshot"))
		require.NoError(t, subTx.Commit(ctx))
		_, err = blocker.Exec(ctx, "SELECT pg_advisory_unlock($1)", key)
		require.NoError(t, err)
		r := <-done
		require.NoError(t, r.err)
		require.False(t, r.state.Subscribed, "a later SELECT would incorrectly adopt the foreign subscription")
		require.NoError(t, tx.Commit(ctx))
		current, err := d.GetMailboxByName(ctx, accountID, "StatementSnapshot")
		require.NoError(t, err)
		require.True(t, current.Subscribed)
	})
	t.Run("failed and rolled back creation are not committed identities", func(t *testing.T) {
		tx, err := d.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		state, err := d.CreateMailboxReturningState(ctx, tx, accountID, accountID, "Original", nil, "")
		require.ErrorIs(t, err, consts.ErrDBUniqueViolation)
		require.Nil(t, state)
		state, err = d.CreateMailboxReturningState(ctx, tx, accountID, accountID, "RolledBack", nil, "")
		require.NoError(t, err)
		require.Positive(t, state.ID)
		require.NoError(t, tx.Rollback(ctx))
		_, err = d.GetMailboxByName(ctx, accountID, "RolledBack")
		require.ErrorIs(t, err, consts.ErrMailboxNotFound)
	})
	t.Run("default unsubscribe is an unchanged request", func(t *testing.T) {
		tx, err := d.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		require.NoError(t, d.CreateDefaultMailboxes(ctx, tx, accountID))
		require.NoError(t, tx.Commit(ctx))
		sub := changeSub("INBOX", false)
		require.False(t, sub.Changed)
		require.True(t, sub.Mailbox.Subscribed)
	})
	t.Run("rename results identify exact rows and preserve prior subscription separately", func(t *testing.T) {
		parent := create("Tree", nil)
		child := create("Tree/Kid", &parent.ID)
		require.True(t, changeSub(child.Name, true).Changed)
		tx, err := d.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		changes, err := d.RenameMailboxReturningNames(ctx, tx, parent.ID, accountID, accountID, "RenamedTree", nil)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		byID := make(map[int64]MailboxNameMutation)
		for _, c := range changes {
			byID[c.ID] = c
		}
		require.Len(t, byID, 2)
		require.Equal(t, "Tree", byID[parent.ID].BeforeName)
		require.Equal(t, "RenamedTree", byID[parent.ID].AfterName)
		require.False(t, byID[parent.ID].SubscribedSet, "owner rename keeps prior snapshot subscription state")
		require.Equal(t, child.Name, byID[child.ID].BeforeName)
		require.Equal(t, "RenamedTree/Kid", byID[child.ID].AfterName)
		require.False(t, byID[child.ID].SubscribedSet)
		var key string
		require.NoError(t, d.GetWritePool().QueryRow(ctx, "SELECT LOWER($1::text)", "RenamedTree/Kid").Scan(&key))
		require.Equal(t, key, byID[child.ID].AfterKey)
		got, err := d.GetMailboxByName(ctx, accountID, "RenamedTree/Kid")
		require.NoError(t, err)
		require.True(t, got.Subscribed)
	})
	t.Run("non-owner rename records viewer subscription on destination names", func(t *testing.T) {
		viewerTx, err := d.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer viewerTx.Rollback(ctx)
		viewerEmail := fmt.Sprintf("viewer_%d@example.com", time.Now().UnixNano())
		viewerID, err := d.CreateAccount(ctx, viewerTx, CreateAccountRequest{
			Email: viewerEmail, Password: "password", IsPrimary: true, HashType: "bcrypt",
		})
		require.NoError(t, err)
		require.NoError(t, d.Subscribe(ctx, viewerTx, viewerID, "NonOwnerSrc"))
		require.NoError(t, d.Subscribe(ctx, viewerTx, viewerID, "NonOwnerDst/GhostChild"))
		require.NoError(t, viewerTx.Commit(ctx))

		srcParent := create("NonOwnerSrc", nil)
		srcChild := create("NonOwnerSrc/GhostChild", &srcParent.ID)

		tx, err := d.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		changes, err := d.RenameMailboxReturningNames(ctx, tx, srcParent.ID, accountID, viewerID, "NonOwnerDst", nil)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))

		byID := make(map[int64]MailboxNameMutation)
		for _, c := range changes {
			byID[c.ID] = c
		}
		require.Len(t, byID, 2)
		require.True(t, byID[srcParent.ID].SubscribedSet)
		var parentSubscribed, childSubscribed bool
		require.NoError(t, d.GetWritePool().QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM subscriptions WHERE account_id=$1 AND LOWER(mailbox_name)=LOWER($2::text))", viewerID, "NonOwnerDst").Scan(&parentSubscribed))
		require.False(t, parentSubscribed, "viewer's subscription stayed on NonOwnerSrc")
		require.True(t, byID[srcChild.ID].SubscribedSet)
		require.NoError(t, d.GetWritePool().QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM subscriptions WHERE account_id=$1 AND LOWER(mailbox_name)=LOWER($2::text))", viewerID, "NonOwnerDst/GhostChild").Scan(&childSubscribed))
		require.True(t, childSubscribed, "viewer already held a subscription on NonOwnerDst/GhostChild")
	})
}

// The subscription is name-based, but its attribution must remain tied to the
// row locked before the write, even if a foreign command would rename/delete it.
func TestSubscriptionMutationLocksIdentity(t *testing.T) {
	d, accountID := setupMailboxTestDatabase(t)
	defer d.Close()
	ctx := context.Background()
	for _, operation := range []string{"rename", "delete"} {
		t.Run(operation, func(t *testing.T) {
			name := "Identity-" + operation
			require.NoError(t, d.CreateMailboxForUser(ctx, accountID, name))
			mailbox, err := d.GetMailboxByName(ctx, accountID, name)
			require.NoError(t, err)
			tx, err := d.GetWritePool().Begin(ctx)
			require.NoError(t, err)
			defer tx.Rollback(ctx)
			state, err := d.UpdateSubscriptionReturningState(ctx, tx, accountID, name, true)
			require.NoError(t, err)
			require.Equal(t, mailbox.ID, state.Mailbox.ID)
			foreign, err := d.GetWritePool().Begin(ctx)
			require.NoError(t, err)
			defer foreign.Rollback(ctx)
			var pid int
			require.NoError(t, foreign.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid))
			done := make(chan error, 1)
			go func() {
				query := "UPDATE mailboxes SET name=name||'-new' WHERE id=$1"
				if operation == "delete" {
					query = "UPDATE mailboxes SET deleted_at=now() WHERE id=$1"
				}
				_, e := foreign.Exec(ctx, query, mailbox.ID)
				if e == nil {
					e = foreign.Commit(ctx)
				}
				done <- e
			}()
			require.Eventually(t, func() bool {
				var waiting bool
				e := d.GetWritePool().QueryRow(ctx, "SELECT COALESCE(bool_or(wait_event_type='Lock'),false) FROM pg_stat_activity WHERE pid=$1", pid).Scan(&waiting)
				return e == nil && waiting
			}, 5*time.Second, 5*time.Millisecond, "foreign identity change must wait for the subscription transaction")
			require.NoError(t, tx.Commit(ctx))
			require.NoError(t, <-done)
			require.Equal(t, mailbox.Name, state.Mailbox.Name, "later writes do not alter the result")
		})
	}
}
