//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/integration_tests/common"
	imapsrv "github.com/migadu/sora/server/imap"
	"github.com/stretchr/testify/require"
)

type notifyOwnTreeSnapshotCounter struct{ reads atomic.Int64 }

func (c *notifyOwnTreeSnapshotCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.Contains(d.SQL, "WITH accessible_mailboxes") && strings.Contains(d.SQL, "(subs.mailbox_name IS NOT NULL) AS subscribed") {
		c.reads.Add(1)
	}
	return ctx
}
func (*notifyOwnTreeSnapshotCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {
}

var notifyOwnTreeListRe = regexp.MustCompile(`^\* LIST \(([^)]*)\) "/" "?([^"( ]+)"?`)

// Actual PostgreSQL/wire regression: suppressing this connection's
// creation cannot absorb a later foreign subscription or replacement identity.
func TestNotifyOwnCreateKeepsForeignTreeEvents(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	const interval = 3 * time.Second
	imapsrv.SetNotifyPollIntervalForTests(interval)
	t.Cleanup(func() { imapsrv.SetNotifyPollIntervalForTests(notifyTestPollInterval) })
	for _, mode := range []string{"foreign_subscribe", "foreign_replacement"} {
		t.Run(mode, func(t *testing.T) {
			srv, owner := common.SetupIMAPServer(t)
			defer srv.Close()
			counter := &notifyOwnTreeSnapshotCounter{}
			address := startTracedIMAPServer(t, srv.ResilientDB, counter)
			login := fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password)
			client := dialRawIMAP(t, address)
			client.do(login)
			client.do("SELECT INBOX")
			other := dialRawIMAP(t, srv.Address)
			other.do(login)
			ctx := context.Background()
			accountID, err := srv.ResilientDB.GetAccountIDByEmailWithRetry(ctx, owner.Email)
			require.NoError(t, err)
			client.do("NOTIFY SET (PERSONAL (MailboxName SubscriptionChange))")
			bootstrapReads := counter.reads.Load()
			require.Positive(t, bootstrapReads, "the actual NOTIFY bootstrap must be observed")
			client.do("CREATE ReviewTarget")
			before, err := srv.ResilientDB.GetMailboxByNameWithRetry(ctx, accountID, "ReviewTarget")
			require.NoError(t, err)
			switch mode {
			case "foreign_subscribe":
				other.do("SUBSCRIBE ReviewTarget")
			case "foreign_replacement":
				other.do("DELETE ReviewTarget")
				other.do("CREATE ReviewTarget")
				after, lookupErr := srv.ResilientDB.GetMailboxByNameWithRetry(ctx, accountID, "ReviewTarget")
				require.NoError(t, lookupErr)
				require.NotEqual(t, before.ID, after.ID, "replacement must be a distinct mailbox")
				t.Logf("own identity id=%d UIDVALIDITY=%d; foreign replacement id=%d UIDVALIDITY=%d", before.ID, before.UIDValidity, after.ID, after.UIDValidity)
			}
			other.do("CREATE ReviewMarker")
			// This is an observed interleaving guard: the mailbox snapshot has
			// not begun while all commands committed, rather than an assumption
			// that the configured timer has not fired.
			require.Equal(t, bootstrapReads, counter.reads.Load(), "fixture: pump read a snapshot before writes finished")
			lines := readNotifyUntil(t, client, 3*interval, func(lines []string) bool {
				for _, line := range lines {
					if m := notifyOwnTreeListRe.FindStringSubmatch(line); m != nil && m[2] == "ReviewMarker" {
						return true
					}
				}
				return false
			})
			lines = append(lines, readNotifyFor(t, client, interval+interval/2)...)
			found := false
			for _, line := range lines {
				if m := notifyOwnTreeListRe.FindStringSubmatch(line); m != nil && m[2] == "ReviewTarget" {
					found = mode == "foreign_replacement" || strings.Contains(m[1], `\Subscribed`)
				}
			}
			require.True(t, found, "foreign event was absorbed by own CREATE despite observed later marker and another pump tick: %q", lines)
		})
	}
}

func TestNotifyOwnTreeAttributionInterleavings(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	const interval = 3 * time.Second
	imapsrv.SetNotifyPollIntervalForTests(interval)
	t.Cleanup(func() { imapsrv.SetNotifyPollIntervalForTests(notifyTestPollInterval) })
	for _, mode := range []string{"foreign_rename", "idempotent_subscribe", "foreign_parent", "rename_keeps_foreign_subscription"} {
		t.Run(mode, func(t *testing.T) {
			srv, owner := common.SetupIMAPServer(t)
			defer srv.Close()
			counter := &notifyOwnTreeSnapshotCounter{}
			address := startTracedIMAPServer(t, srv.ResilientDB, counter)
			login := fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password)
			client := dialRawIMAP(t, address)
			client.do(login)
			other := dialRawIMAP(t, srv.Address)
			other.do(login)
			if mode == "rename_keeps_foreign_subscription" {
				client.do("CREATE ReviewTarget")
			}
			client.do("NOTIFY SET (PERSONAL (MailboxName SubscriptionChange))")
			bootstrap := counter.reads.Load()
			require.Positive(t, bootstrap)
			var wantName string
			subscribed := false
			switch mode {
			case "foreign_rename":
				client.do("CREATE ReviewTarget")
				other.do("RENAME ReviewTarget ReviewMoved")
				wantName = "ReviewMoved"
			case "idempotent_subscribe":
				client.do("CREATE ReviewTarget")
				other.do("SUBSCRIBE ReviewTarget")
				client.do("SUBSCRIBE ReviewTarget") // successful, but changed no row
				wantName, subscribed = "ReviewTarget", true
			case "foreign_parent":
				other.do("CREATE ReviewParent")
				client.do("CREATE ReviewParent/Child")
				wantName = "ReviewParent"
			case "rename_keeps_foreign_subscription":
				other.do("SUBSCRIBE ReviewTarget")
				client.do("RENAME ReviewTarget ReviewMoved")
				wantName, subscribed = "ReviewMoved", true
			}
			other.do("CREATE ReviewMarker")
			require.Equal(t, bootstrap, counter.reads.Load(), "all writes must commit before the pump's next snapshot")
			lines := readNotifyUntil(t, client, 3*interval, func(lines []string) bool {
				var marker, wanted bool
				for _, line := range lines {
					if m := notifyOwnTreeListRe.FindStringSubmatch(line); m != nil {
						marker = marker || m[2] == "ReviewMarker"
						wanted = wanted || m[2] == wantName && (!subscribed || strings.Contains(m[1], `\Subscribed`))
					}
				}
				return marker && wanted
			})
			var found bool
			for _, line := range lines {
				if m := notifyOwnTreeListRe.FindStringSubmatch(line); m != nil {
					found = found || m[2] == wantName && (!subscribed || strings.Contains(m[1], `\Subscribed`))
					if mode == "foreign_parent" {
						require.NotEqual(t, "ReviewParent/Child", m[2], "the existing parent is foreign; only the child is own-created")
					}
				}
			}
			require.True(t, found, "foreign event disappeared: %q", lines)
		})
	}
}

func TestNotifyOwnCreateInFlightKeepsForeignEvents(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	imapsrv.SetNotifyPollIntervalForTests(100 * time.Millisecond)
	t.Cleanup(func() { imapsrv.SetNotifyPollIntervalForTests(notifyTestPollInterval) })
	srv, owner := common.SetupIMAPServer(t)
	defer srv.Close()
	counter := &notifyOwnTreeSnapshotCounter{}
	address := startTracedIMAPServer(t, srv.ResilientDB, counter)
	login := fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password)
	client := dialRawIMAP(t, address)
	client.do(login)
	client.do("CREATE ReviewForeign")
	other := dialRawIMAP(t, srv.Address)
	other.do(login)
	client.do("NOTIFY SET (PERSONAL (MailboxName SubscriptionChange))")
	bootstrap := counter.reads.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool := srv.ResilientDB.GetOperationalDatabase().GetWritePool()
	const key = int64(1577000010)
	blocker, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer blocker.Release()
	_, err = blocker.Exec(ctx, "SELECT pg_advisory_lock($1)", key)
	require.NoError(t, err)
	defer blocker.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", key)
	_, err = pool.Exec(ctx, fmt.Sprintf(`
		CREATE FUNCTION test_notify_own_create_barrier() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN PERFORM pg_advisory_xact_lock(%d::bigint); RETURN NEW; END $$;
		CREATE TRIGGER test_notify_own_create_barrier AFTER INSERT ON mailboxes
		FOR EACH ROW WHEN (NEW.name='ReviewInflight') EXECUTE FUNCTION test_notify_own_create_barrier();`, key))
	require.NoError(t, err)
	defer pool.Exec(context.Background(), "DROP TRIGGER test_notify_own_create_barrier ON mailboxes; DROP FUNCTION test_notify_own_create_barrier()")
	done := make(chan []string, 1)
	go func() {
		untagged, _ := client.do("CREATE ReviewInflight")
		done <- splitUntaggedResponses(untagged)
	}()
	require.Eventually(t, func() bool {
		var waiting bool
		err := pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=$1 AND NOT granted)", uint32(key)).Scan(&waiting)
		return err == nil && waiting
	}, 5*time.Second, 5*time.Millisecond)
	other.do("SUBSCRIBE ReviewForeign")
	other.do("CREATE ReviewMarker")
	// Pump snapshots really ran while the command was blocked, with the
	// foreign changes already committed. They must not consume those events.
	require.Eventually(t, func() bool { return counter.reads.Load() >= bootstrap+2 }, 5*time.Second, 5*time.Millisecond)
	_, err = blocker.Exec(ctx, "SELECT pg_advisory_unlock($1)", key)
	require.NoError(t, err)
	var lines []string
	select {
	case lines = <-done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	observed := func(responses []string) bool {
		var marker, subscribed bool
		for _, line := range responses {
			if m := notifyOwnTreeListRe.FindStringSubmatch(line); m != nil {
				marker = marker || m[2] == "ReviewMarker"
				subscribed = subscribed || m[2] == "ReviewForeign" && strings.Contains(m[1], `\Subscribed`)
			}
		}
		return marker && subscribed
	}
	if !observed(lines) {
		lines = append(lines, readNotifyUntil(t, client, 5*time.Second, func(later []string) bool {
			return observed(append(slices.Clone(lines), later...))
		})...)
	}
	var marker, subscribed bool
	for _, line := range lines {
		if m := notifyOwnTreeListRe.FindStringSubmatch(line); m != nil {
			require.NotEqual(t, "ReviewInflight", m[2], "own committed creation is suppressed")
			marker = marker || m[2] == "ReviewMarker"
			subscribed = subscribed || m[2] == "ReviewForeign" && strings.Contains(m[1], `\Subscribed`)
		}
	}
	require.True(t, marker && subscribed, "foreign events survive snapshots taken during the own command: %q", lines)
	client.do("NOTIFY NONE")
}
