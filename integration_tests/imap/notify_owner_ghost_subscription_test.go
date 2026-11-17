//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	imapsrv "github.com/migadu/sora/server/imap"
	"github.com/stretchr/testify/require"
)

func TestNotifyOwnerRenameKeepsKnownGhostDescendants(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	const interval = 3 * time.Second
	imapsrv.SetNotifyPollIntervalForTests(interval)
	t.Cleanup(func() { imapsrv.SetNotifyPollIntervalForTests(notifyTestPollInterval) })
	srv, owner := common.SetupIMAPServer(t)
	defer srv.Close()
	counter := &notifyOwnTreeSnapshotCounter{}
	address := startTracedIMAPServer(t, srv.ResilientDB, counter)
	watcher := dialRawIMAP(t, address)
	login := fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password)
	watcher.do(login)
	other := dialRawIMAP(t, srv.Address)
	other.do(login)
	watcher.do("CREATE ReviewOld")
	watcher.do("SUBSCRIBE ReviewOld/Ghost")
	watcher.do("SUBSCRIBE ReviewNew/StaleGhost")
	watcher.do("NOTIFY SET (PERSONAL (MailboxName SubscriptionChange))")
	bootstrap := counter.reads.Load()
	require.Positive(t, bootstrap)
	watcher.do("RENAME ReviewOld ReviewNew")
	// The actual owner writer moves source ghost subscriptions and clears the
	// destination namespace, including names with no mailbox rows.
	accountID, err := srv.ResilientDB.GetAccountIDByEmailWithRetry(context.Background(), owner.Email)
	require.NoError(t, err)
	names, err := srv.ResilientDB.GetSubscribedMailboxNamesByKeyWithRetry(context.Background(), accountID)
	require.NoError(t, err)
	require.Contains(t, names, "reviewnew/ghost")
	require.NotContains(t, names, "reviewold/ghost")
	require.NotContains(t, names, "reviewnew/staleghost")
	watcher.do("CREATE ReviewNew/Ghost")
	watcher.do("CREATE ReviewNew/StaleGhost")
	other.do("CREATE ReviewMarker")
	require.Equal(t, bootstrap, counter.reads.Load(), "own changes must finish before the next snapshot")
	lines := readNotifyUntil(t, watcher, 3*interval, func(lines []string) bool {
		for _, line := range lines {
			if m := notifyOwnTreeListRe.FindStringSubmatch(line); m != nil && m[2] == "ReviewMarker" {
				return true
			}
		}
		return false
	})
	lines = append(lines, readNotifyFor(t, watcher, interval+interval/2)...)
	for _, line := range lines {
		if m := notifyOwnTreeListRe.FindStringSubmatch(line); m != nil {
			require.Equal(t, "ReviewMarker", m[2], "own rename/materialization produced a tree event: %q", lines)
		}
	}
	other.do("SUBSCRIBE ReviewNew/StaleGhost")
	lines = readNotifyUntil(t, watcher, 3*interval, func(lines []string) bool {
		for _, line := range lines {
			if m := notifyOwnTreeListRe.FindStringSubmatch(line); m != nil && m[2] == "ReviewNew/StaleGhost" && strings.Contains(m[1], `\Subscribed`) {
				return true
			}
		}
		return false
	})
	require.Contains(t, strings.Join(lines, "\n"), `\Subscribed`, "later foreign subscription must remain visible")
}
