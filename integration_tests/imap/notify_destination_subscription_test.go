//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	imapsrv "github.com/migadu/sora/server/imap"
	"github.com/stretchr/testify/require"
)

func TestNotifyNonOwnerRenameKeepsForeignDestinationSubscription(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	const interval = 3 * time.Second
	imapsrv.SetNotifyPollIntervalForTests(interval)
	t.Cleanup(func() { imapsrv.SetNotifyPollIntervalForTests(notifyTestPollInterval) })
	for _, mode := range []string{"foreign_new", "preexisting", "own_ghost", "idempotent_own_after_foreign"} {
		t.Run(mode, func(t *testing.T) {
			srv, owner := common.SetupIMAPServer(t)
			defer srv.Close()
			member := fmt.Sprintf("case-rename-%d@example.com", time.Now().UnixNano())
			_, err := srv.ResilientDB.CreateAccountWithRetry(context.Background(), db.CreateAccountRequest{Email: member, Password: "password", HashType: "bcrypt", IsPrimary: true})
			require.NoError(t, err)
			o := dialRawIMAP(t, srv.Address)
			o.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
			o.do("CREATE Shared/Team")
			o.do("CREATE Shared/Team/Old")
			o.do(fmt.Sprintf("SETACL Shared/Team %s lrkx", member))
			o.do(fmt.Sprintf("SETACL Shared/Team/Old %s lrkx", member))
			counter := &notifyOwnTreeSnapshotCounter{}
			address := startTracedIMAPServer(t, srv.ResilientDB, counter)
			watcher := dialRawIMAP(t, address)
			login := fmt.Sprintf("LOGIN %s password", member)
			watcher.do(login)
			other := dialRawIMAP(t, srv.Address)
			other.do(login)
			if mode == "preexisting" {
				watcher.do("SUBSCRIBE Shared/Team/New")
			}
			watcher.do("NOTIFY SET (SUBTREE Shared (MailboxName SubscriptionChange))")
			bootstrap := counter.reads.Load()
			require.Positive(t, bootstrap)
			switch mode {
			case "foreign_new", "idempotent_own_after_foreign":
				other.do("SUBSCRIBE Shared/Team/New")
			}
			if mode == "own_ghost" || mode == "idempotent_own_after_foreign" {
				watcher.do("SUBSCRIBE Shared/Team/New")
			}
			_, tagged := watcher.do("RENAME Shared/Team/Old Shared/Team/New")
			require.Contains(t, tagged, " OK ", "non-owner rename must actually succeed")
			o.do("CREATE Shared/Team/Marker")
			require.Equal(t, bootstrap, counter.reads.Load(), "all writes must commit before the pump's next snapshot")
			lines := readNotifyUntil(t, watcher, 3*interval, func(lines []string) bool {
				for _, line := range lines {
					if m := notifyOwnTreeListRe.FindStringSubmatch(line); m != nil && m[2] == "Shared/Team/Marker" {
						return true
					}
				}
				return false
			})
			lines = append(lines, readNotifyFor(t, watcher, interval+interval/2)...)
			found := false
			for _, line := range lines {
				if m := notifyOwnTreeListRe.FindStringSubmatch(line); m != nil && m[2] == "Shared/Team/New" && strings.Contains(m[1], `\Subscribed`) {
					found = true
				}
			}
			require.Equal(t, mode == "foreign_new" || mode == "idempotent_own_after_foreign", found, "only an unobserved foreign destination subscription must be reported: %q", lines)
		})
	}
}
