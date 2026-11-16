//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	imapsrv "github.com/migadu/sora/server/imap"
	"github.com/stretchr/testify/require"
)

func TestNotifyOwnAppendForeignStoreBeforeFirstPoll(t *testing.T) {
	t.Run("FlagChange enabled", func(t *testing.T) { ownAppendForeignStoreBeforeFirstPoll(t, false) })
	t.Run("FlagChange filtered", func(t *testing.T) { ownAppendForeignStoreBeforeFirstPoll(t, true) })
}

func ownAppendForeignStoreBeforeFirstPoll(t *testing.T, filtered bool) {
	common.SkipIfDatabaseUnavailable(t)
	imapsrv.SetNotifyPollIntervalForTests(time.Hour)
	defer imapsrv.SetNotifyPollIntervalForTests(300 * time.Millisecond)
	server, account, fake := common.SetupIMAPServerWithRealS3(t)
	defer server.Close()
	c := dialRawIMAP(t, server.Address)
	login := fmt.Sprintf("LOGIN %s %s", account.Email, account.Password)
	c.do(login)
	c.appendMsg("INBOX", strings.Replace(notifyTestMessage, "NOTIFY integration test", "seed", 1))
	baseline := selectHighestModSeq(t, c, "INBOX")
	if filtered {
		c.do("NOTIFY SET (SELECTED (MessageNew (UID FLAGS) MessageExpunge))")
	} else {
		c.do("NOTIFY SET (SELECTED (MessageNew (UID FLAGS) MessageExpunge FlagChange))")
	}
	entered, resume := make(chan struct{}), make(chan struct{})
	var once, enteredOnce sync.Once
	release := func() { once.Do(func() { close(resume) }) }
	defer release()
	fake.OnPut(func(string) {
		enteredOnce.Do(func() { close(entered) })
		<-resume
	})
	defer fake.OnPut(nil)
	tag := c.nextTag()
	_, err := fmt.Fprintf(c.conn, "%s APPEND INBOX {%d+}\r\n%s\r\n", tag, len(notifyTestMessage), notifyTestMessage)
	require.NoError(t, err)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("own APPEND did not reach post-commit upload barrier")
	}
	ctx := context.Background()
	accountID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)
	mailbox, err := server.ResilientDB.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	require.NoError(t, err)
	var uid uint32
	var created, updated uint64
	pool := server.ResilientDB.GetDatabase().GetReadPool()
	require.NoError(t, pool.QueryRow(ctx, `SELECT m.uid, m.created_modseq, ms.updated_modseq FROM messages m JOIN message_state ms ON ms.message_id=m.id AND ms.mailbox_id=m.mailbox_id WHERE m.mailbox_id=$1 ORDER BY m.uid DESC LIMIT 1`, mailbox.ID).Scan(&uid, &created, &updated))
	initialUpdated := updated
	other := dialRawIMAP(t, server.Address)
	other.do(login)
	other.do("SELECT INBOX")
	other.do(fmt.Sprintf(`UID STORE %d +FLAGS (\Flagged)`, uid))
	require.NoError(t, pool.QueryRow(ctx, `SELECT ms.updated_modseq FROM message_state ms JOIN messages m ON ms.message_id=m.id AND ms.mailbox_id=m.mailbox_id WHERE ms.mailbox_id=$1 AND m.uid=$2`, mailbox.ID, uid).Scan(&updated))
	require.Greater(t, updated, initialUpdated)
	release()
	got, tagged := c.collect(tag, "own APPEND with overlapping foreign STORE")
	require.Contains(t, tagged, "APPENDUID")
	more, _ := c.do("NOOP")
	got = append(got, more...)
	t.Logf("uid=%d created=%d updated=%d responses=%q", uid, created, updated, got)
	if !filtered {
		require.Contains(t, strings.Join(got, "\n"), `\Flagged`, "foreign flag change was hidden when the poll passed the new message")
		return
	}
	first, _ := c.do("ENABLE CONDSTORE")
	codes := highestModSeqCodes(t, first)
	require.Len(t, codes, 1)
	t.Logf("baseline=%d first enabling responses=%q", baseline, first)
	if codes[0] != baseline {
		t.Errorf("reported highest %d passed filtered post-creation flag change; want conservative baseline %d", codes[0], baseline)
	}
	resync, _ := c.do(fmt.Sprintf("UID FETCH %d (UID FLAGS) (CHANGEDSINCE %d)", uid, codes[0]))
	t.Logf("resync from adopted %d = %q", codes[0], resync)
	require.Contains(t, strings.Join(resync, "\n"), `\Flagged`, "client adopting reported HIGHESTMODSEQ lost the flag change")
}
