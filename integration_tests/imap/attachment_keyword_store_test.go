//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// RFC 9979 §4 forbids both attachment keywords on a message, including after
// mutable flag operations rather than only at initial delivery or APPEND.
func TestIMAP_AttachmentKeywordStoreExclusivity(t *testing.T) {
	b, account := common.SetupIMAPServer(t)
	defer b.Close()
	c, err := imapclient.DialInsecure(b.Address, nil)
	require.NoError(t, err)
	defer c.Close()
	require.NoError(t, c.Login(account.Email, account.Password).Wait())
	_, err = c.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	for _, tc := range []struct {
		name, initial, want string
		op                  imap.StoreFlagsOp
		requested           []imap.Flag
	}{
		{"add replaces negative", "$hasnoattachment", "$hasattachment", imap.StoreFlagsAdd, []imap.Flag{"$HASATTACHMENT"}},
		{"add replaces positive", "$hasattachment", "$hasnoattachment", imap.StoreFlagsAdd, []imap.Flag{"$HASNOATTACHMENT"}},
		{"add conflicting pair clears both", "$hasnoattachment", "", imap.StoreFlagsAdd, []imap.Flag{"$hasattachment", "$HASNOATTACHMENT"}},
		{"set conflicting pair clears both", "$hasnoattachment", "", imap.StoreFlagsSet, []imap.Flag{imap.FlagSeen, "Work", "$HASATTACHMENT", "$hasnoattachment"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uid := appendRaw(t, c, "INBOX", "Subject: "+tc.name+"\r\n\r\nbody", []imap.Flag{imap.FlagSeen, "Work", imap.Flag(tc.initial)})
			_, err := c.Store(imap.UIDSetNum(uid), &imap.StoreFlags{Op: tc.op, Flags: tc.requested}, nil).Collect()
			require.NoError(t, err)
			assertAttachmentStoreFlags(t, fetchFlags(t, c, uid), tc.want)
		})
	}
	t.Run("switch at keyword cap", func(t *testing.T) {
		flags := []imap.Flag{imap.FlagSeen, "Work", "$hasnoattachment"}
		for i := 0; i < db.MaxCustomKeywordsPerMessage-2; i++ {
			flags = append(flags, imap.Flag(fmt.Sprintf("kw%d", i)))
		}
		uid := appendRaw(t, c, "INBOX", "Subject: full flags\r\n\r\nbody", flags)
		_, err := c.Store(imap.UIDSetNum(uid), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{"$hasattachment"}}, nil).Collect()
		require.NoError(t, err, "replacing one keyword must not consume an extra slot")
		got := fetchFlags(t, c, uid)
		assertAttachmentStoreFlags(t, got, "$hasattachment")
		require.Equal(t, db.MaxCustomKeywordsPerMessage, db.DistinctKeywordCount(got))
	})
}

func assertAttachmentStoreFlags(t *testing.T, flags []imap.Flag, want string) {
	t.Helper()
	require.Contains(t, flags, imap.FlagSeen)
	require.Contains(t, flags, imap.Flag("Work"))
	for _, keyword := range []string{"$hasattachment", "$hasnoattachment"} {
		n, _ := countFold(flags, keyword)
		if strings.EqualFold(keyword, want) {
			require.Equal(t, 1, n, "flags = %v", flags)
		} else {
			require.Zero(t, n, "flags = %v", flags)
		}
	}
}

// Single-message DB writers are used independently of STORE, including by the
// User API. They must enforce the same policy as the IMAP batch update path.
func TestIMAP_AttachmentKeywordOtherFlagWriters(t *testing.T) {
	b, account := common.SetupIMAPServer(t)
	defer b.Close()
	c, err := imapclient.DialInsecure(b.Address, nil)
	require.NoError(t, err)
	defer c.Close()
	require.NoError(t, c.Login(account.Email, account.Password).Wait())
	_, err = c.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	ctx := context.Background()
	accountID, err := b.ResilientDB.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)
	mailbox, err := b.ResilientDB.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	require.NoError(t, err)
	for _, operation := range []string{"single add", "single set", "user api add", "user api conflicting pair"} {
		t.Run(operation, func(t *testing.T) {
			uid := appendRaw(t, c, "INBOX", "Subject: "+operation+"\r\n\r\nbody", []imap.Flag{imap.FlagSeen, "Work", "$hasnoattachment"})
			want := "$hasattachment"
			switch operation {
			case "single add":
				_, _, err = b.ResilientDB.AddMessageFlagsWithRetry(ctx, uid, mailbox.ID, []imap.Flag{"$HASATTACHMENT"})
			case "single set":
				_, _, err = b.ResilientDB.SetMessageFlagsWithRetry(ctx, uid, mailbox.ID, []imap.Flag{imap.FlagSeen, "Work", "$HASATTACHMENT", "$hasnoattachment"})
				want = ""
			default:
				var id int64
				require.NoError(t, b.ResilientDB.QueryRowWithRetry(ctx, "SELECT id FROM messages WHERE mailbox_id = $1 AND uid = $2", mailbox.ID, uid).Scan(&id))
				add := []string{"$HASATTACHMENT"}
				if operation == "user api conflicting pair" {
					add = append(add, "$hasnoattachment")
					want = ""
				}
				err = b.ResilientDB.UpdateMessageFlagsWithRetry(ctx, accountID, id, add, nil)
			}
			require.NoError(t, err)
			assertAttachmentStoreFlags(t, fetchFlags(t, c, uid), want)
		})
	}
}

func TestIMAP_AttachmentKeywordConcurrentStore(t *testing.T) {
	b, account := common.SetupIMAPServer(t)
	defer b.Close()
	dial := func() *imapclient.Client {
		t.Helper()
		c, err := imapclient.DialInsecure(b.Address, nil)
		require.NoError(t, err)
		t.Cleanup(func() { c.Close() })
		require.NoError(t, c.Login(account.Email, account.Password).Wait())
		_, err = c.Select("INBOX", nil).Wait()
		require.NoError(t, err)
		return c
	}
	c1, c2 := dial(), dial()
	for i := 0; i < 12; i++ {
		uid := appendRaw(t, c1, "INBOX", fmt.Sprintf("Subject: concurrent-%d\r\n\r\nbody", i), []imap.Flag{imap.FlagSeen, "Work"})
		start := make(chan struct{})
		errors := make(chan error, 2)
		var wg sync.WaitGroup
		for _, update := range []struct {
			c       *imapclient.Client
			keyword imap.Flag
			work    imap.Flag
		}{{c1, "$HASATTACHMENT", "First"}, {c2, "$hasnoattachment", "Second"}} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, err := update.c.Store(imap.UIDSetNum(uid), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{update.keyword, update.work}}, nil).Collect()
				errors <- err
			}()
		}
		close(start)
		wg.Wait()
		require.NoError(t, <-errors)
		require.NoError(t, <-errors)
		flags := fetchFlags(t, c1, uid)
		has, _ := countFold(flags, "$hasattachment")
		hasNo, _ := countFold(flags, "$hasnoattachment")
		require.Equal(t, 1, has+hasNo, "flags = %v", flags)
		require.Contains(t, flags, imap.Flag("First"))
		require.Contains(t, flags, imap.Flag("Second"))
	}
}
