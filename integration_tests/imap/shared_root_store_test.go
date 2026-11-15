//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// liveMessagesIn counts the live messages of accountID's own mailbox named name, in
// any case.
func liveMessagesIn(t *testing.T, server *common.TestServer, accountID int64, name string) int {
	t.Helper()
	var n int
	require.NoError(t, server.ResilientDB.QueryRowWithRetry(context.Background(), `
		SELECT COUNT(*) FROM messages m JOIN mailboxes mb ON m.mailbox_id = mb.id
		WHERE mb.account_id = $1 AND LOWER(mb.name) = LOWER($2)
		  AND mb.deleted_at IS NULL AND m.expunged_at IS NULL`, accountID, name).Scan(&n))
	return n
}

// TestSharedNamespaceRootHoldsNoMessages: the shared namespace root ("Shared" for
// "Shared/") is a container. LIST marks it \Noselect, "It is not possible to use this
// name as a selectable mailbox" (RFC 9051 §7.3.1), and SELECT refuses it. APPEND,
// COPY and MOVE must refuse it as their destination too, or the message is stored
// where no client can read it (#1299).
func TestSharedNamespaceRootHoldsNoMessages(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	accountID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
	require.NoError(t, err)

	c, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer c.Logout()
	require.NoError(t, c.Login(account.Email, account.Password).Wait())

	appendMsg := func(mailbox, subject string) error {
		literal := "From: sender@example.com\r\nSubject: " + subject + "\r\n\r\nbody\r\n"
		cmd := c.Append(mailbox, int64(len(literal)), nil)
		if _, err := cmd.Write([]byte(literal)); err != nil {
			return err
		}
		if err := cmd.Close(); err != nil {
			return err
		}
		_, err := cmd.Wait()
		return err
	}

	// The root cannot be created either (CREATE refuses it), so even before it exists
	// the answer is [CANNOT], not [TRYCREATE]: RFC 9051 §6.3.12 sends TRYCREATE only
	// "Unless it is certain that the destination mailbox cannot be created".
	t.Run("APPEND before the root exists", func(t *testing.T) {
		requireResponseCode(t, appendMsg("Shared", "before-root"), imap.ResponseCodeCannot, "APPEND Shared")
	})

	team := fmt.Sprintf("Shared/Team-%d", common.GetTimestamp())
	require.NoError(t, c.Create(team, nil).Wait(), "CREATE %s also creates the root", team)

	for _, name := range []string{"Shared", "shared", "SHARED"} {
		t.Run("APPEND "+name, func(t *testing.T) {
			requireResponseCode(t, appendMsg(name, "append-"+name), imap.ResponseCodeCannot, "APPEND "+name)
		})
	}

	require.NoError(t, appendMsg("INBOX", "inbox-message"))
	_, err = c.Select("INBOX", nil).Wait()
	require.NoError(t, err)

	t.Run("COPY", func(t *testing.T) {
		_, err := c.Copy(imap.SeqSetNum(1), "Shared").Wait()
		requireResponseCode(t, err, imap.ResponseCodeCannot, "COPY 1 Shared")
	})
	t.Run("UID COPY", func(t *testing.T) {
		_, err := c.Copy(imap.UIDSetNum(1), "shared").Wait()
		requireResponseCode(t, err, imap.ResponseCodeCannot, "UID COPY 1 shared")
	})
	t.Run("MOVE", func(t *testing.T) {
		_, err := c.Move(imap.SeqSetNum(1), "Shared").Wait()
		requireResponseCode(t, err, imap.ResponseCodeCannot, "MOVE 1 Shared")
	})

	if n := liveMessagesIn(t, server, accountID, "Shared"); n != 0 {
		t.Errorf("the namespace root holds %d messages, want 0", n)
	}
	if n := liveMessagesIn(t, server, accountID, "INBOX"); n != 1 {
		t.Errorf("INBOX holds %d messages, want its 1 message, which MOVE must not take away", n)
	}

	// The mailboxes under the root take messages as before.
	t.Run("mailbox under the root", func(t *testing.T) {
		require.NoError(t, appendMsg(team, "append-team"))
		_, err := c.Copy(imap.SeqSetNum(1), team).Wait()
		require.NoError(t, err)
		require.Equal(t, 2, liveMessagesIn(t, server, accountID, team))
	})
}

// TestSharedNamespaceRootPersonalWithSharingOff: with [shared_mailboxes] disabled
// there is no namespace root, and a personal mailbox called "Shared" takes messages
// like any other.
func TestSharedNamespaceRootPersonalWithSharingOff(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServerWithOptions(t, &common.IMAPServerOpts{
		SharedMailboxes: &config.SharedMailboxesConfig{Enabled: false, NamespacePrefix: "Shared/"},
	})
	defer server.Close()
	accountID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
	require.NoError(t, err)

	c, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer c.Logout()
	require.NoError(t, c.Login(account.Email, account.Password).Wait())

	require.NoError(t, c.Create("Shared", nil).Wait())
	for _, mailbox := range []string{"Shared", "INBOX", "INBOX"} {
		literal := "From: sender@example.com\r\nSubject: personal\r\n\r\nbody\r\n"
		cmd := c.Append(mailbox, int64(len(literal)), nil)
		_, err = cmd.Write([]byte(literal))
		require.NoError(t, err)
		require.NoError(t, cmd.Close())
		_, err = cmd.Wait()
		require.NoError(t, err, "APPEND to %s", mailbox)
	}

	_, err = c.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	_, err = c.Copy(imap.SeqSetNum(1), "Shared").Wait()
	require.NoError(t, err, "COPY into a personal mailbox called Shared")
	_, err = c.Move(imap.SeqSetNum(2), "Shared").Wait()
	require.NoError(t, err, "MOVE into a personal mailbox called Shared")
	require.Equal(t, 3, liveMessagesIn(t, server, accountID, "Shared"))
}
