//go:build integration

package imap_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func appendQuotaTestMessage(t *testing.T, c *imapclient.Client, mailbox, body string) {
	t.Helper()
	cmd := c.Append(mailbox, int64(len(body)), nil)
	_, err := cmd.Write([]byte(body))
	require.NoError(t, err)
	require.NoError(t, cmd.Close())
	_, err = cmd.Wait()
	require.NoError(t, err)
}

// TestIMAP_Quota covers RFC 9208 as Sora serves it: one root "" per account with a
// STORAGE resource whose limit the Admin API sets, report-only, SETQUOTA refused.
func TestIMAP_Quota(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	ctx := context.Background()

	c, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer c.Logout()
	require.NoError(t, c.Login(account.Email, account.Password).Wait())

	t.Run("Capabilities", func(t *testing.T) {
		caps, err := c.Capability().Wait()
		require.NoError(t, err)
		assert.True(t, caps.Has(imap.CapQuota), "QUOTA advertised")
		assert.True(t, caps.Has(imap.Cap("QUOTA=RES-STORAGE")), "QUOTA=RES-STORAGE advertised")
		assert.False(t, caps.Has(imap.Cap("QUOTA=RES-MESSAGE")), "MESSAGE is not a reported resource")
		assert.False(t, caps.Has(imap.Cap("QUOTASET")), "SETQUOTA is not offered")
	})

	t.Run("UnlimitedRootHasNoResources", func(t *testing.T) {
		roots, err := c.GetQuotaRoot("INBOX").Wait()
		require.NoError(t, err)
		require.Len(t, roots, 1)
		assert.Equal(t, "", roots[0].Root)
		assert.Empty(t, roots[0].Resources, "an unlimited account reports no limits")
	})

	const message = "From: a@example.com\r\nTo: b@example.com\r\nSubject: quota\r\n\r\nBody of the quota test message.\r\n"
	appendQuotaTestMessage(t, c, "INBOX", message)

	limit := int64(10 << 20)
	require.NoError(t, server.ResilientDB.SetAccountStorageQuotaWithRetry(ctx, account.Email, &limit))

	wantStorage := imap.QuotaResourceData{
		Usage: (int64(len(message)) + 1023) / 1024,
		Limit: limit / 1024,
	}

	t.Run("GetQuotaRootReportsStorage", func(t *testing.T) {
		roots, err := c.GetQuotaRoot("INBOX").Wait()
		require.NoError(t, err)
		require.Len(t, roots, 1)
		assert.Equal(t, "", roots[0].Root)
		assert.Equal(t, map[imap.QuotaResourceType]imap.QuotaResourceData{imap.QuotaResourceStorage: wantStorage}, roots[0].Resources)
	})

	t.Run("GetQuota", func(t *testing.T) {
		data, err := c.GetQuota("").Wait()
		require.NoError(t, err)
		assert.Equal(t, wantStorage, data.Resources[imap.QuotaResourceStorage])
	})

	t.Run("UnknownRootIsNo", func(t *testing.T) {
		_, err := c.GetQuota("INBOX").Wait()
		var imapErr *imap.Error
		require.True(t, errors.As(err, &imapErr), "want a tagged NO, got %v", err)
		assert.Equal(t, imap.StatusResponseTypeNo, imapErr.Type)
	})

	t.Run("MailboxNotYetCreatedGetsTheRoot", func(t *testing.T) {
		// RFC 9208 §4.1.2: the roots a mailbox would get when created.
		roots, err := c.GetQuotaRoot(fmt.Sprintf("NotCreated-%d", common.GetTimestamp())).Wait()
		require.NoError(t, err)
		require.Len(t, roots, 1)
		assert.Equal(t, "", roots[0].Root)
	})

	t.Run("SetQuotaIsRefused", func(t *testing.T) {
		err := c.SetQuota("", map[imap.QuotaResourceType]int64{imap.QuotaResourceStorage: 1}).Wait()
		var imapErr *imap.Error
		require.True(t, errors.As(err, &imapErr), "want a tagged NO, got %v", err)
		assert.Equal(t, imap.ResponseCodeNoPerm, imapErr.Code)
	})

	t.Run("StatusDeletedStorage", func(t *testing.T) {
		_, err := c.Select("INBOX", nil).Wait()
		require.NoError(t, err)
		status, err := c.Status("INBOX", &imap.StatusOptions{DeletedStorage: true}).Wait()
		require.NoError(t, err)
		require.NotNil(t, status.DeletedStorage)
		assert.Equal(t, int64(0), *status.DeletedStorage)

		require.NoError(t, c.Store(imap.SeqSetNum(1), &imap.StoreFlags{
			Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagDeleted},
		}, nil).Close())

		status, err = c.Status("INBOX", &imap.StatusOptions{DeletedStorage: true}).Wait()
		require.NoError(t, err)
		require.NotNil(t, status.DeletedStorage)
		assert.Equal(t, int64(len(message)), *status.DeletedStorage)
	})

	t.Run("ClearingTheLimit", func(t *testing.T) {
		require.NoError(t, server.ResilientDB.SetAccountStorageQuotaWithRetry(ctx, account.Email, nil))
		roots, err := c.GetQuotaRoot("INBOX").Wait()
		require.NoError(t, err)
		require.Len(t, roots, 1)
		assert.Empty(t, roots[0].Resources)
	})
}

// TestIMAP_QuotaRootOfSharedMailbox: a mailbox another account owns counts against
// its owner, so it gets no root of the reader's, and the owner's figures stay hidden.
func TestIMAP_QuotaRootOfSharedMailbox(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()
	ctx := context.Background()

	domain := strings.Split(owner.Email, "@")[1]
	readerEmail := fmt.Sprintf("quota-reader-%d@%s", common.GetTimestamp(), domain)
	_, err := server.ResilientDB.CreateAccountWithRetry(ctx, db.CreateAccountRequest{
		Email: readerEmail, Password: "password2", HashType: "bcrypt", IsPrimary: true,
	})
	require.NoError(t, err)

	limit := int64(1 << 30)
	require.NoError(t, server.ResilientDB.SetAccountStorageQuotaWithRetry(ctx, owner.Email, &limit))

	c1, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer c1.Logout()
	require.NoError(t, c1.Login(owner.Email, owner.Password).Wait())

	shared := fmt.Sprintf("Shared/Quota-%d", common.GetTimestamp())
	require.NoError(t, c1.Create(shared, nil).Wait())
	defer func() { c1.Delete(shared).Wait() }()

	ownerID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(ctx, owner.Email)
	require.NoError(t, err)
	require.NoError(t, server.ResilientDB.GrantMailboxAccessByIdentifierWithRetry(ctx, ownerID, readerEmail, shared, "lr"))

	// The owner's own shared mailbox is under the owner's root.
	roots, err := c1.GetQuotaRoot(shared).Wait()
	require.NoError(t, err)
	require.Len(t, roots, 1)
	assert.Contains(t, roots[0].Resources, imap.QuotaResourceStorage)

	c2, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer c2.Logout()
	require.NoError(t, c2.Login(readerEmail, "password2").Wait())

	roots, err = c2.GetQuotaRoot(shared).Wait()
	require.NoError(t, err)
	assert.Empty(t, roots, "another owner's mailbox has no root of the reader's")

	// A shared name that does not exist answers the same.
	roots, err = c2.GetQuotaRoot(shared + "-missing").Wait()
	require.NoError(t, err)
	assert.Empty(t, roots)

	// The reader's own root is theirs, unlimited.
	data, err := c2.GetQuota("").Wait()
	require.NoError(t, err)
	assert.Empty(t, data.Resources)
}
