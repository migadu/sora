//go:build integration

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/stretchr/testify/require"
)

const (
	deleteCmdHelperEmailEnv   = "SORA_ADMIN_DELETE_CMD_HELPER_EMAIL"
	deleteCmdHelperMailboxEnv = "SORA_ADMIN_DELETE_CMD_HELPER_MAILBOX"
	deleteCmdHelperPurgeEnv   = "SORA_ADMIN_DELETE_CMD_HELPER_PURGE"
)

// TestMailboxDeleteCommandHelper runs `sora-admin mailbox delete` in a subprocess
// because handleMailboxDelete calls os.Exit on error.
func TestMailboxDeleteCommandHelper(t *testing.T) {
	email := os.Getenv(deleteCmdHelperEmailEnv)
	if email == "" {
		t.Skip("helper process for runMailboxDelete")
	}
	name := os.Getenv("SORA_TEST_DB_NAME")
	if name == "" {
		name = "sora_test_db"
	}
	globalConfig.Database = config.DatabaseConfig{Write: &config.DatabaseEndpointConfig{
		Hosts: []string{"localhost"}, Port: "5432", User: "postgres", Name: name,
	}}
	globalConfig.SharedMailboxes = renameTestSharedConfig()
	args := []string{"sora-admin", "mailbox", "delete", "--email", email,
		"--mailbox", os.Getenv(deleteCmdHelperMailboxEnv), "--confirm"}
	if os.Getenv(deleteCmdHelperPurgeEnv) == "1" {
		args = append(args, "--purge")
	}
	os.Args = args
	handleMailboxDelete(context.Background())
}

func runMailboxDelete(t *testing.T, email, mailbox string, purge bool) (string, bool) {
	t.Helper()
	purgeVal := "0"
	if purge {
		purgeVal = "1"
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMailboxDeleteCommandHelper$")
	cmd.Env = append(os.Environ(),
		deleteCmdHelperEmailEnv+"="+email,
		deleteCmdHelperMailboxEnv+"="+mailbox,
		deleteCmdHelperPurgeEnv+"="+purgeVal,
	)
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

func insertAdminTestMessage(t *testing.T, ctx context.Context, rdb *resilient.ResilientDatabase, accountID, mailboxID int64, mailboxName, tag string) int64 {
	t.Helper()
	var bodyStruct imap.BodyStructure = &imap.BodyStructureSinglePart{
		Type:    "text",
		Subtype: "plain",
	}
	now := time.Now()
	msgID, _, err := rdb.InsertMessageFromImporterWithRetry(ctx, &db.InsertMessageOptions{
		AccountID:     accountID,
		MailboxID:     mailboxID,
		MailboxName:   mailboxName,
		ContentHash:   fmt.Sprintf("hash-%s-%d", tag, now.UnixNano()),
		S3Domain:      "example.com",
		S3Localpart:   "test",
		MessageID:     fmt.Sprintf("<%s-%d@example.com>", tag, now.UnixNano()),
		InReplyTo:     []string{},
		Subject:       "Subject " + tag,
		SentDate:      now,
		InternalDate:  now,
		Flags:         []imap.Flag{},
		Size:          64,
		BodyStructure: &bodyStruct,
		Recipients:    []helpers.Recipient{},
	})
	require.NoError(t, err)
	return msgID
}

func isMessageExpunged(t *testing.T, ctx context.Context, rdb *resilient.ResilientDatabase, msgID int64) bool {
	t.Helper()
	var expunged bool
	err := rdb.GetOperationalDatabase().GetWritePool().QueryRow(ctx,
		`SELECT expunged_at IS NOT NULL FROM messages WHERE id = $1`, msgID).Scan(&expunged)
	require.NoError(t, err)
	return expunged
}

func TestMailboxDeletePurgeRefusesInboxWithoutExpungingMessages(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	ctx := context.Background()

	for _, name := range []string{"INBOX", "inbox"} {
		t.Run(name, func(t *testing.T) {
			account := common.CreateTestAccount(t, rdb)
			accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, account.Email)
			require.NoError(t, err)

			inbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
			require.NoError(t, err)

			msgID := insertAdminTestMessage(t, ctx, rdb, accountID, inbox.ID, "INBOX", "inbox-msg-"+name)
			require.False(t, isMessageExpunged(t, ctx, rdb, msgID))

			out, ok := runMailboxDelete(t, account.Email, name, true)
			require.False(t, ok, "mailbox delete --purge on %q must fail:\n%s", name, out)

			stillThere, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
			require.NoError(t, err, "INBOX must still exist after refused delete of %q", name)
			require.Equal(t, inbox.ID, stillThere.ID)
			require.False(t, isMessageExpunged(t, ctx, rdb, msgID),
				"refused mailbox delete --purge on %q must not expunge INBOX messages:\n%s", name, out)
		})
	}
}

func TestMailboxDeletePurgeSharedMailboxPermissionsAndOwnerMessages(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	ctx := context.Background()

	domain := fmt.Sprintf("shared-purge-%d.example.com", time.Now().UnixNano())
	owner := common.CreateTestAccountWithEmail(t, rdb, "owner@"+domain, "password123")
	grantee := common.CreateTestAccountWithEmail(t, rdb, "grantee@"+domain, "password123")

	ownerID, err := rdb.GetAccountIDByEmailWithRetry(ctx, owner.Email)
	require.NoError(t, err)
	granteeID, err := rdb.GetAccountIDByEmailWithRetry(ctx, grantee.Email)
	require.NoError(t, err)

	shared := renameTestSharedConfig()
	shared.AllowUserCreate = true
	sharedCtx := context.WithValue(ctx, consts.ConfigContextKey, &config.Config{SharedMailboxes: shared})

	t.Run("refuses grantee without delete right before purging", func(t *testing.T) {
		const sharedName = "Shared/NoDelete"
		require.NoError(t, rdb.CreateMailboxForUserWithRetry(sharedCtx, ownerID, sharedName))

		sharedMbox, err := rdb.GetMailboxByNameWithRetry(sharedCtx, ownerID, sharedName)
		require.NoError(t, err)

		ownerMsgID := insertAdminTestMessage(t, ctx, rdb, ownerID, sharedMbox.ID, sharedName, "nodelete-owner-msg")
		granteeMsgID := insertAdminTestMessage(t, ctx, rdb, granteeID, sharedMbox.ID, sharedName, "nodelete-grantee-msg")

		require.NoError(t, rdb.GrantMailboxAccessByIdentifierWithRetry(sharedCtx, ownerID, grantee.Email, sharedName, "lrs"))

		out, ok := runMailboxDelete(t, grantee.Email, sharedName, true)
		require.False(t, ok, "grantee without 'x' right must be refused:\n%s", out)

		_, err = rdb.GetMailboxByNameWithRetry(sharedCtx, ownerID, sharedName)
		require.NoError(t, err, "Shared/NoDelete must remain live when grantee lacks 'x' right")
		require.False(t, isMessageExpunged(t, ctx, rdb, ownerMsgID),
			"owner's message must remain live when grantee lacks 'x' right:\n%s", out)
		require.False(t, isMessageExpunged(t, ctx, rdb, granteeMsgID),
			"grantee's message must remain live when grantee lacks 'x' right:\n%s", out)
	})

	t.Run("purges owner-stored messages when grantee has delete right", func(t *testing.T) {
		const sharedName = "Shared/CanDelete"
		require.NoError(t, rdb.CreateMailboxForUserWithRetry(sharedCtx, ownerID, sharedName))

		sharedMbox, err := rdb.GetMailboxByNameWithRetry(sharedCtx, ownerID, sharedName)
		require.NoError(t, err)

		ownerMsgID := insertAdminTestMessage(t, ctx, rdb, ownerID, sharedMbox.ID, sharedName, "candelete-owner-msg")
		granteeMsgID := insertAdminTestMessage(t, ctx, rdb, granteeID, sharedMbox.ID, sharedName, "candelete-grantee-msg")

		require.NoError(t, rdb.GrantMailboxAccessByIdentifierWithRetry(sharedCtx, ownerID, grantee.Email, sharedName, "lrsx"))

		out, ok := runMailboxDelete(t, grantee.Email, sharedName, true)
		require.True(t, ok, "grantee with 'x' right must succeed:\n%s", out)

		_, err = rdb.GetMailboxByNameWithRetry(sharedCtx, ownerID, sharedName)
		require.ErrorIs(t, err, consts.ErrMailboxNotFound, "Shared/CanDelete must be soft-deleted:\n%s", out)
		require.True(t, isMessageExpunged(t, ctx, rdb, ownerMsgID),
			"owner-stored message in Shared/CanDelete must be expunged by --purge:\n%s", out)
		require.True(t, isMessageExpunged(t, ctx, rdb, granteeMsgID),
			"grantee-stored message in Shared/CanDelete must be expunged by --purge:\n%s", out)
	})
}

func TestMailboxRenameRefusesInboxWithoutCreatingParents(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	ctx := context.Background()

	for _, tc := range []struct {
		name    string
		oldName string
		newName string
		leaked  string
	}{
		{name: "INBOX with new parent hierarchy", oldName: "INBOX", newName: "LeakedParent/MovedInbox", leaked: "LeakedParent"},
		{name: "lowercase inbox", oldName: "inbox", newName: "MovedInbox"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account := common.CreateTestAccount(t, rdb)
			accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, account.Email)
			require.NoError(t, err)

			inboxBefore, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
			require.NoError(t, err)

			out, ok := runMailboxRename(t, account.Email, tc.oldName, tc.newName)
			require.False(t, ok, "renaming %q must be refused:\n%s", tc.oldName, out)

			inboxAfter, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
			require.NoError(t, err, "INBOX must remain present after refused rename")
			require.Equal(t, inboxBefore.ID, inboxAfter.ID)
			require.Equal(t, "INBOX", inboxAfter.Name)

			if tc.leaked != "" {
				_, err = rdb.GetMailboxByNameWithRetry(ctx, accountID, tc.leaked)
				require.ErrorIs(t, err, consts.ErrMailboxNotFound,
					"refused INBOX rename must not create destination parents:\n%s", out)
			}
			_, err = rdb.GetMailboxByNameWithRetry(ctx, accountID, tc.newName)
			require.ErrorIs(t, err, consts.ErrMailboxNotFound)
		})
	}
}
