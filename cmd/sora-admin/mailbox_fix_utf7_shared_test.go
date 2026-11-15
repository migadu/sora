//go:build integration

package main

import (
	"context"
	"errors"
	"regexp"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// TestMailboxFixUTF7SharedNamespaceBoundary covers issue #1049: fix-utf7 renamed
// without the shared mailbox config in the context, so db.RenameMailbox skipped the
// namespace boundary check (issue #160) that "mailbox rename" and IMAP RENAME get. A
// personal mailbox whose name decodes onto namespace_prefix became a personal mailbox
// inside the shared namespace, its children with it.
func TestMailboxFixUTF7SharedNamespaceBoundary(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	ctx := context.Background()

	previousConfig := globalConfig
	t.Cleanup(func() { globalConfig = previousConfig })
	globalConfig.SharedMailboxes = config.SharedMailboxesConfig{
		Enabled:         true,
		NamespacePrefix: "Partagés/",
		DefaultRights:   "lrswipkxtea",
	}
	sharedCtx := context.WithValue(ctx, consts.ConfigContextKey, &config.Config{SharedMailboxes: globalConfig.SharedMailboxes})

	// setup creates an account with these mailboxes, created as the server creates
	// them with sharing enabled, and checks which of them are shared.
	setup := func(t *testing.T, mailboxes []string, shared map[string]bool) (string, int64) {
		t.Helper()
		account := common.CreateTestAccount(t, rdb)
		accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, account.Email)
		require.NoError(t, err)
		for _, name := range mailboxes {
			_, err := rdb.ResolveOrCreateMailboxPathWithRetry(sharedCtx, accountID, name)
			require.NoError(t, err, "create %q", name)
		}
		for name, want := range shared {
			mbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, name)
			require.NoError(t, err)
			isShared, err := rdb.IsMailboxSharedWithRetry(ctx, mbox.ID)
			require.NoError(t, err)
			require.Equal(t, want, isShared, "is_shared of %q", name)
		}
		return account.Email, accountID
	}
	exists := func(t *testing.T, accountID int64, name string) bool {
		t.Helper()
		_, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, name)
		if errors.Is(err, consts.ErrMailboxNotFound) {
			return false
		}
		require.NoError(t, err, "look up %q", name)
		return true
	}

	// "Partag&AOk-s" is not under the prefix as stored, so it is a personal mailbox.
	t.Run("personal mailbox not renamed into the shared namespace", func(t *testing.T) {
		email, accountID := setup(t,
			[]string{"Partag&AOk-s/Docs", "R&AOk-pertoire"},
			map[string]bool{"Partag&AOk-s": false, "Partag&AOk-s/Docs": false, "R&AOk-pertoire": false})

		out := runMailboxFixUTF7(t, ctx, email)

		require.Regexp(t, regexp.MustCompile(`(?m)^\s+FAIL\s+account_id=\d+\s+"Partag&AOk-s"\s+->\s+"Partagés"\s+\(error: `+
			regexp.QuoteMeta(consts.ErrMailboxSharedBoundary.Error())+`\)$`), out)
		require.True(t, exists(t, accountID, "Partag&AOk-s"), "the refused mailbox keeps its name")
		require.True(t, exists(t, accountID, "Partag&AOk-s/Docs"), "its child keeps its name")
		require.False(t, exists(t, accountID, "Partagés"), "no personal mailbox may be the shared root")
		require.False(t, exists(t, accountID, "Partagés/Docs"), "no personal mailbox may be under the shared prefix")
		require.True(t, exists(t, accountID, "Répertoire"), "a personal mailbox that stays personal is renamed")
	})

	t.Run("shared mailbox renamed within the shared namespace", func(t *testing.T) {
		email, accountID := setup(t,
			[]string{"Partagés/R&AOk-sum&AOk-"},
			map[string]bool{"Partagés/R&AOk-sum&AOk-": true})

		runMailboxFixUTF7(t, ctx, email)

		require.True(t, exists(t, accountID, "Partagés/Résumé"))
		require.False(t, exists(t, accountID, "Partagés/R&AOk-sum&AOk-"))
	})
}
