//go:build integration

package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRestoreMessagesCommand_SharedNamespace: `messages restore` gives the restore the
// [shared_mailboxes] config, so a deleted mailbox in the shared namespace, and the
// namespace root above it, come back as shared mailboxes the account owns, as
// `mailbox create` makes them (#1289). They came back personal, which IMAP cannot share.
func TestRestoreMessagesCommand_SharedNamespace(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, account.Email)
	require.NoError(t, err)

	// What DeleteMailbox leaves of a message of Shared/Team: expunged, no mailbox, the
	// name recorded in mailbox_path.
	_, err = rdb.GetDatabase().GetWritePool().Exec(ctx, `
		INSERT INTO messages (account_id, mailbox_id, mailbox_path, uid, s3_domain, s3_localpart, content_hash,
			subject, message_id, recipients_json, body_structure, internal_date, sent_date, size, created_modseq, expunged_at)
		VALUES ($1, NULL, 'Shared/Team', 1, 'example.com', 'restore', $2, 'team', '<team@example.com>',
			'[]'::jsonb, ''::bytea, now(), now(), 100, nextval('messages_modseq'), now())`,
		accountID, fmt.Sprintf("restore-shared-%d", time.Now().UnixNano()))
	require.NoError(t, err)

	cfg := AdminConfig{
		Database:        *configTestDatabase(t),
		SharedMailboxes: config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: "Shared/", DefaultRights: "lrswipkxtea"},
	}
	mailbox := "Shared/Team"
	require.NoError(t, restoreMessages(ctx, cfg, account.Email, &mailbox, nil, nil, nil, true))

	for _, name := range []string{"Shared", "Shared/Team"} {
		var shared bool
		var domain string
		require.NoError(t, rdb.GetDatabase().GetWritePool().QueryRow(ctx, `
			SELECT COALESCE(is_shared, FALSE), COALESCE(owner_domain, '')
			FROM mailboxes WHERE account_id = $1 AND name = $2 AND deleted_at IS NULL`,
			accountID, name).Scan(&shared, &domain), "mailbox %s", name)
		assert.True(t, shared, "%s is_shared", name)
		assert.Equal(t, "example.com", domain, "%s owner_domain", name)
	}
}
