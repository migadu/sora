//go:build integration

package db_test

import (
	"context"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMailboxNameCaseInsensitiveGetOrCreate verifies Option A: mailbox names are
// case-insensitive. Requesting any name in a different case must resolve to the
// single existing mailbox (preserving its stored case) and must never create a
// case-variant duplicate — backed by the UNIQUE(account_id, LOWER(name)) index.
//
// Before the fix the lookups were case-sensitive (WHERE name = $2) while the
// uniqueness constraint was case-sensitive too, so "Inbox"/"archive" created
// second rows that the case-insensitive read path then resolved to arbitrarily,
// stranding messages.
func TestMailboxNameCaseInsensitiveGetOrCreate(t *testing.T) {
	rdb := common.SetupTestDatabase(t)
	ctx := context.Background()

	account := common.CreateTestAccount(t, rdb)
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)

	t.Run("INBOX is reserved and canonically spelled", func(t *testing.T) {
		canonical, err := rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID, "INBOX")
		require.NoError(t, err)
		require.Equal(t, "INBOX", canonical.Name)

		for _, variant := range []string{"Inbox", "inbox", "INbOx"} {
			mb, err := rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID, variant)
			require.NoError(t, err, "get-or-create %q", variant)
			assert.Equalf(t, canonical.ID, mb.ID,
				"GetOrCreateMailbox(%q) must return the canonical INBOX (id=%d), got id=%d name=%q",
				variant, canonical.ID, mb.ID, mb.Name)
			// INBOX is special: every variant resolves to the canonical "INBOX" spelling.
			assert.Equalf(t, "INBOX", mb.Name, "INBOX must keep canonical spelling, got %q", mb.Name)
		}

		assertSingleCaseFold(t, rdb, accountID, "inbox")
	})

	t.Run("non-INBOX names are case-insensitive and preserve case", func(t *testing.T) {
		// First request wins the stored spelling.
		created, err := rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID, "Archive")
		require.NoError(t, err)
		require.Equal(t, "Archive", created.Name)

		for _, variant := range []string{"archive", "ARCHIVE", "ArChIvE"} {
			mb, err := rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID, variant)
			require.NoError(t, err, "get-or-create %q", variant)
			assert.Equalf(t, created.ID, mb.ID,
				"GetOrCreateMailbox(%q) must return the existing Archive (id=%d), got id=%d name=%q",
				variant, created.ID, mb.ID, mb.Name)
			// Non-INBOX names keep the first-stored case (not normalized).
			assert.Equalf(t, "Archive", mb.Name, "Archive must keep its stored case, got %q", mb.Name)
		}

		assertSingleCaseFold(t, rdb, accountID, "archive")
	})
}

// assertSingleCaseFold asserts exactly one mailbox of the account case-folds to
// foldedName — the invariant the case-insensitive unique index guarantees.
func assertSingleCaseFold(t *testing.T, rdb *resilient.ResilientDatabase, accountID int64, foldedName string) {
	t.Helper()
	var n int
	err := rdb.QueryRowWithRetry(context.Background(),
		`SELECT COUNT(*) FROM mailboxes WHERE account_id = $1 AND LOWER(name) = $2`,
		accountID, foldedName).Scan(&n)
	require.NoError(t, err)
	assert.Equalf(t, 1, n,
		"exactly one mailbox must case-fold to %q regardless of requested case (found %d)", foldedName, n)
}
