//go:build integration

package resilient_test

import (
	"context"
	"strings"
	"testing"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetOrCreateMailboxByNameWithRetry_Hierarchical(t *testing.T) {
	// Setup real database environment using the common helper
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
	require.NoError(t, err)

	// 1. Create a nested mailbox "A/B/C" implicitly using GetOrCreateMailboxByNameWithRetry
	mailboxName := "A" + string(consts.MailboxDelimiter) + "B" + string(consts.MailboxDelimiter) + "C"

	mailbox, err := rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID, mailboxName)
	require.NoError(t, err)
	require.NotNil(t, mailbox)
	assert.Equal(t, mailboxName, mailbox.Name)

	// 2. Fetch all mailboxes from DB to verify structure
	dbLayer := rdb.GetOperationalDatabase()

	// A and A/B should be implicitly created as parents
	parentA, err := dbLayer.GetMailboxByName(ctx, accountID, "A")
	require.NoError(t, err, "Parent mailbox 'A' should have been auto-created")
	require.True(t, parentA.HasChildren, "Parent 'A' should have HasChildren=true")

	parentAB, err := dbLayer.GetMailboxByName(ctx, accountID, "A/B")
	require.NoError(t, err, "Parent mailbox 'A/B' should have been auto-created")
	require.True(t, parentAB.HasChildren, "Parent 'A/B' should have HasChildren=true")

	childC, err := dbLayer.GetMailboxByName(ctx, accountID, "A/B/C")
	require.NoError(t, err, "Child mailbox 'A/B/C' should exist")
	require.False(t, childC.HasChildren, "Child 'A/B/C' should have HasChildren=false")

	// Ensure the child path properly inherits from parent A/B
	// Since path is hex encoded, we can fetch it. It should be 48 chars long (16 * 3 levels).
	assert.Equal(t, 48, len(childC.Path), "Path should be 48 chars (3 levels of nesting)")
}

// TestGetOrCreateMailboxByNameWithRetry_HierarchyLevels is issue #457. The
// get-or-create behind Sieve fileinto :create, the Admin API and the importer names
// a mailbox as IMAP CREATE does: a trailing delimiter is no part of the name (RFC
// 3501 §6.3.3: "the name created is without the trailing hierarchy delimiter"),
// and a name with an empty, "." or ".." level is refused with
// ErrMailboxInvalidName before anything is created, so no mailbox with an empty
// level ("x/", "") ever appears.
func TestGetOrCreateMailboxByNameWithRetry_HierarchyLevels(t *testing.T) {
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)

	trailing, err := rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID, "Foo/")
	require.NoError(t, err)
	assert.Equal(t, "Foo", trailing.Name)
	plain, err := rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID, "Foo")
	require.NoError(t, err)
	assert.Equal(t, trailing.ID, plain.ID, `"Foo/" and "Foo" must name one mailbox`)

	for _, name := range []string{"x//y", "/lead", "/", "", "a/../b", "a/./b", ".."} {
		_, err := rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID, name)
		assert.ErrorIs(t, err, consts.ErrMailboxInvalidName, "name %q", name)
	}

	mailboxes, err := rdb.GetMailboxesWithRetry(ctx, accountID, false)
	require.NoError(t, err)
	for _, mb := range mailboxes {
		assert.False(t, mb.Name == "" || strings.HasPrefix(mb.Name, "/") || strings.HasSuffix(mb.Name, "/") ||
			strings.Contains(mb.Name, "//"), "mailbox %q has an empty hierarchy level", mb.Name)
		assert.NotContains(t, []string{"x", "a"}, mb.Name, "a refused name created its parent %q", mb.Name)
	}
}
