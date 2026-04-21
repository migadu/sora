//go:build integration

package resilient_test

import (
	"context"
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
