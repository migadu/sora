package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/require"
)

// TestGetMailboxByName_SameNamedMailboxesAreChosenInOrder covers issue #161. Names
// are unique per owner, so a user can see several mailboxes of one name: their own
// and others' shared ones. GetMailboxByName unioned them with UNION ALL … LIMIT 1 and
// no ORDER BY, so which one SELECT, APPEND or SETACL acted on was whatever row
// PostgreSQL produced first. The choice is now the user's own, then one granted to
// them directly, then one granted to "anyone", and the oldest among equals.
func TestGetMailboxByName_SameNamedMailboxesAreChosenInOrder(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db := setupTestDatabase(t)
	defer db.Close()

	ctx := context.WithValue(context.Background(), consts.ConfigContextKey, &config.Config{
		SharedMailboxes: config.SharedMailboxesConfig{
			Enabled: true, NamespacePrefix: "Shared/", AllowAnyoneIdentifier: true, // this test compares direct and anyone grants
		},
	})
	ts := time.Now().UnixNano()
	domain := fmt.Sprintf("order-%d.example.com", ts)
	address := func(local string) string { return local + "@" + domain }
	older := createTestAccount(t, db, address("older"), "password")
	newer := createTestAccount(t, db, address("newer"), "password")
	user := createTestAccount(t, db, address("user"), "password")

	create := func(owner int64, name string) {
		t.Helper()
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		require.NoError(t, db.CreateMailbox(ctx, tx, owner, name, nil))
		require.NoError(t, tx.Commit(ctx))
	}
	grant := func(owner int64, name, identifier string) {
		t.Helper()
		require.NoError(t, db.GrantMailboxAccessByIdentifier(ctx, owner, identifier, name, "lr"))
	}
	ownerOf := func(name string) int64 {
		t.Helper()
		mbox, err := db.GetMailboxByName(ctx, user, name)
		require.NoError(t, err)
		return mbox.AccountID
	}

	// Two others' mailboxes granted the same way: the older one. The newer one's grant
	// is written first, so its row is the one a plan without ORDER BY meets first.
	team := "Shared/Team"
	create(older, team)
	create(newer, team)
	grant(newer, team, address("user"))
	grant(older, team, address("user"))
	require.Equal(t, older, ownerOf(team), "of two mailboxes granted alike, the older")

	// A mailbox granted directly comes before one granted to "anyone", however old.
	desk := "Shared/Desk"
	create(older, desk)
	create(newer, desk)
	grant(older, desk, AnyoneIdentifier)
	grant(newer, desk, address("user"))
	require.Equal(t, newer, ownerOf(desk), "a direct grant before an \"anyone\" grant")

	// The user's own mailbox comes before any shared to them.
	create(user, team)
	require.Equal(t, user, ownerOf(team), "the user's own mailbox first")
}
