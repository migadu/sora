package db

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMailboxNameKeys: each name gets LOWER(name) as the database computes it, in
// order, and a name PostgreSQL cannot hold the empty key instead of a query error.
func TestMailboxNameKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("requires PostgreSQL")
	}
	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	names := []string{"INBOX", "a\x00", "İx/y", "ΑΣ", "\xff", "ſx", "", "Kx"}
	keys, err := database.MailboxNameKeys(ctx, names)
	require.NoError(t, err)
	require.Len(t, keys, len(names))
	for i, name := range names {
		switch name {
		case "a\x00", "\xff":
			assert.Empty(t, keys[i], "key of unstorable name %q", name)
		default:
			var want string
			require.NoError(t, database.GetWritePool().QueryRow(ctx, `SELECT LOWER($1::text)`, name).Scan(&want))
			assert.Equal(t, want, keys[i], "key of %q", name)
		}
	}

	keys, err = database.MailboxNameKeys(ctx, []string{"\xff"})
	require.NoError(t, err)
	assert.Equal(t, []string{""}, keys)

	keys, err = database.MailboxNameKeys(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, keys)
}
