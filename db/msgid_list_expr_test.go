package db

import (
	"context"
	"strings"
	"testing"

	"github.com/migadu/sora/helpers"
	"github.com/stretchr/testify/require"
)

// msgIDListExpr is helpers.SplitMessageIDs in SQL: SEARCH HEADER In-Reply-To and
// References must see the same ids THREAD and ENVELOPE do.
func TestMsgIDListExprMatchesSplitMessageIDs(t *testing.T) {
	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	for _, stored := range []string{
		"", "a@x", "a@x b@x",
		`"foo bar"@x`, `"foo bar"@x b@x`, `a@x "Foo Bar"@X c@x`,
		`"<inner>"@x`, `"a\" b"@x c@x`, `"a\\" b@x`, `a@["] b@x`,
		`"unterminated b@x`, `b"@x "c d"@x`, `"a" b"@x`, `"x y"z@x`,
		`a@[x>y] z@x`, `a@[<x>] z@x`, `a@[>"] "x y"@x`, "a\u00a0b@x z@x", "\"q r\"@x a\u3000b@x",
	} {
		var got *string
		require.NoError(t, db.GetWritePool().QueryRow(ctx,
			"SELECT "+msgIDListExpr("$1::text"), stored).Scan(&got))
		ids := helpers.SplitMessageIDs(strings.ToLower(stored))
		if len(ids) == 0 {
			require.Nil(t, got, "msgIDListExpr(%q)", stored)
			continue
		}
		want := "<" + strings.Join(ids, "> <") + ">"
		require.NotNil(t, got, "msgIDListExpr(%q)", stored)
		require.Equal(t, want, *got, "msgIDListExpr(%q)", stored)
	}
}
