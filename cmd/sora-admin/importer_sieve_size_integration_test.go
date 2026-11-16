//go:build integration

package main

import (
	"context"
	"fmt"
	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestImportSieveSizePreservesWorkingScriptAndContinuesMail(t *testing.T) {
	ctx := context.Background()
	rdb := setupSieveTestDatabase(t)
	defer rdb.Close()
	for _, tc := range []struct {
		name   string
		size   int
		dry    bool
		refuse bool
	}{
		{"over_limit_import", 65537, false, true}, {"over_limit_dry_run", 65537, true, true}, {"exact_limit_import", 65536, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			email := fmt.Sprintf("size-%d@example.com", time.Now().UnixNano())
			accountID := createSieveTestAccount(t, rdb, email, "password123")
			original := "# previous working script\nkeep;\n"
			previous, err := rdb.CreateScriptWithRetry(ctx, accountID, "previous", original)
			require.NoError(t, err)
			require.NoError(t, rdb.SetScriptActiveWithRetry(ctx, previous.ID, accountID, true))
			maildir := newMaildirWith(t, map[string][]byte{"1700000001.M1P1.host:2,S": cachedSizeMessage("Kept", 100)})
			path := filepath.Join(t.TempDir(), "script.sieve")
			script := sieveScriptOfSize(t, tc.size)
			require.NoError(t, os.WriteFile(path, []byte(script), 0644))
			importer, err := NewImporter(ctx, maildir, email, 1, rdb, nil, ImporterOptions{TestMode: true, SievePath: path, DryRun: tc.dry})
			require.NoError(t, err)
			defer importer.Close()
			require.NoError(t, importer.Run())
			active, err := rdb.GetActiveScriptWithRetry(ctx, accountID)
			require.NoError(t, err)
			require.Equal(t, previous.ID, active.ID)
			if tc.refuse {
				require.Equal(t, original, active.Script)
				require.Contains(t, importer.sieveOutcome, "NOT")
				require.Contains(t, importer.sieveOutcome, "65536")
			} else {
				require.Equal(t, script, active.Script)
				require.Contains(t, importer.sieveOutcome, "activated")
			}
			count, err := rdb.GetMessageCountForMailboxWithRetry(ctx, accountID, "INBOX")
			if tc.dry {
				require.ErrorIs(t, err, consts.ErrMailboxNotFound)
				require.Zero(t, count)
			} else {
				require.NoError(t, err)
				require.Equal(t, 1, count)
				require.Equal(t, int64(1), importer.importedMessages)
			}
			require.False(t, strings.Contains(importer.sieveOutcome, "INACTIVE"))
		})
	}
}
