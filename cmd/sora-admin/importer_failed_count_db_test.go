//go:build integration

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// With --batch-transaction a batch is stored or rolled back as a whole. A preserved UID
// the mailbox already uses aborts the PostgreSQL transaction, so the whole batch is rolled
// back: the conflicting message is reported once, with its own reason, and every other
// message of the batch once, as rolled back (#546).
func TestImportBatchTransactionCountsEachMessageOnce(t *testing.T) {
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	rdb := setupTestDatabase(t)
	defer rdb.Close()

	ctx := context.Background()
	email := fmt.Sprintf("batch-tx-count-%d@example.com", time.Now().UnixNano())
	createTestAccount(t, rdb, email, "testpassword123")

	maildirPath := filepath.Join(t.TempDir(), "Maildir")
	for _, dir := range []string{"cur", "new", "tmp"} {
		require.NoError(t, os.MkdirAll(filepath.Join(maildirPath, dir), 0755))
	}
	// The uidlist gives both files UID 10, so the second insert collides with the first.
	require.NoError(t, os.WriteFile(filepath.Join(maildirPath, "dovecot-uidlist"),
		[]byte("3 V5555555555 N11\n10 :a.eml\n10 :b.eml\n"), 0644))
	for _, name := range []string{"a", "b"} {
		content := fmt.Sprintf("From: sender@example.com\r\nTo: %s\r\nSubject: %s\r\nMessage-ID: <%s@example.com>\r\n\r\nBody %s\r\n", email, name, name, name)
		require.NoError(t, os.WriteFile(filepath.Join(maildirPath, "cur", name+".eml:2,S"), []byte(content), 0644))
	}

	importer, err := NewImporter(ctx, maildirPath, email, 1, rdb, nil, ImporterOptions{
		TestMode:             true,
		PreserveUIDs:         true,
		BatchTransactionMode: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { importer.Close() })

	err = importer.Run()
	require.Error(t, err)
	assert.Equal(t, "import completed with 2 failed messages", err.Error())
	assert.Equal(t, int64(2), importer.failedMessages,
		"the summary's Failed count differs from the messages that failed")
	assert.Zero(t, importer.importedMessages)
	assert.Zero(t, importer.skippedMessages)

	reasons := make(map[string][]string)
	for _, f := range importer.failedPaths {
		reasons[filepath.Base(f.path)] = append(reasons[filepath.Base(f.path)], f.reason)
	}
	require.Len(t, reasons, 2, "both messages are listed as failed")
	var conflicts, rolledBack int
	for name, rs := range reasons {
		if !assert.Len(t, rs, 1, "%s is listed more than once: %q", name, rs) {
			continue
		}
		switch {
		case strings.Contains(rs[0], "preserved UID already in use"):
			conflicts++
		case strings.HasPrefix(rs[0], "batch transaction aborted"):
			rolledBack++
		default:
			t.Errorf("%s failed for an unexpected reason: %s", name, rs[0])
		}
	}
	assert.Equal(t, 1, conflicts, "the conflicting message is reported with its own reason")
	assert.Equal(t, 1, rolledBack, "the other message is reported as rolled back")

	address, err := server.NewAddress(email)
	require.NoError(t, err)
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, address.FullAddress())
	require.NoError(t, err)
	var rows int
	require.NoError(t, rdb.GetOperationalDatabase().ReadPool.QueryRow(ctx,
		`SELECT COUNT(*) FROM messages WHERE account_id = $1`, accountID).Scan(&rows))
	assert.Zero(t, rows, "the batch was rolled back")
}
