//go:build integration

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/migadu/sora/helpers"
	"github.com/stretchr/testify/require"
)

func TestMaildirImporter_FTSKeepsTextBesideSkippedPart(t *testing.T) {
	rdb := setupTestDatabase(t)
	defer rdb.Close()
	for _, batch := range []bool{false, true} {
		t.Run(fmt.Sprintf("batch=%v", batch), func(t *testing.T) {
			email := fmt.Sprintf("maildir-fts-%v@example.com", batch)
			accountID := rerunAccount(t, rdb, email)
			maildir := rerunMaildir(t, 1)
			files, err := os.ReadDir(filepath.Join(maildir, "cur"))
			require.NoError(t, err)
			body := "From: sender@example.com\r\nTo: " + email + "\r\nSubject: maildir parity\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b1\r\n\r\n--b1\r\nContent-Type: image/png; name=a b.png\r\nContent-Disposition: inline\r\n\r\nPNG\r\n--b1\r\nContent-Type: text/plain\r\n\r\nhello words\r\n--b1--\r\n"
			require.NoError(t, os.WriteFile(filepath.Join(maildir, "cur", files[0].Name()), []byte(body), 0600))
			importer := runImport(t, rdb, maildir, email, ImporterOptions{TestMode: true, BatchSize: 10, BatchTransactionMode: batch})
			require.Equal(t, int64(1), importer.importedMessages)
			var text string
			var indexed bool
			require.NoError(t, rdb.QueryRowWithRetry(context.Background(), `SELECT COALESCE(f.text_body,''),COALESCE(f.text_body_tsv @@ plainto_tsquery('simple','hello'),false) FROM messages m LEFT JOIN messages_fts_v2 f ON f.account_id=m.account_id AND f.content_hash=m.content_hash WHERE m.account_id=$1 AND m.content_hash=$2 AND m.expunged_at IS NULL`, accountID, helpers.HashContent([]byte(body))).Scan(&text, &indexed))
			require.True(t, strings.Contains(text, "hello words") || indexed, "maildir lost partial text: %q", text)
		})
	}
}
