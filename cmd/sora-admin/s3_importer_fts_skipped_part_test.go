//go:build integration

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// TestS3Importer_FTSKeepsTextBesideSkippedPart: ExtractPlaintextBody skips an inline
// part whose Content-Type parameters do not parse and still returns the text part,
// with an error naming the skipped part. `import s3` must stage that text for
// full-text search, as LMTP and `import maildir` do; it staged "", so SEARCH BODY
// found the message only when LMTP had delivered it (#1808).
func TestS3Importer_FTSKeepsTextBesideSkippedPart(t *testing.T) {
	rdb := setupTestDatabase(t)
	defer rdb.Close()
	ctx := context.Background()

	const email = "s3import-fts-skipped@example.com"
	createSimpleTestAccount(t, rdb, email, "testpassword123")
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, email)
	require.NoError(t, err)

	_, s3storage := common.NewFakeS3Storage(t)
	body := []byte("From: sender@example.org\r\n" +
		"To: " + email + "\r\n" +
		"Subject: probe\r\n" +
		"Date: Mon, 02 Nov 2026 10:00:00 +0000\r\n" +
		"Message-ID: <fts-skipped-part@example.org>\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=b1\r\n" +
		"\r\n" +
		"--b1\r\n" +
		"Content-Type: image/png; name=a b.png\r\n" +
		"Content-Disposition: inline\r\n" +
		"\r\n" +
		"PNG\r\n" +
		"--b1\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"hello words\r\n" +
		"--b1--\r\n")
	hash := helpers.HashContent(body)
	key := helpers.NewS3Key("example.com", "s3import-fts-skipped", hash)
	require.NoError(t, s3storage.Put(key, bytes.NewReader(body), int64(len(body))))

	si, err := NewS3Importer(ctx, rdb, s3storage, S3ImporterOptions{Email: email, Workers: 1, CleanupDB: true, InstanceID: "test-instance"})
	require.NoError(t, err)
	defer si.Close()
	_, err = si.db.Exec(`INSERT INTO s3_objects (key, size, last_modified, etag, domain, local_part, content_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, key, len(body), "2026-11-02T10:00:00Z", "etag",
		"example.com", "s3import-fts-skipped", hash)
	require.NoError(t, err)
	si.totalObjects = 1
	require.NoError(t, si.lookupAccount())
	require.NoError(t, si.importFromS3())
	require.EqualValues(t, 1, si.importedMessages)

	// The text is staged in text_body until the FTS worker turns it into
	// text_body_tsv; an empty text stages no row at all.
	var textBody string
	var indexed bool
	require.NoError(t, rdb.QueryRowWithRetry(ctx, `
		SELECT COALESCE(f.text_body, ''), COALESCE(f.text_body_tsv @@ plainto_tsquery('simple', 'hello'), false)
		FROM messages m
		LEFT JOIN messages_fts_v2 f ON f.content_hash = m.content_hash AND f.account_id = m.account_id
		WHERE m.account_id = $1 AND m.content_hash = $2 AND m.expunged_at IS NULL
	`, accountID, hash).Scan(&textBody, &indexed))
	require.True(t, strings.Contains(textBody, "hello words") || indexed,
		"messages_fts_v2 must hold the text part's text, got text_body %q", textBody)
}
