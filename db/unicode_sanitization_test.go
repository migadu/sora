package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInsertMessage_BadUnicodeData proves that messages with problematic Unicode data
// (NULL bytes, invalid UTF-8, backslash escape sequences like \u0000) are safely
// inserted into PostgreSQL without triggering SQLSTATE 22P05
// ("unsupported Unicode escape sequence") or other text encoding errors.
//
// This test exercises the real database path to ensure sanitization works end-to-end.
func TestInsertMessage_BadUnicodeData(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupMessageTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	makeBodyStructure := func() *imap.BodyStructure {
		bs := imap.BodyStructure(&imap.BodyStructureSinglePart{
			Type:     "text",
			Subtype:  "plain",
			Params:   map[string]string{"charset": "utf-8"},
			Encoding: "7bit",
			Size:     100,
		})
		return &bs
	}

	tests := []struct {
		name          string
		subject       string
		messageID     string
		body          string
		headers       string
		inReplyTo     []string
		recipients    []helpers.Recipient
		wantSubject   string // expected subject after sanitization
		wantMessageID string // expected message_id (empty = auto-generated)
	}{
		{
			name:          "backslash-u escape sequences (original SQLSTATE 22P05 trigger)",
			subject:       "Invoice \\u0000 Payment",
			messageID:     "<msg-backslash-u@example.com>",
			body:          "Please see \\u0000 attached invoice \\u1234 for details \\uABCD end",
			headers:       "From: sender@example.com\r\nSubject: Invoice \\u0000 Payment\r\n",
			wantSubject:   "Invoice \\u0000 Payment",
			wantMessageID: "<msg-backslash-u@example.com>",
		},
		{
			name:          "NULL bytes in subject and body",
			subject:       "Hello\x00World",
			messageID:     "<msg-null-bytes@example.com>",
			body:          "Body with\x00null\x00bytes",
			headers:       "From: test@example.com\r\n",
			wantSubject:   "HelloWorld",
			wantMessageID: "<msg-null-bytes@example.com>",
		},
		{
			name:          "invalid UTF-8 sequences",
			subject:       "Subject\xFFwith\xFEbad bytes",
			messageID:     "<msg-invalid-utf8@example.com>",
			body:          "Body\xFFwith\xFEinvalid\xC0sequences",
			headers:       "From: test@example.com\r\n",
			wantSubject:   "Subjectwithbad bytes",
			wantMessageID: "<msg-invalid-utf8@example.com>",
		},
		{
			name:          "combined: NULL bytes, invalid UTF-8, and backslash escapes",
			subject:       "Combined\x00\\u0000\xFFtest",
			messageID:     "<msg-combined@example.com>",
			body:          "Body\x00with\\u1234and\xFFinvalid",
			headers:       "From: test\x00@example.com\r\nX-Data: \\u0000\r\n",
			wantSubject:   "Combined\\u0000test",
			wantMessageID: "<msg-combined@example.com>",
		},
		{
			name:          "message ID with NULL bytes becomes auto-generated",
			subject:       "Normal subject",
			messageID:     "\x00\x00\x00",
			body:          "Normal body",
			headers:       "From: test@example.com\r\n",
			wantSubject:   "Normal subject",
			wantMessageID: "", // empty messageID after sanitization triggers auto-generation
		},
		{
			name:      "recipients with bad unicode in sort fields",
			subject:   "Recipient test",
			messageID: "<msg-recipients@example.com>",
			body:      "Normal body",
			headers:   "From: test@example.com\r\n",
			recipients: []helpers.Recipient{
				{EmailAddress: "from\x00@example.com", AddressType: "from", Name: "Sender\xFFName"},
				{EmailAddress: "to@example.com", AddressType: "to", Name: "To\x00Name"},
			},
			wantSubject:   "Recipient test",
			wantMessageID: "<msg-recipients@example.com>",
		},
		{
			name:          "in-reply-to with bad unicode",
			subject:       "Reply test",
			messageID:     "<msg-reply@example.com>",
			body:          "Normal body",
			headers:       "From: test@example.com\r\n",
			inReplyTo:     []string{"<parent\x00@example.com>", "<other\xFF@example.com>"},
			wantSubject:   "Reply test",
			wantMessageID: "<msg-reply@example.com>",
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx, err := db.GetWritePool().Begin(ctx)
			require.NoError(t, err)
			defer tx.Rollback(ctx)

			now := time.Now()
			contentHash := fmt.Sprintf("unicode-test-hash-%d-%d", i, now.UnixNano())

			recipients := tt.recipients
			if recipients == nil {
				recipients = []helpers.Recipient{
					{EmailAddress: "from@example.com", AddressType: "from", Name: "Sender"},
				}
			}
			inReplyTo := tt.inReplyTo
			if inReplyTo == nil {
				inReplyTo = []string{}
			}

			options := &InsertMessageOptions{
				AccountID:     accountID,
				MailboxID:     mailboxID,
				MailboxName:   "INBOX",
				S3Domain:      "example.com",
				S3Localpart:   "test/unicode-sanitize",
				ContentHash:   contentHash,
				MessageID:     tt.messageID,
				Flags:         []imap.Flag{},
				InternalDate:  now,
				Size:          int64(len(tt.body)),
				Subject:       tt.subject,
				PlaintextBody: tt.body,
				RawHeaders:    tt.headers,
				SentDate:      now.Add(-time.Hour),
				InReplyTo:     inReplyTo,
				BodyStructure: makeBodyStructure(),
				Recipients:    recipients,
			}

			upload := PendingUpload{
				AccountID:   accountID,
				ContentHash: contentHash,
				InstanceID:  "test-instance",
				Size:        int64(len(tt.body)),
				Attempts:    0,
				CreatedAt:   now,
				UpdatedAt:   now,
			}

			// This is the key assertion: InsertMessage must NOT return an error.
			// Before sanitization was added, this would fail with:
			//   ERROR: unsupported Unicode escape sequence (SQLSTATE 22P05)
			messageRowID, uid, err := db.InsertMessage(ctx, tx, options, upload)
			assert.NoError(t, err, "InsertMessage should succeed with problematic Unicode data")
			assert.Greater(t, uid, int64(0), "UID should be assigned")

			err = tx.Commit(ctx)
			require.NoError(t, err, "Transaction commit should succeed")

			// Verify the message was stored and is readable
			var storedSubject, storedMessageID string
			err = db.GetReadPool().QueryRow(ctx,
				"SELECT subject, message_id FROM messages WHERE id = $1",
				messageRowID).Scan(&storedSubject, &storedMessageID)
			require.NoError(t, err, "Should be able to read back the stored message")

			// Verify subject was sanitized correctly
			assert.Equal(t, tt.wantSubject, storedSubject,
				"Subject should be sanitized (NULL bytes and invalid UTF-8 removed, backslashes preserved)")

			// Verify message_id
			if tt.wantMessageID != "" {
				assert.Equal(t, tt.wantMessageID, storedMessageID)
			} else {
				// Auto-generated message IDs have the pattern <timestamp@mailbox>
				assert.NotEmpty(t, storedMessageID, "Auto-generated message ID should not be empty")
			}

			// Verify messages_fts was stored (FTS indexing didn't crash)
			var contentExists bool
			err = db.GetReadPool().QueryRow(ctx,
				"SELECT EXISTS(SELECT 1 FROM messages_fts WHERE content_hash = $1)",
				contentHash).Scan(&contentExists)
			require.NoError(t, err)
			assert.True(t, contentExists, "messages_fts row should exist (FTS indexing succeeded)")

			t.Logf("OK: message inserted with UID=%d, subject=%q", uid, storedSubject)
		})
	}
}
