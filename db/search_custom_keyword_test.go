package db

import (
	"context"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSearchCustomKeyword(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupSearchTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	now := time.Now()

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	msg := "From: test@example.com\r\nTo: user@example.com\r\nSubject: Case Test\r\n\r\nBody\r\n"
	uidVal := uint32(10)
	options := &InsertMessageOptions{
		AccountID:     accountID,
		MailboxID:     mailboxID,
		MailboxName:   "INBOX",
		Flags:         []imap.Flag{"WAREHOUSING"},
		PreservedUID:  &uidVal,
		InternalDate:  now,
		SentDate:      now,
		Subject:       "Case Test",
		Size:          int64(len(msg)),
		PlaintextBody: msg,
	}

	_, uid, err := db.InsertMessageFromImporter(ctx, tx, options)
	require.NoError(t, err)
	assert.Equal(t, int64(10), uid)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Now try to search for it using different cases
	t.Run("Exact Case Search", func(t *testing.T) {
		criteria := &imap.SearchCriteria{
			Flag: []imap.Flag{"WAREHOUSING"},
		}
		messages, err := db.GetMessagesWithCriteria(ctx, mailboxID, criteria, 0)
		assert.NoError(t, err)
		assert.Len(t, messages, 1)
		if len(messages) == 1 {
			assert.Equal(t, imap.UID(10), messages[0].UID)
		}
	})

	t.Run("Different Case Search", func(t *testing.T) {
		criteria := &imap.SearchCriteria{
			Flag: []imap.Flag{"warehousing"},
		}
		messages, err := db.GetMessagesWithCriteria(ctx, mailboxID, criteria, 0)
		assert.NoError(t, err)
		assert.Len(t, messages, 1)
		if len(messages) == 1 {
			assert.Equal(t, imap.UID(10), messages[0].UID)
		}
	})

	t.Run("Non-existent Search", func(t *testing.T) {
		criteria := &imap.SearchCriteria{
			Flag: []imap.Flag{"nonexistent"},
		}
		messages, err := db.GetMessagesWithCriteria(ctx, mailboxID, criteria, 0)
		assert.NoError(t, err)
		assert.Empty(t, messages)
	})

	t.Run("Not Flag Search Matches", func(t *testing.T) {
		criteria := &imap.SearchCriteria{
			NotFlag: []imap.Flag{"nonexistent"},
		}
		messages, err := db.GetMessagesWithCriteria(ctx, mailboxID, criteria, 0)
		assert.NoError(t, err)
		assert.Len(t, messages, 1)
	})

	t.Run("Not Flag Search Doesn't Match", func(t *testing.T) {
		criteria := &imap.SearchCriteria{
			NotFlag: []imap.Flag{"warehousing"},
		}
		messages, err := db.GetMessagesWithCriteria(ctx, mailboxID, criteria, 0)
		assert.NoError(t, err)
		assert.Empty(t, messages)
	})
}
