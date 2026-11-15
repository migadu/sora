package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A message without a Date: header that parses has no date to report. RFC 9051 section
// 7.5.2: "If the Date, Subject, In-Reply-To, and Message-ID header fields are absent in
// the [RFC5322] header, the corresponding member of the envelope is NIL". SORT and THREAD
// still need one, and RFC 5256 section 2.2 names it: "If the sent date cannot be
// determined (a Date: header is missing or cannot be parsed), the INTERNALDATE for that
// message is used as the sent date." Ingress passes such a message with a zero
// InsertMessageOptions.SentDate.

// TestBuildEnvelopeDateIsNotInternalDate: the envelope date is the message's Date: header
// or NIL, never its INTERNALDATE.
func TestBuildEnvelopeDateIsNotInternalDate(t *testing.T) {
	internal := time.Date(2025, 2, 9, 10, 0, 0, 0, time.UTC)
	header := time.Date(2020, 1, 2, 3, 4, 5, 0, time.FixedZone("", -8*3600))

	env, err := BuildEnvelope(&Message{InternalDate: internal, RecipientsJSON: []byte("[]")})
	require.NoError(t, err)
	assert.True(t, env.Date.IsZero(), "a message without a sent date has a NIL envelope date, got %v", env.Date)

	env, err = BuildEnvelope(&Message{SentDate: header, InternalDate: internal, RecipientsJSON: []byte("[]")})
	require.NoError(t, err)
	assert.True(t, env.Date.Equal(header), "envelope date %v, want the Date: header %v", env.Date, header)
}

// TestAbsentDateHeaderReportedAsNIL stores messages with and without a Date: header
// through every insert path and checks what each reader makes of the date: the stored
// sent_date (SORT, SENT* search), the IMAP ENVELOPE, THREAD's input and the User API.
func TestAbsentDateHeaderReportedAsNIL(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupMessageTestDatabase(t)
	defer db.Close()
	ctx := context.Background()
	ts := time.Now().UnixNano()

	internal := time.Date(2025, 2, 9, 10, 0, 0, 0, time.UTC)
	header := time.Date(2020, 1, 2, 3, 4, 5, 0, time.FixedZone("", -8*3600))

	insert := func(path, name string, sent time.Time) int64 {
		t.Helper()
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		var bs imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain", Size: 64}
		hash := fmt.Sprintf("envdate_%s_%s_%d", path, name, ts)
		opts := &InsertMessageOptions{
			AccountID:     accountID,
			MailboxID:     mailboxID,
			MailboxName:   "INBOX",
			S3Domain:      "example.com",
			S3Localpart:   "envdate",
			ContentHash:   hash,
			MessageID:     hash + "@example.com",
			InternalDate:  internal,
			SentDate:      sent,
			Size:          64,
			Subject:       "issue1029 " + path + " " + name,
			BodyStructure: &bs,
		}
		var uid int64
		switch path {
		case "live":
			_, uid, err = db.InsertMessage(ctx, tx, opts, PendingUpload{
				InstanceID: "envdate", ContentHash: hash, Size: 64, AccountID: accountID,
			})
		case "importer":
			_, uid, err = db.InsertMessageFromImporter(ctx, tx, opts)
		case "batch":
			var uids []int64
			_, uids, _, err = db.InsertMessagesFromImporterBatch(ctx, tx, []*InsertMessageOptions{opts})
			if err == nil {
				require.Len(t, uids, 1)
				uid = uids[0]
			}
		}
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		return uid
	}

	// want maps each UID to its Date: header; the zero time means it has none.
	want := map[int64]time.Time{}
	for _, path := range []string{"live", "importer", "batch"} {
		want[insert(path, "absent", time.Time{})] = time.Time{}
		want[insert(path, "present", header)] = header
	}

	// sentDate is what SORT and THREAD order by: the header, else the INTERNALDATE.
	sentDate := func(uid int64) time.Time {
		if want[uid].IsZero() {
			return internal
		}
		return header
	}

	t.Run("StoredSentDate", func(t *testing.T) {
		for uid := range want {
			var stored time.Time
			require.NoError(t, db.GetReadPool().QueryRow(ctx,
				`SELECT sent_date FROM messages WHERE mailbox_id = $1 AND uid = $2`, mailboxID, uid).Scan(&stored))
			assert.True(t, stored.Equal(sentDate(uid)), "uid %d: stored sent_date %v, want %v", uid, stored, sentDate(uid))
		}
	})

	t.Run("ENVELOPE", func(t *testing.T) {
		msgs, err := db.ListMessages(ctx, mailboxID)
		require.NoError(t, err)
		require.Len(t, msgs, len(want))
		for i := range msgs {
			env, err := BuildEnvelope(&msgs[i])
			require.NoError(t, err)
			uid := int64(msgs[i].UID)
			assert.True(t, env.Date.Equal(want[uid]), "uid %d: envelope date %v, want %v", uid, env.Date, want[uid])
		}
		for uid := range want {
			env, err := db.GetMessageEnvelope(ctx, imap.UID(uid), mailboxID)
			require.NoError(t, err)
			assert.True(t, env.Date.Equal(want[uid]), "GetMessageEnvelope uid %d: envelope date %v, want %v", uid, env.Date, want[uid])
		}
	})

	t.Run("THREAD", func(t *testing.T) {
		msgs, err := db.GetMessagesForThreading(ctx, mailboxID, accountID, &imap.SearchCriteria{}, false, false, 0)
		require.NoError(t, err)
		require.Len(t, msgs, len(want))
		for _, m := range msgs {
			uid := int64(m.UID)
			assert.True(t, m.SentDate.Equal(sentDate(uid)), "uid %d: thread sent date %v, want %v", uid, m.SentDate, sentDate(uid))
		}
	})

	// The User API documents date as "The Date header; the internal date when the
	// message has none" (user_api_openapi.yaml).
	t.Run("UserAPI", func(t *testing.T) {
		msgs, err := db.GetMessagesForMailbox(ctx, accountID, "INBOX", 0, 0, false)
		require.NoError(t, err)
		require.Len(t, msgs, len(want))
		for _, m := range msgs {
			assert.True(t, m.Date.Equal(sentDate(m.UID)), "uid %d: date %v, want %v", m.UID, m.Date, sentDate(m.UID))
		}
	})
}
