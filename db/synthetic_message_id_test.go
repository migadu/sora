package db

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A message stored without a Message-ID header gets a synthetic message_id so the
// duplicate checks keep working: "<nanos@mailbox>" on the live path (InsertMessage) and
// syntheticMessageID's "<hash@mailbox.synthetic.invalid>" on the importer and batch paths.
// Unlike every ID the ingress parser returns, it keeps its angle brackets. It is not the
// message's header and must never be reported as one: RFC 9051 section 7.5.2 makes the
// ENVELOPE member of an absent Message-ID NIL, and RFC 5256 section 3 (BASE.6.4.THREAD,
// REFERENCES step 1(A)) gives such a message a unique ID no reference can name.

// TestBuildEnvelopeSyntheticMessageIDIsNIL: the envelope leaves MessageID empty (go-imap
// writes NIL) for a synthetic ID, instead of handing it to go-imap, which wraps it in a
// second pair of brackets.
func TestBuildEnvelopeSyntheticMessageIDIsNIL(t *testing.T) {
	cases := []struct {
		stored, want string
	}{
		{"<1794682113526073000@INBOX>", ""},
		{syntheticMessageID("0123abcd", "INBOX"), ""},
		{syntheticMessageID("0123abcd", "Archive/2026"), ""},
		{"present@example.com", "present@example.com"},
		{"", ""},
	}
	for _, tc := range cases {
		env, err := BuildEnvelope(&Message{MessageID: tc.stored, RecipientsJSON: []byte("[]")})
		require.NoError(t, err)
		assert.Equal(t, tc.want, env.MessageID, "stored message_id %q", tc.stored)
	}
}

// TestSyntheticMessageIDNotReportedAsHeader stores messages through the live and importer
// paths with and without a Message-ID, and checks every reader that reports message_id as
// the message's header: the IMAP ENVELOPE, THREAD's input, the User API's list, search
// and single-message views, and the Admin API / sora-admin deleted-message listing.
func TestSyntheticMessageIDNotReportedAsHeader(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupMessageTestDatabase(t)
	defer db.Close()
	ctx := context.Background()
	ts := time.Now().UnixNano()

	type stored struct {
		rowID int64
		uid   int64
	}
	insert := func(name, messageID string, importer bool) stored {
		t.Helper()
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		var bs imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain", Size: 64}
		now := time.Now()
		hash := fmt.Sprintf("synthid_%s_%d", name, ts)
		opts := &InsertMessageOptions{
			AccountID:     accountID,
			MailboxID:     mailboxID,
			MailboxName:   "INBOX",
			S3Domain:      "example.com",
			S3Localpart:   "synthid",
			ContentHash:   hash,
			MessageID:     messageID,
			InternalDate:  now,
			SentDate:      now,
			Size:          64,
			Subject:       "issue851 " + name,
			BodyStructure: &bs,
		}
		var row, uid int64
		if importer {
			row, uid, err = db.InsertMessageFromImporter(ctx, tx, opts)
		} else {
			row, uid, err = db.InsertMessage(ctx, tx, opts, PendingUpload{
				InstanceID: "synthid", ContentHash: hash, Size: 64, AccountID: accountID,
			})
		}
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		return stored{row, uid}
	}

	live := insert("live", "", false)
	imported := insert("imported", "", true)
	present := insert("present", "present-851@example.com", false)
	want := map[int64]string{
		live.uid:     "",
		imported.uid: "",
		present.uid:  "present-851@example.com",
	}

	// Control: the synthetic IDs are still stored, bracketed, for duplicate detection.
	for _, m := range []stored{live, imported} {
		var messageID string
		require.NoError(t, db.GetReadPool().QueryRow(ctx, `SELECT message_id FROM messages WHERE id = $1`, m.rowID).Scan(&messageID))
		require.True(t, strings.HasPrefix(messageID, "<"), "stored synthetic message_id %q", messageID)
	}

	t.Run("ENVELOPE", func(t *testing.T) {
		for uid, id := range want {
			env, err := db.GetMessageEnvelope(ctx, imap.UID(uid), mailboxID)
			require.NoError(t, err)
			assert.Equal(t, id, env.MessageID, "uid %d", uid)
		}
	})

	t.Run("THREAD", func(t *testing.T) {
		msgs, err := db.GetMessagesForThreading(ctx, mailboxID, accountID, &imap.SearchCriteria{}, true, false, 0)
		require.NoError(t, err)
		require.Len(t, msgs, len(want))
		for _, m := range msgs {
			assert.Equal(t, want[int64(m.UID)], m.MessageID, "uid %d", m.UID)
		}
	})

	t.Run("UserAPIList", func(t *testing.T) {
		msgs, err := db.GetMessagesForMailbox(ctx, accountID, "INBOX", 0, 0, false)
		require.NoError(t, err)
		require.Len(t, msgs, len(want))
		for _, m := range msgs {
			assert.Equal(t, want[m.UID], m.MessageID, "uid %d", m.UID)
		}
	})

	t.Run("UserAPISearch", func(t *testing.T) {
		msgs, _, err := db.SearchMessagesInMailbox(ctx, accountID, "INBOX", "issue851", UserAPISearchFilter{})
		require.NoError(t, err)
		require.Len(t, msgs, len(want))
		for _, m := range msgs {
			assert.Equal(t, want[m.UID], m.MessageID, "uid %d", m.UID)
		}
	})

	t.Run("UserAPIGet", func(t *testing.T) {
		for _, m := range []stored{live, imported, present} {
			msg, err := db.GetMessageByID(ctx, accountID, m.rowID)
			require.NoError(t, err)
			assert.Equal(t, want[m.uid], msg.MessageID, "uid %d", m.uid)
		}
	})

	t.Run("ListDeletedMessages", func(t *testing.T) {
		historical := insert("historical", "<1700000000000000000@INBOX>", false)

		var email string
		require.NoError(t, db.GetReadPool().QueryRow(ctx,
			`SELECT address FROM credentials WHERE account_id = $1 AND primary_identity`, accountID).Scan(&email))

		expungeTx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer expungeTx.Rollback(ctx)
		_, err = db.ExpungeMessageUIDs(ctx, expungeTx, mailboxID,
			imap.UID(live.uid), imap.UID(imported.uid), imap.UID(historical.uid), imap.UID(present.uid))
		require.NoError(t, err)
		require.NoError(t, expungeTx.Commit(ctx))

		wantByRowID := map[int64]string{
			live.rowID:       "",
			imported.rowID:   "",
			historical.rowID: "",
			present.rowID:    "present-851@example.com",
		}

		deleted, err := db.ListDeletedMessages(ctx, ListDeletedMessagesParams{Email: email})
		require.NoError(t, err)
		require.Len(t, deleted, len(wantByRowID))
		for _, m := range deleted {
			expected, ok := wantByRowID[m.ID]
			require.True(t, ok, "unexpected row id %d", m.ID)
			assert.Equal(t, expected, m.MessageID, "row id %d", m.ID)
		}

		// RestoreMessages resolves rows from messages directly, so stripping synthetic
		// IDs in ListDeletedMessages leaves both ID-based and criteria-based restores
		// and duplicate detection untouched.
		restoreTx1, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer restoreTx1.Rollback(ctx)
		restored, err := db.RestoreMessages(ctx, restoreTx1, RestoreMessagesParams{
			Email:      email,
			MessageIDs: []int64{imported.rowID, historical.rowID},
		})
		require.NoError(t, err)
		assert.Equal(t, int64(2), restored)
		require.NoError(t, restoreTx1.Commit(ctx))

		inbox := "INBOX"
		restoreTx2, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer restoreTx2.Rollback(ctx)
		restored, err = db.RestoreMessages(ctx, restoreTx2, RestoreMessagesParams{
			Email:       email,
			MailboxPath: &inbox,
		})
		require.NoError(t, err)
		assert.Equal(t, int64(2), restored)
		require.NoError(t, restoreTx2.Commit(ctx))

		for _, m := range []stored{live, imported, historical} {
			var storedID string
			var expungedAt *time.Time
			require.NoError(t, db.GetReadPool().QueryRow(ctx,
				`SELECT message_id, expunged_at FROM messages WHERE id = $1`, restoredCopyID(t, db, m.rowID)).Scan(&storedID, &expungedAt))
			assert.Nil(t, expungedAt, "row id %d should be restored", m.rowID)
			assert.True(t, strings.HasPrefix(storedID, "<"), "stored synthetic message_id %q for row %d", storedID, m.rowID)
		}
	})
}
