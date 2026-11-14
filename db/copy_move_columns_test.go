package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// COPY and MOVE write a new messages row for every message they carry (CopyMessages, and
// both INSERT paths of MoveMessages). Those INSERT ... SELECT statements name their columns
// by hand, so a column added to messages later is silently dropped by them unless it is
// added there as well, and the copy then answers SEARCH, SORT and THREAD as a different
// message. "references" (migration 000036) was lost that way.

// perRowMessageColumns are the messages columns a COPY or MOVE does not take from the
// source row, because they describe the row rather than the message. Every other column
// must hold the same value on the new row as on the source row.
var perRowMessageColumns = map[string]string{
	"id":              "the new row's own key",
	"uid":             "assigned by the destination mailbox",
	"mailbox_id":      "the destination mailbox",
	"mailbox_path":    "the destination mailbox's name",
	"created_modseq":  "the new row's own modseq",
	"expunged_at":     "MOVE expunges the source row, not the new one",
	"expunged_modseq": "MOVE expunges the source row, not the new one",
	"created_at":      "the new row's own timestamp",
	"updated_at":      "the new row's own timestamp",
	// Migration 000047: the key that recognises an MTA redelivery into the mailbox the
	// original delivery went to, NULL on every path that is not an MTA delivery. A COPY
	// or MOVE is not one.
	"delivery_hash": "set by MTA delivery only",
}

func TestCopyMoveCarryEveryMessageColumn(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db, accountID, inboxID := setupSearchTestDatabase(t)
	defer db.Close()
	ctx := context.Background()
	archiveID := createTestMailbox(t, db, accountID, "Archive")

	var bs imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain", Size: 100}
	base := time.Now().UnixNano()
	// Every header column is populated, extra_addresses included (two To and two Cc).
	insert := func(n int) (id int64, uid imap.UID) {
		t.Helper()
		hash := fmt.Sprintf("copymovecols-%d-%d", base, n)
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		id, u, err := db.InsertMessage(ctx, tx, &InsertMessageOptions{
			AccountID: accountID, MailboxID: inboxID, MailboxName: "INBOX",
			S3Domain: "example.com", S3Localpart: "copymovecols", ContentHash: hash,
			MessageID: fmt.Sprintf("%s@example.com", hash), InternalDate: time.Now(), SentDate: time.Now(),
			Size: 100, Subject: fmt.Sprintf("Re: message %d", n), BodyStructure: &bs,
			InReplyTo:  []string{"parent@example.com"},
			References: []string{"ancestor@example.com", "parent@example.com"},
			Recipients: []helpers.Recipient{
				{AddressType: "to", Name: "Carol", EmailAddress: "carol@example.com"},
				{AddressType: "to", Name: "Bob", EmailAddress: "bob@example.com"},
				{AddressType: "cc", Name: "Dave", EmailAddress: "dave@example.org"},
				{AddressType: "cc", EmailAddress: "erin@example.org"},
				{AddressType: "from", Name: "Alice", EmailAddress: "alice@example.com"},
			},
		}, PendingUpload{InstanceID: "test", ContentHash: hash, Size: 100, AccountID: accountID})
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		return id, imap.UID(u)
	}
	copySrcID, copySrcUID := insert(1)
	moveSrcID, moveSrcUID := insert(2)
	sameSrcID, sameSrcUID := insert(3)

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	copied, _, err := db.CopyMessages(ctx, tx, &[]imap.UID{copySrcUID}, inboxID, archiveID, accountID, "example.com", "copymovecols", "test", nil, nil)
	require.NoError(t, err)
	moved, err := db.MoveMessages(ctx, tx, &[]imap.UID{moveSrcUID}, inboxID, archiveID, accountID, "example.com", "copymovecols", "test", nil)
	require.NoError(t, err)
	sameMoved, err := db.MoveMessages(ctx, tx, &[]imap.UID{sameSrcUID}, inboxID, inboxID, accountID, "example.com", "copymovecols", "test", nil)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	row := func(t *testing.T, where string, args ...any) map[string]any {
		t.Helper()
		var r map[string]any
		require.NoError(t, db.GetReadPool().QueryRow(ctx, `SELECT to_jsonb(m) FROM messages m WHERE `+where, args...).Scan(&r))
		return r
	}
	paths := []struct {
		name          string
		srcID         int64
		destMailboxID int64
		destUID       imap.UID
	}{
		{"COPY", copySrcID, archiveID, copied[copySrcUID]},
		{"MOVE", moveSrcID, archiveID, moved[moveSrcUID]},
		{"MOVE within the mailbox", sameSrcID, inboxID, sameMoved[sameSrcUID]},
	}
	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			require.NotZero(t, p.destUID)
			src := row(t, "id = $1", p.srcID)
			dest := row(t, "mailbox_id = $1 AND uid = $2 AND expunged_at IS NULL", p.destMailboxID, p.destUID)
			require.Equal(t, len(src), len(dest))
			for col, want := range src {
				if _, perRow := perRowMessageColumns[col]; perRow {
					continue
				}
				// A NULL on both rows would hide a dropped column.
				require.NotNil(t, want, "column %q is NULL on the source row, so this test cannot tell "+
					"whether %s carries it: populate it above or list it in perRowMessageColumns", col, p.name)
				assert.Equal(t, want, dest[col], "%s dropped or changed column %q", p.name, col)
			}
		})
	}

	// What the dropped column broke: HEADER References and THREAD in the destination.
	search := func(t *testing.T, mailboxID int64) []imap.UID {
		t.Helper()
		res, err := db.SearchMessagesWithCriteria(ctx, mailboxID, accountID, &imap.SearchCriteria{
			Header: []imap.SearchCriteriaHeaderField{{Key: "References", Value: "<ancestor@example.com>"}},
		}, 0, 100)
		require.NoError(t, err)
		uids := []imap.UID{}
		for _, r := range res {
			uids = append(uids, r.UID)
		}
		return uids
	}
	threadRefs := func(t *testing.T, mailboxID int64) map[imap.UID]string {
		t.Helper()
		res, err := db.GetMessagesForThreading(ctx, mailboxID, accountID, &imap.SearchCriteria{}, false, false, 0)
		require.NoError(t, err)
		refs := map[imap.UID]string{}
		for _, r := range res {
			refs[r.UID] = r.References
		}
		return refs
	}
	const wantRefs = "ancestor@example.com parent@example.com"

	t.Run("HEADER References after COPY and MOVE", func(t *testing.T) {
		assert.ElementsMatch(t, []imap.UID{copied[copySrcUID], moved[moveSrcUID]}, search(t, archiveID))
		assert.ElementsMatch(t, []imap.UID{copySrcUID, sameMoved[sameSrcUID]}, search(t, inboxID))
	})
	t.Run("THREAD references after COPY and MOVE", func(t *testing.T) {
		assert.Equal(t, map[imap.UID]string{copied[copySrcUID]: wantRefs, moved[moveSrcUID]: wantRefs}, threadRefs(t, archiveID))
		assert.Equal(t, map[imap.UID]string{copySrcUID: wantRefs, sameMoved[sameSrcUID]: wantRefs}, threadRefs(t, inboxID))
	})
}
