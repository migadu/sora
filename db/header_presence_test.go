package db

import (
	"context"
	"fmt"
	"github.com/emersion/go-message"
	"github.com/migadu/go-imap"
	"github.com/migadu/sora/helpers"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
	"time"
)

func TestHeaderPresenceForwardOnlyMixedPredicatesAndCopies(t *testing.T) {
	d, account, box := setupSearchTestDatabase(t)
	defer d.Close()
	ctx := context.Background()
	var bs imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain", Size: 100}
	raws := []string{
		"From: undisclosed:;\r\nTo: undisclosed:;\r\nCc: undisclosed:;\r\n\r\nbody",
		"From:\r\nTo:\r\nCc:\r\n\r\nbody",
		"\r\nbody",
		"From: a@example.com\r\nTo: b@example.com\r\nCc: c@example.com\r\n\r\nbody",
		"\r\nlegacy body",
	}
	var uids []imap.UID
	for i, raw := range raws {
		e, err := message.Read(strings.NewReader(raw))
		require.NoError(t, err)
		mask := helpers.ExtractHeaderPresence(e.Header)
		if i == 4 {
			mask = nil
		}
		o := &InsertMessageOptions{AccountID: account, MailboxID: box, MailboxName: "INBOX", ContentHash: fmt.Sprintf("presence-%d-%d", time.Now().UnixNano(), i), MessageID: fmt.Sprintf("presence-%d-%d@example.org", time.Now().UnixNano(), i), InternalDate: time.Now(), SentDate: time.Now(), Size: 100, BodyStructure: &bs, Recipients: helpers.ExtractRecipients(e.Header), HeaderPresence: mask, S3Domain: "example.com", S3Localpart: "presence"}
		tx, err := d.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		var uid int64
		switch i % 4 {
		case 0:
			_, uid, err = d.InsertMessage(ctx, tx, o, PendingUpload{InstanceID: "test", ContentHash: o.ContentHash, Size: o.Size, AccountID: account})
		case 1:
			_, uid, err = d.InsertMessageFromImporter(ctx, tx, o)
		case 2:
			_, us, _, e := d.InsertMessagesBatch(ctx, tx, []*InsertMessageOptions{o}, nil)
			err = e
			if e == nil {
				uid = us[0]
			}
		case 3:
			_, us, _, e := d.InsertMessagesFromImporterBatch(ctx, tx, []*InsertMessageOptions{o})
			err = e
			if e == nil {
				uid = us[0]
			}
		}
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		uids = append(uids, imap.UID(uid))
	}
	header := func(key string, explicit bool) imap.SearchCriteria {
		return imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: key, Value: "", IsHeader: explicit}}}
	}
	search := func(c imap.SearchCriteria) []imap.UID {
		xs, err := d.SearchMessagesWithCriteria(ctx, box, account, &c, 0, 100)
		require.NoError(t, err)
		got := []imap.UID{}
		for _, x := range xs {
			got = append(got, x.UID)
		}
		return got
	}
	for _, key := range []string{"From", "To", "Cc"} {
		h := header(key, true)
		require.ElementsMatch(t, []imap.UID{uids[0], uids[1], uids[3], uids[4]}, search(h), key)
		require.ElementsMatch(t, []imap.UID{uids[2]}, search(imap.SearchCriteria{Not: []imap.SearchCriteria{h}}))
		a := header(key, false)
		require.ElementsMatch(t, []imap.UID{uids[3], uids[4]}, search(a), "envelope "+key)
		require.ElementsMatch(t, []imap.UID{uids[0], uids[1], uids[2]}, search(imap.SearchCriteria{Not: []imap.SearchCriteria{a}}))
	}
	require.ElementsMatch(t, uids, search(imap.SearchCriteria{Or: [][2]imap.SearchCriteria{{header("Cc", true), {Not: []imap.SearchCriteria{header("From", true)}}}}}))
	require.Empty(t, search(imap.SearchCriteria{Header: header("Cc", true).Header, Not: []imap.SearchCriteria{header("From", true)}}))
	require.ElementsMatch(t, []imap.UID{uids[4]}, search(header("Subject", true)), "known absence vs unchanged legacy subject predicate")
	// A new database row is not new ingested content: copy/move retain NULL.
	dest := createTestMailbox(t, d, account, "PresenceCopies")
	for _, i := range []int{0, 4} {
		tx, err := d.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		set := []imap.UID{uids[i]}
		_, _, err = d.CopyMessages(ctx, tx, &set, box, dest, account, "example.com", "presence", "test", nil, nil)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
	}
	var known, unknown int
	require.NoError(t, d.GetWritePool().QueryRow(ctx, "SELECT count(*) FILTER(WHERE header_presence IS NOT NULL),count(*) FILTER(WHERE header_presence IS NULL) FROM messages WHERE mailbox_id=$1 AND expunged_at IS NULL", dest).Scan(&known, &unknown))
	require.Equal(t, 1, known)
	require.Equal(t, 1, unknown)
	movedBox := createTestMailbox(t, d, account, "PresenceMoved")
	tx, err := d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	set := []imap.UID{1, 2}
	_, err = d.MoveMessages(ctx, tx, &set, dest, movedBox, account, "example.com", "presence", "test", nil, nil)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	require.NoError(t, d.GetWritePool().QueryRow(ctx, "SELECT count(*) FILTER(WHERE header_presence IS NOT NULL),count(*) FILTER(WHERE header_presence IS NULL) FROM messages WHERE mailbox_id=$1 AND expunged_at IS NULL", movedBox).Scan(&known, &unknown))
	require.Equal(t, 1, known)
	require.Equal(t, 1, unknown)
	// Restoring an old row creates a fresh UID, not fresh header knowledge.
	var ids []int64
	rows, err := d.GetWritePool().Query(ctx, "SELECT id FROM messages WHERE mailbox_id=$1 AND expunged_at IS NULL", movedBox)
	require.NoError(t, err)
	for rows.Next() {
		var id int64
		require.NoError(t, rows.Scan(&id))
		ids = append(ids, id)
	}
	rows.Close()
	require.NoError(t, rows.Err())
	tx, err = d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, "UPDATE messages SET expunged_at=now(),expunged_modseq=nextval('messages_modseq') WHERE id=ANY($1)", ids)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	var email string
	require.NoError(t, d.GetWritePool().QueryRow(ctx, "SELECT address FROM credentials WHERE account_id=$1 LIMIT 1", account).Scan(&email))
	tx, err = d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	n, err := d.RestoreMessages(ctx, tx, RestoreMessagesParams{Email: email, MessageIDs: ids})
	require.NoError(t, err)
	require.Equal(t, int64(2), n)
	require.NoError(t, tx.Commit(ctx))
	require.NoError(t, d.GetWritePool().QueryRow(ctx, "SELECT count(*) FILTER(WHERE header_presence IS NOT NULL),count(*) FILTER(WHERE header_presence IS NULL) FROM messages WHERE mailbox_id=$1 AND expunged_at IS NULL", movedBox).Scan(&known, &unknown))
	require.Equal(t, 1, known)
	require.Equal(t, 1, unknown)

}
