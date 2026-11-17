package db

import (
	"context"
	"fmt"
	"github.com/emersion/go-message"
	"github.com/migadu/go-imap"
	"github.com/migadu/sora/helpers"
	"github.com/stretchr/testify/assert"
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
	require.ElementsMatch(t, []imap.UID{uids[4]}, search(header("Subject", false)), `SUBJECT "" must match only present Subject or NULL legacy metadata`)
	require.ElementsMatch(t, []imap.UID{uids[0], uids[1], uids[2], uids[3]}, search(imap.SearchCriteria{Not: []imap.SearchCriteria{header("Subject", false)}}), `NOT SUBJECT "" must match known absent Subject`)
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

func TestSubjectEmptySearchUsesHeaderPresence(t *testing.T) {
	// Unit SQL generation check (nil *Database: buildSearchCriteria does not dereference receiver).
	var nilDB *Database
	subjectBit, ok := helpers.HeaderPresenceBit("subject")
	require.True(t, ok)

	for _, key := range []string{"Subject", "SUBJECT", "subject"} {
		paramCounter := 0
		explicitSQL, _, err := nilDB.buildSearchCriteria(&imap.SearchCriteria{
			Header: []imap.SearchCriteriaHeaderField{{Key: key, Value: "", IsHeader: true}},
		}, "p", &paramCounter)
		require.NoError(t, err)

		paramCounter = 0
		shorthandSQL, _, err := nilDB.buildSearchCriteria(&imap.SearchCriteria{
			Header: []imap.SearchCriteriaHeaderField{{Key: key, Value: "", IsHeader: false}},
		}, "p", &paramCounter)
		require.NoError(t, err)

		assert.Contains(t, shorthandSQL, fmt.Sprintf("(m.header_presence & %d) <> 0", subjectBit), "key %q", key)
		assert.Equal(t, explicitSQL, shorthandSQL, "SUBJECT \"\" and HEADER %s \"\" share the presence/legacy predicate", key)
	}

	// Non-empty SUBJECT search still uses substring matching on LOWER(m.subject).
	paramCounter := 0
	nonEmptySQL, _, err := nilDB.buildSearchCriteria(&imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: "hello", IsHeader: false}},
	}, "p", &paramCounter)
	require.NoError(t, err)
	assert.Contains(t, nonEmptySQL, "strpos(LOWER(m.subject), @")
	assert.NotContains(t, nonEmptySQL, "header_presence")

	// PostgreSQL execution across absent, present-empty, non-empty, and NULL legacy rows.
	d, account, box := setupSearchTestDatabase(t)
	defer d.Close()
	ctx := context.Background()
	var bs imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain", Size: 64}

	fixtures := []struct {
		raw     string
		subject string
		legacy  bool
	}{
		{raw: "From: a@example.com\r\n\r\nabsent subject", subject: "", legacy: false},
		{raw: "From: a@example.com\r\nSubject:\r\n\r\nempty subject", subject: "", legacy: false},
		{raw: "From: a@example.com\r\nSubject: Hello World\r\n\r\nnon-empty subject", subject: "Hello World", legacy: false},
		{raw: "From: a@example.com\r\n\r\nlegacy absent subject", subject: "", legacy: true},
		{raw: "From: a@example.com\r\nSubject: Legacy Subject\r\n\r\nlegacy present subject", subject: "Legacy Subject", legacy: true},
	}

	var uids []imap.UID
	base := time.Now().UnixNano()
	for i, fx := range fixtures {
		ent, err := message.Read(strings.NewReader(fx.raw))
		require.NoError(t, err)
		mask := helpers.ExtractHeaderPresence(ent.Header)
		if fx.legacy {
			mask = nil
		}
		o := &InsertMessageOptions{
			AccountID:      account,
			MailboxID:      box,
			MailboxName:    "INBOX",
			ContentHash:    fmt.Sprintf("subj-presence-%d-%d", base, i),
			MessageID:      fmt.Sprintf("subj-presence-%d-%d@example.org", base, i),
			InternalDate:   time.Now().Add(time.Duration(i) * time.Second),
			SentDate:       time.Now().Add(time.Duration(i) * time.Second),
			Size:           64,
			Subject:        fx.subject,
			BodyStructure:  &bs,
			Recipients:     helpers.ExtractRecipients(ent.Header),
			HeaderPresence: mask,
			S3Domain:       "example.com",
			S3Localpart:    "subjpresence",
		}
		tx, err := d.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		_, uid, err := d.InsertMessage(ctx, tx, o, PendingUpload{
			InstanceID:  "test",
			ContentHash: o.ContentHash,
			Size:        o.Size,
			AccountID:   account,
		})
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		uids = append(uids, imap.UID(uid))
	}

	uidAbsent := uids[0]
	uidEmpty := uids[1]
	uidNonEmpty := uids[2]
	uidLegacyAbsent := uids[3]
	uidLegacyPresent := uids[4]

	searchUIDs := func(c imap.SearchCriteria) []imap.UID {
		xs, err := d.SearchMessagesWithCriteria(ctx, box, account, &c, 0, 100)
		require.NoError(t, err)
		got := []imap.UID{}
		for _, x := range xs {
			got = append(got, x.UID)
		}
		return got
	}

	subjEmpty := imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: "", IsHeader: false}},
	}
	hdrSubjEmpty := imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: "", IsHeader: true}},
	}

	wantPresentOrLegacy := []imap.UID{uidEmpty, uidNonEmpty, uidLegacyAbsent, uidLegacyPresent}
	assert.ElementsMatch(t, wantPresentOrLegacy, searchUIDs(subjEmpty), `SUBJECT ""`)
	assert.ElementsMatch(t, []imap.UID{uidAbsent}, searchUIDs(imap.SearchCriteria{Not: []imap.SearchCriteria{subjEmpty}}), `NOT SUBJECT ""`)
	assert.ElementsMatch(t, wantPresentOrLegacy, searchUIDs(hdrSubjEmpty), `HEADER Subject ""`)
	assert.ElementsMatch(t, []imap.UID{uidAbsent}, searchUIDs(imap.SearchCriteria{Not: []imap.SearchCriteria{hdrSubjEmpty}}), `NOT HEADER Subject ""`)

	// Non-empty SUBJECT search remains case-insensitive substring matching.
	assert.ElementsMatch(t, []imap.UID{uidNonEmpty}, searchUIDs(imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: "hello", IsHeader: false}},
	}))

	// SORT and THREAD with SUBJECT "" share the same search criteria builder.
	sorted, err := d.SearchMessagesSorted(ctx, box, account, &subjEmpty, []imap.SortCriterion{{Key: imap.SortKeyArrival}}, 0, 100)
	require.NoError(t, err)
	var sortedUIDs []imap.UID
	for _, s := range sorted {
		sortedUIDs = append(sortedUIDs, s.UID)
	}
	assert.Equal(t, wantPresentOrLegacy, sortedUIDs, `SORT (ARRIVAL) SUBJECT ""`)

	threadMsgs, err := d.GetMessagesForThreading(ctx, box, account, &subjEmpty, true, false, 100)
	require.NoError(t, err)
	var threadUIDs []imap.UID
	for _, tm := range threadMsgs {
		threadUIDs = append(threadUIDs, tm.UID)
	}
	assert.ElementsMatch(t, wantPresentOrLegacy, threadUIDs, `THREAD SUBJECT ""`)
}
