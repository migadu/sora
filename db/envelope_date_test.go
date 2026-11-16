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

// TestSentUTCOffsetUnknownZone: a sent date in UTC, ParseDateHeader's date of a zone that
// is unknown (helpers.ZoneUnknown, RFC 5322 section 3.3 "-0000"), is stored without an
// offset and read back in UTC, so its ENVELOPE date is written "-0000". It is searched by
// its UTC day, the day it names. A zone of offset zero ("+0000") keeps its offset.
func TestSentUTCOffsetUnknownZone(t *testing.T) {
	unknown := time.Date(2019, 1, 1, 12, 0, 0, 0, time.UTC)
	assert.Nil(t, sentUTCOffset(unknown), "an unknown zone has no offset")
	// pgx decodes sent_date in time.Local.
	got := sentDateInHeaderZone(unknown.Local(), sentUTCOffset(unknown))
	assert.True(t, got.Equal(unknown) && got.Location() == time.UTC, "read back as %v, want %v in UTC", got, unknown)

	universal := time.Date(2019, 1, 1, 12, 0, 0, 0, time.FixedZone("", 0))
	if offset := sentUTCOffset(universal); assert.NotNil(t, offset, "+0000") {
		assert.Equal(t, int32(0), *offset)
	}
	got = sentDateInHeaderZone(universal.Local(), sentUTCOffset(universal))
	assert.True(t, got.Equal(universal) && got.Location() != time.UTC, "read back as %v, want %v not in UTC", got, universal)
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

// TestEnvelopeDateKeepsHeaderZone: the ENVELOPE date names the day, time of day and zone
// the Date: header was written in, through every insert path and every reader that builds
// a Message for it. RFC 9051 section 7.5.2: the envelope "is computed by the server by
// parsing the [RFC5322] header into the component parts"; sent_date keeps only the instant
// and sent_utc_offset (migration 000060) the header's zone. A row without an offset
// (written before that migration) is given in UTC, never in the server's zone, as is a
// date whose zone is unknown (helpers.ZoneUnknown): go-imap writes both "-0000".
func TestEnvelopeDateKeepsHeaderZone(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupMessageTestDatabase(t)
	defer db.Close()
	ctx := context.Background()
	ts := time.Now().UnixNano()

	const layout = "Mon, 02 Jan 2006 15:04:05 -0700" // go-imap's envelope date layout
	// At most one of these zones can be the server's, so a date given in the server's
	// zone fails at least two of them.
	zones := []*time.Location{
		time.FixedZone("", -8*3600),
		time.FixedZone("", 5*3600+45*60),
		time.FixedZone("", 0),
	}
	instant := time.Date(2025, 1, 1, 4, 0, 0, 0, time.UTC)

	insert := func(path string, sent time.Time) int64 {
		t.Helper()
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		var bs imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain", Size: 64}
		_, offset := sent.Zone()
		hash := fmt.Sprintf("envzone_%s_%d_%t_%d", path, offset, sent.Location() == time.UTC, ts)
		opts := &InsertMessageOptions{
			AccountID:     accountID,
			MailboxID:     mailboxID,
			MailboxName:   "INBOX",
			S3Domain:      "example.com",
			S3Localpart:   "envzone",
			ContentHash:   hash,
			MessageID:     hash + "@example.com",
			InternalDate:  instant,
			SentDate:      sent,
			Size:          64,
			Subject:       "issue1064 " + path,
			BodyStructure: &bs,
		}
		var uid int64
		switch path {
		case "live":
			_, uid, err = db.InsertMessage(ctx, tx, opts, PendingUpload{
				InstanceID: "envzone", ContentHash: hash, Size: 64, AccountID: accountID,
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

	// want maps each UID to its envelope date member, and inUTC the UIDs whose date
	// must be given in UTC, the zone go-imap writes "-0000".
	want := map[int64]string{}
	inUTC := map[int64]bool{}
	for _, path := range []string{"live", "importer", "batch"} {
		for _, zone := range zones {
			sent := instant.In(zone)
			want[insert(path, sent)] = sent.Format(layout)
		}
		// A Date: whose zone is unknown: ParseDateHeader gives it in UTC.
		uid := insert(path, instant.UTC())
		want[uid], inUTC[uid] = instant.Format(layout), true
	}
	// A row written before migration 000060 has no offset: it is given in UTC.
	legacy := insert("live", instant.In(time.FixedZone("", 2*3600)))
	_, err := db.GetWritePool().Exec(ctx,
		`UPDATE messages SET sent_utc_offset = NULL WHERE mailbox_id = $1 AND uid = $2`, mailboxID, legacy)
	require.NoError(t, err)
	want[legacy], inUTC[legacy] = instant.Format(layout), true

	for uid := range inUTC {
		var offset *int32
		require.NoError(t, db.GetReadPool().QueryRow(ctx,
			`SELECT sent_utc_offset FROM messages WHERE mailbox_id = $1 AND uid = $2`, mailboxID, uid).Scan(&offset))
		assert.Nil(t, offset, "uid %d: a date in UTC is stored without an offset", uid)
	}

	check := func(reader string, msgs []Message) {
		t.Helper()
		require.Len(t, msgs, len(want), reader)
		for i := range msgs {
			env, err := BuildEnvelope(&msgs[i])
			require.NoError(t, err)
			uid := int64(msgs[i].UID)
			assert.Equal(t, want[uid], env.Date.Format(layout), "%s uid %d: envelope date", reader, uid)
			assert.Equal(t, inUTC[uid], env.Date.Location() == time.UTC,
				"%s uid %d: envelope date %v in UTC (zone -0000)", reader, uid, env.Date)
			assert.Equal(t, inUTC[uid], env.DateUnknownZone, "%s uid %d: explicit unknown-zone hint", reader, uid)
		}
	}

	msgs, err := db.ListMessages(ctx, mailboxID)
	require.NoError(t, err)
	check("ListMessages", msgs)

	var uids imap.UIDSet
	for uid := range want {
		uids.AddNum(imap.UID(uid))
	}
	msgs, err = db.GetMessagesByNumSet(ctx, mailboxID, uids)
	require.NoError(t, err)
	check("GetMessagesByNumSet(UID)", msgs)

	var all imap.SeqSet
	all.AddRange(1, 0)
	msgs, err = db.GetMessagesByNumSet(ctx, mailboxID, all, true)
	require.NoError(t, err)
	check("GetMessagesByNumSet(1:*)", msgs)

	for uid, date := range want {
		env, err := db.GetMessageEnvelope(ctx, imap.UID(uid), mailboxID)
		require.NoError(t, err)
		assert.Equal(t, date, env.Date.Format(layout), "GetMessageEnvelope uid %d: envelope date", uid)
		assert.Equal(t, inUTC[uid], env.Date.Location() == time.UTC,
			"GetMessageEnvelope uid %d: envelope date %v in UTC (zone -0000)", uid, env.Date)
		assert.Equal(t, inUTC[uid], env.DateUnknownZone, "GetMessageEnvelope uid %d: explicit unknown-zone hint", uid)
	}
}
