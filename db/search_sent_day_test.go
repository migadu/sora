package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 9051 §6.4.4 (the same text is in RFC 3501):
//
//	SENTBEFORE <date>  Messages whose [RFC5322] Date: header field (disregarding time and
//	                   timezone) is earlier than the specified date.
//	SENTON <date>      Messages whose [RFC5322] Date: header field (disregarding time and
//	                   timezone) is within the specified date.
//	SENTSINCE <date>   Messages whose [RFC5322] Date: header field (disregarding time and
//	                   timezone) is within or later than the specified date.
//
// Disregarding the timezone of "Tue, 31 Dec 2024 20:00:00 -0800" leaves 31 Dec 2024: the
// day is the one the header names, not the UTC day of the instant (1 Jan 2025 04:00 UTC).

// sentDayFixture is one message of the SENT* fixture: its Date: header and the calendar
// day that header names.
type sentDayFixture struct {
	name string
	sent time.Time
}

func sentDayZone(hours, minutes int) *time.Location {
	offset := hours*3600 + minutes*60
	if hours < 0 {
		offset = hours*3600 - minutes*60
	}
	return time.FixedZone("", offset)
}

// sentDayFixtures are dated around the turn of 2024/2025 in zones from -12:00 to +14:00,
// the full range of real zones, so the header's own day and the UTC day of the instant
// differ wherever they can. The names give the day the header itself names.
var sentDayFixtures = []sentDayFixture{
	{"30-Dec 12:00 +0000", time.Date(2024, 12, 30, 12, 0, 0, 0, time.UTC)},
	{"31-Dec 20:00 -0800 (1-Jan 04:00 UTC)", time.Date(2024, 12, 31, 20, 0, 0, 0, sentDayZone(-8, 0))},
	{"31-Dec 23:59:59 +1400 (31-Dec 09:59:59 UTC)", time.Date(2024, 12, 31, 23, 59, 59, 0, sentDayZone(14, 0))},
	{"31-Dec 23:59:59 -1200 (1-Jan 11:59:59 UTC)", time.Date(2024, 12, 31, 23, 59, 59, 0, sentDayZone(-12, 0))},
	{"31-Dec 18:30 -0530 (1-Jan 00:00 UTC)", time.Date(2024, 12, 31, 18, 30, 0, 0, sentDayZone(-5, 30))},
	{"1-Jan 08:00 +1000 (31-Dec 22:00 UTC)", time.Date(2025, 1, 1, 8, 0, 0, 0, sentDayZone(10, 0))},
	{"1-Jan 00:00 +1400 (31-Dec 10:00 UTC)", time.Date(2025, 1, 1, 0, 0, 0, 0, sentDayZone(14, 0))},
	{"1-Jan 00:00 -1200 (1-Jan 12:00 UTC)", time.Date(2025, 1, 1, 0, 0, 0, 0, sentDayZone(-12, 0))},
	{"1-Jan 05:29:59 +0530 (31-Dec 23:59:59 UTC)", time.Date(2025, 1, 1, 5, 29, 59, 0, sentDayZone(5, 30))},
	{"3-Jan 12:00 +0000", time.Date(2025, 1, 3, 12, 0, 0, 0, time.UTC)},
}

// sentDayOptions describes a message with the given Date: header time.
func sentDayOptions(accountID, mailboxID int64, name string, sent time.Time) *InsertMessageOptions {
	var bs imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain", Size: 100}
	hash := fmt.Sprintf("sentday-%d", time.Now().UnixNano())
	return &InsertMessageOptions{
		AccountID: accountID, MailboxID: mailboxID, MailboxName: "INBOX",
		S3Domain: "example.com", S3Localpart: "sentday", ContentHash: hash,
		MessageID: hash + "@example.com", Subject: name, BodyStructure: &bs, Size: 100,
		// Far from every searched date, so a key reading the wrong column finds nothing.
		InternalDate: time.Date(2030, 6, 15, 12, 0, 0, 0, time.UTC),
		SentDate:     sent,
		Recipients:   []helpers.Recipient{{AddressType: "from", EmailAddress: "sender@example.com"}},
	}
}

// insertSentDayMessage stores a message through InsertMessage, the path every ingress
// (APPEND, LMTP, Admin API delivery) takes, with the given Date: header time.
func insertSentDayMessage(t *testing.T, db *Database, accountID, mailboxID int64, name string, sent time.Time) imap.UID {
	t.Helper()
	ctx := context.Background()
	opts := sentDayOptions(accountID, mailboxID, name, sent)
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	_, uid, err := db.InsertMessage(ctx, tx, opts,
		PendingUpload{InstanceID: "test", ContentHash: opts.ContentHash, Size: 100, AccountID: accountID})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	return imap.UID(uid)
}

// TestSearchSentKeysUseHeaderDay is the regression test for #867: SENTBEFORE, SENTON and
// SENTSINCE match the day the Date: header names in its own zone, through every statement
// that takes search criteria (SEARCH, SORT, THREAD).
func TestSearchSentKeysUseHeaderDay(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db, accountID, mailboxID := setupSearchTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	uidOf := map[string]imap.UID{}
	for _, f := range sentDayFixtures {
		uidOf[f.name] = insertSentDayMessage(t, db, accountID, mailboxID, f.name, f.sent)
	}

	day := func(y int, mo time.Month, d int) time.Time { return time.Date(y, mo, d, 0, 0, 0, 0, time.UTC) }
	dec30, dec31, jan1, jan2, jan3 := day(2024, 12, 30), day(2024, 12, 31), day(2025, 1, 1), day(2025, 1, 2), day(2025, 1, 3)
	// go-imap decodes SENTON d as SentSince = d, SentBefore = d + 24h.
	senton := func(d time.Time) imap.SearchCriteria {
		return imap.SearchCriteria{SentSince: d, SentBefore: d.Add(24 * time.Hour)}
	}

	onDec31 := []string{
		"31-Dec 20:00 -0800 (1-Jan 04:00 UTC)",
		"31-Dec 23:59:59 +1400 (31-Dec 09:59:59 UTC)",
		"31-Dec 23:59:59 -1200 (1-Jan 11:59:59 UTC)",
		"31-Dec 18:30 -0530 (1-Jan 00:00 UTC)",
	}
	onJan1 := []string{
		"1-Jan 08:00 +1000 (31-Dec 22:00 UTC)",
		"1-Jan 00:00 +1400 (31-Dec 10:00 UTC)",
		"1-Jan 00:00 -1200 (1-Jan 12:00 UTC)",
		"1-Jan 05:29:59 +0530 (31-Dec 23:59:59 UTC)",
	}
	join := func(parts ...[]string) []string {
		var all []string
		for _, p := range parts {
			all = append(all, p...)
		}
		return all
	}

	tests := []struct {
		key      string
		criteria imap.SearchCriteria
		want     []string
	}{
		{"SENTON 31-Dec-2024", senton(dec31), onDec31},
		{"SENTON 1-Jan-2025", senton(jan1), onJan1},
		{"SENTON 2-Jan-2025", senton(jan2), nil},
		{"SENTBEFORE 31-Dec-2024", imap.SearchCriteria{SentBefore: dec31}, []string{"30-Dec 12:00 +0000"}},
		{"SENTBEFORE 1-Jan-2025", imap.SearchCriteria{SentBefore: jan1}, join([]string{"30-Dec 12:00 +0000"}, onDec31)},
		{"SENTSINCE 1-Jan-2025", imap.SearchCriteria{SentSince: jan1}, join(onJan1, []string{"3-Jan 12:00 +0000"})},
		{"SENTSINCE 2-Jan-2025", imap.SearchCriteria{SentSince: jan2}, []string{"3-Jan 12:00 +0000"}},
		{"NOT SENTBEFORE 1-Jan-2025", imap.SearchCriteria{Not: []imap.SearchCriteria{{SentBefore: jan1}}}, join(onJan1, []string{"3-Jan 12:00 +0000"})},
		{"NOT SENTON 31-Dec-2024", imap.SearchCriteria{Not: []imap.SearchCriteria{senton(dec31)}}, join([]string{"30-Dec 12:00 +0000", "3-Jan 12:00 +0000"}, onJan1)},
		{"OR SENTON 30-Dec-2024 SENTON 3-Jan-2025", imap.SearchCriteria{Or: [][2]imap.SearchCriteria{{senton(dec30), senton(jan3)}}}, []string{"30-Dec 12:00 +0000", "3-Jan 12:00 +0000"}},
	}

	nameOf := map[imap.UID]string{}
	for name, uid := range uidOf {
		nameOf[uid] = name
	}
	// Results are compared by fixture name, so a failure says which Date: headers moved.
	names := func(uids []imap.UID) []string {
		out := []string{}
		for _, uid := range uids {
			out = append(out, nameOf[uid])
		}
		return out
	}
	commands := []struct {
		name string
		run  func(c *imap.SearchCriteria) []imap.UID
	}{
		{"SEARCH", func(c *imap.SearchCriteria) []imap.UID {
			res, err := db.SearchMessagesWithCriteria(ctx, mailboxID, accountID, c, 0, len(sentDayFixtures))
			require.NoError(t, err)
			out := []imap.UID{}
			for _, r := range res {
				out = append(out, r.UID)
			}
			return out
		}},
		{"SORT", func(c *imap.SearchCriteria) []imap.UID {
			res, err := db.SearchMessagesSorted(ctx, mailboxID, accountID, c, []imap.SortCriterion{{Key: imap.SortKeyDate}}, 0, len(sentDayFixtures))
			require.NoError(t, err)
			out := []imap.UID{}
			for _, r := range res {
				out = append(out, r.UID)
			}
			return out
		}},
		{"THREAD", func(c *imap.SearchCriteria) []imap.UID {
			res, err := db.GetMessagesForThreading(ctx, mailboxID, accountID, c, false, false, 0)
			require.NoError(t, err)
			out := []imap.UID{}
			for _, r := range res {
				out = append(out, r.UID)
			}
			return out
		}},
	}
	for _, cmd := range commands {
		for _, tt := range tests {
			t.Run(cmd.name+" "+tt.key, func(t *testing.T) {
				criteria := tt.criteria
				want := tt.want
				if want == nil {
					want = []string{}
				}
				assert.ElementsMatch(t, want, names(cmd.run(&criteria)))
			})
		}
	}
}

// TestSearchSentKeysSkipMessagesWithoutDateHeader is the regression test for #1118: a
// message without a Date: header has no Date: header day, so SENTBEFORE, SENTON and
// SENTSINCE match none of it (RFC 9051 §6.4.4: "Messages whose [RFC5322] Date: header
// field ..."), and NOT of them matches it. sent_date holds its INTERNALDATE, the sent date
// SORT and THREAD order it by (RFC 5256 §2.2), which the SENT* keys must not mistake for
// a header. Every statement that takes search criteria is checked, the full-text query
// shapes included.
func TestSearchSentKeysSkipMessagesWithoutDateHeader(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db, accountID, mailboxID := setupSearchTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	day := func(y int, mo time.Month, d int) time.Time { return time.Date(y, mo, d, 0, 0, 0, 0, time.UTC) }
	insert := func(name string, sent, internal time.Time) imap.UID {
		t.Helper()
		opts := sentDayOptions(accountID, mailboxID, name, sent)
		opts.InternalDate = internal
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		_, uid, err := db.InsertMessage(ctx, tx, opts,
			PendingUpload{InstanceID: "test", ContentHash: opts.ContentHash, Size: 100, AccountID: accountID})
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		return imap.UID(uid)
	}
	const (
		noDate = "msg without Date: (INTERNALDATE 1-Jan-2020 10:00 +0000)"
		jan1   = "msg dated 1-Jan-2020 12:00 +0000"
		jan3   = "msg dated 3-Jan-2020 12:00 +0000"
	)
	nameOf := map[imap.UID]string{
		insert(noDate, time.Time{}, time.Date(2020, 1, 1, 10, 0, 0, 0, time.UTC)):    noDate,
		insert(jan1, time.Date(2020, 1, 1, 12, 0, 0, 0, time.UTC), day(2030, 6, 15)): jan1,
		insert(jan3, time.Date(2020, 1, 3, 12, 0, 0, 0, time.UTC), day(2030, 6, 15)): jan3,
	}

	senton := func(d time.Time) imap.SearchCriteria {
		return imap.SearchCriteria{SentSince: d, SentBefore: d.Add(24 * time.Hour)}
	}
	tests := []struct {
		key      string
		criteria imap.SearchCriteria
		want     []string
	}{
		// The fixture itself: the message is found by its INTERNALDATE.
		{"ON 1-Jan-2020", imap.SearchCriteria{Since: day(2020, 1, 1), Before: day(2020, 1, 2)}, []string{noDate}},
		{"SENTON 1-Jan-2020", senton(day(2020, 1, 1)), []string{jan1}},
		{"SENTSINCE 1-Jan-2020", imap.SearchCriteria{SentSince: day(2020, 1, 1)}, []string{jan1, jan3}},
		{"SENTBEFORE 2-Jan-2020", imap.SearchCriteria{SentBefore: day(2020, 1, 2)}, []string{jan1}},
		// More than a day from the INTERNALDATE, where sent_date alone decides.
		{"SENTSINCE 1-Dec-2019", imap.SearchCriteria{SentSince: day(2019, 12, 1)}, []string{jan1, jan3}},
		{"SENTBEFORE 1-Feb-2020", imap.SearchCriteria{SentBefore: day(2020, 2, 1)}, []string{jan1, jan3}},
		{"NOT SENTON 1-Jan-2020", imap.SearchCriteria{Not: []imap.SearchCriteria{senton(day(2020, 1, 1))}}, []string{noDate, jan3}},
		{"NOT SENTBEFORE 1-Feb-2020", imap.SearchCriteria{Not: []imap.SearchCriteria{{SentBefore: day(2020, 2, 1)}}}, []string{noDate}},
		{"OR SENTON 1-Jan-2020 SENTON 3-Jan-2020", imap.SearchCriteria{Or: [][2]imap.SearchCriteria{{senton(day(2020, 1, 1)), senton(day(2020, 1, 3))}}}, []string{jan1, jan3}},
	}

	uids := func(res []SearchMessageResult, err error) []imap.UID {
		t.Helper()
		require.NoError(t, err)
		out := []imap.UID{}
		for _, r := range res {
			out = append(out, r.UID)
		}
		return out
	}
	// Each statement shape of getSearchMessagesQueryExecutor, and THREAD's. TEXT "msg" and
	// NOT BODY "zzzz" match every fixture (the subjects; no body has an FTS row), so they
	// only steer the search onto the full-text shapes; a mailbox count of ftsCTEThreshold
	// selects the prefiltered ones.
	withTerm := func(c imap.SearchCriteria, text, notBody bool) *imap.SearchCriteria {
		if text {
			c.Text = append(c.Text, "msg")
		}
		if notBody {
			c.Not = append(c.Not, imap.SearchCriteria{Body: []string{"zzzz"}})
		}
		return &c
	}
	commands := []struct {
		name string
		run  func(c imap.SearchCriteria) []imap.UID
	}{
		{"SEARCH", func(c imap.SearchCriteria) []imap.UID {
			return uids(db.SearchMessagesWithCriteria(ctx, mailboxID, accountID, &c, 0, 3))
		}},
		{"SEARCH TEXT", func(c imap.SearchCriteria) []imap.UID {
			return uids(db.SearchMessagesWithCriteria(ctx, mailboxID, accountID, withTerm(c, true, false), 0, 3))
		}},
		{"SEARCH TEXT prefiltered", func(c imap.SearchCriteria) []imap.UID {
			return uids(db.SearchMessagesWithCriteria(ctx, mailboxID, accountID, withTerm(c, true, false), 0, ftsCTEThreshold))
		}},
		{"SEARCH NOT BODY", func(c imap.SearchCriteria) []imap.UID {
			return uids(db.SearchMessagesWithCriteria(ctx, mailboxID, accountID, withTerm(c, false, true), 0, 3))
		}},
		{"SEARCH NOT BODY prefiltered", func(c imap.SearchCriteria) []imap.UID {
			return uids(db.SearchMessagesWithCriteria(ctx, mailboxID, accountID, withTerm(c, false, true), 0, ftsCTEThreshold))
		}},
		{"SORT", func(c imap.SearchCriteria) []imap.UID {
			return uids(db.SearchMessagesSorted(ctx, mailboxID, accountID, &c, []imap.SortCriterion{{Key: imap.SortKeyDate}}, 0, 3))
		}},
		{"THREAD", func(c imap.SearchCriteria) []imap.UID {
			res, err := db.GetMessagesForThreading(ctx, mailboxID, accountID, &c, false, false, 0)
			require.NoError(t, err)
			out := []imap.UID{}
			for _, r := range res {
				out = append(out, r.UID)
			}
			return out
		}},
	}
	for _, cmd := range commands {
		for _, tt := range tests {
			t.Run(cmd.name+" "+tt.key, func(t *testing.T) {
				got := []string{}
				for _, uid := range cmd.run(tt.criteria) {
					got = append(got, nameOf[uid])
				}
				assert.ElementsMatch(t, tt.want, got)
			})
		}
	}
}

// TestSentDateOffsetStored checks what the insert paths record for the Date: header's
// zone: its offset from UTC in seconds, which COPY and MOVE carry with the rest of the row
// (TestCopyMoveCarryEveryMessageColumn), and NULL for a zone further than a day from UTC,
// which the RFC 5322 §3.3 grammar admits (zone = ( "+" / "-" ) 4DIGIT) but no real zone
// is. Such a message, like every row written before the column existed, is searched by
// its UTC day.
func TestSentDateOffsetStored(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db, accountID, mailboxID := setupSearchTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	offsetOf := func(uid imap.UID) *int32 {
		t.Helper()
		var off *int32
		require.NoError(t, db.GetReadPool().QueryRow(ctx,
			`SELECT sent_utc_offset FROM messages WHERE mailbox_id = $1 AND uid = $2`, mailboxID, uid).Scan(&off))
		return off
	}

	pst := insertSentDayMessage(t, db, accountID, mailboxID, "pst", time.Date(2024, 12, 31, 20, 0, 0, 0, sentDayZone(-8, 0)))
	ist := insertSentDayMessage(t, db, accountID, mailboxID, "ist", time.Date(2025, 1, 1, 5, 29, 59, 0, sentDayZone(5, 30)))
	// 2 Jan 01:00 +2500 is the instant 1 Jan 00:00 UTC.
	absurd := insertSentDayMessage(t, db, accountID, mailboxID, "absurd", time.Date(2025, 1, 2, 1, 0, 0, 0, time.FixedZone("", 25*3600)))

	if off := offsetOf(pst); assert.NotNil(t, off) {
		assert.Equal(t, int32(-8*3600), *off)
	}
	if off := offsetOf(ist); assert.NotNil(t, off) {
		assert.Equal(t, int32(5*3600+30*60), *off)
	}
	assert.Nil(t, offsetOf(absurd), "an offset beyond a day is not stored")

	// The importer's single and batch inserts.
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	_, imported, err := db.InsertMessageFromImporter(ctx, tx, sentDayOptions(accountID, mailboxID, "imported", time.Date(2024, 12, 31, 20, 0, 0, 0, sentDayZone(-8, 0))))
	require.NoError(t, err)
	_, batched, _, err := db.InsertMessagesBatch(ctx, tx, []*InsertMessageOptions{sentDayOptions(accountID, mailboxID, "batched", time.Date(2024, 12, 31, 20, 0, 0, 0, sentDayZone(-8, 0)))}, nil)
	require.NoError(t, err)
	require.Len(t, batched, 1)
	require.NoError(t, tx.Commit(ctx))
	for name, uid := range map[string]imap.UID{"InsertMessageFromImporter": imap.UID(imported), "InsertMessagesBatch": imap.UID(batched[0])} {
		if off := offsetOf(uid); assert.NotNil(t, off, name) {
			assert.Equal(t, int32(-8*3600), *off, name)
		}
	}

	// A row without an offset (the absurd zone, or any row older than the column) keeps
	// the UTC day of its instant.
	legacy := insertSentDayMessage(t, db, accountID, mailboxID, "legacy", time.Date(2024, 12, 31, 20, 0, 0, 0, sentDayZone(-8, 0)))
	_, err = db.GetWritePool().Exec(ctx, `UPDATE messages SET sent_utc_offset = NULL WHERE mailbox_id = $1 AND uid = $2`, mailboxID, legacy)
	require.NoError(t, err)

	jan1 := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	res, err := db.SearchMessagesWithCriteria(ctx, mailboxID, accountID, &imap.SearchCriteria{SentSince: jan1, SentBefore: jan1.Add(24 * time.Hour)}, 0, 10)
	require.NoError(t, err)
	var got []imap.UID
	for _, r := range res {
		got = append(got, r.UID)
	}
	assert.ElementsMatch(t, []imap.UID{ist, absurd, legacy}, got, "SENTON 1-Jan-2025")
}

// sentPlanNode is the subset of an EXPLAIN (ANALYZE, FORMAT JSON) node TestSentDateSearchIsIndexOnly reads.
type sentPlanNode struct {
	NodeType     string         `json:"Node Type"`
	RelationName string         `json:"Relation Name"`
	IndexName    string         `json:"Index Name"`
	Plans        []sentPlanNode `json:"Plans"`
}

func (n sentPlanNode) walk(visit func(sentPlanNode)) {
	visit(n)
	for _, c := range n.Plans {
		c.walk(visit)
	}
}

// TestSentDateSearchIsIndexOnly guards the cost of the SENT* keys: the zone offset is not
// in the header covering index (idx_messages_mailbox_headers_v2), so the mailbox must still
// be read through an Index Only Scan, and the offset looked up only for the messages sent
// within a day of the searched date, where the zone can decide the day. Neither is
// sent_date_unknown (#1118): the mailbox's messages without a Date: header are checked
// through their own partial index.
func TestSentDateSearchIsIndexOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db, accountID, mailboxID := setupSearchTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	bs := imap.BodyStructure(&imap.BodyStructureSinglePart{Type: "text", Subtype: "plain", Size: 100})
	bsBytes, err := helpers.SerializeBodyStructureGob(&bs)
	require.NoError(t, err)

	// One message an hour from 1 Jan 2024 on, so a day either side of the searched date
	// holds 48 of them.
	const rows = 20000
	start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err = db.GetWritePool().Exec(ctx, `
		WITH inserted AS (
			INSERT INTO messages
			(account_id, mailbox_id, mailbox_path, uid, message_id, in_reply_to, content_hash, s3_domain, s3_localpart,
			 internal_date, size, subject, sent_date, body_structure, recipients_json, created_modseq,
			 subject_sort, from_name_sort, from_email_sort, to_name_sort, to_email_sort, cc_email_sort)
			SELECT $1, $2, 'INBOX', g, '<sentplan-' || g || '@test>', '', 'sentplanhash-' || g, 'd', 'lp-' || g,
			       $5::timestamptz + (g || ' hours')::interval, 100, 'Report ' || g, $5::timestamptz + (g || ' hours')::interval,
			       $3, '[]'::jsonb, nextval('messages_modseq'),
			       'report ' || g, 'sender', 'sender@example.com', 'me', 'me@example.com', NULL
			FROM generate_series(1, $4::int) g
			RETURNING id, mailbox_id
		)
		INSERT INTO message_state (message_id, mailbox_id, flags, custom_flags)
		SELECT id, mailbox_id, 0, '[]'::jsonb FROM inserted`, accountID, mailboxID, bsBytes, rows, start)
	require.NoError(t, err)
	// A few messages without a Date: header, sent_date being their INTERNALDATE, well after
	// the searched date: SENTSINCE must leave them out (#1118).
	const noDateRows = 5
	_, err = db.GetWritePool().Exec(ctx, `UPDATE messages SET sent_date_unknown = TRUE
		WHERE mailbox_id = $1 AND uid BETWEEN 15000 AND $2`, mailboxID, 15000+noDateRows-1)
	require.NoError(t, err)
	_, err = db.GetWritePool().Exec(ctx, "VACUUM ANALYZE messages")
	require.NoError(t, err)
	_, err = db.GetWritePool().Exec(ctx, "VACUUM ANALYZE message_state")
	require.NoError(t, err)

	tracer := &queryCapturingTracer{}
	tracedPool := newCapturingPool(t, ctx, db.GetReadPool(), tracer)
	defer tracedPool.Close()
	traced := &Database{WritePool: db.GetWritePool(), ReadPool: tracedPool}

	// SENTSINCE 1-Jun-2025: every message from then on (hours 12408 to 20000).
	since := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	wantMatches := rows - int(since.Sub(start).Hours()) + 1 - noDateRows
	results, err := traced.SearchMessagesWithCriteria(ctx, mailboxID, accountID, &imap.SearchCriteria{SentSince: since}, 0, rows)
	require.NoError(t, err)
	require.Len(t, results, wantMatches)

	var searchStmt *capturedQuery
	for i, q := range tracer.captured() {
		if strings.Contains(q.SQL, "FROM messages m") && strings.Contains(q.SQL, "sent_date") {
			searchStmt = &tracer.captured()[i]
		}
	}
	require.NotNil(t, searchStmt, "harness broken: the search statement was not captured")

	conn, err := db.GetReadPool().Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()
	tx, err := conn.Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, "SET LOCAL enable_seqscan = off")
	require.NoError(t, err)
	// Counting the offset lookups needs function statistics, which only a superuser may
	// switch on for a session.
	var superuser bool
	require.NoError(t, tx.QueryRow(ctx, "SELECT current_setting('is_superuser') = 'on'").Scan(&superuser))
	if superuser {
		_, err = tx.Exec(ctx, "SET LOCAL track_functions = 'all'")
		require.NoError(t, err)
	}
	var raw []byte
	err = tx.QueryRow(ctx, "EXPLAIN (ANALYZE, FORMAT JSON) "+searchStmt.SQL, searchStmt.Args...).Scan(&raw)
	require.NoError(t, err, "failed to EXPLAIN the captured statement:\n%s", searchStmt.SQL)
	var explained []struct {
		Plan sentPlanNode `json:"Plan"`
	}
	require.NoError(t, json.Unmarshal(raw, &explained))
	require.Len(t, explained, 1)

	indexName, _ := headerIndex(t)
	const noDateIndex = "idx_messages_mailbox_sent_date_unknown"
	var indexOnly, noDateIndexed bool
	var other []string
	explained[0].Plan.walk(func(n sentPlanNode) {
		if n.RelationName != "messages" {
			return
		}
		if n.NodeType == "Index Only Scan" && n.IndexName == indexName {
			indexOnly = true
			return
		}
		if n.NodeType == "Index Only Scan" && n.IndexName == noDateIndex {
			noDateIndexed = true
			return
		}
		other = append(other, n.NodeType+" "+n.IndexName)
	})
	assert.True(t, indexOnly, "SENTSINCE must read the mailbox through an Index Only Scan on %s; plan:\n%s", indexName, string(raw))
	assert.True(t, noDateIndexed, "SENTSINCE must read the messages without a Date: header through an Index Only Scan on %s; plan:\n%s", noDateIndex, string(raw))
	assert.Empty(t, other, "SENTSINCE must not read messages any other way; plan:\n%s", string(raw))

	// An imported mailbox can have many messages without usable Date headers.
	// When their IDs outgrow work_mem, NOT IN stops hashing them and rescans a
	// materialized list for each candidate. Inspect the real captured SEARCH
	// statement without executing that quadratic plan.
	_, err = db.GetWritePool().Exec(ctx, `UPDATE messages SET sent_date_unknown = TRUE
		WHERE mailbox_id = $1 AND uid <= $2`, mailboxID, rows/2)
	require.NoError(t, err)
	_, err = db.GetWritePool().Exec(ctx, "ANALYZE messages")
	require.NoError(t, err)
	_, err = tx.Exec(ctx, "SET LOCAL work_mem = '64kB'")
	require.NoError(t, err)
	err = tx.QueryRow(ctx, "EXPLAIN (FORMAT JSON) "+searchStmt.SQL, searchStmt.Args...).Scan(&raw)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &explained))
	var materializedNoDateSet bool
	explained[0].Plan.walk(func(n sentPlanNode) {
		if n.NodeType == "Materialize" {
			n.walk(func(child sentPlanNode) {
				if child.IndexName == noDateIndex {
					materializedNoDateSet = true
				}
			})
		}
	})
	assert.False(t, materializedNoDateSet, "SEARCH must not rescan a materialized no-Date set per message when it outgrows work_mem; plan:\n%s", string(raw))

	if !superuser {
		t.Log("not a superuser: offset lookups not counted")
		return
	}
	var lookups int64
	err = tx.QueryRow(ctx, `SELECT COALESCE(sum(calls), 0) FROM pg_stat_xact_user_functions WHERE funcname = 'message_sent_utc_offset'`).Scan(&lookups)
	require.NoError(t, err)
	assert.Equal(t, int64(48), lookups, "the zone offset must be looked up exactly for the 48 messages within a day of the date")
}
