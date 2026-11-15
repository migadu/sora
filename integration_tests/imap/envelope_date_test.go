//go:build integration

package imap_test

import (
	"fmt"
	"testing"
	"time"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIMAP_EnvelopeDate_UsesDateHeaderNotInternalDate is a regression test for
// audit finding H1 (2026-07-01 IMAP command-correctness audit).
//
// db/fetch.go:16 BuildEnvelope sets `envelope.Date = msg.InternalDate`, but
// RFC 3501 §7.4.2 defines the ENVELOPE "date" field as the message's
// origination Date: header — carried separately as msg.SentDate.
//
// The two diverge whenever INTERNALDATE != the Date: header. We force that here
// by APPENDing with an explicit date-time (options.Time), which becomes
// INTERNALDATE while SentDate keeps the message's Date: header value.
//
//	Date: header  -> 2020-01-01  (SentDate; the RFC-correct ENVELOPE date)
//	APPEND time   -> 2025-02-09  (INTERNALDATE)
//
// Expected (RFC-correct): env.Date == 2020-01-01 (Date: header).
// Actual   (bug):         env.Date == 2025-02-09 (INTERNALDATE).
//
// Fix: db/fetch.go should use msg.SentDate (falling back to InternalDate only
// when SentDate.IsZero()).
func TestIMAP_EnvelopeDate_UsesDateHeaderNotInternalDate(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login failed: %v", err)
	}

	dateHeader := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)  // -> SentDate
	appendTime := time.Date(2025, 2, 9, 10, 0, 0, 0, time.UTC) // -> InternalDate

	msg := "From: sender@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Envelope Date Test\r\n" +
		"Date: " + dateHeader.Format("Mon, 02 Jan 2006 15:04:05 -0700") + "\r\n" +
		"Message-ID: <envdate@example.com>\r\n" +
		"\r\n" +
		"Envelope date must come from the Date: header, not INTERNALDATE.\r\n"

	appendCmd := c.Append("INBOX", int64(len(msg)), &imap.AppendOptions{Time: appendTime})
	if _, err := appendCmd.Write([]byte(msg)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	appendData, err := appendCmd.Wait()
	if err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}

	msgs, err := c.Fetch(imap.UIDSetNum(appendData.UID), &imap.FetchOptions{
		Envelope:     true,
		InternalDate: true,
	}).Collect()
	if err != nil {
		t.Fatalf("FETCH failed: %v", err)
	}
	if len(msgs) != 1 || msgs[0].Envelope == nil {
		t.Fatalf("expected 1 message with ENVELOPE, got %d", len(msgs))
	}

	envDate := msgs[0].Envelope.Date.UTC().Truncate(time.Second)
	internalDate := msgs[0].InternalDate.UTC().Truncate(time.Second)
	t.Logf("Date: header (want) : %v", dateHeader)
	t.Logf("INTERNALDATE        : %v", internalDate)
	t.Logf("ENVELOPE date (got) : %v", envDate)

	if !envDate.Equal(dateHeader) {
		if envDate.Equal(appendTime) {
			t.Errorf("REGRESSION: ENVELOPE date is INTERNALDATE %v, must be the Date: header %v (RFC 3501 §7.4.2)",
				appendTime, dateHeader)
		} else {
			t.Errorf("REGRESSION: ENVELOPE date %v does not match the Date: header %v (RFC 3501 §7.4.2)",
				envDate, dateHeader)
		}
	}
}

// TestIMAP_EnvelopeAbsentDateIsNIL: a message without a Date: header has a NIL date
// member in its ENVELOPE, however it reached the mailbox. RFC 9051 section 7.5.2: "If the
// Date, Subject, In-Reply-To, and Message-ID header fields are absent in the [RFC5322]
// header, the corresponding member of the envelope is NIL". Before the fix the APPEND
// time was reported as the Date: header.
func TestIMAP_EnvelopeAbsentDateIsNIL(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	rc := dialRaw(t, server.Address)
	defer rc.conn.Close()
	rc.login(account)

	rc.append("a1", "INBOX", "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: no date\r\n\r\nbody\r\n")
	rc.append("a2", "INBOX", "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: dated\r\nDate: Thu, 02 Jan 2020 03:04:05 -0800\r\n\r\nbody\r\n")
	for _, name := range []string{"Copied", "Moved"} {
		_, tagged := rc.cmd("c", "CREATE "+name)
		require.Contains(t, tagged, "OK")
	}
	_, tagged := rc.cmd("s", "SELECT INBOX")
	require.Contains(t, tagged, "OK")

	untagged, tagged := rc.cmd("f", "FETCH 1:2 (ENVELOPE)")
	require.Contains(t, tagged, "OK")
	require.Len(t, untagged, 2, "one FETCH response per message: %v", untagged)
	require.Contains(t, untagged[0], `(ENVELOPE (NIL "no date" `,
		"the date member must be NIL for a message without a Date: header: %s", untagged[0])
	require.Contains(t, untagged[1], `(ENVELOPE ("`, "a Date: header is reported: %s", untagged[1])
	require.Contains(t, untagged[1], `Jan 2020`, "a Date: header is reported: %s", untagged[1])

	_, tagged = rc.cmd("cp", "COPY 1 Copied")
	require.Contains(t, tagged, "OK")
	_, tagged = rc.cmd("mv", "MOVE 1 Moved")
	require.Contains(t, tagged, "OK")

	for _, name := range []string{"Copied", "Moved"} {
		_, tagged := rc.cmd("s", "SELECT "+name)
		require.Contains(t, tagged, "OK")
		untagged, tagged := rc.cmd("f", "FETCH 1 (ENVELOPE)")
		require.Contains(t, tagged, "OK")
		require.Len(t, untagged, 1, "%s: %v", name, untagged)
		require.Contains(t, untagged[0], `(ENVELOPE (NIL "no date" `,
			"%s: the date member must stay NIL: %s", name, untagged[0])
	}
}

// TestIMAP_EnvelopeDateKeepsHeaderZone: the ENVELOPE date names the day, time of day and
// zone the Date: header was written in, whatever zone the server runs in. RFC 9051 section
// 7.5.2: the envelope "is computed by the server by parsing the [RFC5322] header into the
// component parts", and the section 8 example gives the date member as the header's own
// "Wed, 17 Jul 1996 02:23:25 -0700 (PDT)". Before the fix the date was the stored instant
// in the server's zone: "Tue, 31 Dec 2024 20:00:00 -0800" came out as
// "Wed, 01 Jan 2025 04:00:00 +0000" on a server in UTC.
func TestIMAP_EnvelopeDateKeepsHeaderZone(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	rc := dialRaw(t, server.Address)
	defer rc.conn.Close()
	rc.login(account)

	// Date: header -> the envelope date member. At most one of these zones can be the
	// server's, so a date rendered in the server's zone fails at least two of them.
	dates := []struct{ header, envelope string }{
		{"Tue, 31 Dec 2024 20:00:00 -0800", `"Tue, 31 Dec 2024 20:00:00 -0800"`},
		{"Wed, 1 Jan 2025 05:45:00 +0545", `"Wed, 01 Jan 2025 05:45:00 +0545"`},
		{"Wed, 01 Jan 2025 00:00:00 +0000", `"Wed, 01 Jan 2025 00:00:00 +0000"`},
	}
	for i, d := range dates {
		rc.append(fmt.Sprintf("a%d", i), "INBOX", "From: alice@example.com\r\nTo: bob@example.com\r\n"+
			fmt.Sprintf("Subject: zone %d\r\nDate: %s\r\n\r\nbody\r\n", i, d.header))
	}
	_, tagged := rc.cmd("c", "CREATE Copied")
	require.Contains(t, tagged, "OK")
	_, tagged = rc.cmd("s", "SELECT INBOX")
	require.Contains(t, tagged, "OK")
	_, tagged = rc.cmd("cp", "COPY 1:* Copied")
	require.Contains(t, tagged, "OK")

	for _, name := range []string{"INBOX", "Copied"} {
		_, tagged := rc.cmd("s", "SELECT "+name)
		require.Contains(t, tagged, "OK")
		untagged, tagged := rc.cmd("f", "FETCH 1:* (ENVELOPE)")
		require.Contains(t, tagged, "OK")
		require.Len(t, untagged, len(dates), "%s: one FETCH response per message: %v", name, untagged)
		for i, d := range dates {
			assert.Contains(t, untagged[i], "(ENVELOPE ("+d.envelope+" ",
				"%s: Date: %s must be reported in its own zone: %s", name, d.header, untagged[i])
		}
	}
}

// TestIMAP_EnvelopeDateObsoleteZone: an alphabetic Date: zone (RFC 5322 section 4.3
// obs-zone, which a receiver MUST accept per section 4) is stored at the offset that section
// gives it ("PDT is semantically equivalent to -0700"), and a military or unknown zone as
// "-0000", whatever zone the server runs in. Before the fix net/mail looked the name up in
// time.Local: PDT came out as +0000 on a server in UTC, EST in July as 03:23:25 -0400 on
// one in America/New_York, and a military or lower-case zone did not parse at all (NIL).
// At most one of PDT and EST can be the server's in July, so a zone looked up in the
// server's zone fails at least one of them.
func TestIMAP_EnvelopeDateObsoleteZone(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	rc := dialRaw(t, server.Address)
	defer rc.conn.Close()
	rc.login(account)

	dates := []struct{ header, envelope string }{
		{"Wed, 17 Jul 1996 02:23:25 PDT", `"Wed, 17 Jul 1996 02:23:25 -0700"`},
		{"Wed, 17 Jul 1996 02:23:25 EST", `"Wed, 17 Jul 1996 02:23:25 -0500"`},
		{"Wed, 17 Jan 1996 02:23:25 CST (Central Standard Time)", `"Wed, 17 Jan 1996 02:23:25 -0600"`},
		{"Wed, 17 Jul 1996 02:23:25 pdt", `"Wed, 17 Jul 1996 02:23:25 -0700"`},
		{"Wed, 17 Jul 1996 02:23:25 Z", `"Wed, 17 Jul 1996 02:23:25 +0000"`},
		{"Wed, 17 Jan 1996 02:23:25 CET", `"Wed, 17 Jan 1996 02:23:25 +0000"`},
	}
	for i, d := range dates {
		rc.append(fmt.Sprintf("a%d", i), "INBOX", "From: alice@example.com\r\nTo: bob@example.com\r\n"+
			fmt.Sprintf("Subject: obs %d\r\nDate: %s\r\n\r\nbody\r\n", i, d.header))
	}
	_, tagged := rc.cmd("s", "SELECT INBOX")
	require.Contains(t, tagged, "OK")
	untagged, tagged := rc.cmd("f", "FETCH 1:* (ENVELOPE)")
	require.Contains(t, tagged, "OK")
	require.Len(t, untagged, len(dates), "one FETCH response per message: %v", untagged)
	for i, d := range dates {
		assert.Contains(t, untagged[i], "(ENVELOPE ("+d.envelope+" ",
			"Date: %s must be read at its RFC 5322 offset: %s", d.header, untagged[i])
	}
}
