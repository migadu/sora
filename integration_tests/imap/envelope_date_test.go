//go:build integration

package imap_test

import (
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
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
