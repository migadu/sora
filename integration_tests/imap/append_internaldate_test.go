//go:build integration

package imap_test

import (
	"testing"
	"time"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_AppendInternalDate_CommandDateTakesPrecedence verifies that when an
// APPEND command includes an explicit date-time parameter, that date is stored
// as INTERNALDATE — even when the message itself contains a different Date: header.
//
// RFC 3501 §6.3.11:
//
//	"If a date-time is specified, the internal date SHOULD be set in the
//	 resulting message; otherwise, the internal date of the resulting message
//	 is set to the current date and time by default."
//
// The bug: server/imap/append.go first parses sentDate from the message's
// Date: header. options.Time (the APPEND command parameter) is only used when
// sentDate.IsZero(). So if the message has any Date: header, the APPEND
// command's explicit date is silently ignored.
func TestIMAP_AppendInternalDate_CommandDateTakesPrecedence(t *testing.T) {
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
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT INBOX failed: %v", err)
	}

	// Message carries an old Date: header (year 2020).
	oldMsgDate := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	// The APPEND command specifies a clearly different date (year 2025).
	appendCmdDate := time.Date(2025, 2, 9, 10, 0, 0, 0, time.UTC).Truncate(time.Second)

	msg := "From: sender@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: InternalDate Precedence Test\r\n" +
		"Date: " + oldMsgDate.Format("Mon, 02 Jan 2006 15:04:05 -0700") + "\r\n" +
		"\r\n" +
		"Testing INTERNALDATE vs Date: header priority."

	appendCmd := c.Append("INBOX", int64(len(msg)), &imap.AppendOptions{
		Time: appendCmdDate,
	})
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

	// FETCH INTERNALDATE for the appended message
	fetchResults, err := c.Fetch(
		imap.UIDSetNum(appendData.UID),
		&imap.FetchOptions{InternalDate: true, UID: true},
	).Collect()
	if err != nil {
		t.Fatalf("FETCH failed: %v", err)
	}
	if len(fetchResults) == 0 {
		t.Fatal("FETCH returned no results")
	}

	internalDate := fetchResults[0].InternalDate.UTC().Truncate(time.Second)
	t.Logf("Message Date: header : %v", oldMsgDate)
	t.Logf("APPEND command date  : %v", appendCmdDate)
	t.Logf("FETCH INTERNALDATE   : %v", internalDate)

	// ── Assertion ─────────────────────────────────────────────────────────────
	// Before the fix: internalDate equals oldMsgDate (2020-01-01) because
	// options.Time is only consulted when sentDate.IsZero().
	if !internalDate.Equal(appendCmdDate) {
		if internalDate.Equal(oldMsgDate) {
			t.Errorf("FAIL: INTERNALDATE is %v (from Date: header), should be %v (from APPEND command)",
				internalDate, appendCmdDate)
			t.Errorf("RFC 3501 §6.3.11 violation: APPEND date-time parameter must take precedence")
		} else {
			t.Errorf("FAIL: INTERNALDATE %v does not match expected APPEND command date %v",
				internalDate, appendCmdDate)
		}
	} else {
		t.Logf("PASS: INTERNALDATE correctly set to APPEND command date %v", appendCmdDate)
	}
}

// TestIMAP_AppendInternalDate_NoCommandDateUsesCurrentTime verifies that an
// APPEND without a date-time gets the current time as INTERNALDATE, even when
// the message carries an old Date: header, and that the Date: header is still
// reported as the ENVELOPE date.
//
// RFC 9051 §6.3.12 (same text in RFC 3501 §6.3.11):
//
//	"If a date-time is specified, the internal date SHOULD be set in the
//	 resulting message; otherwise, the internal date of the resulting message
//	 is set to the current date and time by default."
func TestIMAP_AppendInternalDate_NoCommandDateUsesCurrentTime(t *testing.T) {
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
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT INBOX failed: %v", err)
	}

	// An old Date: header (a restored or re-filed copy); no APPEND date-time.
	msgDate := time.Date(2020, 1, 2, 11, 4, 5, 0, time.UTC)
	msg := "From: sender@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: InternalDate Current Time Test\r\n" +
		"Date: Thu, 02 Jan 2020 03:04:05 -0800\r\n" +
		"\r\n" +
		"No APPEND date-time: INTERNALDATE is the time of the APPEND.\r\n"

	before := time.Now().Truncate(time.Second)
	appendCmd := c.Append("INBOX", int64(len(msg)), nil) // no AppendOptions.Time
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
	after := time.Now().Add(time.Second)

	fetchResults, err := c.Fetch(
		imap.UIDSetNum(appendData.UID),
		&imap.FetchOptions{InternalDate: true, Envelope: true, UID: true},
	).Collect()
	if err != nil {
		t.Fatalf("FETCH failed: %v", err)
	}
	if len(fetchResults) != 1 || fetchResults[0].Envelope == nil {
		t.Fatalf("FETCH returned %d results (envelope present: %v), want one with an envelope",
			len(fetchResults), len(fetchResults) == 1 && fetchResults[0].Envelope != nil)
	}

	internalDate := fetchResults[0].InternalDate.UTC()
	if internalDate.Before(before) || internalDate.After(after) {
		t.Errorf("INTERNALDATE = %v, want the time of the APPEND (within [%v, %v]); Date: header is %v",
			internalDate, before.UTC(), after.UTC(), msgDate)
	}
	if envDate := fetchResults[0].Envelope.Date.UTC(); !envDate.Equal(msgDate) {
		t.Errorf("ENVELOPE date = %v, want the Date: header %v", envDate, msgDate)
	}
}

// TestIMAP_AppendInternalDate_NoDateHeaderNoCommandDate verifies that when
// neither a Date: header nor an APPEND date-time is present, INTERNALDATE is
// set to a reasonable current-time value (not zero / epoch).
func TestIMAP_AppendInternalDate_NoDateHeaderNoCommandDate(t *testing.T) {
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
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT INBOX failed: %v", err)
	}

	before := time.Now().Truncate(time.Second)

	// No Date: header, no options.Time
	msg := "From: sender@example.com\r\nSubject: No-Date Test\r\n\r\nMessage with no date header."
	appendCmd := c.Append("INBOX", int64(len(msg)), nil)
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

	after := time.Now().Add(time.Second) // generous upper bound

	fetchResults, err := c.Fetch(
		imap.UIDSetNum(appendData.UID),
		&imap.FetchOptions{InternalDate: true, UID: true},
	).Collect()
	if err != nil {
		t.Fatalf("FETCH failed: %v", err)
	}
	if len(fetchResults) == 0 {
		t.Fatal("FETCH returned no results")
	}

	internalDate := fetchResults[0].InternalDate.UTC()
	t.Logf("FETCH INTERNALDATE: %v", internalDate)

	if internalDate.IsZero() {
		t.Errorf("FAIL: INTERNALDATE must not be zero when neither Date: header nor APPEND date is present")
	} else if internalDate.Before(before) || internalDate.After(after) {
		t.Errorf("FAIL: INTERNALDATE %v is outside the expected current-time window [%v, %v]",
			internalDate, before, after)
	} else {
		t.Logf("PASS: INTERNALDATE %v is within the current-time window", internalDate)
	}
}
