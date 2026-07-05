//go:build integration

package imap_test

import (
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_AppendUID_SaveToSent reproduces the Thunderbird "save a sent copy"
// flow and asserts the server returns a correct APPENDUID (RFC 4315).
//
// Why this matters: after SMTP send, Thunderbird's compose pipeline runs
// Copy → Filter. The Copy stage is the IMAP APPEND into Sent; it completes on
// the tagged "OK [APPENDUID <uidvalidity> <uid>]". The Filter stage then does
// folder.GetMessageHeader(messageKey) with messageKey == the UID from APPENDUID
// and runs PostOutgoing message filters. If the APPENDUID is wrong — zero UID,
// wrong UIDVALIDITY, or a UID that does not actually resolve to the just-saved
// message — the client cannot locate the header it just wrote, which manifests
// as the "Saving message… Status: Filter" popup hanging.
//
// This test locks down that invariant: the returned (UIDVALIDITY, UID) must be
// non-zero, the UIDVALIDITY must match the mailbox, and a UID FETCH of the
// returned UID must return exactly the message we appended.
func TestIMAP_AppendUID_SaveToSent(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Learn the Sent mailbox's UIDVALIDITY up front — Thunderbird keeps this and
	// expects the APPENDUID to carry the same value.
	sel, err := c.Select("Sent", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT Sent failed: %v", err)
	}
	mailboxUIDValidity := sel.UIDValidity
	if mailboxUIDValidity == 0 {
		t.Fatal("SELECT Sent returned UIDVALIDITY 0 (RFC 3501 requires a non-zero UIDVALIDITY)")
	}
	t.Logf("Sent UIDVALIDITY=%d, initial NumMessages=%d", mailboxUIDValidity, sel.NumMessages)

	const subject = "Save-to-Sent APPENDUID Test"
	sentCopy := "From: " + account.Email + "\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject: " + subject + "\r\n" +
		"Message-ID: <appenduid-sent-1@example.com>\r\n" +
		"\r\n" +
		"This is the sent copy Thunderbird saves after SMTP submission.\r\n"

	// APPEND with \Seen, exactly as Thunderbird flags a saved sent message.
	appendCmd := c.Append("Sent", int64(len(sentCopy)), &imap.AppendOptions{
		Flags: []imap.Flag{imap.FlagSeen},
	})
	if _, err := appendCmd.Write([]byte(sentCopy)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	appendData, err := appendCmd.Wait()
	if err != nil {
		t.Fatalf("APPEND to Sent failed: %v", err)
	}

	// ── APPENDUID assertions ──────────────────────────────────────────────────
	if appendData == nil {
		t.Fatal("APPEND returned no APPENDUID response code (data is nil); UIDPLUS clients cannot locate the saved message")
	}
	t.Logf("APPENDUID: UIDVALIDITY=%d UID=%d", appendData.UIDValidity, appendData.UID)

	if appendData.UID == 0 {
		t.Error("APPENDUID UID is 0 — Thunderbird would use messageKey=0 and fail to find the saved header")
	}
	if appendData.UIDValidity == 0 {
		t.Error("APPENDUID UIDVALIDITY is 0 (RFC 4315 requires the mailbox UIDVALIDITY)")
	}
	if appendData.UIDValidity != mailboxUIDValidity {
		t.Errorf("APPENDUID UIDVALIDITY=%d does not match Sent mailbox UIDVALIDITY=%d",
			appendData.UIDValidity, mailboxUIDValidity)
	}

	// ── The Thunderbird invariant: the returned UID must resolve to the message
	// we just saved. This mirrors folder.GetMessageHeader(messageKey) in the
	// Filter stage. A UID FETCH of the APPENDUID must return exactly one message
	// with the subject we appended.
	fetched, err := c.Fetch(
		imap.UIDSetNum(appendData.UID),
		&imap.FetchOptions{UID: true, Envelope: true},
	).Collect()
	if err != nil {
		t.Fatalf("UID FETCH of APPENDUID %d failed: %v", appendData.UID, err)
	}
	if len(fetched) != 1 {
		t.Fatalf("UID FETCH of APPENDUID %d returned %d messages, want exactly 1 (client cannot locate the saved message)",
			appendData.UID, len(fetched))
	}
	if got := fetched[0].UID; got != appendData.UID {
		t.Errorf("UID FETCH returned UID %d, want %d (APPENDUID)", got, appendData.UID)
	}
	if got := fetched[0].Envelope.Subject; got != subject {
		t.Errorf("UID FETCH of APPENDUID resolved to subject %q, want %q — APPENDUID points at the wrong message",
			got, subject)
	}
	t.Logf("APPENDUID %d correctly resolves to the saved message %q", appendData.UID, subject)
}

// TestIMAP_AppendUID_SequentialSavesMonotonic verifies that saving several
// messages to Sent in one session (a busy Thunderbird session) yields strictly
// increasing, distinct UIDs sharing one UIDVALIDITY, and that every returned UID
// remains independently fetchable. A duplicated or non-monotonic UID would make
// Thunderbird's per-message filter lookup ambiguous.
func TestIMAP_AppendUID_SequentialSavesMonotonic(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	sel, err := c.Select("Sent", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT Sent failed: %v", err)
	}
	uidValidity := sel.UIDValidity

	const n = 3
	uids := make([]imap.UID, 0, n)
	for i := 0; i < n; i++ {
		subject := "Sequential Sent Save"
		msg := "From: " + account.Email + "\r\n" +
			"To: recipient@example.com\r\n" +
			"Subject: " + subject + "\r\n" +
			"\r\n" +
			"Sequential save body.\r\n"

		appendCmd := c.Append("Sent", int64(len(msg)), &imap.AppendOptions{
			Flags: []imap.Flag{imap.FlagSeen},
		})
		if _, err := appendCmd.Write([]byte(msg)); err != nil {
			t.Fatalf("APPEND #%d write failed: %v", i+1, err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("APPEND #%d close failed: %v", i+1, err)
		}
		appendData, err := appendCmd.Wait()
		if err != nil {
			t.Fatalf("APPEND #%d failed: %v", i+1, err)
		}
		if appendData == nil {
			t.Fatalf("APPEND #%d returned no APPENDUID", i+1)
		}
		if appendData.UIDValidity != uidValidity {
			t.Errorf("APPEND #%d UIDVALIDITY=%d, want stable %d", i+1, appendData.UIDValidity, uidValidity)
		}
		if appendData.UID == 0 {
			t.Errorf("APPEND #%d returned UID 0", i+1)
		}
		if i > 0 && appendData.UID <= uids[i-1] {
			t.Errorf("APPEND #%d UID=%d is not strictly greater than previous UID=%d (UIDs must be monotonically increasing)",
				i+1, appendData.UID, uids[i-1])
		}
		uids = append(uids, appendData.UID)
	}
	t.Logf("Sequential APPENDUID UIDs: %v (UIDVALIDITY=%d)", uids, uidValidity)

	// Every returned UID must still resolve to exactly one message.
	for i, uid := range uids {
		fetched, err := c.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{UID: true}).Collect()
		if err != nil {
			t.Fatalf("UID FETCH of save #%d (UID=%d) failed: %v", i+1, uid, err)
		}
		if len(fetched) != 1 {
			t.Errorf("UID FETCH of save #%d (UID=%d) returned %d messages, want 1", i+1, uid, len(fetched))
		}
	}
}
