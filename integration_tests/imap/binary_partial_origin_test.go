//go:build integration

package imap_test

import (
	"testing"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_BinaryPartial_IncludesOriginOctet is a regression test for audit
// finding H4 (2026-07-01 IMAP command-correctness audit).
//
// RFC 3516 §4.2.2 / RFC 3501 §7.4.2: a partial BINARY fetch MUST echo the
// <origin octet> in the response, e.g. `BINARY[]<0> ~{10}...`. The fork's
// WriteBinarySection ignores section.Partial and emits `BINARY[] ~{10}...`,
// dropping the `<0>`. Strict clients treat the missing origin as a malformed
// FETCH.
//
// The go-imap client now parses the echoed <origin> into Section.Partial, so we
// can observe its presence directly.
//
// Expected: the response section carries Partial (the echoed origin).
// Actual (bug): Partial is nil because the server omitted the origin octet.
func TestIMAP_BinaryPartial_IncludesOriginOctet(t *testing.T) {
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

	msg := "From: sender@example.com\r\nTo: " + account.Email +
		"\r\nSubject: Binary Partial Test\r\n\r\n" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 body long enough for a partial fetch\r\n"
	ac := c.Append("INBOX", int64(len(msg)), nil)
	if _, err := ac.Write([]byte(msg)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := ac.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	if _, err := ac.Wait(); err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}

	// Request a partial BINARY fetch: BINARY[]<0.10>.
	opts := &imap.FetchOptions{
		BinarySection: []*imap.FetchItemBinarySection{
			{Partial: &imap.SectionPartial{Offset: 0, Size: 10}},
		},
	}
	msgs, err := c.Fetch(imap.SeqSetNum(1), opts).Collect()
	if err != nil {
		t.Fatalf("partial BINARY FETCH failed: %v", err)
	}
	if len(msgs) != 1 || len(msgs[0].BinarySection) != 1 {
		t.Fatalf("expected 1 message with 1 binary section, got %d msgs", len(msgs))
	}

	sec := msgs[0].BinarySection[0]
	t.Logf("got %d bytes; Section.Partial=%+v", len(sec.Bytes), sec.Section.Partial)

	if len(sec.Bytes) != 10 {
		t.Errorf("expected 10 bytes from <0.10> partial fetch, got %d", len(sec.Bytes))
	}
	if sec.Section.Partial == nil {
		t.Errorf("REGRESSION: partial BINARY response omits the <origin> octet; " +
			"RFC 3516 §4.2.2 requires the response to echo e.g. BINARY[]<0>.")
	}
}
