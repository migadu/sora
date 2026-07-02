//go:build integration

package imap_test

import (
	"strings"
	"testing"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_Store_Keyword_NilSubstring_Preserved is a regression test for a Medium
// audit finding (Unit 6, 2026-07-01).
//
// helpers.SanitizeFlags rejects any flag whose uppercased value *contains* the
// substring "NIL" or "NULL" (helpers/sanitizer.go), not just the exact tokens.
// So a legitimate client keyword like "Nile" is silently stripped: STORE reports
// OK but the keyword is never persisted — data loss with no [LIMIT]-style signal.
//
// Expected: after STORE +FLAGS (Nile), FETCH FLAGS reports the "Nile" keyword.
// Actual (bug): "Nile" is dropped; FETCH FLAGS does not include it.
func TestIMAP_Store_Keyword_NilSubstring_Preserved(t *testing.T) {
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
		"\r\nSubject: Keyword NIL Substring Test\r\n\r\nbody\r\n"
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

	// "Nile" contains the substring "NIL" and is silently dropped by SanitizeFlags.
	const keyword = imap.Flag("Nile")
	if _, err := c.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{keyword},
	}, nil).Collect(); err != nil {
		t.Fatalf("STORE +FLAGS (Nile) failed: %v", err)
	}

	msgs, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Flags: true}).Collect()
	if err != nil {
		t.Fatalf("FETCH FLAGS failed: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}

	found := false
	for _, f := range msgs[0].Flags {
		if strings.EqualFold(string(f), string(keyword)) {
			found = true
		}
	}
	t.Logf("flags after STORE +FLAGS (Nile): %v", msgs[0].Flags)

	if !found {
		t.Errorf("REGRESSION: keyword %q was silently dropped by SanitizeFlags "+
			"(substring \"NIL\"); STORE returned OK but the keyword is not persisted.", keyword)
	}
}
