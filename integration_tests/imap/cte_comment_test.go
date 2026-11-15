//go:build integration

package imap_test

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/imap"
)

// TestIMAP_TransferEncodingComment covers #1075. RFC 2045 §1: MIME fields "can
// include RFC 822 comments, which have no semantic content and should be
// ignored during MIME processing", so a part with "Content-Transfer-Encoding:
// base64 (encoded)" is base64 for the stored BODYSTRUCTURE, the full-text index
// and PREVIEW alike.
func TestIMAP_TransferEncodingComment(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServerWithOptions(t, &common.IMAPServerOpts{
		Preview: imap.PreviewOptions{Enabled: true},
	})
	defer server.Close()

	c := dialPreview(t, server.Address, account)
	if err := c.conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// The recipient makes the content hash unique to this run: the FTS worker
	// reuses a vector already computed for the same body under another account.
	c.appendMessage("From: a@example.com\nTo: " + account.Email + "\nSubject: comment\nMIME-Version: 1.0\n" +
		"Content-Type: text/plain\nContent-Transfer-Encoding: base64 (encoded)\n\naGVsbG8gd29ybGQK\n")
	if err := server.FlushFTSQueue(); err != nil {
		t.Fatalf("flush FTS queue: %v", err)
	}

	if got := c.ok("FETCH 1 (BODYSTRUCTURE)"); !strings.Contains(got, `NIL NIL "base64" `) {
		t.Errorf("BODYSTRUCTURE = %q, want body-fld-enc \"base64\"", got)
	}
	if got := c.ok("UID SEARCH BODY hello"); !regexp.MustCompile(`^\* SEARCH \d+$`).MatchString(got) {
		t.Errorf("UID SEARCH BODY hello = %q, want the message", got)
	}
	if got := c.ok("FETCH 1 (PREVIEW)"); !strings.Contains(got, `PREVIEW "hello world"`) {
		t.Errorf("PREVIEW = %q, want %q", got, "hello world")
	}
}
