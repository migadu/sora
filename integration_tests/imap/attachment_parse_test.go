//go:build integration

package imap_test

import (
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// A malformed multipart still has to be accepted and fetched, but the body
// structure extractor's synthetic text/plain fallback must not classify it.
func TestIMAP_AppendMalformedMimeLeavesAttachmentUnknown(t *testing.T) {
	b, account := common.SetupIMAPServer(t)
	defer b.Close()
	c, err := imapclient.DialInsecure(b.Address, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err = c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatal(err)
	}
	raw := strings.Join([]string{
		"Subject: malformed multipart",
		`Content-Type: multipart/mixed; boundary="declared"`, "",
		"--actual", "Content-Type: text/plain", "", "See attached.",
		"--actual", "Content-Type: application/pdf",
		`Content-Disposition: attachment; filename="report.pdf"`, "", "JVBERi0=",
		"--actual--", "",
	}, "\r\n")
	uid := appendRaw(t, c, "INBOX", raw, nil)
	if _, err = c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	flags := fetchFlags(t, c, uid)
	for _, f := range flags {
		if strings.EqualFold(string(f), "$hasattachment") || strings.EqualFold(string(f), "$hasnoattachment") {
			t.Fatalf("APPEND of malformed MIME stored %v; want unknown attachment status", flags)
		}
	}
	// The fallback remains usable as BODYSTRUCTURE rather than rejecting mail.
	if _, err := c.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{
		BodyStructure: &imap.FetchItemBodyStructure{Extended: true},
	}).Collect(); err != nil {
		t.Fatal(err)
	}
}
