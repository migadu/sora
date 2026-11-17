//go:build integration

package imap_test

import (
	"testing"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_AppendFTSKeepsTextBesideSkippedPart: ExtractPlaintextBody skips an inline
// part whose Content-Type parameters do not parse and still returns the text part,
// with an error naming the skipped part. APPEND must index that text, as LMTP does;
// it stored "", so SEARCH BODY found the message only when LMTP had delivered it
// (#1808).
func TestIMAP_AppendFTSKeepsTextBesideSkippedPart(t *testing.T) {
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

	raw := "From: sender@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: probe\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=b1\r\n" +
		"\r\n" +
		"--b1\r\n" +
		"Content-Type: image/png; name=a b.png\r\n" +
		"Content-Disposition: inline\r\n" +
		"\r\n" +
		"PNG\r\n" +
		"--b1\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"hello words\r\n" +
		"--b1--\r\n"
	appendCmd := c.Append("INBOX", int64(len(raw)), nil)
	if _, err := appendCmd.Write([]byte(raw)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	appended, err := appendCmd.Wait()
	if err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	if err := server.FlushFTSQueue(); err != nil {
		t.Fatalf("Failed to flush FTS queue: %v", err)
	}

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT INBOX failed: %v", err)
	}
	data, err := c.UIDSearch(&imap.SearchCriteria{Body: []string{"hello"}}, nil).Wait()
	if err != nil {
		t.Fatalf("UID SEARCH BODY failed: %v", err)
	}
	if uids := data.AllUIDs(); len(uids) != 1 || uids[0] != appended.UID {
		t.Fatalf("UID SEARCH BODY \"hello\" = %v, want [%d]: the text part's text was not indexed", uids, appended.UID)
	}
}
