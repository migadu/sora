//go:build integration

package imap_test

import (
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// appendRaw appends msg to mailbox with flags and returns its UID.
func appendRaw(t *testing.T, c *imapclient.Client, mailbox, msg string, flags []imap.Flag) imap.UID {
	t.Helper()
	cmd := c.Append(mailbox, int64(len(msg)), &imap.AppendOptions{Flags: flags})
	if _, err := cmd.Write([]byte(msg)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := cmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	data, err := cmd.Wait()
	if err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}
	return data.UID
}

// TestIMAP_AppendSetsAttachmentKeyword: APPEND fills in the RFC 9979 §4
// attachment keyword when the client set neither, and keeps the client's own.
func TestIMAP_AppendSetsAttachmentKeyword(t *testing.T) {
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

	plain := "From: a@example.com\r\nSubject: plain\r\n\r\nhello\r\n"
	withPDF := strings.Join([]string{
		"From: a@example.com",
		"Subject: attached",
		`Content-Type: multipart/mixed; boundary="b"`,
		"",
		"--b",
		"Content-Type: text/plain",
		"",
		"see attached",
		"--b",
		"Content-Type: application/pdf",
		`Content-Disposition: attachment; filename="report.pdf"`,
		"",
		"JVBERi0=",
		"--b--",
		"",
	}, "\r\n")

	uidPlain := appendRaw(t, c, "INBOX", plain, nil)
	uidPDF := appendRaw(t, c, "INBOX", withPDF, []imap.Flag{imap.FlagSeen})
	uidClient := appendRaw(t, c, "INBOX", plain, []imap.Flag{"$HasAttachment"})

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT INBOX failed: %v", err)
	}

	tests := []struct {
		name      string
		uid       imap.UID
		want, not imap.Flag
	}{
		{"plain message", uidPlain, "$hasnoattachment", "$hasattachment"},
		{"PDF attachment", uidPDF, "$hasattachment", "$hasnoattachment"},
		{"client's own keyword is kept", uidClient, "$hasattachment", "$hasnoattachment"},
	}
	for _, tt := range tests {
		flags := fetchFlags(t, c, tt.uid)
		if n, _ := countFold(flags, string(tt.want)); n != 1 {
			t.Errorf("%s: flags = %v, want %s", tt.name, flags, tt.want)
		}
		if n, _ := countFold(flags, string(tt.not)); n != 0 {
			t.Errorf("%s: flags = %v, want no %s", tt.name, flags, tt.not)
		}
	}
}
