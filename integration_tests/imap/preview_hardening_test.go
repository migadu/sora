//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/imap"
)

func TestIMAP_FetchPreviewMIMEHardening(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServerWithOptions(t, &common.IMAPServerOpts{
		Preview: imap.PreviewOptions{Enabled: true},
	})
	defer server.Close()
	mixed := func(parts ...string) string {
		return "Content-Type: multipart/mixed; boundary=outer\n\n--outer\n" +
			strings.Join(parts, "\n--outer\n") + "\n--outer--\n"
	}
	plain := "Content-Type: text/plain\n\nActual message"
	cases := []struct{ name, message, want string }{
		{"unknown disposition", mixed("Content-Type: text/plain\nContent-Disposition: x-private\n\nPrivate attachment", plain), "Actual message"},
		{"malformed disposition", mixed("Content-Type: text/plain\nContent-Disposition: \"attachment\"; filename=secret.txt\n\nPrivate attachment", plain), "Actual message"},
		{"implicit digest message", mixed("Content-Type: multipart/digest; boundary=digest\n\n--digest\n\nFrom: sender@example.com\nSubject: Encapsulated message\n\nPrivate attachment\n--digest--", plain), "Actual message"},
		{"unknown attachment encoding", mixed("Content-Type: application/octet-stream\nContent-Disposition: attachment\nContent-Transfer-Encoding: x-uuencode\n\nEncoded attachment", plain), "Actual message"},
		{"unknown encoding and charset", mixed("Content-Type: text/plain; charset=x-unknown\nContent-Transfer-Encoding: x-uuencode\n\nEncoded bytes", plain), "Actual message"},
		{"malformed nested multipart", mixed("Content-Type: text/html\n\n<p>HTML fallback</p>", "Content-Type: multipart/related\n\nNo boundary", plain), "Actual message"},
		{"usable content type", "Content-Type: text/plain; name=mail body.txt\n\nActual message", "Actual message"},
		{"preformatted reply", "Content-Type: text/html\n\n<pre>&gt; Earlier proposal " + strings.Repeat("old detail ", 30) + "\n\nActual message\n-- \nPrivate signature</pre>", "Actual message"},
		{"implicit head end", "Content-Type: text/html\n\n<head><meta charset=utf-8><p>Actual message</p>", "Actual message"},
		{"HTML PGP armor", "Content-Type: text/html\n\n<div>-----BEGIN PGP MESSAGE-----</div><div>Encrypted bytes</div>", ""},
		{"header field limit", strings.Repeat("X:\n", 300) + "\nOutside header budget", ""},
		{"part count limit", "Content-Type: multipart/mixed; boundary=many\n\n" + strings.Repeat("--many\n\n\n", 200) + "--many\nContent-Type: text/plain\n\nOutside part budget\n--many--\n", ""},
		{"charset decoding", "Content-Type: text/plain; charset=iso-8859-1\n\nGr\xfc\xdfe", "Grüße"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := dialPreview(t, server.Address, account)
			if err := c.conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
				t.Fatal(err)
			}
			c.appendMessage("From: sender@example.com\nSubject: " + tc.name + "\n" + tc.message)
			for _, item := range []string{"PREVIEW (LAZY)", "PREVIEW"} {
				command := fmt.Sprintf("FETCH %d (%s)", i+1, item)
				got := c.ok(command)
				if tc.want == "" {
					if !strings.Contains(got, `PREVIEW ""`) {
						t.Errorf("%s = %q, want empty preview", command, got)
					}
				} else if !strings.Contains(got, tc.want) || strings.Contains(got, "Private attachment") || strings.Contains(got, "Private signature") {
					t.Errorf("%s = %q, want %q", command, got, tc.want)
				}
			}
			c.ok("NOOP")
		})
	}
}

func TestIMAP_FetchPreviewRelatedRoot(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServerWithOptions(t, &common.IMAPServerOpts{
		Preview: imap.PreviewOptions{Enabled: true},
	})
	defer server.Close()
	c := dialPreview(t, server.Address, account)
	if err := c.conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	c.appendMessage("From: sender@example.com\nSubject: Meeting update\nMIME-Version: 1.0\n" +
		"Content-Type: multipart/related; type=\"text/html\"; boundary=b; start=\"<root@example.com>\"\n\n" +
		"--b\nContent-Type: text/html\nContent-ID: <archive@example.com>\n\n" +
		"<p>Archived message: The meeting is confirmed.</p>\n" +
		"--b\nContent-Type: text/html\nContent-ID: <root@example.com>\n\n" +
		"<p>The meeting is cancelled.</p><a href=\"cid:archive@example.com\">Previous message</a>\n" +
		"--b--\n")

	for _, item := range []string{"PREVIEW (LAZY)", "PREVIEW"} {
		command := fmt.Sprintf("FETCH 1 (%s)", item)
		got := c.ok(command)
		if !strings.Contains(got, `PREVIEW "The meeting is cancelled. Previous message"`) || strings.Contains(got, "confirmed") {
			t.Errorf("%s = %q, want the related root without the archived resource", command, got)
		}
	}
}
