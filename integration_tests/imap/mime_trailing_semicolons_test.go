//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	imapserver "github.com/migadu/sora/server/imap"
)

func TestIMAP_TrailingSemicolonMIMEReadParity(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServerWithOptions(t, &common.IMAPServerOpts{Preview: imapserver.PreviewOptions{Enabled: true}})
	defer server.Close()
	c := dialPreview(t, server.Address, account)
	for i, suffix := range []string{"", ";;", "; ;"} {
		t.Run(fmt.Sprintf("multipart_%q", suffix), func(t *testing.T) {
			raw := fmt.Sprintf("From: sender@example.com\nTo: %s\nSubject: multipart-%d\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=B%s\n\n--B\nContent-Type: text/plain; charset=utf-8\n\nhello words\n--B--\n", account.Email, i, suffix)
			c.appendMessage(raw)
			out := c.ok(fmt.Sprintf("FETCH %d (BODYSTRUCTURE BODY.PEEK[1] PREVIEW)", i+1))
			if !strings.Contains(out, "BODY[1] {11}") || !strings.Contains(out, "hello words") || !strings.Contains(strings.ToUpper(out), `"TEXT" "PLAIN"`) {
				t.Fatalf("wire MIME fields disagree: %q", out)
			}
		})
	}
	t.Run("single-part_charset", func(t *testing.T) {
		c.appendMessage("From: sender@example.com\nSubject: charset\nMIME-Version: 1.0\nContent-Type: text/plain; charset=iso-8859-1;;\n\ncaf\xe9 words")
		out := c.ok("FETCH 4 (BODYSTRUCTURE BODY.PEEK[1] PREVIEW)")
		if !strings.Contains(out, "BODY[1] {10}") || !strings.Contains(out, "caf\xe9 words") || !strings.Contains(out, "café words") || !strings.Contains(strings.ToLower(out), "iso-8859-1") {
			t.Fatalf("charset wire fields disagree: %q", out)
		}
	})
	if err := server.FlushFTSQueue(); err != nil {
		t.Fatal(err)
	}
	if out := c.ok("SEARCH BODY words"); strings.TrimSpace(out) != "* SEARCH 1 2 3 4" {
		t.Fatalf("new-ingress FTS omitted recovered MIME text: %q", out)
	}
}
